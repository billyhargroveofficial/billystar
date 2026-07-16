use crate::host_state::{
    AddressFamily, InterfaceIdentity, IpPrefix, NamespaceIdentity, RoutePurpose, RouteResource,
    SessionId,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCommand {
    program: &'static str,
    args: Vec<String>,
}

impl RouteCommand {
    fn new(program: &'static str, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }

    fn display(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }

    pub fn program(&self) -> &'static str {
        self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteStep {
    apply: RouteCommand,
    undo: RouteCommand,
}

impl RouteStep {
    fn new(apply: RouteCommand, undo: RouteCommand) -> Self {
        Self { apply, undo }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoutePlatform {
    Macos,
    Linux,
    Windows,
    Unsupported,
}

fn current_platform() -> RoutePlatform {
    if cfg!(target_os = "macos") {
        RoutePlatform::Macos
    } else if cfg!(target_os = "linux") {
        RoutePlatform::Linux
    } else if cfg!(target_os = "windows") {
        RoutePlatform::Windows
    } else {
        RoutePlatform::Unsupported
    }
}

/// Owns only the route mutations that completed successfully.
///
/// Each entry is the exact inverse of one applied command. If a later command in
/// the same installation fails, already-applied commands are rolled back before
/// the error is returned. Normal cleanup runs the same journal in reverse order.
pub struct RouteGuard {
    undo: Vec<RouteCommand>,
    /// Present only for the journal-backed Linux route path.  Keeping the
    /// durable interface identity beside the inverse lets live teardown prove
    /// the exact route delta before the caller acknowledges its WAL removal.
    #[cfg(any(test, target_os = "linux"))]
    strict_linux_owned: Option<LinuxOwnedRouteRuntime>,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug)]
struct LinuxOwnedRouteRuntime {
    spec: LinuxOwnedRouteSpec,
    resource: RouteResource,
}

/// A Linux carrier path captured before split-default routes point at the TUN.
///
/// Endpoint refresh must never call `ip route get` after `0.0.0.0/1` and
/// `128.0.0.0/1` are installed: at that point the lookup can select the tunnel
/// itself and create a recursive carrier route.  Keep this small, typed snapshot
/// and use it for every later staged bypass belonging to the same underlay path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxUnderlayPath {
    gateway: Option<Ipv4Addr>,
    iface: String,
}

pub const SHADOWPIPE_ROUTE_PROTOCOL: u8 = 186;
pub const LINUX_MAIN_ROUTE_TABLE: u32 = 254;
pub const MAX_LINUX_RECOVERY_ROUTES: usize = 128;
pub const MAX_LINUX_ROUTE_INSPECTION_BYTES: usize = 64 * 1024;
pub const MAX_LINUX_ROUTE_INSPECTION_RECORDS: usize = MAX_LINUX_RECOVERY_ROUTES;
pub const MAX_LINUX_ROUTE_COMMAND_STDERR_BYTES: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const LINUX_ROUTE_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Per-session Linux route owner attributes. Protocol 186 is a cooperative
/// reservation, not authentication; the non-zero metric uses the full 32-bit
/// kernel field as a fail-closed collision detector derived from the CSPRNG
/// session identity. Durable ownership still comes from the complete journal
/// identity and exact runtime inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxRouteOwner {
    protocol: u8,
    metric: u32,
}

impl LinuxRouteOwner {
    pub fn for_session(session: SessionId) -> Self {
        let bytes = session.as_bytes();
        let entropy = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Self {
            protocol: SHADOWPIPE_ROUTE_PROTOCOL,
            metric: if entropy == 0 { 1 } else { entropy },
        }
    }

    pub fn protocol(self) -> u8 {
        self.protocol
    }

    pub fn metric(self) -> u32 {
        self.metric
    }
}

/// Complete typed identity of one owned IPv4 route in Linux main table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxOwnedRouteSpec {
    purpose: RoutePurpose,
    destination: Ipv4Addr,
    prefix_len: u8,
    gateway: Option<Ipv4Addr>,
    iface: String,
    owner: LinuxRouteOwner,
}

impl LinuxOwnedRouteSpec {
    pub fn endpoint_bypass(
        endpoint: Ipv4Addr,
        path: &LinuxUnderlayPath,
        owner: LinuxRouteOwner,
    ) -> Result<Self> {
        Self::bypass(RoutePurpose::EndpointBypass, endpoint, path, owner)
    }

    pub fn ssh_bypass(
        client: Ipv4Addr,
        path: &LinuxUnderlayPath,
        owner: LinuxRouteOwner,
    ) -> Result<Self> {
        Self::bypass(RoutePurpose::SshBypass, client, path, owner)
    }

    fn bypass(
        purpose: RoutePurpose,
        destination: Ipv4Addr,
        path: &LinuxUnderlayPath,
        owner: LinuxRouteOwner,
    ) -> Result<Self> {
        validate_linux_iface(&path.iface)?;
        Ok(Self {
            purpose,
            destination,
            prefix_len: 32,
            gateway: path.gateway,
            iface: path.iface.clone(),
            owner,
        })
    }

    fn from_journal_resource(resource: &RouteResource) -> Result<Self> {
        anyhow::ensure!(
            resource.family == AddressFamily::Ipv4,
            "owned route recovery supports IPv4 resources only"
        );
        anyhow::ensure!(
            resource.table == LINUX_MAIN_ROUTE_TABLE,
            "owned route must use Linux main table {LINUX_MAIN_ROUTE_TABLE}"
        );
        anyhow::ensure!(
            resource.protocol == SHADOWPIPE_ROUTE_PROTOCOL,
            "owned route must use protocol {SHADOWPIPE_ROUTE_PROTOCOL}"
        );
        anyhow::ensure!(resource.metric != 0, "owned route metric must be non-zero");
        anyhow::ensure!(
            resource.output.ifindex != 0,
            "owned route output ifindex must be non-zero"
        );
        validate_linux_iface(&resource.output.name)?;
        let IpAddr::V4(destination) = resource.destination.address else {
            anyhow::bail!("owned IPv4 route has a non-IPv4 destination")
        };
        let gateway = match resource.gateway {
            Some(IpAddr::V4(gateway)) => Some(gateway),
            Some(IpAddr::V6(_)) => anyhow::bail!("owned IPv4 route has an IPv6 gateway"),
            None => None,
        };
        match resource.purpose {
            RoutePurpose::SplitDefault => {
                anyhow::ensure!(
                    resource.destination.prefix_len == 1
                        && gateway.is_none()
                        && (destination == Ipv4Addr::UNSPECIFIED
                            || destination == Ipv4Addr::new(128, 0, 0, 0)),
                    "invalid split-default journal resource"
                );
            }
            RoutePurpose::EndpointBypass | RoutePurpose::SshBypass => {
                anyhow::ensure!(
                    resource.destination.prefix_len == 32,
                    "invalid bypass journal resource"
                );
            }
        }
        Ok(Self {
            purpose: resource.purpose,
            destination,
            prefix_len: resource.destination.prefix_len,
            gateway,
            iface: resource.output.name.clone(),
            owner: LinuxRouteOwner {
                protocol: resource.protocol,
                metric: resource.metric,
            },
        })
    }

    pub fn purpose(&self) -> RoutePurpose {
        self.purpose
    }

    pub fn journal_resource_with_ifindex(&self, ifindex: u32) -> Result<RouteResource> {
        anyhow::ensure!(ifindex != 0, "owned route output ifindex must be non-zero");
        validate_linux_iface(&self.iface)?;
        match self.purpose {
            RoutePurpose::SplitDefault => anyhow::ensure!(
                self.prefix_len == 1 && self.gateway.is_none(),
                "invalid split-default owned route"
            ),
            RoutePurpose::EndpointBypass | RoutePurpose::SshBypass => {
                anyhow::ensure!(self.prefix_len == 32, "invalid bypass owned route")
            }
        }
        Ok(RouteResource {
            purpose: self.purpose,
            family: AddressFamily::Ipv4,
            table: LINUX_MAIN_ROUTE_TABLE,
            destination: IpPrefix {
                address: IpAddr::V4(self.destination),
                prefix_len: self.prefix_len,
            },
            gateway: self.gateway.map(IpAddr::V4),
            output: InterfaceIdentity {
                name: self.iface.clone(),
                ifindex,
            },
            protocol: self.owner.protocol,
            metric: self.owner.metric,
        })
    }

    /// Convert to the durable route vocabulary using the interface identity
    /// currently visible in this process' Linux network namespace.
    #[cfg(target_os = "linux")]
    pub fn journal_resource(&self) -> Result<RouteResource> {
        self.journal_resource_with_ifindex(linux_ifindex(&self.iface)?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn journal_resource(&self) -> Result<RouteResource> {
        anyhow::bail!("Linux route ifindex capture is only available on Linux")
    }

    pub fn split_default(
        destination: Ipv4Addr,
        iface: impl Into<String>,
        owner: LinuxRouteOwner,
    ) -> Result<Self> {
        anyhow::ensure!(
            destination == Ipv4Addr::UNSPECIFIED || destination == Ipv4Addr::new(128, 0, 0, 0),
            "split-default destination must be 0.0.0.0 or 128.0.0.0"
        );
        let iface = iface.into();
        validate_linux_iface(&iface)?;
        Ok(Self {
            purpose: RoutePurpose::SplitDefault,
            destination,
            prefix_len: 1,
            gateway: None,
            iface,
            owner,
        })
    }

    pub fn destination(&self) -> Ipv4Addr {
        self.destination
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.gateway
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn owner(&self) -> LinuxRouteOwner {
        self.owner
    }

    fn destination_prefix(&self) -> String {
        format!("{}/{}", self.destination, self.prefix_len)
    }

    fn exact_route_arguments(&self) -> Vec<String> {
        let mut arguments = vec!["unicast".to_string(), self.destination_prefix()];
        if let Some(gateway) = self.gateway {
            arguments.extend(["via".to_string(), gateway.to_string()]);
        }
        arguments.extend([
            "dev".to_string(),
            self.iface.clone(),
            "table".to_string(),
            LINUX_MAIN_ROUTE_TABLE.to_string(),
            "proto".to_string(),
            self.owner.protocol.to_string(),
            "metric".to_string(),
            self.owner.metric.to_string(),
            "scope".to_string(),
            if self.gateway.is_some() {
                "global".to_string()
            } else {
                "link".to_string()
            },
        ]);
        arguments
    }

    fn command(&self, operation: &'static str) -> RouteCommand {
        let mut arguments = vec!["-4".to_string(), "route".to_string(), operation.to_string()];
        arguments.extend(self.exact_route_arguments());
        RouteCommand {
            program: "ip",
            args: arguments,
        }
    }

    #[cfg(test)]
    fn steps(&self) -> Vec<RouteStep> {
        vec![RouteStep::new(self.command("add"), self.command("del"))]
    }
}

fn validate_linux_iface(iface: &str) -> Result<()> {
    anyhow::ensure!(
        !iface.is_empty()
            && iface.len() < 16
            && !iface.bytes().any(|byte| byte == 0 || byte == b'/')
            && !iface.chars().any(char::is_whitespace),
        "invalid Linux interface name {iface:?}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_ifindex(iface: &str) -> Result<u32> {
    use std::ffi::CString;

    validate_linux_iface(iface)?;
    let iface = CString::new(iface).context("Linux interface name contains NUL")?;
    // SAFETY: `iface` is a live, NUL-terminated C string for the duration of
    // the call. `if_nametoindex` does not retain the pointer.
    let ifindex = unsafe { libc::if_nametoindex(iface.as_ptr()) };
    if ifindex == 0 {
        return Err(std::io::Error::last_os_error()).context("resolve Linux interface ifindex");
    }
    Ok(ifindex)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxOwnedRouteClassification {
    ExactOwnedPresent,
    Absent,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxIpRouteRecord {
    dst: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<Ipv4Addr>,
    dev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    metric: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
}

impl LinuxOwnedRouteSpec {
    fn json_destination(&self) -> String {
        if self.prefix_len == 32 {
            self.destination.to_string()
        } else {
            self.destination_prefix()
        }
    }

    fn expected_json_record(&self, include_protocol: bool) -> LinuxIpRouteRecord {
        LinuxIpRouteRecord {
            dst: self.json_destination(),
            gateway: self.gateway,
            dev: self.iface.clone(),
            protocol: include_protocol.then(|| self.owner.protocol.to_string()),
            // `-N` asks iproute2 to emit scope identifiers numerically.
            scope: self.gateway.is_none().then(|| "253".to_string()),
            metric: self.owner.metric,
            flags: Vec::new(),
        }
    }
}

fn parse_linux_route_listing(output: &[u8]) -> Result<Vec<LinuxIpRouteRecord>> {
    anyhow::ensure!(
        output.len() <= MAX_LINUX_ROUTE_INSPECTION_BYTES,
        "Linux route JSON exceeds {} bytes",
        MAX_LINUX_ROUTE_INSPECTION_BYTES
    );
    let mut records: Vec<LinuxIpRouteRecord> =
        serde_json::from_slice(output).context("parse strict Linux route JSON")?;
    anyhow::ensure!(
        records.len() <= MAX_LINUX_ROUTE_INSPECTION_RECORDS,
        "Linux route JSON exceeds {} records",
        MAX_LINUX_ROUTE_INSPECTION_RECORDS
    );
    for record in &mut records {
        match record.flags.as_slice() {
            [] => {}
            [flag] if flag == "linkdown" => record.flags.clear(),
            _ => anyhow::bail!(
                "Linux route has identity-affecting, duplicate, or unknown flags: {:?}",
                record.flags
            ),
        }
    }
    Ok(records)
}

fn classify_linux_owned_route_detailed(
    session: SessionId,
    resource: &RouteResource,
    inspection_json: &[u8],
    live_ifindex: Option<u32>,
) -> Result<LinuxOwnedRouteClassification> {
    let spec = LinuxOwnedRouteSpec::from_journal_resource(resource)?;
    anyhow::ensure!(
        spec.owner == LinuxRouteOwner::for_session(session),
        "owned route attributes do not match the journal session"
    );
    let records = parse_linux_route_listing(inspection_json)?;
    if records.is_empty() {
        return Ok(LinuxOwnedRouteClassification::Absent);
    }
    if records.len() != 1
        || records[0] != spec.expected_json_record(true)
        || live_ifindex != Some(resource.output.ifindex)
    {
        return Ok(LinuxOwnedRouteClassification::Conflict);
    }
    Ok(LinuxOwnedRouteClassification::ExactOwnedPresent)
}

/// Pure classification of one exact-prefix `ip -j -N -4 route show` result.
/// Malformed, oversized, duplicate, modified, or interface-reused observations
/// all collapse to `Conflict`; only an empty array means `Absent`.
pub fn classify_linux_owned_route(
    session: SessionId,
    resource: &RouteResource,
    inspection_json: &[u8],
    live_ifindex: Option<u32>,
) -> LinuxOwnedRouteClassification {
    classify_linux_owned_route_detailed(session, resource, inspection_json, live_ifindex)
        .unwrap_or(LinuxOwnedRouteClassification::Conflict)
}

#[derive(Clone, Debug)]
struct LinuxRecoveryTarget {
    #[cfg(any(test, target_os = "linux"))]
    ordinal: usize,
    spec: LinuxOwnedRouteSpec,
    resource: RouteResource,
}

fn validate_linux_recovery_resources(
    session: SessionId,
    resources: &[RouteResource],
) -> Result<Vec<LinuxRecoveryTarget>> {
    anyhow::ensure!(
        resources.len() <= MAX_LINUX_RECOVERY_ROUTES,
        "Linux route recovery exceeds {MAX_LINUX_RECOVERY_ROUTES} resources"
    );
    let mut destinations = BTreeSet::new();
    let mut owner_metric = None;
    let expected_owner = LinuxRouteOwner::for_session(session);
    let mut targets = Vec::with_capacity(resources.len());
    for resource in resources {
        let spec = LinuxOwnedRouteSpec::from_journal_resource(resource)?;
        anyhow::ensure!(
            spec.owner == expected_owner,
            "owned route attributes do not match the journal session"
        );
        anyhow::ensure!(
            destinations.insert((spec.destination, spec.prefix_len)),
            "duplicate owned route destination {}/{}",
            spec.destination,
            spec.prefix_len
        );
        if let Some(expected) = owner_metric {
            anyhow::ensure!(
                spec.owner.metric == expected,
                "owned recovery resources have multiple session metrics"
            );
        } else {
            owner_metric = Some(spec.owner.metric);
        }
        targets.push(LinuxRecoveryTarget {
            #[cfg(any(test, target_os = "linux"))]
            ordinal: targets.len(),
            spec,
            resource: resource.clone(),
        });
    }
    Ok(targets)
}

#[cfg(any(test, target_os = "linux"))]
fn route_removal_rank(purpose: RoutePurpose) -> u8 {
    match purpose {
        RoutePurpose::SplitDefault => 0,
        RoutePurpose::EndpointBypass | RoutePurpose::SshBypass => 1,
    }
}

fn owner_inspection_command() -> RouteCommand {
    RouteCommand::new(
        "ip",
        &[
            "-j", "-N", "-4", "route", "show", "table", "254", "proto", "186",
        ],
    )
}

fn exact_inspection_command(spec: &LinuxOwnedRouteSpec) -> RouteCommand {
    RouteCommand {
        program: "ip",
        args: vec![
            "-j".to_string(),
            "-N".to_string(),
            "-4".to_string(),
            "route".to_string(),
            "show".to_string(),
            "table".to_string(),
            LINUX_MAIN_ROUTE_TABLE.to_string(),
            "exact".to_string(),
            spec.destination_prefix(),
        ],
    }
}

/// Deterministic read-only inspection set: first the complete reserved-protocol
/// namespace, then one unfiltered exact-prefix query per journal resource.
pub fn linux_owned_route_inspection_commands(
    session: SessionId,
    resources: &[RouteResource],
) -> Result<Vec<RouteCommand>> {
    let mut targets = validate_linux_recovery_resources(session, resources)?;
    targets.sort_by_key(|target| (target.spec.destination, target.spec.prefix_len));
    let mut commands = Vec::with_capacity(targets.len() + 1);
    commands.push(owner_inspection_command());
    commands.extend(
        targets
            .iter()
            .map(|target| exact_inspection_command(&target.spec)),
    );
    Ok(commands)
}

/// Exact single-route deletion. Every kernel identity field from the durable
/// resource is retained; no replace, flush, prefix-only, or heuristic deletion
/// is ever generated.
pub fn linux_owned_route_delete_command(
    session: SessionId,
    resource: &RouteResource,
) -> Result<RouteCommand> {
    let spec = LinuxOwnedRouteSpec::from_journal_resource(resource)?;
    anyhow::ensure!(
        spec.owner == LinuxRouteOwner::for_session(session),
        "owned route attributes do not match the journal session"
    );
    Ok(spec.command("del"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedRouteState {
    ExactRemaining,
    #[cfg(any(test, target_os = "linux"))]
    Absent,
    #[cfg(any(test, target_os = "linux"))]
    Removed,
}

#[derive(Clone, Debug)]
struct PreparedRouteEntry {
    target: LinuxRecoveryTarget,
    initial: LinuxOwnedRouteClassification,
    state: PreparedRouteState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxRoutePrepareError {
    Conflict { detail: String },
    Operational { detail: String },
}

impl std::fmt::Display for LinuxRoutePrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { detail } => {
                write!(formatter, "Linux route preflight conflict: {detail}")
            }
            Self::Operational { detail } => {
                write!(
                    formatter,
                    "Linux route preflight operation failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for LinuxRoutePrepareError {}

#[cfg(any(test, target_os = "linux"))]
impl LinuxRoutePrepareError {
    fn conflict(error: impl std::fmt::Display) -> Self {
        Self::Conflict {
            detail: error.to_string(),
        }
    }

    fn operational(error: impl std::fmt::Display) -> Self {
        Self::Operational {
            detail: error.to_string(),
        }
    }
}

/// Late convergence errors are intentionally typed: ownership, ordering,
/// namespace, or race evidence must poison the durable journal, while inability
/// to run/inspect/delete through the bounded CLI remains safe to retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxRouteConvergeError {
    Conflict { detail: String },
    Operational { detail: String },
}

impl LinuxRouteConvergeError {
    #[cfg(any(test, target_os = "linux"))]
    fn conflict(error: impl std::fmt::Display) -> Self {
        Self::Conflict {
            detail: error.to_string(),
        }
    }

    fn operational(error: impl std::fmt::Display) -> Self {
        Self::Operational {
            detail: error.to_string(),
        }
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict { .. })
    }
}

impl std::fmt::Display for LinuxRouteConvergeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { detail } => {
                write!(formatter, "Linux route convergence conflict: {detail}")
            }
            Self::Operational { detail } => {
                write!(
                    formatter,
                    "Linux route convergence operation failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for LinuxRouteConvergeError {}

#[cfg(any(test, target_os = "linux"))]
fn map_namespace_prepare_error(error: anyhow::Error) -> LinuxRoutePrepareError {
    error
        .downcast_ref::<LinuxRoutePrepareError>()
        .cloned()
        .unwrap_or_else(|| LinuxRoutePrepareError::operational(error))
}

#[cfg(any(test, target_os = "linux"))]
fn map_namespace_convergence_error(error: anyhow::Error) -> LinuxRouteConvergeError {
    error
        .downcast_ref::<LinuxRouteConvergeError>()
        .cloned()
        .unwrap_or_else(|| LinuxRouteConvergeError::operational(error))
}

#[cfg(any(test, target_os = "linux"))]
fn map_execution_convergence_error(error: anyhow::Error) -> LinuxRouteConvergeError {
    error
        .downcast_ref::<LinuxRouteConvergeError>()
        .cloned()
        .unwrap_or_else(|| LinuxRouteConvergeError::operational(error))
}

/// A conflict-free, all-routes preflight that can service the generic host
/// recovery driver's one-resource-at-a-time checkpoints. The caller must pass
/// resources in journal operation order; route-relative removal order is then
/// split-default first followed by bypass routes, matching host-state ranks.
pub struct PreparedLinuxRouteRecovery {
    #[cfg(any(test, target_os = "linux"))]
    session: SessionId,
    #[cfg(any(test, target_os = "linux"))]
    same_boot: bool,
    expected_namespace: NamespaceIdentity,
    entries: Vec<PreparedRouteEntry>,
}

impl PreparedLinuxRouteRecovery {
    pub fn expected_namespace(&self) -> NamespaceIdentity {
        self.expected_namespace
    }

    pub fn classification(
        &self,
        resource: &RouteResource,
    ) -> Option<LinuxOwnedRouteClassification> {
        self.entries
            .iter()
            .find(|entry| &entry.target.resource == resource)
            .map(|entry| entry.initial)
    }

    pub fn classifications(&self) -> Vec<(RouteResource, LinuxOwnedRouteClassification)> {
        self.entries
            .iter()
            .map(|entry| (entry.target.resource.clone(), entry.initial))
            .collect()
    }

    pub fn remaining_exact_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state == PreparedRouteState::ExactRemaining)
            .count()
    }

    #[cfg(any(test, target_os = "linux"))]
    fn expected_owner_records_excluding(&self, excluded: Option<usize>) -> Vec<LinuxIpRouteRecord> {
        let mut expected: Vec<_> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(index, entry)| {
                Some(*index) != excluded && entry.state == PreparedRouteState::ExactRemaining
            })
            .map(|(_, entry)| entry.target.spec.expected_json_record(false))
            .collect();
        expected.sort();
        expected
    }

    #[cfg(any(test, target_os = "linux"))]
    fn expected_owner_records_for_step(
        &self,
        target_index: usize,
        target_is_exact: bool,
    ) -> Vec<LinuxIpRouteRecord> {
        let mut expected: Vec<_> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(index, entry)| {
                if *index == target_index {
                    target_is_exact
                } else {
                    entry.state == PreparedRouteState::ExactRemaining
                }
            })
            .map(|(_, entry)| entry.target.spec.expected_json_record(false))
            .collect();
        expected.sort();
        expected
    }

    #[cfg(any(test, target_os = "linux"))]
    fn verify_owner_census_against(
        output: &[u8],
        expected: &[LinuxIpRouteRecord],
    ) -> std::result::Result<(), LinuxRouteConvergeError> {
        let mut actual =
            parse_linux_route_listing(output).map_err(LinuxRouteConvergeError::operational)?;
        if actual.iter().any(|record| record.protocol.is_some()) {
            return Err(LinuxRouteConvergeError::operational(
                "reserved-protocol listing unexpectedly retained a protocol field",
            ));
        }
        actual.sort();
        if actual != expected {
            return Err(LinuxRouteConvergeError::conflict(
                "reserved-protocol route namespace contains unknown, duplicate, missing, or racing state",
            ));
        }
        Ok(())
    }

    #[cfg(any(test, target_os = "linux"))]
    fn verify_owner_census(
        &self,
        output: &[u8],
        excluded: Option<usize>,
    ) -> std::result::Result<(), LinuxRouteConvergeError> {
        Self::verify_owner_census_against(output, &self.expected_owner_records_excluding(excluded))
    }

    #[cfg(any(test, target_os = "linux"))]
    fn classify_current_with<R>(
        &self,
        index: usize,
        output: &[u8],
        resolve_ifindex: &mut R,
    ) -> std::result::Result<LinuxOwnedRouteClassification, LinuxRouteConvergeError>
    where
        R: FnMut(&str) -> Result<u32>,
    {
        let entry = &self.entries[index];
        let parsed =
            parse_linux_route_listing(output).map_err(LinuxRouteConvergeError::operational)?;
        let live_ifindex =
            if parsed.len() == 1 && parsed[0] == entry.target.spec.expected_json_record(true) {
                Some(
                    resolve_ifindex(&entry.target.resource.output.name)
                        .map_err(LinuxRouteConvergeError::operational)?,
                )
            } else {
                None
            };
        classify_linux_owned_route_detailed(
            self.session,
            &entry.target.resource,
            output,
            live_ifindex,
        )
        .map_err(LinuxRouteConvergeError::conflict)
    }

    #[cfg(any(test, target_os = "linux"))]
    fn next_pending_index(&self) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.state != PreparedRouteState::Removed)
    }

    #[cfg(any(test, target_os = "linux"))]
    fn prepare_with<N, I, R>(
        session: SessionId,
        expected_namespace: NamespaceIdentity,
        resources: &[RouteResource],
        mut verify_namespace: N,
        mut inspect: I,
        mut resolve_ifindex: R,
    ) -> std::result::Result<Self, LinuxRoutePrepareError>
    where
        N: FnMut() -> Result<()>,
        I: FnMut(&RouteCommand) -> Result<Vec<u8>>,
        R: FnMut(&str) -> Result<u32>,
    {
        let mut targets = validate_linux_recovery_resources(session, resources)
            .map_err(LinuxRoutePrepareError::conflict)?;
        targets.sort_by_key(|target| (route_removal_rank(target.spec.purpose), target.ordinal));
        verify_namespace().map_err(map_namespace_prepare_error)?;

        let owner_before =
            inspect(&owner_inspection_command()).map_err(LinuxRoutePrepareError::operational)?;
        let mut entries = Vec::with_capacity(targets.len());
        let mut expected_present = Vec::new();
        for target in targets {
            verify_namespace().map_err(map_namespace_prepare_error)?;
            let output = inspect(&exact_inspection_command(&target.spec))
                .map_err(LinuxRoutePrepareError::operational)?;
            let parsed =
                parse_linux_route_listing(&output).map_err(LinuxRoutePrepareError::operational)?;
            let live_ifindex =
                if parsed.len() == 1 && parsed[0] == target.spec.expected_json_record(true) {
                    Some(
                        resolve_ifindex(&target.resource.output.name)
                            .map_err(LinuxRoutePrepareError::operational)?,
                    )
                } else {
                    None
                };
            let classification = classify_linux_owned_route_detailed(
                session,
                &target.resource,
                &output,
                live_ifindex,
            )
            .map_err(LinuxRoutePrepareError::conflict)?;
            let state = match classification {
                LinuxOwnedRouteClassification::ExactOwnedPresent => {
                    expected_present.push(target.spec.expected_json_record(false));
                    PreparedRouteState::ExactRemaining
                }
                LinuxOwnedRouteClassification::Absent => PreparedRouteState::Absent,
                LinuxOwnedRouteClassification::Conflict => {
                    return Err(LinuxRoutePrepareError::Conflict {
                        detail: format!(
                            "owned route differs at {}/{}",
                            target.spec.destination, target.spec.prefix_len
                        ),
                    })
                }
            };
            entries.push(PreparedRouteEntry {
                target,
                initial: classification,
                state,
            });
        }
        verify_namespace().map_err(map_namespace_prepare_error)?;
        let owner_after =
            inspect(&owner_inspection_command()).map_err(LinuxRoutePrepareError::operational)?;
        expected_present.sort();
        for (boundary, output) in [("before", owner_before), ("after", owner_after)] {
            let mut owner_records =
                parse_linux_route_listing(&output).map_err(LinuxRoutePrepareError::operational)?;
            if owner_records.iter().any(|record| record.protocol.is_some()) {
                return Err(LinuxRoutePrepareError::Operational {
                    detail: format!(
                        "reserved-protocol {boundary} listing retained a protocol field"
                    ),
                });
            }
            owner_records.sort();
            if owner_records != expected_present {
                return Err(LinuxRoutePrepareError::Conflict {
                    detail: format!(
                        "reserved-protocol {boundary} census has unknown, duplicate, missing, or racing state"
                    ),
                });
            }
        }
        Ok(Self {
            session,
            same_boot: true,
            expected_namespace,
            entries,
        })
    }

    #[cfg(any(test, target_os = "linux"))]
    fn remove_exact_with<N, I, R, E>(
        &mut self,
        resource: &RouteResource,
        mut verify_namespace: N,
        mut inspect: I,
        mut resolve_ifindex: R,
        mut execute: E,
    ) -> std::result::Result<(), LinuxRouteConvergeError>
    where
        N: FnMut() -> Result<()>,
        I: FnMut(&RouteCommand) -> Result<Vec<u8>>,
        R: FnMut(&str) -> Result<u32>,
        E: FnMut(&RouteCommand, &RouteResource) -> Result<()>,
    {
        let index = self
            .entries
            .iter()
            .position(|entry| &entry.target.resource == resource)
            .ok_or_else(|| {
                LinuxRouteConvergeError::conflict("route was not authorized by prepared recovery")
            })?;
        let state = self.entries[index].state;
        if state == PreparedRouteState::Removed {
            return Err(LinuxRouteConvergeError::conflict(
                "prepared route removal was replayed",
            ));
        }
        if self.next_pending_index() != Some(index) {
            return Err(LinuxRouteConvergeError::conflict(
                "prepared route removal call is out of host-state order",
            ));
        }

        verify_namespace().map_err(map_namespace_convergence_error)?;
        let spec = self.entries[index].target.spec.clone();
        let exact_command = exact_inspection_command(&spec);
        let first_exact = inspect(&exact_command).map_err(LinuxRouteConvergeError::operational)?;
        let current = self.classify_current_with(index, &first_exact, &mut resolve_ifindex)?;
        if current == LinuxOwnedRouteClassification::Conflict {
            return Err(LinuxRouteConvergeError::conflict(format!(
                "owned route conflicted after prepared preflight at {}/{}",
                spec.destination, spec.prefix_len
            )));
        }
        if !self.same_boot && current != LinuxOwnedRouteClassification::Absent {
            return Err(LinuxRouteConvergeError::conflict(
                "volatile Linux route cannot be attributed to a journal owner from a different boot",
            ));
        }

        verify_namespace().map_err(map_namespace_convergence_error)?;
        let owner_output =
            inspect(&owner_inspection_command()).map_err(LinuxRouteConvergeError::operational)?;
        Self::verify_owner_census_against(
            &owner_output,
            &self.expected_owner_records_for_step(
                index,
                current == LinuxOwnedRouteClassification::ExactOwnedPresent,
            ),
        )?;

        verify_namespace().map_err(map_namespace_convergence_error)?;
        let immediate_exact =
            inspect(&exact_command).map_err(LinuxRouteConvergeError::operational)?;
        let immediate =
            self.classify_current_with(index, &immediate_exact, &mut resolve_ifindex)?;
        if immediate != current || immediate == LinuxOwnedRouteClassification::Conflict {
            return Err(LinuxRouteConvergeError::conflict(format!(
                "owned route raced between census and convergence at {}/{}",
                spec.destination, spec.prefix_len
            )));
        }

        if immediate == LinuxOwnedRouteClassification::ExactOwnedPresent {
            verify_namespace().map_err(map_namespace_convergence_error)?;
            let live_ifindex = resolve_ifindex(&resource.output.name)
                .map_err(LinuxRouteConvergeError::operational)?;
            if live_ifindex != resource.output.ifindex {
                return Err(LinuxRouteConvergeError::conflict(
                    "owned route output ifindex changed immediately before deletion",
                ));
            }
            let delete = spec.command("del");
            execute(&delete, resource).map_err(|error| {
                let mapped = map_execution_convergence_error(error);
                match mapped {
                    LinuxRouteConvergeError::Conflict { detail } => {
                        LinuxRouteConvergeError::Conflict {
                            detail: format!(
                                "delete exact owned Linux route {}: {detail}",
                                delete.display()
                            ),
                        }
                    }
                    LinuxRouteConvergeError::Operational { detail } => {
                        LinuxRouteConvergeError::Operational {
                            detail: format!(
                                "delete exact owned Linux route {}: {detail}",
                                delete.display()
                            ),
                        }
                    }
                }
            })?;
        }

        verify_namespace().map_err(map_namespace_convergence_error)?;
        let post_exact_output =
            inspect(&exact_command).map_err(LinuxRouteConvergeError::operational)?;
        let post_exact = parse_linux_route_listing(&post_exact_output)
            .map_err(LinuxRouteConvergeError::operational)?;
        if !post_exact.is_empty() {
            return Err(LinuxRouteConvergeError::conflict(format!(
                "owned route remained or reappeared after exact deletion at {}/{}",
                spec.destination, spec.prefix_len
            )));
        }
        verify_namespace().map_err(map_namespace_convergence_error)?;
        let post_owner =
            inspect(&owner_inspection_command()).map_err(LinuxRouteConvergeError::operational)?;
        self.verify_owner_census(&post_owner, Some(index))?;
        self.entries[index].state = PreparedRouteState::Removed;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn drain_bounded_until_child_done<R>(
    mut reader: R,
    limit: usize,
    child_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(Vec<u8>, bool)>
where
    R: std::io::Read + std::os::fd::AsRawFd,
{
    use std::sync::atomic::Ordering;

    let fd = reader.as_raw_fd();
    // SAFETY: fd is the live pipe descriptor owned by reader.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd remains live and F_SETFL receives the flags obtained above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut captured = Vec::with_capacity(limit.min(8 * 1024));
    let mut overflow = false;
    let mut chunk = [0u8; 8 * 1024];
    loop {
        // Once the direct child is reaped and overflow has already been proven,
        // do not let a pipe-inheriting descendant keep the reader alive by
        // writing forever. Before child completion we continue draining so the
        // actual route command can never block on a full pipe.
        if overflow && child_done.load(Ordering::Acquire) {
            break;
        }
        let read = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if child_done.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            Err(error) => return Err(error),
        };
        let remaining = limit.saturating_sub(captured.len());
        let retained = remaining.min(read);
        captured.extend_from_slice(&chunk[..retained]);
        overflow |= retained != read;
        // Continue draining after the bound is reached so a child cannot block
        // forever on a full pipe. Excess bytes are deliberately discarded.
    }
    Ok((captured, overflow))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
#[derive(Debug)]
struct BoundedRouteCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_overflow: bool,
    stderr_overflow: bool,
}

#[cfg(target_os = "linux")]
fn trusted_linux_route_executable(program: &str) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let candidates: Vec<std::path::PathBuf> = if Path::new(program).is_absolute() {
        vec![Path::new(program).to_path_buf()]
    } else {
        anyhow::ensure!(program == "ip", "untrusted Linux route helper {program:?}");
        ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect()
    };

    for candidate in candidates {
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        let Some(parent) = candidate.parent() else {
            continue;
        };
        let Ok(parent_metadata) = std::fs::metadata(parent) else {
            continue;
        };
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
            || !parent_metadata.file_type().is_dir()
            || parent_metadata.uid() != 0
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            continue;
        }
        let canonical = std::fs::canonicalize(&candidate).with_context(|| {
            format!("canonicalize trusted route helper {}", candidate.display())
        })?;
        let canonical_metadata = std::fs::metadata(&canonical)
            .with_context(|| format!("stat canonical route helper {}", canonical.display()))?;
        anyhow::ensure!(
            canonical_metadata.file_type().is_file()
                && canonical_metadata.uid() == 0
                && canonical_metadata.permissions().mode() & 0o022 == 0,
            "canonical route helper {} is not root-owned and non-writable",
            canonical.display()
        );
        for ancestor in canonical.ancestors().skip(1) {
            let ancestor_metadata = std::fs::metadata(ancestor).with_context(|| {
                format!(
                    "stat canonical route helper ancestor {}",
                    ancestor.display()
                )
            })?;
            anyhow::ensure!(
                ancestor_metadata.file_type().is_dir()
                    && ancestor_metadata.uid() == 0
                    && ancestor_metadata.permissions().mode() & 0o022 == 0,
                "canonical route helper ancestor {} is not a root-owned, non-writable directory",
                ancestor.display()
            );
        }
        return Ok(canonical);
    }
    anyhow::bail!("no root-owned, non-writable absolute Linux route helper for {program:?}")
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn kill_route_process_group(pid: u32) -> Option<String> {
    let process_group = i32::try_from(pid).ok()?;
    // SAFETY: every bounded route command is spawned as the leader of a fresh
    // process group, so a negative pid cannot target the caller's group.
    if unsafe { libc::kill(-process_group, libc::SIGKILL) } == 0 {
        return None;
    }
    let error = std::io::Error::last_os_error();
    (error.raw_os_error() != Some(libc::ESRCH)).then(|| error.to_string())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn terminate_process_group_and_reap(
    child: &mut std::process::Child,
) -> (Option<String>, std::io::Result<std::process::ExitStatus>) {
    let pid = child.id();
    let mut kill_error = kill_route_process_group(pid);
    // Always target the direct child as well. A compromised or accidentally
    // wrapped helper can leave the process group created at spawn (setsid or
    // setpgid), making kill(-original_pid) return ESRCH while the direct child
    // is still alive. Waiting after only that group attempt would violate the
    // advertised deadline forever.
    if let Err(error) = child.kill() {
        if error.kind() != std::io::ErrorKind::InvalidInput {
            kill_error = Some(match kill_error {
                Some(group_error) => {
                    format!("process-group kill: {group_error}; child kill: {error}")
                }
                None => format!("direct child kill: {error}"),
            });
        }
    }
    // Always wait after the kill attempt. This is the zombie-safety boundary.
    let wait_result = loop {
        match child.wait() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    (kill_error, wait_result)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn run_bounded_route_subprocess(
    command: &RouteCommand,
    timeout: std::time::Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<BoundedRouteCommandOutput> {
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[cfg(target_os = "linux")]
    let executable = trusted_linux_route_executable(command.program)?;
    #[cfg(not(target_os = "linux"))]
    let executable = std::path::PathBuf::from(command.program);
    let mut process = Command::new(&executable);
    process
        .args(&command.args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = process
        .spawn()
        .with_context(|| format!("start bounded route command {}", command.display()))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = terminate_process_group_and_reap(&mut child);
            anyhow::bail!("bounded route command stdout pipe unavailable")
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            let _ = terminate_process_group_and_reap(&mut child);
            anyhow::bail!("bounded route command stderr pipe unavailable")
        }
    };
    let child_done = Arc::new(AtomicBool::new(false));
    let stdout_done = Arc::clone(&child_done);
    let stderr_done = Arc::clone(&child_done);
    let started = Instant::now();

    let (status, stdout, stderr) = std::thread::scope(|scope| -> Result<_> {
        let stdout_reader =
            scope.spawn(move || drain_bounded_until_child_done(stdout, stdout_limit, stdout_done));
        let stderr_reader =
            scope.spawn(move || drain_bounded_until_child_done(stderr, stderr_limit, stderr_done));

        let mut terminal_error = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(error) = kill_route_process_group(child.id()) {
                        terminal_error = Some(anyhow::anyhow!(
                            "kill route subprocess descendants after direct-child exit: {error}"
                        ));
                    }
                    break Some(status);
                }
                Ok(None) if started.elapsed() >= timeout => {
                    let (kill_error, wait_result) = terminate_process_group_and_reap(&mut child);
                    let wait_detail = wait_result
                        .as_ref()
                        .map(|status| format!("reaped with {status}"))
                        .unwrap_or_else(|error| format!("wait failed: {error}"));
                    terminal_error = Some(anyhow::anyhow!(
                        "route command {} timed out after {:?}; kill: {}; {wait_detail}",
                        command.display(),
                        timeout,
                        kill_error.as_deref().unwrap_or("ok")
                    ));
                    break wait_result.ok();
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(error) => {
                    let (kill_error, wait_result) = terminate_process_group_and_reap(&mut child);
                    terminal_error = Some(anyhow::anyhow!(
                        "poll route command {}: {error}; kill: {}; wait: {}",
                        command.display(),
                        kill_error.as_deref().unwrap_or("ok"),
                        wait_result
                            .as_ref()
                            .map(|status| status.to_string())
                            .unwrap_or_else(|wait_error| wait_error.to_string())
                    ));
                    break wait_result.ok();
                }
            }
        };
        child_done.store(true, Ordering::Release);
        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("route stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("route stderr reader panicked"))??;
        if let Some(error) = terminal_error {
            return Err(error);
        }
        let status = status.ok_or_else(|| anyhow::anyhow!("route command had no exit status"))?;
        Ok((status, stdout, stderr))
    })?;

    Ok(BoundedRouteCommandOutput {
        status,
        stdout: stdout.0,
        stderr: stderr.0,
        stdout_overflow: stdout.1,
        stderr_overflow: stderr.1,
    })
}

#[cfg(target_os = "linux")]
fn query_linux_route(command: &RouteCommand) -> Result<Vec<u8>> {
    anyhow::ensure!(
        command.program == "ip"
            && command.args.iter().any(|argument| argument == "route")
            && command.args.iter().any(|argument| argument == "show")
            && !command.args.iter().any(|argument| matches!(
                argument.as_str(),
                "add" | "append" | "change" | "del" | "delete" | "flush" | "replace"
            )),
        "refusing non-read-only Linux route inspection command"
    );
    let output = run_bounded_route_subprocess(
        command,
        LINUX_ROUTE_COMMAND_TIMEOUT,
        MAX_LINUX_ROUTE_INSPECTION_BYTES,
        MAX_LINUX_ROUTE_COMMAND_STDERR_BYTES,
    )?;
    anyhow::ensure!(
        !output.stdout_overflow,
        "Linux route inspection stdout exceeded bound"
    );
    anyhow::ensure!(
        !output.stderr_overflow,
        "Linux route inspection stderr exceeded bound"
    );
    anyhow::ensure!(
        output.status.success(),
        "read-only route inspection {} failed: {}",
        command.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

#[cfg(any(test, target_os = "linux"))]
fn run_bounded_route_command_strict_status(
    command: &RouteCommand,
    timeout: std::time::Duration,
) -> Result<()> {
    let output = run_bounded_route_subprocess(
        command,
        timeout,
        MAX_LINUX_ROUTE_COMMAND_STDERR_BYTES,
        MAX_LINUX_ROUTE_COMMAND_STDERR_BYTES,
    )
    .with_context(|| format!("run bounded route command {}", command.display()))?;
    anyhow::ensure!(
        !output.stdout_overflow && !output.stderr_overflow,
        "route command {} exceeded bounded output",
        command.display()
    );
    anyhow::ensure!(
        output.status.success(),
        "route command {} failed: {}",
        command.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_strict_linux_route_mutation(command: &RouteCommand) -> Result<()> {
    let route_index = command.args.iter().position(|argument| argument == "route");
    anyhow::ensure!(
        command.program == "ip"
            && route_index.is_some_and(|index| {
                command
                    .args
                    .get(index + 1)
                    .is_some_and(|argument| matches!(argument.as_str(), "add" | "del" | "delete"))
            })
            && !command
                .args
                .iter()
                .any(|argument| matches!(argument.as_str(), "flush" | "replace")),
        "refusing non-exact Linux route mutation"
    );
    run_bounded_route_command_strict_status(command, LINUX_ROUTE_COMMAND_TIMEOUT)
}

#[cfg(target_os = "linux")]
fn current_network_namespace() -> Result<NamespaceIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata("/proc/thread-self/ns/net")
        .context("inspect current Linux network namespace")?;
    Ok(NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// Capture the namespace identity on the calling thread. Startup recovery uses
/// the journaled identity on the same boot and this current identity after a
/// reboot, while still treating any surviving volatile route as a conflict.
#[cfg(target_os = "linux")]
pub fn current_linux_network_namespace_identity() -> Result<NamespaceIdentity> {
    current_network_namespace()
}

#[cfg(not(target_os = "linux"))]
pub fn current_linux_network_namespace_identity() -> Result<NamespaceIdentity> {
    anyhow::bail!("Linux network namespace identity is available only on Linux")
}

#[cfg(target_os = "linux")]
fn ensure_network_namespace_for_prepare(
    expected: NamespaceIdentity,
) -> std::result::Result<(), LinuxRoutePrepareError> {
    let current = current_network_namespace().map_err(LinuxRoutePrepareError::operational)?;
    if current != expected {
        return Err(LinuxRoutePrepareError::conflict(
            "current Linux network namespace differs from the route journal owner",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_network_namespace_for_convergence(
    expected: NamespaceIdentity,
) -> std::result::Result<(), LinuxRouteConvergeError> {
    let current = current_network_namespace().map_err(LinuxRouteConvergeError::operational)?;
    if current != expected {
        return Err(LinuxRouteConvergeError::conflict(
            "current Linux network namespace differs from the route journal owner",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_linux_recovery_delete(command: &RouteCommand) -> Result<()> {
    anyhow::ensure!(
        command.program == "ip"
            && command
                .args
                .get(1)
                .is_some_and(|argument| argument == "route")
            && command
                .args
                .get(2)
                .is_some_and(|argument| argument == "del")
            && !command
                .args
                .iter()
                .any(|argument| matches!(argument.as_str(), "flush" | "replace")),
        "refusing non-exact Linux route recovery mutation"
    );
    run_strict_linux_route_mutation(command)
        .with_context(|| format!("run strict route recovery delete {}", command.display()))
}

#[cfg(target_os = "linux")]
impl PreparedLinuxRouteRecovery {
    /// Complete the all-route read-only preflight. Any malformed, missing,
    /// duplicate, unknown, or modified owned state returns an error without
    /// constructing a prepared object or exposing a mutation.
    pub fn prepare(
        session: SessionId,
        expected_namespace: NamespaceIdentity,
        resources: &[RouteResource],
        same_boot: bool,
    ) -> std::result::Result<Self, LinuxRoutePrepareError> {
        let mut prepared = Self::prepare_with(
            session,
            expected_namespace,
            resources,
            || ensure_network_namespace_for_prepare(expected_namespace).map_err(anyhow::Error::new),
            query_linux_route,
            linux_ifindex,
        )?;
        prepared.same_boot = same_boot;
        Ok(prepared)
    }

    /// Converge one route authorized by `prepare`. Preflight-absent resources
    /// are verified absent and perform no mutation; exact resources are allowed
    /// only in host-state route order and are revalidated immediately.
    pub fn converge_absent(
        &mut self,
        resource: &RouteResource,
    ) -> std::result::Result<(), LinuxRouteConvergeError> {
        let expected_namespace = self.expected_namespace;
        self.remove_exact_with(
            resource,
            || {
                ensure_network_namespace_for_convergence(expected_namespace)
                    .map_err(anyhow::Error::new)
            },
            query_linux_route,
            linux_ifindex,
            |command, resource| {
                ensure_network_namespace_for_convergence(expected_namespace)
                    .map_err(anyhow::Error::new)?;
                // Narrow the remaining CLI race: `ip` accepts an interface
                // name, not the journaled numeric OIF. A direct rtnetlink
                // delete with RTA_OIF would remove the final lookup window.
                let live_ifindex = linux_ifindex(&resource.output.name)?;
                if live_ifindex != resource.output.ifindex {
                    return Err(anyhow::Error::new(LinuxRouteConvergeError::conflict(
                        "owned route output ifindex changed immediately before deletion",
                    )));
                }
                run_linux_recovery_delete(command)
            },
        )
    }

    pub fn remove_exact(
        &mut self,
        resource: &RouteResource,
    ) -> std::result::Result<(), LinuxRouteConvergeError> {
        self.converge_absent(resource)
    }
}

#[cfg(not(target_os = "linux"))]
impl PreparedLinuxRouteRecovery {
    pub fn prepare(
        _session: SessionId,
        _expected_namespace: NamespaceIdentity,
        _resources: &[RouteResource],
        _same_boot: bool,
    ) -> std::result::Result<Self, LinuxRoutePrepareError> {
        Err(LinuxRoutePrepareError::Operational {
            detail: "owned Linux route recovery is only available on Linux".to_string(),
        })
    }

    pub fn converge_absent(
        &mut self,
        _resource: &RouteResource,
    ) -> std::result::Result<(), LinuxRouteConvergeError> {
        Err(LinuxRouteConvergeError::operational(
            "owned Linux route recovery is only available on Linux",
        ))
    }

    pub fn remove_exact(
        &mut self,
        _resource: &RouteResource,
    ) -> std::result::Result<(), LinuxRouteConvergeError> {
        self.converge_absent(_resource)
    }
}

impl LinuxUnderlayPath {
    /// Capture the effective path to an endpoint. Callers must do this before
    /// installing any Shadowpipe split-default route.
    #[cfg(target_os = "linux")]
    pub fn capture(destination: Ipv4Addr) -> Result<Self> {
        let destination = destination.to_string();
        let command = RouteCommand::new("ip", &["-4", "route", "get", &destination]);
        let output = run_bounded_route_subprocess(
            &command,
            LINUX_ROUTE_COMMAND_TIMEOUT,
            MAX_LINUX_ROUTE_INSPECTION_BYTES,
            MAX_LINUX_ROUTE_COMMAND_STDERR_BYTES,
        )
        .with_context(|| format!("bounded ip -4 route get {destination}"))?;
        anyhow::ensure!(
            !output.stdout_overflow && !output.stderr_overflow,
            "ip -4 route get {destination} exceeded bounded output"
        );
        anyhow::ensure!(
            output.status.success(),
            "ip -4 route get {destination} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Self::parse_route_get(&String::from_utf8_lossy(&output.stdout))
            .with_context(|| format!("parse pre-tunnel path to {destination}"))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn capture(_destination: Ipv4Addr) -> Result<Self> {
        anyhow::bail!("Linux underlay path capture is only available on Linux")
    }

    #[cfg(any(test, target_os = "linux"))]
    fn parse_route_get(line: &str) -> Result<Self> {
        // iproute2 prints one logical lookup as a non-indented record followed
        // by optional indented cache metadata (commonly a bare `cache` line).
        // Count logical records rather than physical lines: accepting only one
        // physical line rejects normal Linux output, while flattening multiple
        // unindented records could accidentally select one ambiguous path.
        let logical_records = line
            .lines()
            .filter(|candidate| !candidate.trim().is_empty())
            .filter(|candidate| {
                candidate
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
            })
            .count();
        anyhow::ensure!(
            logical_records == 1,
            "expected exactly one ip route get result"
        );
        let tokens: Vec<&str> = line.split_whitespace().collect();
        anyhow::ensure!(!tokens.is_empty(), "empty ip route get output");
        anyhow::ensure!(
            !tokens
                .iter()
                .any(|token| matches!(*token, "unreachable" | "blackhole" | "prohibit" | "throw")),
            "route is not a usable unicast underlay path: {}",
            line.trim()
        );

        let mut gateway = None;
        let mut iface = None;
        let mut index = 0usize;
        while index + 1 < tokens.len() {
            match tokens[index] {
                "via" => {
                    anyhow::ensure!(gateway.is_none(), "route output has duplicate via fields");
                    gateway = Some(tokens[index + 1].parse::<Ipv4Addr>().with_context(|| {
                        format!(
                            "invalid IPv4 gateway in route output: {}",
                            tokens[index + 1]
                        )
                    })?);
                    index += 2;
                }
                "dev" => {
                    anyhow::ensure!(iface.is_none(), "route output has duplicate dev fields");
                    iface = Some(tokens[index + 1].to_string());
                    index += 2;
                }
                _ => index += 1,
            }
        }
        let iface = iface.ok_or_else(|| anyhow::anyhow!("route output has no dev: {line}"))?;
        validate_linux_iface(&iface).context("invalid underlay path")?;
        Ok(Self { gateway, iface })
    }

    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.gateway
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// Install one endpoint bypass using the pre-tunnel next hop. The returned
    /// guard owns only this exact route.
    pub fn install_bypass(&self, endpoint: Ipv4Addr) -> Result<RouteGuard> {
        RouteGuard::install_steps(linux_server_bypass_steps(
            endpoint,
            self.gateway,
            &self.iface,
        ))
    }

    pub fn owned_bypass_spec(
        &self,
        endpoint: Ipv4Addr,
        owner: LinuxRouteOwner,
    ) -> Result<LinuxOwnedRouteSpec> {
        LinuxOwnedRouteSpec::endpoint_bypass(endpoint, self, owner)
    }

    pub fn owned_ssh_bypass_spec(
        &self,
        client: Ipv4Addr,
        owner: LinuxRouteOwner,
    ) -> Result<LinuxOwnedRouteSpec> {
        LinuxOwnedRouteSpec::ssh_bypass(client, self, owner)
    }
}

#[cfg(any(test, target_os = "linux"))]
fn parse_live_owner_census(output: &[u8]) -> Result<Vec<LinuxIpRouteRecord>> {
    let mut records = parse_linux_route_listing(output)
        .context("parse complete reserved-protocol route census")?;
    anyhow::ensure!(
        records.iter().all(|record| record.protocol.is_none()),
        "reserved-protocol census unexpectedly retained a protocol field"
    );
    records.sort();
    anyhow::ensure!(
        records.windows(2).all(|pair| pair[0] != pair[1]),
        "reserved-protocol census contains a duplicate route"
    );
    Ok(records)
}

#[cfg(any(test, target_os = "linux"))]
fn ensure_same_live_namespace(
    expected: NamespaceIdentity,
    current: NamespaceIdentity,
    boundary: &str,
) -> Result<()> {
    anyhow::ensure!(
        current == expected,
        "Linux network namespace changed {boundary}"
    );
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn install_linux_owned_with<N, I, R, E>(
    spec: &LinuxOwnedRouteSpec,
    resource: &RouteResource,
    mut namespace: N,
    mut inspect: I,
    mut resolve_ifindex: R,
    mut execute: E,
) -> Result<RouteGuard>
where
    N: FnMut() -> Result<NamespaceIdentity>,
    I: FnMut(&RouteCommand) -> Result<Vec<u8>>,
    R: FnMut(&str) -> Result<u32>,
    E: FnMut(&RouteCommand) -> Result<()>,
{
    let durable_spec = LinuxOwnedRouteSpec::from_journal_resource(resource)
        .context("validate durable owned-route identity")?;
    anyhow::ensure!(
        &durable_spec == spec,
        "durable owned-route identity differs from requested route"
    );

    let initial_namespace = namespace().context("capture Linux route namespace before add")?;
    let mut owner_before = parse_live_owner_census(
        &inspect(&owner_inspection_command()).context("inspect route owner census before add")?,
    )?;
    let exact_command = exact_inspection_command(spec);
    let exact_before = parse_linux_route_listing(
        &inspect(&exact_command).context("inspect exact route before add")?,
    )
    .context("parse exact route census before add")?;
    anyhow::ensure!(
        exact_before.is_empty(),
        "refusing owned route add because the exact destination is already occupied"
    );
    let expected_owner = spec.expected_json_record(false);
    anyhow::ensure!(
        owner_before.binary_search(&expected_owner).is_err(),
        "exact route is absent but reserved-protocol census already contains its identity"
    );
    let before_ifindex = resolve_ifindex(&resource.output.name)
        .context("resolve route output ifindex before add")?;
    anyhow::ensure!(
        before_ifindex == resource.output.ifindex,
        "route output ifindex differs from the durable pre-add identity"
    );
    ensure_same_live_namespace(
        initial_namespace,
        namespace().context("recheck Linux route namespace before add")?,
        "before owned route add",
    )?;

    let add = spec.command("add");
    execute(&add).with_context(|| format!("add exact owned route {}", add.display()))?;

    ensure_same_live_namespace(
        initial_namespace,
        namespace().context("recheck Linux route namespace after add")?,
        "during owned route add",
    )?;
    let exact_after = parse_linux_route_listing(
        &inspect(&exact_command).context("inspect exact route after add")?,
    )
    .context("parse exact route census after add")?;
    anyhow::ensure!(
        exact_after == vec![spec.expected_json_record(true)],
        "owned route post-add exact census differs from the requested identity"
    );
    let after_ifindex =
        resolve_ifindex(&resource.output.name).context("resolve route output ifindex after add")?;
    anyhow::ensure!(
        after_ifindex == resource.output.ifindex,
        "route output ifindex changed during owned route add"
    );
    let owner_after = parse_live_owner_census(
        &inspect(&owner_inspection_command()).context("inspect route owner census after add")?,
    )?;
    owner_before.push(expected_owner);
    owner_before.sort();
    anyhow::ensure!(
        owner_after == owner_before,
        "reserved-protocol route census changed by more than the exact owned add"
    );
    ensure_same_live_namespace(
        initial_namespace,
        namespace().context("final Linux route namespace check after add")?,
        "during owned route post-add census",
    )?;

    Ok(RouteGuard {
        undo: vec![spec.command("del")],
        strict_linux_owned: Some(LinuxOwnedRouteRuntime {
            spec: spec.clone(),
            resource: resource.clone(),
        }),
    })
}

#[cfg(any(test, target_os = "linux"))]
fn remove_linux_owned_with<N, I, R, E>(
    runtime: &LinuxOwnedRouteRuntime,
    mut namespace: N,
    mut inspect: I,
    mut resolve_ifindex: R,
    mut execute: E,
) -> Result<()>
where
    N: FnMut() -> Result<NamespaceIdentity>,
    I: FnMut(&RouteCommand) -> Result<Vec<u8>>,
    R: FnMut(&str) -> Result<u32>,
    E: FnMut(&RouteCommand) -> Result<()>,
{
    let initial_namespace = namespace().context("capture Linux route namespace before delete")?;
    let mut owner_before = parse_live_owner_census(
        &inspect(&owner_inspection_command())
            .context("inspect route owner census before delete")?,
    )?;
    let exact_command = exact_inspection_command(&runtime.spec);
    let exact_before = parse_linux_route_listing(
        &inspect(&exact_command).context("inspect exact route before delete")?,
    )
    .context("parse exact route census before delete")?;
    let expected_exact = runtime.spec.expected_json_record(true);
    let expected_owner = runtime.spec.expected_json_record(false);

    if exact_before.is_empty() {
        anyhow::ensure!(
            owner_before.binary_search(&expected_owner).is_err(),
            "exact route is absent but reserved-protocol census still contains its identity"
        );
        ensure_same_live_namespace(
            initial_namespace,
            namespace().context("recheck Linux route namespace for absent delete")?,
            "during absent owned route verification",
        )?;
        return Ok(());
    }

    anyhow::ensure!(
        exact_before == vec![expected_exact],
        "refusing owned route delete because the exact destination identity changed"
    );
    let live_ifindex = resolve_ifindex(&runtime.resource.output.name)
        .context("resolve route output ifindex before delete")?;
    anyhow::ensure!(
        live_ifindex == runtime.resource.output.ifindex,
        "refusing owned route delete because the output ifindex changed"
    );
    let owner_position = owner_before.binary_search(&expected_owner).map_err(|_| {
        anyhow::anyhow!("reserved-protocol census is missing the exact owned route")
    })?;
    owner_before.remove(owner_position);
    ensure_same_live_namespace(
        initial_namespace,
        namespace().context("recheck Linux route namespace before delete")?,
        "before owned route delete",
    )?;

    let delete = runtime.spec.command("del");
    execute(&delete).with_context(|| format!("delete exact owned route {}", delete.display()))?;

    ensure_same_live_namespace(
        initial_namespace,
        namespace().context("recheck Linux route namespace after delete")?,
        "during owned route delete",
    )?;
    let exact_after = parse_linux_route_listing(
        &inspect(&exact_command).context("inspect exact route after delete")?,
    )
    .context("parse exact route census after delete")?;
    anyhow::ensure!(
        exact_after.is_empty(),
        "owned route remained or reappeared after strict live delete"
    );
    let owner_after = parse_live_owner_census(
        &inspect(&owner_inspection_command()).context("inspect route owner census after delete")?,
    )?;
    anyhow::ensure!(
        owner_after == owner_before,
        "reserved-protocol route census changed by more than the exact owned delete"
    );
    ensure_same_live_namespace(
        initial_namespace,
        namespace().context("final Linux route namespace check after delete")?,
        "during owned route post-delete census",
    )?;
    Ok(())
}

impl RouteGuard {
    fn empty() -> Self {
        Self {
            undo: Vec::new(),
            #[cfg(any(test, target_os = "linux"))]
            strict_linux_owned: None,
        }
    }

    fn install_steps(steps: Vec<RouteStep>) -> Result<Self> {
        let undo = apply_steps_with(steps, run_command)?;
        Ok(Self {
            undo,
            #[cfg(any(test, target_os = "linux"))]
            strict_linux_owned: None,
        })
    }

    /// Add an owned host route for the tunnel endpoint without replacing an
    /// existing route. The returned guard must be kept alive for as long as the
    /// bypass is required.
    pub fn install_server_bypass(server_ip: &str, gateway: &str, iface: &str) -> Result<Self> {
        Self::install_steps(server_bypass_steps(
            current_platform(),
            server_ip,
            gateway,
            iface,
        ))
    }

    /// Linux: pin `server_ip` via the current default route (before split routes).
    /// The returned guard owns the added host route and restores the prior
    /// no-host-route state when dropped.
    #[cfg(target_os = "linux")]
    pub fn install_server_bypass_linux(server_ip: Ipv4Addr) -> Result<Self> {
        Self::install_host_via_default_route(server_ip, "server")
    }

    /// Linux: if `$SSH_CONNECTION` is set, add an owned bypass for the
    /// operator's SSH source IP before split-default routes are installed.
    #[cfg(target_os = "linux")]
    pub fn install_ssh_bypass_linux() -> Result<Self> {
        let conn = match std::env::var("SSH_CONNECTION") {
            Ok(value) if !value.is_empty() => value,
            _ => return Ok(Self::empty()),
        };
        let ssh_client = conn
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("invalid SSH_CONNECTION: {conn}"))?;
        let ip: Ipv4Addr = ssh_client
            .parse()
            .with_context(|| format!("SSH client IP is not IPv4: {ssh_client}"))?;
        Self::install_host_via_default_route(ip, "ssh")
    }

    #[cfg(target_os = "linux")]
    fn install_host_via_default_route(host: Ipv4Addr, label: &str) -> Result<Self> {
        let path = LinuxUnderlayPath::capture(host)
            .with_context(|| format!("capture pre-tunnel path for {label}"))?;
        path.install_bypass(host)
            .with_context(|| format!("install pre-tunnel bypass for {label}"))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn install_ssh_bypass_linux() -> Result<Self> {
        Ok(Self::empty())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn install_server_bypass_linux(_server_ip: Ipv4Addr) -> Result<Self> {
        Ok(Self::empty())
    }

    pub fn install_split(iface: &str) -> Result<Self> {
        Self::install_steps(split_steps(current_platform(), iface))
    }

    /// Add an owned peer route. Unlike the old shared `installed` flag, this
    /// journal records the peer's exact delete command, so dropping the guard
    /// cannot accidentally remove split-default routes instead.
    pub fn install_peer(iface: &str, peer: &str) -> Result<Self> {
        Self::install_steps(peer_steps(current_platform(), iface, peer))
    }

    #[cfg(target_os = "linux")]
    pub fn install_linux_owned(spec: &LinuxOwnedRouteSpec) -> Result<Self> {
        let resource = spec
            .journal_resource()
            .context("capture exact owned-route identity before install")?;
        Self::install_linux_owned_journaled(spec, &resource)
    }

    /// Install exactly the route identity that the caller has already written
    /// to its WAL. This closes the ifindex race between durable planning and
    /// post-add acknowledgement.
    #[cfg(target_os = "linux")]
    pub fn install_linux_owned_journaled(
        spec: &LinuxOwnedRouteSpec,
        resource: &RouteResource,
    ) -> Result<Self> {
        install_linux_owned_with(
            spec,
            resource,
            current_network_namespace,
            query_linux_route,
            linux_ifindex,
            run_strict_linux_route_mutation,
        )
    }

    #[cfg(not(target_os = "linux"))]
    pub fn install_linux_owned(_spec: &LinuxOwnedRouteSpec) -> Result<Self> {
        anyhow::bail!("owned Linux routes are only available on Linux")
    }

    #[cfg(not(target_os = "linux"))]
    pub fn install_linux_owned_journaled(
        _spec: &LinuxOwnedRouteSpec,
        _resource: &RouteResource,
    ) -> Result<Self> {
        anyhow::bail!("owned Linux routes are only available on Linux")
    }

    /// Try to remove every route still owned by this guard. Failed exact
    /// inverses remain journaled in memory so the coordinator can retry without
    /// losing ownership evidence.
    pub fn try_remove(&mut self) -> Result<()> {
        #[cfg(any(test, target_os = "linux"))]
        if let Some(runtime) = self.strict_linux_owned.clone() {
            #[cfg(target_os = "linux")]
            {
                remove_linux_owned_with(
                    &runtime,
                    current_network_namespace,
                    query_linux_route,
                    linux_ifindex,
                    run_strict_linux_route_mutation,
                )?;
                self.undo.clear();
                self.strict_linux_owned = None;
                return Ok(());
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = runtime;
                anyhow::bail!("strict owned Linux route cleanup is unavailable on this platform")
            }
        }
        self.try_remove_with(run_command)
    }

    fn try_remove_with<F>(&mut self, mut execute: F) -> Result<()>
    where
        F: FnMut(&RouteCommand) -> Result<()>,
    {
        #[cfg(any(test, target_os = "linux"))]
        anyhow::ensure!(
            self.strict_linux_owned.is_none(),
            "strict owned Linux route cleanup requires exact census validation"
        );
        let mut failed = Vec::new();
        let mut errors = Vec::new();
        while let Some(command) = self.undo.pop() {
            if let Err(error) = execute(&command) {
                errors.push(format!("{}: {error:#}", command.display()));
                failed.push(command);
            }
        }
        // Preserve the original pop order for a later retry.
        failed.reverse();
        self.undo = failed;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "failed to remove owned route(s): {}",
                errors.join("; ")
            ))
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(error) = self.try_remove() {
            tracing::warn!(
                %error,
                remaining = self.undo.len(),
                "route cleanup failed; exact unremoved operations remain"
            );
        }
    }
}

fn split_steps(platform: RoutePlatform, iface: &str) -> Vec<RouteStep> {
    match platform {
        RoutePlatform::Macos => vec![
            RouteStep::new(
                RouteCommand::new("route", &["add", "-net", "0.0.0.0/1", "-interface", iface]),
                RouteCommand::new(
                    "route",
                    &["delete", "-net", "0.0.0.0/1", "-interface", iface],
                ),
            ),
            RouteStep::new(
                RouteCommand::new(
                    "route",
                    &["add", "-net", "128.0.0.0/1", "-interface", iface],
                ),
                RouteCommand::new(
                    "route",
                    &["delete", "-net", "128.0.0.0/1", "-interface", iface],
                ),
            ),
        ],
        RoutePlatform::Linux => vec![
            RouteStep::new(
                RouteCommand::new("ip", &["route", "add", "0.0.0.0/1", "dev", iface]),
                RouteCommand::new("ip", &["route", "del", "0.0.0.0/1", "dev", iface]),
            ),
            RouteStep::new(
                RouteCommand::new("ip", &["route", "add", "128.0.0.0/1", "dev", iface]),
                RouteCommand::new("ip", &["route", "del", "128.0.0.0/1", "dev", iface]),
            ),
        ],
        RoutePlatform::Windows => vec![
            RouteStep::new(
                RouteCommand::new(
                    "route",
                    &[
                        "add",
                        "0.0.0.0",
                        "mask",
                        "128.0.0.0",
                        "0.0.0.0",
                        "if",
                        iface,
                    ],
                ),
                RouteCommand::new(
                    "route",
                    &[
                        "delete",
                        "0.0.0.0",
                        "mask",
                        "128.0.0.0",
                        "0.0.0.0",
                        "if",
                        iface,
                    ],
                ),
            ),
            RouteStep::new(
                RouteCommand::new(
                    "route",
                    &[
                        "add",
                        "128.0.0.0",
                        "mask",
                        "128.0.0.0",
                        "128.0.0.0",
                        "if",
                        iface,
                    ],
                ),
                RouteCommand::new(
                    "route",
                    &[
                        "delete",
                        "128.0.0.0",
                        "mask",
                        "128.0.0.0",
                        "128.0.0.0",
                        "if",
                        iface,
                    ],
                ),
            ),
        ],
        RoutePlatform::Unsupported => Vec::new(),
    }
}

fn peer_steps(platform: RoutePlatform, iface: &str, peer: &str) -> Vec<RouteStep> {
    match platform {
        RoutePlatform::Macos => vec![RouteStep::new(
            RouteCommand::new("route", &["add", "-host", peer, "-interface", iface]),
            RouteCommand::new("route", &["delete", "-host", peer, "-interface", iface]),
        )],
        RoutePlatform::Linux => vec![RouteStep::new(
            RouteCommand::new("ip", &["route", "add", peer, "dev", iface]),
            RouteCommand::new("ip", &["route", "del", peer, "dev", iface]),
        )],
        RoutePlatform::Windows => vec![RouteStep::new(
            RouteCommand::new(
                "route",
                &[
                    "add",
                    peer,
                    "mask",
                    "255.255.255.255",
                    "0.0.0.0",
                    "if",
                    iface,
                ],
            ),
            RouteCommand::new(
                "route",
                &[
                    "delete",
                    peer,
                    "mask",
                    "255.255.255.255",
                    "0.0.0.0",
                    "if",
                    iface,
                ],
            ),
        )],
        RoutePlatform::Unsupported => Vec::new(),
    }
}

fn server_bypass_steps(
    platform: RoutePlatform,
    server_ip: &str,
    gateway: &str,
    iface: &str,
) -> Vec<RouteStep> {
    match platform {
        RoutePlatform::Macos => vec![RouteStep::new(
            RouteCommand::new("route", &["add", "-host", server_ip, "-gateway", gateway]),
            RouteCommand::new(
                "route",
                &["delete", "-host", server_ip, "-gateway", gateway],
            ),
        )],
        RoutePlatform::Linux => vec![RouteStep::new(
            RouteCommand::new(
                "ip",
                &["route", "add", server_ip, "via", gateway, "dev", iface],
            ),
            RouteCommand::new(
                "ip",
                &["route", "del", server_ip, "via", gateway, "dev", iface],
            ),
        )],
        RoutePlatform::Windows => vec![RouteStep::new(
            RouteCommand::new(
                "route",
                &[
                    "add",
                    server_ip,
                    "mask",
                    "255.255.255.255",
                    gateway,
                    "if",
                    iface,
                ],
            ),
            RouteCommand::new(
                "route",
                &[
                    "delete",
                    server_ip,
                    "mask",
                    "255.255.255.255",
                    gateway,
                    "if",
                    iface,
                ],
            ),
        )],
        RoutePlatform::Unsupported => Vec::new(),
    }
}

fn linux_server_bypass_steps(
    endpoint: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    iface: &str,
) -> Vec<RouteStep> {
    let endpoint = endpoint.to_string();
    let mut add = vec!["route".to_string(), "add".to_string(), endpoint.clone()];
    let mut del = vec!["route".to_string(), "del".to_string(), endpoint];
    if let Some(gateway) = gateway {
        let gateway = gateway.to_string();
        add.extend(["via".to_string(), gateway.clone()]);
        del.extend(["via".to_string(), gateway]);
    }
    add.extend(["dev".to_string(), iface.to_string()]);
    del.extend(["dev".to_string(), iface.to_string()]);
    vec![RouteStep::new(
        RouteCommand {
            program: "ip",
            args: add,
        },
        RouteCommand {
            program: "ip",
            args: del,
        },
    )]
}

fn apply_steps_with<F>(steps: Vec<RouteStep>, mut execute: F) -> Result<Vec<RouteCommand>>
where
    F: FnMut(&RouteCommand) -> Result<()>,
{
    let mut undo = Vec::with_capacity(steps.len());
    for step in steps {
        if let Err(error) = execute(&step.apply) {
            let cleanup_errors = rollback_with(&mut undo, &mut execute);
            if cleanup_errors.is_empty() {
                return Err(error).with_context(|| {
                    format!("route transaction failed at {}", step.apply.display())
                });
            }
            return Err(anyhow::anyhow!(
                "route transaction failed at {}: {error:#}; rollback errors: {}",
                step.apply.display(),
                cleanup_errors.join("; ")
            ));
        }
        undo.push(step.undo);
    }
    Ok(undo)
}

fn rollback_with<F>(undo: &mut Vec<RouteCommand>, execute: &mut F) -> Vec<String>
where
    F: FnMut(&RouteCommand) -> Result<()>,
{
    let mut errors = Vec::new();
    while let Some(command) = undo.pop() {
        if let Err(error) = execute(&command) {
            errors.push(format!("{}: {error:#}", command.display()));
        }
    }
    errors
}

fn run_command(command: &RouteCommand) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_strict_linux_route_mutation(command)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let out = Command::new(command.program)
            .args(&command.args)
            .output()
            .with_context(|| format!("run {}", command.display()))?;
        if out.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(anyhow::anyhow!(
            "{} failed: {}",
            command.display(),
            stderr.trim()
        ))
    }
}

pub fn keys_path_default() -> &'static Path {
    Path::new("/etc/shadowpipe/keys.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_state::{
        HostStateJournalV2, OperationRecord, OperationState, OwnedResource, OwnerIdentity,
    };
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet};

    fn recovery_session() -> SessionId {
        SessionId::from_bytes([0x5a; 16])
    }

    #[cfg(target_os = "linux")]
    fn linux_process_is_running(pid: libc::pid_t) -> bool {
        let path = format!("/proc/{pid}/stat");
        match std::fs::read_to_string(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => true,
            Ok(stat) => stat
                .rsplit_once(") ")
                .and_then(|(_, tail)| tail.chars().next())
                .is_some_and(|state| state != 'Z' && state != 'X'),
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_linux_process_not_running(pid: libc::pid_t) {
        for _ in 0..100 {
            if !linux_process_is_running(pid) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // SAFETY: pid came from this test's isolated background fixture.
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        panic!("route runner left live descendant pid {pid}");
    }

    fn recovery_resources() -> Vec<RouteResource> {
        let owner = LinuxRouteOwner::for_session(recovery_session());
        let underlay = LinuxUnderlayPath {
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
            iface: "eth0".to_string(),
        };
        vec![
            LinuxOwnedRouteSpec::split_default(Ipv4Addr::UNSPECIFIED, "sptun0", owner)
                .unwrap()
                .journal_resource_with_ifindex(77)
                .unwrap(),
            LinuxOwnedRouteSpec::split_default(Ipv4Addr::new(128, 0, 0, 0), "sptun0", owner)
                .unwrap()
                .journal_resource_with_ifindex(77)
                .unwrap(),
            LinuxOwnedRouteSpec::endpoint_bypass(Ipv4Addr::new(203, 0, 113, 7), &underlay, owner)
                .unwrap()
                .journal_resource_with_ifindex(42)
                .unwrap(),
            LinuxOwnedRouteSpec::ssh_bypass(Ipv4Addr::new(198, 51, 100, 9), &underlay, owner)
                .unwrap()
                .journal_resource_with_ifindex(42)
                .unwrap(),
        ]
    }

    fn exact_output(resource: &RouteResource) -> Vec<u8> {
        let spec = LinuxOwnedRouteSpec::from_journal_resource(resource).unwrap();
        serde_json::to_vec(&vec![spec.expected_json_record(true)]).unwrap()
    }

    fn owner_output(resources: &[RouteResource]) -> Vec<u8> {
        let records: Vec<_> = resources
            .iter()
            .map(|resource| {
                LinuxOwnedRouteSpec::from_journal_resource(resource)
                    .unwrap()
                    .expected_json_record(false)
            })
            .collect();
        serde_json::to_vec(&records).unwrap()
    }

    fn exact_outputs(resources: &[RouteResource]) -> BTreeMap<String, Vec<u8>> {
        resources
            .iter()
            .map(|resource| {
                let spec = LinuxOwnedRouteSpec::from_journal_resource(resource).unwrap();
                (spec.destination_prefix(), exact_output(resource))
            })
            .collect()
    }

    fn fixture_ifindex(iface: &str) -> Result<u32> {
        match iface {
            "sptun0" => Ok(77),
            "eth0" => Ok(42),
            "eth1" => Ok(43),
            _ => anyhow::bail!("unexpected interface {iface}"),
        }
    }

    fn destination_prefix(resource: &RouteResource) -> String {
        LinuxOwnedRouteSpec::from_journal_resource(resource)
            .unwrap()
            .destination_prefix()
    }

    fn live_destinations(resources: &[RouteResource]) -> RefCell<BTreeSet<String>> {
        RefCell::new(resources.iter().map(destination_prefix).collect())
    }

    fn prepare_simulated(
        resources: &[RouteResource],
        live: &RefCell<BTreeSet<String>>,
    ) -> std::result::Result<PreparedLinuxRouteRecovery, LinuxRoutePrepareError> {
        PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            resources,
            || Ok(()),
            |command| {
                if command == &owner_inspection_command() {
                    let present: Vec<_> = resources
                        .iter()
                        .filter(|resource| live.borrow().contains(&destination_prefix(resource)))
                        .cloned()
                        .collect();
                    return Ok(owner_output(&present));
                }
                let destination = command
                    .args()
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("inspection destination missing"))?;
                let resource = resources
                    .iter()
                    .find(|resource| destination_prefix(resource) == *destination)
                    .ok_or_else(|| anyhow::anyhow!("unknown inspection destination"))?;
                Ok(if live.borrow().contains(destination) {
                    exact_output(resource)
                } else {
                    b"[]".to_vec()
                })
            },
            fixture_ifindex,
        )
    }

    fn converge_simulated(
        prepared: &mut PreparedLinuxRouteRecovery,
        resources: &[RouteResource],
        live: &RefCell<BTreeSet<String>>,
        inspections: &Cell<usize>,
        executed: &RefCell<Vec<RouteCommand>>,
        resource: &RouteResource,
    ) -> Result<()> {
        prepared
            .remove_exact_with(
                resource,
                || Ok(()),
                |command| {
                    inspections.set(inspections.get() + 1);
                    if command == &owner_inspection_command() {
                        let present: Vec<_> = resources
                            .iter()
                            .filter(|candidate| {
                                live.borrow().contains(&destination_prefix(candidate))
                            })
                            .cloned()
                            .collect();
                        return Ok(owner_output(&present));
                    }
                    let destination = command
                        .args()
                        .last()
                        .ok_or_else(|| anyhow::anyhow!("inspection destination missing"))?;
                    let candidate = resources
                        .iter()
                        .find(|candidate| destination_prefix(candidate) == *destination)
                        .ok_or_else(|| anyhow::anyhow!("unknown inspection destination"))?;
                    Ok(if live.borrow().contains(destination) {
                        exact_output(candidate)
                    } else {
                        b"[]".to_vec()
                    })
                },
                fixture_ifindex,
                |command, resource| {
                    live.borrow_mut().remove(&destination_prefix(resource));
                    executed.borrow_mut().push(command.clone());
                    Ok(())
                },
            )
            .map_err(anyhow::Error::new)
    }

    fn simulate_recovery(
        resources: &[RouteResource],
        owner_pre: Vec<u8>,
        exact_pre: BTreeMap<String, Vec<u8>>,
    ) -> (
        Result<Vec<LinuxOwnedRouteClassification>>,
        Vec<RouteCommand>,
        Vec<String>,
    ) {
        let removed = RefCell::new(BTreeSet::new());
        let executed = RefCell::new(Vec::new());
        let events = RefCell::new(Vec::new());
        let prepared = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            resources,
            || Ok(()),
            |command| {
                events
                    .borrow_mut()
                    .push(format!("inspect:{}", command.display()));
                if command == &owner_inspection_command() {
                    return Ok(owner_pre.clone());
                }
                let destination = command
                    .args
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("inspection destination missing"))?;
                exact_pre
                    .get(destination)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing fixture for {destination}"))
            },
            |iface| match iface {
                "sptun0" => Ok(77),
                "eth0" => Ok(42),
                _ => anyhow::bail!("unexpected interface {iface}"),
            },
        );
        let mut prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return (
                    Err(error.into()),
                    executed.into_inner(),
                    events.into_inner(),
                );
            }
        };
        let classifications = prepared.classifications();
        let result = (|| {
            for (resource, _) in &classifications {
                prepared.remove_exact_with(
                    resource,
                    || Ok(()),
                    |command| {
                        events
                            .borrow_mut()
                            .push(format!("inspect:{}", command.display()));
                        if command == &owner_inspection_command() {
                            let present: Vec<_> = resources
                                .iter()
                                .filter(|candidate| {
                                    let spec =
                                        LinuxOwnedRouteSpec::from_journal_resource(candidate)
                                            .unwrap();
                                    exact_pre
                                        .get(&spec.destination_prefix())
                                        .is_some_and(|output| output != b"[]")
                                        && !removed.borrow().contains(&spec.json_destination())
                                })
                                .cloned()
                                .collect();
                            return Ok(owner_output(&present));
                        }
                        let destination = command
                            .args
                            .last()
                            .ok_or_else(|| anyhow::anyhow!("inspection destination missing"))?;
                        let spec = LinuxOwnedRouteSpec::from_journal_resource(resource).unwrap();
                        if removed.borrow().contains(&spec.json_destination()) {
                            return Ok(b"[]".to_vec());
                        }
                        exact_pre
                            .get(destination)
                            .cloned()
                            .ok_or_else(|| anyhow::anyhow!("missing fixture for {destination}"))
                    },
                    |iface| match iface {
                        "sptun0" => Ok(77),
                        "eth0" => Ok(42),
                        _ => anyhow::bail!("unexpected interface {iface}"),
                    },
                    |command, resource| {
                        events
                            .borrow_mut()
                            .push(format!("execute:{}", command.display()));
                        let spec = LinuxOwnedRouteSpec::from_journal_resource(resource).unwrap();
                        removed.borrow_mut().insert(spec.json_destination());
                        executed.borrow_mut().push(command.clone());
                        Ok(())
                    },
                )?;
            }
            Ok(classifications
                .iter()
                .map(|(_, classification)| *classification)
                .collect())
        })();
        (result, executed.into_inner(), events.into_inner())
    }

    #[test]
    fn split_failure_rolls_back_first_route() {
        let steps = split_steps(RoutePlatform::Linux, "sptun0");
        let first_apply = steps[0].apply.clone();
        let first_undo = steps[0].undo.clone();
        let second_apply = steps[1].apply.clone();
        let mut seen = Vec::new();

        let result = apply_steps_with(steps, |command| {
            seen.push(command.clone());
            if command == &second_apply {
                anyhow::bail!("injected second-route failure");
            }
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(seen, vec![first_apply, second_apply, first_undo]);
    }

    #[test]
    fn successful_cleanup_runs_exact_inverses_in_reverse_order() {
        let steps = split_steps(RoutePlatform::Linux, "sptun0");
        let expected = vec![steps[1].undo.clone(), steps[0].undo.clone()];
        let mut undo = apply_steps_with(steps, |_| Ok(())).unwrap();
        let mut seen = Vec::new();

        let errors = rollback_with(&mut undo, &mut |command| {
            seen.push(command.clone());
            Ok(())
        });

        assert!(errors.is_empty());
        assert!(undo.is_empty());
        assert_eq!(seen, expected);
    }

    #[test]
    fn explicit_cleanup_retains_only_failed_exact_inverses_for_retry() {
        let steps = split_steps(RoutePlatform::Linux, "sptun0");
        let first_undo = steps[0].undo.clone();
        let second_undo = steps[1].undo.clone();
        let mut guard = RouteGuard {
            undo: vec![first_undo.clone(), second_undo.clone()],
            strict_linux_owned: None,
        };
        let mut seen = Vec::new();
        let result = guard.try_remove_with(|command| {
            seen.push(command.clone());
            if command == &second_undo {
                anyhow::bail!("injected exact-delete failure")
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(seen, vec![second_undo.clone(), first_undo]);
        assert_eq!(guard.undo, vec![second_undo.clone()]);

        let mut retried = Vec::new();
        guard
            .try_remove_with(|command| {
                retried.push(command.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(retried, vec![second_undo]);
        assert!(guard.undo.is_empty());
    }

    #[test]
    fn peer_guard_owns_only_the_peer_inverse() {
        let steps = peer_steps(RoutePlatform::Macos, "utun9", "10.8.0.1");
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].undo,
            RouteCommand::new(
                "route",
                &["delete", "-host", "10.8.0.1", "-interface", "utun9"]
            )
        );
        assert!(!steps[0]
            .undo
            .args
            .iter()
            .any(|arg| arg == "0.0.0.0/1" || arg == "128.0.0.0/1"));
    }

    #[test]
    fn server_bypass_adds_without_replace_and_has_exact_inverse() {
        let steps = server_bypass_steps(RoutePlatform::Linux, "203.0.113.7", "192.0.2.1", "eth0");
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].apply,
            RouteCommand::new(
                "ip",
                &[
                    "route",
                    "add",
                    "203.0.113.7",
                    "via",
                    "192.0.2.1",
                    "dev",
                    "eth0"
                ]
            )
        );
        assert_eq!(
            steps[0].undo,
            RouteCommand::new(
                "ip",
                &[
                    "route",
                    "del",
                    "203.0.113.7",
                    "via",
                    "192.0.2.1",
                    "dev",
                    "eth0"
                ]
            )
        );
        assert!(!steps[0].apply.args.iter().any(|arg| arg == "replace"));
    }

    #[test]
    fn existing_route_failure_is_not_assumed_owned_or_removed() {
        let steps = server_bypass_steps(RoutePlatform::Linux, "203.0.113.7", "192.0.2.1", "eth0");
        let apply = steps[0].apply.clone();
        let mut seen = Vec::new();

        let result = apply_steps_with(steps, |command| {
            seen.push(command.clone());
            anyhow::bail!("RTNETLINK answers: File exists")
        });

        assert!(result.is_err());
        assert_eq!(seen, vec![apply]);
    }

    #[test]
    fn parses_gateway_and_direct_underlay_paths() {
        let routed = LinuxUnderlayPath::parse_route_get(
            "203.0.113.7 via 192.0.2.1 dev eth0 src 192.0.2.9 uid 1000\n",
        )
        .unwrap();
        assert_eq!(routed.gateway(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(routed.iface(), "eth0");

        let direct =
            LinuxUnderlayPath::parse_route_get("192.0.2.44 dev enp0s5 src 192.0.2.9 uid 1000\n")
                .unwrap();
        assert_eq!(direct.gateway(), None);
        assert_eq!(direct.iface(), "enp0s5");

        let with_cache_continuation = LinuxUnderlayPath::parse_route_get(
            "198.51.100.77 dev sp3wan0 src 192.0.2.9 uid 0\n    cache\n",
        )
        .unwrap();
        assert_eq!(with_cache_continuation.gateway(), None);
        assert_eq!(with_cache_continuation.iface(), "sp3wan0");
    }

    #[test]
    fn underlay_snapshot_builds_exact_gateway_or_direct_bypass() {
        let via = LinuxUnderlayPath {
            gateway: Some("192.0.2.1".parse().unwrap()),
            iface: "eth0".to_string(),
        };
        let via_steps =
            linux_server_bypass_steps("203.0.113.7".parse().unwrap(), via.gateway(), via.iface());
        assert_eq!(
            via_steps[0].apply.args,
            [
                "route",
                "add",
                "203.0.113.7",
                "via",
                "192.0.2.1",
                "dev",
                "eth0"
            ]
        );
        assert_eq!(
            via_steps[0].undo.args,
            [
                "route",
                "del",
                "203.0.113.7",
                "via",
                "192.0.2.1",
                "dev",
                "eth0"
            ]
        );

        let direct_steps = linux_server_bypass_steps("192.0.2.44".parse().unwrap(), None, "enp0s5");
        assert_eq!(
            direct_steps[0].apply.args,
            ["route", "add", "192.0.2.44", "dev", "enp0s5"]
        );
        assert_eq!(
            direct_steps[0].undo.args,
            ["route", "del", "192.0.2.44", "dev", "enp0s5"]
        );
    }

    #[test]
    fn underlay_parser_rejects_unusable_or_ambiguous_paths() {
        assert!(LinuxUnderlayPath::parse_route_get("").is_err());
        assert!(LinuxUnderlayPath::parse_route_get("unreachable 203.0.113.7").is_err());
        assert!(LinuxUnderlayPath::parse_route_get("203.0.113.7 via nope dev eth0").is_err());
        assert!(LinuxUnderlayPath::parse_route_get("203.0.113.7 via 192.0.2.1").is_err());
        assert!(LinuxUnderlayPath::parse_route_get(
            "203.0.113.7 via 192.0.2.1 via 192.0.2.2 dev eth0"
        )
        .is_err());
        assert!(LinuxUnderlayPath::parse_route_get(
            "203.0.113.7 via 192.0.2.1 dev eth0\n203.0.113.8 via 192.0.2.1 dev eth0"
        )
        .is_err());
        assert!(LinuxUnderlayPath::parse_route_get(
            "203.0.113.7 via 192.0.2.1 dev interface-name-is-too-long"
        )
        .is_err());
    }

    #[test]
    fn owned_linux_route_identity_is_exact_and_never_replaces() {
        let session = SessionId::from_bytes([0x42; 16]);
        let owner = LinuxRouteOwner::for_session(session);
        assert_eq!(owner.protocol(), SHADOWPIPE_ROUTE_PROTOCOL);
        assert_eq!(owner.metric(), u32::from_be_bytes([0x42; 4]));
        let mut zero_prefix_session = [1u8; 16];
        zero_prefix_session[..4].fill(0);
        assert_eq!(
            LinuxRouteOwner::for_session(SessionId::from_bytes(zero_prefix_session)).metric(),
            1
        );
        let path = LinuxUnderlayPath {
            gateway: Some("192.0.2.1".parse().unwrap()),
            iface: "eth0".into(),
        };
        let spec = path
            .owned_bypass_spec("203.0.113.7".parse().unwrap(), owner)
            .unwrap();
        let steps = spec.steps();
        assert_eq!(steps.len(), 1);
        let add = &steps[0].apply.args;
        let del = &steps[0].undo.args;
        assert_eq!(&add[..3], &["-4", "route", "add"]);
        assert_eq!(&del[..3], &["-4", "route", "del"]);
        assert_eq!(&add[3..], &del[3..]);
        let metric = owner.metric().to_string();
        for required in [
            "203.0.113.7/32",
            "192.0.2.1",
            "eth0",
            "254",
            "186",
            metric.as_str(),
        ] {
            assert!(add.iter().any(|argument| argument == required));
        }
        assert!(!add.iter().any(|argument| argument == "replace"));
    }

    #[test]
    fn owned_split_routes_share_session_owner_but_have_distinct_destinations() {
        let owner = LinuxRouteOwner::for_session(SessionId::from_bytes([0x24; 16]));
        let low =
            LinuxOwnedRouteSpec::split_default(Ipv4Addr::UNSPECIFIED, "sptun0", owner).unwrap();
        let high = LinuxOwnedRouteSpec::split_default(Ipv4Addr::new(128, 0, 0, 0), "sptun0", owner)
            .unwrap();
        assert_eq!(low.owner(), high.owner());
        assert_eq!(low.prefix_len(), 1);
        assert_ne!(low.destination(), high.destination());
        assert!(
            LinuxOwnedRouteSpec::split_default("10.0.0.0".parse().unwrap(), "sptun0", owner)
                .is_err()
        );
        assert!(LinuxOwnedRouteSpec::split_default(
            Ipv4Addr::UNSPECIFIED,
            "interface-name-too-long",
            owner
        )
        .is_err());
    }

    #[test]
    fn windows_split_and_peer_have_delete_inverses() {
        let split = split_steps(RoutePlatform::Windows, "17");
        assert_eq!(split.len(), 2);
        for step in &split {
            assert_eq!(step.apply.program, "route");
            assert_eq!(step.apply.args.first().map(String::as_str), Some("add"));
            assert_eq!(step.undo.program, "route");
            assert_eq!(step.undo.args.first().map(String::as_str), Some("delete"));
            assert_eq!(step.apply.args[1..], step.undo.args[1..]);
        }

        let peer = peer_steps(RoutePlatform::Windows, "17", "10.8.0.1");
        assert_eq!(peer.len(), 1);
        assert_eq!(
            peer[0].undo.args,
            [
                "delete",
                "10.8.0.1",
                "mask",
                "255.255.255.255",
                "0.0.0.0",
                "if",
                "17"
            ]
        );

        let bypass = server_bypass_steps(RoutePlatform::Windows, "203.0.113.7", "192.0.2.1", "17");
        assert_eq!(bypass.len(), 1);
        assert_eq!(
            bypass[0].apply.args.first().map(String::as_str),
            Some("add")
        );
        assert_eq!(
            bypass[0].undo.args.first().map(String::as_str),
            Some("delete")
        );
        assert_eq!(bypass[0].apply.args[1..], bypass[0].undo.args[1..]);
    }

    #[test]
    fn all_owned_route_purposes_round_trip_through_v2_journal_resources() {
        let session = recovery_session();
        let resources = recovery_resources();
        assert_eq!(resources[0].purpose, RoutePurpose::SplitDefault);
        assert_eq!(resources[1].purpose, RoutePurpose::SplitDefault);
        assert_eq!(resources[2].purpose, RoutePurpose::EndpointBypass);
        assert_eq!(resources[3].purpose, RoutePurpose::SshBypass);
        assert!(resources.iter().all(|resource| {
            resource.protocol == SHADOWPIPE_ROUTE_PROTOCOL
                && resource.metric == LinuxRouteOwner::for_session(session).metric()
                && resource.output.ifindex != 0
        }));

        let direct = LinuxUnderlayPath {
            gateway: None,
            iface: "eth1".to_string(),
        };
        let direct_resource = LinuxOwnedRouteSpec::endpoint_bypass(
            Ipv4Addr::new(192, 0, 2, 44),
            &direct,
            LinuxRouteOwner::for_session(session),
        )
        .unwrap()
        .journal_resource_with_ifindex(43)
        .unwrap();
        assert_eq!(direct_resource.gateway, None);

        let mut journal_resources = resources.clone();
        journal_resources.push(direct_resource);
        let operations = journal_resources
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, resource)| OperationRecord {
                id: u32::try_from(index + 1).unwrap(),
                state: OperationState::Planned,
                resource: OwnedResource::Route(resource),
            })
            .collect();
        let journal = HostStateJournalV2::new(
            OwnerIdentity {
                session_id: session,
                boot_id: None,
                uid: 501,
                pid: 7,
                pid_start_ticks: None,
                network_namespace: Some(NamespaceIdentity {
                    device: 4,
                    inode: 9,
                }),
                mount_namespace: None,
            },
            operations,
        )
        .unwrap();
        let encoded = serde_json::to_vec(&journal).unwrap();
        let decoded: HostStateJournalV2 = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, journal);
    }

    #[test]
    fn inspection_and_delete_builders_are_exact_deterministic_and_non_heuristic() {
        let session = recovery_session();
        let mut resources = recovery_resources();
        resources.reverse();
        let commands = linux_owned_route_inspection_commands(session, &resources).unwrap();
        assert_eq!(commands.len(), resources.len() + 1);
        assert_eq!(commands[0], owner_inspection_command());
        assert!(commands.iter().all(|command| {
            command.program() == "ip"
                && command.args().iter().any(|argument| argument == "show")
                && !command.args().iter().any(|argument| {
                    matches!(
                        argument.as_str(),
                        "add" | "change" | "del" | "delete" | "flush" | "replace"
                    )
                })
        }));
        assert_eq!(commands[1].args().last().unwrap(), "0.0.0.0/1");
        assert_eq!(commands[2].args().last().unwrap(), "128.0.0.0/1");
        assert_eq!(commands[3].args().last().unwrap(), "198.51.100.9/32");
        assert_eq!(commands[4].args().last().unwrap(), "203.0.113.7/32");
        for command in &commands[1..] {
            assert!(!command
                .args()
                .iter()
                .any(|argument| { matches!(argument.as_str(), "proto" | "metric" | "dev") }));
        }

        let delete = linux_owned_route_delete_command(session, &resources[1]).unwrap();
        assert_eq!(&delete.args()[..3], &["-4", "route", "del"]);
        for required in ["table", "254", "proto", "186", "metric"] {
            assert!(delete.args().iter().any(|argument| argument == required));
        }
        assert!(delete.args().iter().any(|argument| argument == "unicast"));
        assert!(delete.args().iter().any(|argument| argument == "scope"));
        let scope = delete
            .args()
            .iter()
            .position(|argument| argument == "scope")
            .unwrap();
        assert_eq!(delete.args()[scope + 1], "global");
        assert!(!delete
            .args()
            .iter()
            .any(|argument| matches!(argument.as_str(), "flush" | "replace")));

        let direct = LinuxOwnedRouteSpec::endpoint_bypass(
            Ipv4Addr::new(192, 0, 2, 44),
            &LinuxUnderlayPath {
                gateway: None,
                iface: "eth1".to_string(),
            },
            LinuxRouteOwner::for_session(session),
        )
        .unwrap()
        .journal_resource_with_ifindex(43)
        .unwrap();
        let direct_delete = linux_owned_route_delete_command(session, &direct).unwrap();
        let scope = direct_delete
            .args()
            .iter()
            .position(|argument| argument == "scope")
            .unwrap();
        assert_eq!(direct_delete.args()[scope + 1], "link");
    }

    #[test]
    fn pure_classifier_distinguishes_exact_absent_and_every_identity_conflict() {
        let session = recovery_session();
        let resource = recovery_resources().remove(2);
        let exact = exact_output(&resource);
        assert_eq!(
            classify_linux_owned_route(session, &resource, &exact, Some(42)),
            LinuxOwnedRouteClassification::ExactOwnedPresent
        );
        assert_eq!(
            classify_linux_owned_route(session, &resource, b"[]", None),
            LinuxOwnedRouteClassification::Absent
        );
        assert_eq!(
            classify_linux_owned_route(session, &resource, &exact, Some(999)),
            LinuxOwnedRouteClassification::Conflict
        );

        for (field, value) in [
            ("gateway", serde_json::json!("192.0.2.254")),
            ("dev", serde_json::json!("eth9")),
            ("protocol", serde_json::json!("185")),
            ("metric", serde_json::json!(12345)),
        ] {
            let mut modified: serde_json::Value = serde_json::from_slice(&exact).unwrap();
            modified[0][field] = value;
            assert_eq!(
                classify_linux_owned_route(
                    session,
                    &resource,
                    &serde_json::to_vec(&modified).unwrap(),
                    Some(42),
                ),
                LinuxOwnedRouteClassification::Conflict,
                "field {field}"
            );
        }

        let records = parse_linux_route_listing(&exact).unwrap();
        let duplicate = serde_json::to_vec(&vec![records[0].clone(), records[0].clone()]).unwrap();
        assert_eq!(
            classify_linux_owned_route(session, &resource, &duplicate, Some(42)),
            LinuxOwnedRouteClassification::Conflict
        );
        let mut unknown_field: serde_json::Value = serde_json::from_slice(&exact).unwrap();
        unknown_field[0]["prefsrc"] = serde_json::json!("192.0.2.9");
        assert_eq!(
            classify_linux_owned_route(
                session,
                &resource,
                &serde_json::to_vec(&unknown_field).unwrap(),
                Some(42),
            ),
            LinuxOwnedRouteClassification::Conflict
        );
    }

    #[test]
    fn literal_iproute_json_fixtures_match_documented_numeric_schema() {
        let session = recovery_session();
        assert_eq!(
            LinuxRouteOwner::for_session(session).metric(),
            1_515_870_810
        );
        let resources = recovery_resources();
        let split = &resources[0];
        let endpoint = &resources[2];
        let split_exact = br#"[{"dst":"0.0.0.0/1","dev":"sptun0","protocol":"186","scope":"253","metric":1515870810,"flags":[]}]"#;
        let endpoint_exact = br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","protocol":"186","metric":1515870810,"flags":[]}]"#;
        let endpoint_owner = br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","metric":1515870810,"flags":[]}]"#;

        assert_eq!(
            classify_linux_owned_route(session, split, split_exact, Some(77)),
            LinuxOwnedRouteClassification::ExactOwnedPresent
        );
        assert_eq!(
            classify_linux_owned_route(session, endpoint, endpoint_exact, Some(42)),
            LinuxOwnedRouteClassification::ExactOwnedPresent
        );

        let direct = LinuxOwnedRouteSpec::endpoint_bypass(
            Ipv4Addr::new(192, 0, 2, 44),
            &LinuxUnderlayPath {
                gateway: None,
                iface: "eth1".to_string(),
            },
            LinuxRouteOwner::for_session(session),
        )
        .unwrap()
        .journal_resource_with_ifindex(43)
        .unwrap();
        let direct_exact = br#"[{"dst":"192.0.2.44","dev":"eth1","protocol":"186","scope":"253","metric":1515870810,"flags":[]}]"#;
        assert_eq!(
            classify_linux_owned_route(session, &direct, direct_exact, Some(43)),
            LinuxOwnedRouteClassification::ExactOwnedPresent
        );

        let prepared = PreparedLinuxRouteRecovery::prepare_with(
            session,
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(endpoint),
            || Ok(()),
            |command| {
                Ok(if command == &owner_inspection_command() {
                    endpoint_owner.to_vec()
                } else {
                    endpoint_exact.to_vec()
                })
            },
            |_| Ok(42),
        )
        .unwrap();
        assert_eq!(
            prepared.classification(endpoint),
            Some(LinuxOwnedRouteClassification::ExactOwnedPresent)
        );
    }

    #[test]
    fn literal_iproute_schema_rejects_type_drift_unknowns_and_duplicates() {
        let session = recovery_session();
        let endpoint = recovery_resources().remove(2);
        for invalid in [
            br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","protocol":186,"metric":1515870810,"flags":[]}]"#.as_slice(),
            br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","protocol":"186","scope":253,"metric":1515870810,"flags":[]}]"#.as_slice(),
            br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","protocol":"186","metric":1515870810,"prefsrc":"192.0.2.9","flags":[]}]"#.as_slice(),
            br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","protocol":"186","metric":1515870810,"flags":[]},{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","protocol":"186","metric":1515870810,"flags":[]}]"#.as_slice(),
        ] {
            assert_eq!(
                classify_linux_owned_route(session, &endpoint, invalid, Some(42)),
                LinuxOwnedRouteClassification::Conflict
            );
        }

        let expected = vec![LinuxOwnedRouteSpec::from_journal_resource(&endpoint)
            .unwrap()
            .expected_json_record(false)];
        let owner_with_protocol = br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","protocol":"186","metric":1515870810,"flags":[]}]"#;
        assert!(matches!(
            PreparedLinuxRouteRecovery::verify_owner_census_against(owner_with_protocol, &expected),
            Err(LinuxRouteConvergeError::Operational { .. })
        ));
        let owner_with_table = br#"[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","table":254,"metric":1515870810,"flags":[]}]"#;
        assert!(parse_linux_route_listing(owner_with_table).is_err());
    }

    #[test]
    fn numeric_scope_and_direct_bypass_are_classified_exactly() {
        let session = recovery_session();
        let split = &recovery_resources()[0];
        let split_json = exact_output(split);
        assert!(String::from_utf8_lossy(&split_json).contains("\"scope\":\"253\""));
        assert_eq!(
            classify_linux_owned_route(session, split, &split_json, Some(77)),
            LinuxOwnedRouteClassification::ExactOwnedPresent
        );

        let direct = LinuxOwnedRouteSpec::endpoint_bypass(
            Ipv4Addr::new(192, 0, 2, 44),
            &LinuxUnderlayPath {
                gateway: None,
                iface: "eth1".to_string(),
            },
            LinuxRouteOwner::for_session(session),
        )
        .unwrap()
        .journal_resource_with_ifindex(43)
        .unwrap();
        assert_eq!(
            classify_linux_owned_route(session, &direct, &exact_output(&direct), Some(43)),
            LinuxOwnedRouteClassification::ExactOwnedPresent
        );
    }

    #[test]
    fn linkdown_is_the_only_normalized_volatile_route_flag() {
        let session = recovery_session();
        let resources = recovery_resources();
        let resource = &resources[0];
        let mut linkdown: serde_json::Value =
            serde_json::from_slice(&exact_output(resource)).unwrap();
        linkdown[0]["flags"] = serde_json::json!(["linkdown"]);
        assert_eq!(
            classify_linux_owned_route(
                session,
                resource,
                &serde_json::to_vec(&linkdown).unwrap(),
                Some(77),
            ),
            LinuxOwnedRouteClassification::ExactOwnedPresent
        );

        for flags in [
            serde_json::json!(["onlink"]),
            serde_json::json!(["pervasive"]),
            serde_json::json!(["mystery"]),
            serde_json::json!(["linkdown", "linkdown"]),
        ] {
            let mut conflicted = linkdown.clone();
            conflicted[0]["flags"] = flags;
            assert_eq!(
                classify_linux_owned_route(
                    session,
                    resource,
                    &serde_json::to_vec(&conflicted).unwrap(),
                    Some(77),
                ),
                LinuxOwnedRouteClassification::Conflict
            );
        }

        let mut owner: serde_json::Value =
            serde_json::from_slice(&owner_output(&resources)).unwrap();
        for record in owner.as_array_mut().unwrap() {
            record["flags"] = serde_json::json!(["linkdown"]);
        }
        let mut exact = exact_outputs(&resources);
        for output in exact.values_mut() {
            let mut record: serde_json::Value = serde_json::from_slice(output).unwrap();
            record[0]["flags"] = serde_json::json!(["linkdown"]);
            *output = serde_json::to_vec(&record).unwrap();
        }
        let (result, executed, _) =
            simulate_recovery(&resources, serde_json::to_vec(&owner).unwrap(), exact);
        assert!(result.is_ok());
        assert_eq!(executed.len(), resources.len());
    }

    #[test]
    fn strict_parser_rejects_malformed_oversized_and_overpopulated_json() {
        let session = recovery_session();
        let resource = recovery_resources().remove(2);
        assert_eq!(
            classify_linux_owned_route(session, &resource, b"[{", Some(42)),
            LinuxOwnedRouteClassification::Conflict
        );
        let oversized = vec![b' '; MAX_LINUX_ROUTE_INSPECTION_BYTES + 1];
        assert_eq!(
            classify_linux_owned_route(session, &resource, &oversized, Some(42)),
            LinuxOwnedRouteClassification::Conflict
        );
        let record = parse_linux_route_listing(&exact_output(&resource)).unwrap()[0].clone();
        let overpopulated =
            serde_json::to_vec(&vec![record; MAX_LINUX_ROUTE_INSPECTION_RECORDS + 1]).unwrap();
        assert_eq!(
            classify_linux_owned_route(session, &resource, &overpopulated, Some(42)),
            LinuxOwnedRouteClassification::Conflict
        );
    }

    #[test]
    fn coherent_recovery_verifies_every_route_before_ranked_strict_deletes() {
        let resources = recovery_resources();
        let (result, executed, events) = simulate_recovery(
            &resources,
            owner_output(&resources),
            exact_outputs(&resources),
        );
        assert_eq!(
            result.unwrap(),
            vec![LinuxOwnedRouteClassification::ExactOwnedPresent; 4]
        );
        assert_eq!(executed.len(), 4);
        assert_eq!(executed[0].args()[4], "0.0.0.0/1");
        assert_eq!(executed[1].args()[4], "128.0.0.0/1");
        assert!(executed.iter().all(|command| {
            command.args().iter().any(|argument| argument == "186")
                && command.args().iter().any(|argument| argument == "metric")
        }));
        let first_execute = events
            .iter()
            .position(|event| event.starts_with("execute:"))
            .unwrap();
        assert!(first_execute >= resources.len() + 2);
        assert!(events[..first_execute]
            .iter()
            .all(|event| event.starts_with("inspect:")));
    }

    #[test]
    fn absent_route_is_not_deleted_and_owner_snapshot_must_agree() {
        let resources = recovery_resources();
        let absent_destination = LinuxOwnedRouteSpec::from_journal_resource(&resources[2])
            .unwrap()
            .destination_prefix();
        let present: Vec<_> = resources
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 2)
            .map(|(_, resource)| resource.clone())
            .collect();
        let mut exact = exact_outputs(&resources);
        exact.insert(absent_destination.clone(), b"[]".to_vec());
        let (result, executed, _) = simulate_recovery(&resources, owner_output(&present), exact);
        let classifications = result.unwrap();
        assert_eq!(
            classifications
                .iter()
                .filter(|classification| {
                    **classification == LinuxOwnedRouteClassification::Absent
                })
                .count(),
            1
        );
        assert_eq!(executed.len(), 3);
        assert!(!executed
            .iter()
            .any(|command| command.args()[4] == absent_destination));
    }

    #[test]
    fn prepared_recovery_enforces_route_order_foreign_replay_and_full_completion() {
        let resources = recovery_resources();
        let live = live_destinations(&resources);
        let mut prepared = prepare_simulated(&resources, &live).unwrap();
        let inspections = Cell::new(0usize);
        let executed = RefCell::new(Vec::new());
        let foreign = LinuxOwnedRouteSpec::endpoint_bypass(
            Ipv4Addr::new(192, 0, 2, 55),
            &LinuxUnderlayPath {
                gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                iface: "eth0".to_string(),
            },
            LinuxRouteOwner::for_session(recovery_session()),
        )
        .unwrap()
        .journal_resource_with_ifindex(42)
        .unwrap();

        assert!(converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &foreign,
        )
        .is_err());
        assert_eq!(inspections.get(), 0, "foreign resource reached host I/O");
        assert!(converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &resources[2],
        )
        .is_err());
        assert_eq!(
            inspections.get(),
            0,
            "out-of-order resource reached host I/O"
        );

        converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &resources[0],
        )
        .unwrap();
        assert_eq!(prepared.remaining_exact_count(), 3);
        let after_first = inspections.get();
        assert!(converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &resources[0],
        )
        .is_err());
        assert_eq!(inspections.get(), after_first, "replay reached host I/O");

        converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &resources[1],
        )
        .unwrap();
        // The generic driver may checkpoint DNS here. Route-relative state
        // deliberately preserves both bypasses across that rank boundary.
        assert_eq!(prepared.remaining_exact_count(), 2);
        for resource in &resources[2..] {
            converge_simulated(
                &mut prepared,
                &resources,
                &live,
                &inspections,
                &executed,
                resource,
            )
            .unwrap();
        }
        assert_eq!(prepared.remaining_exact_count(), 0);
        let destinations: Vec<_> = executed
            .borrow()
            .iter()
            .map(|command| command.args()[4].clone())
            .collect();
        assert_eq!(
            destinations,
            vec![
                "0.0.0.0/1",
                "128.0.0.0/1",
                "203.0.113.7/32",
                "198.51.100.9/32"
            ]
        );
    }

    #[test]
    fn prepared_absent_and_exact_observations_converge_current_state() {
        let resource = recovery_resources().remove(2);
        let resources = vec![resource.clone()];

        let live = RefCell::new(BTreeSet::new());
        let mut prepared = prepare_simulated(&resources, &live).unwrap();
        assert_eq!(
            prepared.classification(&resource),
            Some(LinuxOwnedRouteClassification::Absent)
        );
        let inspections = Cell::new(0usize);
        let executed = RefCell::new(Vec::new());
        converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &resource,
        )
        .unwrap();
        assert!(executed.borrow().is_empty());
        let after_absent = inspections.get();
        assert!(converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &resource,
        )
        .is_err());
        assert_eq!(inspections.get(), after_absent);

        let live = RefCell::new(BTreeSet::new());
        let mut prepared = prepare_simulated(&resources, &live).unwrap();
        live.borrow_mut().insert(destination_prefix(&resource));
        let executed = RefCell::new(Vec::new());
        converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &Cell::new(0),
            &executed,
            &resource,
        )
        .unwrap();
        assert_eq!(
            executed.borrow().len(),
            1,
            "reappeared exact route was not deleted"
        );

        let live = live_destinations(&resources);
        let mut prepared = prepare_simulated(&resources, &live).unwrap();
        live.borrow_mut().clear();
        let executed = RefCell::new(Vec::new());
        converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &Cell::new(0),
            &executed,
            &resource,
        )
        .unwrap();
        assert!(
            executed.borrow().is_empty(),
            "already-disappeared route was mutated"
        );
    }

    #[test]
    fn prepare_brackets_owner_census_and_types_conflict_vs_operational_error() {
        let resource = recovery_resources().remove(2);
        let owner = owner_output(std::slice::from_ref(&resource));
        let exact = exact_output(&resource);
        let owner_calls = Cell::new(0usize);
        let racing = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || Ok(()),
            |command| {
                if command == &owner_inspection_command() {
                    let call = owner_calls.get();
                    owner_calls.set(call + 1);
                    return Ok(if call == 0 {
                        owner.clone()
                    } else {
                        b"[]".to_vec()
                    });
                }
                Ok(exact.clone())
            },
            |_| Ok(42),
        );
        assert!(matches!(
            racing,
            Err(LinuxRoutePrepareError::Conflict { .. })
        ));
        assert_eq!(owner_calls.get(), 2);

        let operational = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || Ok(()),
            |_| anyhow::bail!("injected read-only inspection failure"),
            |_| Ok(42),
        );
        assert!(matches!(
            operational,
            Err(LinuxRoutePrepareError::Operational { .. })
        ));

        let malformed_inspection = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || Ok(()),
            |_| Ok(b"not-json".to_vec()),
            |_| Ok(42),
        );
        assert!(matches!(
            malformed_inspection,
            Err(LinuxRoutePrepareError::Operational { .. })
        ));

        let ifindex_syscall = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || Ok(()),
            |command| {
                Ok(if command == &owner_inspection_command() {
                    owner.clone()
                } else {
                    exact.clone()
                })
            },
            |_| anyhow::bail!("injected if_nametoindex syscall failure"),
        );
        assert!(matches!(
            ifindex_syscall,
            Err(LinuxRoutePrepareError::Operational { .. })
        ));

        let namespace_syscall = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || anyhow::bail!("injected namespace metadata syscall failure"),
            |_| unreachable!("namespace I/O failure must precede inspection"),
            |_| unreachable!("namespace I/O failure must precede ifindex resolution"),
        );
        assert!(matches!(
            namespace_syscall,
            Err(LinuxRoutePrepareError::Operational { .. })
        ));

        let namespace_mismatch = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || {
                Err(anyhow::Error::new(LinuxRoutePrepareError::conflict(
                    "evidenced network namespace mismatch",
                )))
            },
            |_| unreachable!("namespace mismatch must precede inspection"),
            |_| unreachable!("namespace mismatch must precede ifindex resolution"),
        );
        assert!(matches!(
            namespace_mismatch,
            Err(LinuxRoutePrepareError::Conflict { .. })
        ));
    }

    #[test]
    fn empty_prepared_set_still_censuses_reserved_protocol_namespace() {
        let inspections = Cell::new(0usize);
        let prepared = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            &[],
            || Ok(()),
            |_| {
                inspections.set(inspections.get() + 1);
                Ok(b"[]".to_vec())
            },
            |_| anyhow::bail!("empty recovery must not resolve interfaces"),
        )
        .unwrap();
        assert!(prepared.classifications().is_empty());
        assert_eq!(inspections.get(), 2);

        let resource = recovery_resources().remove(2);
        let unexpected_owner = owner_output(std::slice::from_ref(&resource));
        let conflict = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            &[],
            || Ok(()),
            |_| Ok(unexpected_owner.clone()),
            |_| anyhow::bail!("empty recovery must not resolve interfaces"),
        );
        assert!(matches!(
            conflict,
            Err(LinuxRoutePrepareError::Conflict { .. })
        ));
        assert_eq!(
            linux_owned_route_inspection_commands(recovery_session(), &[]).unwrap(),
            vec![owner_inspection_command()]
        );
    }

    #[test]
    fn every_invalid_snapshot_performs_zero_mutations_and_preserves_error_class() {
        let resources = recovery_resources();
        let baseline_owner = owner_output(&resources);
        let baseline_exact = exact_outputs(&resources);

        let mut unknown_records = parse_linux_route_listing(&baseline_owner).unwrap();
        let mut unknown = unknown_records[0].clone();
        unknown.dst = "64.0.0.0/2".to_string();
        unknown_records.push(unknown);
        let (result, executed, _) = simulate_recovery(
            &resources,
            serde_json::to_vec(&unknown_records).unwrap(),
            baseline_exact.clone(),
        );
        assert!(matches!(
            result
                .as_ref()
                .unwrap_err()
                .downcast_ref::<LinuxRoutePrepareError>(),
            Some(LinuxRoutePrepareError::Conflict { .. })
        ));
        assert!(executed.is_empty());

        for (field, value) in [
            ("gateway", serde_json::json!("192.0.2.254")),
            ("dev", serde_json::json!("eth9")),
            ("protocol", serde_json::json!("185")),
            ("metric", serde_json::json!(99999)),
        ] {
            let mut exact = baseline_exact.clone();
            let key = "203.0.113.7/32".to_string();
            let mut changed: serde_json::Value =
                serde_json::from_slice(exact.get(&key).unwrap()).unwrap();
            changed[0][field] = value;
            exact.insert(key, serde_json::to_vec(&changed).unwrap());
            let (result, executed, _) =
                simulate_recovery(&resources, baseline_owner.clone(), exact);
            assert!(result.is_err(), "field {field}");
            assert!(executed.is_empty(), "field {field}");
        }

        let mut duplicate = baseline_exact.clone();
        let record =
            parse_linux_route_listing(duplicate.get("203.0.113.7/32").unwrap()).unwrap()[0].clone();
        duplicate.insert(
            "203.0.113.7/32".to_string(),
            serde_json::to_vec(&vec![record.clone(), record]).unwrap(),
        );
        let (result, executed, _) =
            simulate_recovery(&resources, baseline_owner.clone(), duplicate);
        assert!(result.is_err());
        assert!(executed.is_empty());

        let mut malformed = baseline_exact;
        malformed.insert("203.0.113.7/32".to_string(), b"not-json".to_vec());
        let (result, executed, _) = simulate_recovery(&resources, baseline_owner, malformed);
        assert!(matches!(
            result
                .as_ref()
                .unwrap_err()
                .downcast_ref::<LinuxRoutePrepareError>(),
            Some(LinuxRoutePrepareError::Operational { .. })
        ));
        assert!(executed.is_empty());

        let (result, executed, _) = simulate_recovery(
            &resources,
            vec![b' '; MAX_LINUX_ROUTE_INSPECTION_BYTES + 1],
            exact_outputs(&resources),
        );
        assert!(matches!(
            result
                .as_ref()
                .unwrap_err()
                .downcast_ref::<LinuxRoutePrepareError>(),
            Some(LinuxRoutePrepareError::Operational { .. })
        ));
        assert!(executed.is_empty());
    }

    #[test]
    fn post_delete_reappearance_is_not_reported_as_recovered() {
        let resource = recovery_resources().remove(2);
        let exact = exact_output(&resource);
        let owner = owner_output(std::slice::from_ref(&resource));
        let executions = Cell::new(0usize);
        let mut prepared = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || Ok(()),
            |command| {
                if command == &owner_inspection_command() {
                    Ok(owner.clone())
                } else {
                    Ok(exact.clone())
                }
            },
            |_| Ok(42),
        )
        .unwrap();
        let result = prepared.remove_exact_with(
            &resource,
            || Ok(()),
            |command| {
                if command == &owner_inspection_command() {
                    Ok(owner.clone())
                } else {
                    // The exact tuple is still observed after the strict delete,
                    // modeling an immediate reappearance or incomplete removal.
                    Ok(exact.clone())
                }
            },
            |_| Ok(42),
            |_, _| {
                executions.set(executions.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(executions.get(), 1);
    }

    #[test]
    fn immediate_exact_race_aborts_before_mutation() {
        let resource = recovery_resources().remove(2);
        let resources = vec![resource.clone()];
        let live = live_destinations(&resources);
        let mut prepared = prepare_simulated(&resources, &live).unwrap();
        let exact = exact_output(&resource);
        let owner = owner_output(&resources);
        let exact_calls = Cell::new(0usize);
        let executions = Cell::new(0usize);
        let result = prepared.remove_exact_with(
            &resource,
            || Ok(()),
            |command| {
                if command == &owner_inspection_command() {
                    return Ok(owner.clone());
                }
                let call = exact_calls.get();
                exact_calls.set(call + 1);
                Ok(if call == 0 {
                    exact.clone()
                } else {
                    b"[]".to_vec()
                })
            },
            |_| Ok(42),
            |_, _| {
                executions.set(executions.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(exact_calls.get(), 2);
        assert_eq!(executions.get(), 0);
    }

    #[test]
    fn unknown_reserved_protocol_route_between_steps_aborts_next_mutation() {
        let resources = recovery_resources()[..2].to_vec();
        let live = live_destinations(&resources);
        let mut prepared = prepare_simulated(&resources, &live).unwrap();
        let inspections = Cell::new(0usize);
        let executed = RefCell::new(Vec::new());
        converge_simulated(
            &mut prepared,
            &resources,
            &live,
            &inspections,
            &executed,
            &resources[0],
        )
        .unwrap();
        assert_eq!(executed.borrow().len(), 1);

        let exact = exact_output(&resources[1]);
        let mut owner_records = parse_linux_route_listing(&owner_output(&resources[1..])).unwrap();
        let mut unknown = owner_records[0].clone();
        unknown.dst = "64.0.0.0/2".to_string();
        owner_records.push(unknown);
        let raced_owner = serde_json::to_vec(&owner_records).unwrap();
        let result = prepared.remove_exact_with(
            &resources[1],
            || Ok(()),
            |command| {
                Ok(if command == &owner_inspection_command() {
                    raced_owner.clone()
                } else {
                    exact.clone()
                })
            },
            |_| Ok(77),
            |command, _| {
                executed.borrow_mut().push(command.clone());
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(executed.borrow().len(), 1);
    }

    #[test]
    fn drift_after_complete_preflight_aborts_before_that_delete() {
        let resource = recovery_resources().remove(2);
        let exact = exact_output(&resource);
        let owner = owner_output(std::slice::from_ref(&resource));
        let exact_inspections = Cell::new(0usize);
        let executions = Cell::new(0usize);
        let mut prepared = PreparedLinuxRouteRecovery::prepare_with(
            recovery_session(),
            NamespaceIdentity {
                device: 4,
                inode: 9,
            },
            std::slice::from_ref(&resource),
            || Ok(()),
            |command| {
                if command == &owner_inspection_command() {
                    return Ok(owner.clone());
                }
                let inspection = exact_inspections.get() + 1;
                exact_inspections.set(inspection);
                Ok(if inspection == 1 {
                    exact.clone()
                } else {
                    b"[]".to_vec()
                })
            },
            |_| Ok(42),
        )
        .unwrap();
        let result = prepared.remove_exact_with(
            &resource,
            || Ok(()),
            |command| {
                if command == &owner_inspection_command() {
                    return Ok(owner.clone());
                }
                let inspection = exact_inspections.get() + 1;
                exact_inspections.set(inspection);
                Ok(if inspection == 1 {
                    exact.clone()
                } else {
                    b"[]".to_vec()
                })
            },
            |_| Ok(42),
            |_, _| {
                executions.set(executions.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(exact_inspections.get(), 2);
        assert_eq!(executions.get(), 0);
    }

    #[test]
    fn late_convergence_maps_conflicts_and_operational_failures_without_mutation() {
        let resource = recovery_resources().remove(2);
        let resources = vec![resource.clone()];
        let live = live_destinations(&resources);
        let mut inspection_failure = prepare_simulated(&resources, &live).unwrap();
        let executed = Cell::new(0usize);
        let operational = inspection_failure.remove_exact_with(
            &resource,
            || Ok(()),
            |_| anyhow::bail!("injected route inspection syscall failure"),
            fixture_ifindex,
            |_, _| {
                executed.set(executed.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(
            operational,
            Err(LinuxRouteConvergeError::Operational { .. })
        ));
        assert_eq!(executed.get(), 0);

        let mut namespace_failure = prepare_simulated(&resources, &live).unwrap();
        let namespace = namespace_failure.remove_exact_with(
            &resource,
            || {
                Err(anyhow::Error::new(LinuxRouteConvergeError::conflict(
                    "journal namespace no longer matches",
                )))
            },
            |_| unreachable!("namespace conflict must precede inspection"),
            fixture_ifindex,
            |_, _| unreachable!("namespace conflict must precede deletion"),
        );
        assert!(matches!(
            namespace,
            Err(LinuxRouteConvergeError::Conflict { .. })
        ));

        let mut namespace_syscall_failure = prepare_simulated(&resources, &live).unwrap();
        let namespace_io = namespace_syscall_failure.remove_exact_with(
            &resource,
            || anyhow::bail!("injected namespace metadata syscall failure"),
            |_| unreachable!("namespace I/O failure must precede inspection"),
            fixture_ifindex,
            |_, _| unreachable!("namespace I/O failure must precede deletion"),
        );
        assert!(matches!(
            namespace_io,
            Err(LinuxRouteConvergeError::Operational { .. })
        ));

        let exact = exact_output(&resource);
        let owner = owner_output(std::slice::from_ref(&resource));
        let mut delete_failure = prepare_simulated(&resources, &live).unwrap();
        let delete = delete_failure.remove_exact_with(
            &resource,
            || Ok(()),
            |command| {
                Ok(if command == &owner_inspection_command() {
                    owner.clone()
                } else {
                    exact.clone()
                })
            },
            fixture_ifindex,
            |_, _| anyhow::bail!("injected delete timeout"),
        );
        assert!(matches!(
            delete,
            Err(LinuxRouteConvergeError::Operational { .. })
        ));
    }

    #[test]
    fn different_boot_absent_then_present_route_is_conflict_and_never_deleted() {
        let resource = recovery_resources().remove(2);
        let resources = vec![resource.clone()];
        let live = RefCell::new(BTreeSet::new());
        let mut prepared = prepare_simulated(&resources, &live).unwrap();
        prepared.same_boot = false;
        live.borrow_mut().insert(destination_prefix(&resource));
        let executions = Cell::new(0usize);
        let result = prepared.remove_exact_with(
            &resource,
            || Ok(()),
            |command| {
                Ok(if command == &owner_inspection_command() {
                    owner_output(&resources)
                } else {
                    exact_output(&resource)
                })
            },
            fixture_ifindex,
            |_, _| {
                executions.set(executions.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(LinuxRouteConvergeError::Conflict { .. })
        ));
        assert_eq!(executions.get(), 0);

        let empty = RefCell::new(BTreeSet::new());
        let mut absent = prepare_simulated(&resources, &empty).unwrap();
        absent.same_boot = false;
        let absent_executions = Cell::new(0usize);
        absent
            .remove_exact_with(
                &resource,
                || Ok(()),
                |_| Ok(b"[]".to_vec()),
                |_| unreachable!("absent route must not resolve an interface"),
                |_, _| {
                    absent_executions.set(absent_executions.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(absent_executions.get(), 0);
    }

    #[test]
    fn live_owned_route_add_and_delete_require_exact_pre_post_census() {
        let resource = recovery_resources().remove(2);
        let spec = LinuxOwnedRouteSpec::from_journal_resource(&resource).unwrap();
        let namespace = NamespaceIdentity {
            device: 4,
            inode: 9,
        };
        let live = Cell::new(false);
        let executed = RefCell::new(Vec::new());
        let inspect = |command: &RouteCommand| -> Result<Vec<u8>> {
            if command == &owner_inspection_command() {
                return Ok(if live.get() {
                    owner_output(std::slice::from_ref(&resource))
                } else {
                    b"[]".to_vec()
                });
            }
            Ok(if live.get() {
                exact_output(&resource)
            } else {
                b"[]".to_vec()
            })
        };
        let mut guard = install_linux_owned_with(
            &spec,
            &resource,
            || Ok(namespace),
            inspect,
            |_| Ok(42),
            |command| {
                assert!(command.args().iter().any(|argument| argument == "add"));
                live.set(true);
                executed.borrow_mut().push(command.clone());
                Ok(())
            },
        )
        .unwrap();
        assert!(live.get());
        assert_eq!(executed.borrow().len(), 1);

        let runtime = guard.strict_linux_owned.clone().unwrap();
        remove_linux_owned_with(
            &runtime,
            || Ok(namespace),
            |command| {
                if command == &owner_inspection_command() {
                    return Ok(if live.get() {
                        owner_output(std::slice::from_ref(&resource))
                    } else {
                        b"[]".to_vec()
                    });
                }
                Ok(if live.get() {
                    exact_output(&resource)
                } else {
                    b"[]".to_vec()
                })
            },
            |_| Ok(42),
            |command| {
                assert!(command.args().iter().any(|argument| argument == "del"));
                live.set(false);
                executed.borrow_mut().push(command.clone());
                Ok(())
            },
        )
        .unwrap();
        guard.undo.clear();
        guard.strict_linux_owned = None;
        assert!(!live.get());
        assert_eq!(executed.borrow().len(), 2);
    }

    #[test]
    fn live_owned_route_rejects_durable_ifindex_drift_before_add() {
        let resource = recovery_resources().remove(2);
        let spec = LinuxOwnedRouteSpec::from_journal_resource(&resource).unwrap();
        let executions = Cell::new(0usize);
        let result = install_linux_owned_with(
            &spec,
            &resource,
            || {
                Ok(NamespaceIdentity {
                    device: 4,
                    inode: 9,
                })
            },
            |_| Ok(b"[]".to_vec()),
            |_| Ok(999),
            |_| {
                executions.set(executions.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(executions.get(), 0);
    }

    #[test]
    fn live_owned_route_does_not_report_success_when_owner_post_census_drifts() {
        let resources = recovery_resources();
        let resource = resources[2].clone();
        let spec = LinuxOwnedRouteSpec::from_journal_resource(&resource).unwrap();
        let namespace = NamespaceIdentity {
            device: 4,
            inode: 9,
        };
        let live = Cell::new(false);
        let owner_calls = Cell::new(0usize);
        let executions = Cell::new(0usize);
        let result = install_linux_owned_with(
            &spec,
            &resource,
            || Ok(namespace),
            |command| {
                if command == &owner_inspection_command() {
                    let call = owner_calls.get();
                    owner_calls.set(call + 1);
                    return Ok(if call == 0 {
                        b"[]".to_vec()
                    } else {
                        owner_output(&resources[2..])
                    });
                }
                Ok(if live.get() {
                    exact_output(&resource)
                } else {
                    b"[]".to_vec()
                })
            },
            |_| Ok(42),
            |_| {
                executions.set(executions.get() + 1);
                live.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(executions.get(), 1);
        assert_eq!(owner_calls.get(), 2);
    }

    #[test]
    fn live_delete_does_not_treat_misleading_cannot_find_as_absence() {
        let resource = recovery_resources().remove(2);
        let runtime = LinuxOwnedRouteRuntime {
            spec: LinuxOwnedRouteSpec::from_journal_resource(&resource).unwrap(),
            resource: resource.clone(),
        };
        let namespace = NamespaceIdentity {
            device: 4,
            inode: 9,
        };
        let executions = Cell::new(0usize);
        let result = remove_linux_owned_with(
            &runtime,
            || Ok(namespace),
            |command| {
                Ok(if command == &owner_inspection_command() {
                    owner_output(std::slice::from_ref(&resource))
                } else {
                    exact_output(&resource)
                })
            },
            |_| Ok(42),
            |_| {
                executions.set(executions.get() + 1);
                anyhow::bail!("RTNETLINK answers: Cannot find device sptun0")
            },
        );
        assert!(result.is_err());
        assert_eq!(executions.get(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_subprocess_times_out_kills_reaps_and_never_waits_on_inherited_pipes() {
        let command = RouteCommand {
            program: "/bin/sh",
            args: vec![
                "-c".to_string(),
                "trap '' TERM; sleep 30 & wait".to_string(),
            ],
        };
        let started = std::time::Instant::now();
        let error =
            run_bounded_route_subprocess(&command, std::time::Duration::from_millis(80), 128, 128)
                .expect_err("hanging process group must time out");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_route_subprocess_kills_successful_childs_pipe_holder() {
        let command = RouteCommand {
            program: "/bin/sh",
            args: vec![
                "-c".to_string(),
                "sleep 5 & printf '%s\\n' \"$!\"".to_string(),
            ],
        };
        let started = std::time::Instant::now();
        let output =
            run_bounded_route_subprocess(&command, std::time::Duration::from_secs(2), 128, 128)
                .unwrap();
        assert!(output.status.success());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "route runner waited for descendant pipe EOF: {:?}",
            started.elapsed()
        );
        if let Ok(pid) = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<libc::pid_t>()
        {
            #[cfg(target_os = "linux")]
            assert_linux_process_not_running(pid);
            #[cfg(not(target_os = "linux"))]
            {
                // SAFETY: pid came from the fixture's `$!`; cleanup is
                // best-effort where /proc state inspection is unavailable.
                let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_route_subprocess_sterilizes_privileged_helper_environment() {
        let command = RouteCommand {
            program: "/bin/sh",
            args: vec![
                "-c".to_string(),
                "test \"$PATH\" = /usr/sbin:/usr/bin:/sbin:/bin && \
                 test \"$LC_ALL\" = C && \
                 test -z \"${LD_PRELOAD+x}\" && \
                 test -z \"${XTABLES_LIBDIR+x}\" && \
                 test -z \"${BASH_ENV+x}\""
                    .to_string(),
            ],
        };
        let output =
            run_bounded_route_subprocess(&command, std::time::Duration::from_secs(2), 128, 128)
                .unwrap();
        assert!(
            output.status.success(),
            "sterile route helper rejected its environment: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_route_resolver_rejects_writable_canonical_ancestor() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let nonce = rand::random::<u64>();
        let unsafe_root = std::env::temp_dir().join(format!(
            "shadowpipe-route-unsafe-helper-{}-{nonce}",
            std::process::id()
        ));
        let secure_root = Path::new("/root").join(format!(
            ".shadowpipe-route-secure-helper-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&unsafe_root).unwrap();
        std::fs::create_dir_all(&secure_root).unwrap();
        std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(&secure_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = unsafe_root.join("helper");
        std::fs::copy("/bin/sh", &target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let candidate = secure_root.join("helper");
        symlink(&target, &candidate).unwrap();

        let result = trusted_linux_route_executable(candidate.to_str().unwrap());
        std::fs::remove_dir_all(&secure_root).unwrap();
        std::fs::remove_dir_all(&unsafe_root).unwrap();
        assert!(
            result.is_err(),
            "route resolver accepted a helper below a writable canonical ancestor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn termination_kills_direct_child_even_when_expected_process_group_is_absent() {
        // Spawn without the production runner's process_group(0), which models
        // a direct child that escaped the original group before the timeout.
        // kill(-child_pid) then sees ESRCH; the direct-child fallback must still
        // terminate and reap it without waiting for `sleep` to finish.
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let child_pid = i32::try_from(child.id()).unwrap();
        // SAFETY: querying a live child process group has no side effects.
        let actual_group = unsafe { libc::getpgid(child_pid) };
        assert_ne!(
            actual_group, child_pid,
            "fixture unexpectedly owns pid-named group"
        );

        let started = std::time::Instant::now();
        let (_kill_error, wait_result) = terminate_process_group_and_reap(&mut child);
        let status = wait_result.unwrap();
        assert!(!status.success());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "direct-child fallback waited past its bound: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn misleading_cannot_find_device_stderr_is_not_success_evidence() {
        let command = RouteCommand {
            program: "/bin/sh",
            args: vec![
                "-c".to_string(),
                "printf 'RTNETLINK answers: Cannot find device fake0\\n' >&2; exit 2".to_string(),
            ],
        };
        let error =
            run_bounded_route_command_strict_status(&command, std::time::Duration::from_secs(2))
                .expect_err("stderr text must never override a non-zero exit status");
        assert!(error.to_string().contains("Cannot find device"));
        assert!(
            run_command(&command).is_err(),
            "the platform route runner must not infer absence from stderr"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_subprocess_drains_but_retains_only_configured_output_limits() {
        let command = RouteCommand {
            program: "/bin/sh",
            args: vec![
                "-c".to_string(),
                "i=0; while [ $i -lt 2000 ]; do printf 0123456789; printf abcdefghij >&2; i=$((i+1)); done"
                    .to_string(),
            ],
        };
        let output =
            run_bounded_route_subprocess(&command, std::time::Duration::from_secs(2), 127, 131)
                .unwrap();
        assert!(output.status.success());
        assert!(output.stdout_overflow);
        assert!(output.stderr_overflow);
        assert_eq!(output.stdout.len(), 127);
        assert_eq!(output.stderr.len(), 131);
    }

    #[test]
    fn invalid_session_duplicate_tuple_and_resource_bound_fail_before_inspection() {
        let session = recovery_session();
        let resources = recovery_resources();
        let mut wrong_metric = resources.clone();
        wrong_metric[0].metric += 1;
        assert!(linux_owned_route_inspection_commands(session, &wrong_metric).is_err());
        assert!(linux_owned_route_delete_command(session, &wrong_metric[0]).is_err());
        assert_eq!(
            classify_linux_owned_route(
                session,
                &wrong_metric[0],
                &exact_output(&wrong_metric[0]),
                Some(77),
            ),
            LinuxOwnedRouteClassification::Conflict
        );

        let mut duplicate = resources.clone();
        let mut same_kernel_tuple = resources[2].clone();
        same_kernel_tuple.purpose = RoutePurpose::SshBypass;
        duplicate.push(same_kernel_tuple);
        assert!(linux_owned_route_inspection_commands(session, &duplicate).is_err());

        let over_limit = vec![resources[0].clone(); MAX_LINUX_RECOVERY_ROUTES + 1];
        assert!(linux_owned_route_inspection_commands(session, &over_limit).is_err());
    }
}
