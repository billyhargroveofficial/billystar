//! Client-side leak prevention for full-tunnel mode (Phase A): a fail-closed
//! **kill-switch** and **DNS pinning**, mirroring [`RouteGuard`](crate::routes)'s
//! install-on-create / restore-on-`Drop` shape.
//!
//! ## Validation status (read this)
//!
//! The command/contents *construction* below is pure and unit-tested on any
//! platform. Its Linux runtime effect (`iptables` + `/etc/resolv.conf`) has also
//! passed the disposable OrbStack IPv4 network-namespace gate: direct underlay
//! traffic remained blocked before and during a carrier cut, DNS used the TUN,
//! and graceful shutdown restored firewall and resolver state. That is
//! synthetic Linux evidence, not production, hostile-network, native IPv6,
//! macOS or Windows validation. On non-Linux guard construction returns an
//! explicit unsupported error so callers cannot mistake an inert object for
//! leak protection.

// `Context` is only used by the Linux-gated execution paths (iptables / resolv.conf).
use crate::host_recovery::{PreparedResourceGroup, RecoveryConvergenceError};
use crate::host_state::{
    AddressFamily, FirewallBackend, FirewallChainToken, FirewallEndpointResource,
    FirewallOutputChainOrigin, FirewallResource, FirewallTableOrigin, FirewallTransport,
    OwnedResource, ResourceObservationKind, SessionId, IPV4_STATIC_FIREWALL_RULE_COUNT,
    IPV6_STATIC_FIREWALL_RULE_COUNT,
};
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use anyhow::{Context, Result};
#[cfg(any(test, target_os = "linux"))]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
#[cfg(any(test, target_os = "linux"))]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(any(target_os = "linux", all(test, unix)))]
use std::time::Duration;

#[cfg(test)]
static NEXT_CHAIN_ID: AtomicU32 = AtomicU32::new(0);
#[cfg(target_os = "linux")]
const RESOLV_CONF: &str = "/etc/resolv.conf";

#[cfg(test)]
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointProtocol {
    Tcp,
    Udp,
}

impl EndpointProtocol {
    fn iptables_name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    fn journal_transport(self) -> FirewallTransport {
        match self {
            Self::Tcp => FirewallTransport::Tcp,
            Self::Udp => FirewallTransport::Udp,
        }
    }
}

/// Exact outer-carrier tuple allowed outside the TUN by the kill-switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllowedEndpoint {
    pub address: SocketAddrV4,
    pub protocol: EndpointProtocol,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallCommand {
    pub program: &'static str,
    pub args: Vec<String>,
    /// Optional bounded stdin payload. Used for an atomic `iptables-restore`
    /// release transaction; ordinary single-command mutations leave it empty.
    pub stdin: Option<Vec<u8>>,
}

/// Crash-stable firewall identity. Every value is either a typed host-state
/// journal field or deterministically derived from one; no PID or process-local
/// counter participates in ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KillSwitchIdentity {
    session_id: SessionId,
    ipv4_chain_token: FirewallChainToken,
    ipv6_chain_token: FirewallChainToken,
    backend: FirewallBackend,
}

impl KillSwitchIdentity {
    /// Generate only a new session/chain identity bound to the current
    /// backend. This does **not** capture nft object lifecycle and therefore is
    /// not a journal-install authorization; privileged coordinators must use
    /// [`KillSwitchInstallToken::prepare_runtime`] instead.
    pub fn generate_for_runtime() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::generate(detect_runtime_backend()?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("kill-switch identity generation is Linux-only")
        }
    }

    pub fn generate(backend: FirewallBackend) -> Result<Self> {
        let session_id = SessionId::generate()?;
        let ipv4_chain_token = FirewallChainToken::generate()?;
        let ipv6_chain_token = loop {
            let candidate = FirewallChainToken::generate()?;
            if candidate != ipv4_chain_token {
                break candidate;
            }
        };
        Self::from_parts(session_id, ipv4_chain_token, ipv6_chain_token, backend)
    }

    pub fn from_parts(
        session_id: SessionId,
        ipv4_chain_token: FirewallChainToken,
        ipv6_chain_token: FirewallChainToken,
        backend: FirewallBackend,
    ) -> Result<Self> {
        anyhow::ensure!(
            session_id.as_bytes() != &[0u8; 16],
            "kill-switch session identifier must be non-zero"
        );
        anyhow::ensure!(
            ipv4_chain_token.as_bytes() != &[0u8; 10] && ipv6_chain_token.as_bytes() != &[0u8; 10],
            "kill-switch chain tokens must be non-zero"
        );
        anyhow::ensure!(
            ipv4_chain_token != ipv6_chain_token,
            "IPv4 and IPv6 kill-switch chain tokens must differ"
        );
        Ok(Self {
            session_id,
            ipv4_chain_token,
            ipv6_chain_token,
            backend,
        })
    }

    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    pub const fn ipv4_chain_token(self) -> FirewallChainToken {
        self.ipv4_chain_token
    }

    pub const fn ipv6_chain_token(self) -> FirewallChainToken {
        self.ipv6_chain_token
    }

    pub const fn backend(self) -> FirewallBackend {
        self.backend
    }

    pub fn owner_comment(self) -> String {
        self.session_id.owner_tag()
    }

    pub fn ipv4_chain(self) -> String {
        format!("SP4_{}", self.ipv4_chain_token)
    }

    pub fn ipv6_chain(self) -> String {
        format!("SP6_{}", self.ipv6_chain_token)
    }

    pub fn ipv4_journal_resource(self) -> FirewallResource {
        self.ipv4_journal_resource_with_origin(FirewallTableOrigin::Preexisting)
    }

    pub fn ipv4_journal_resource_with_origin(
        self,
        filter_table_origin: FirewallTableOrigin,
    ) -> FirewallResource {
        let output_chain_origin = match filter_table_origin {
            FirewallTableOrigin::AbsentBeforeInstall => {
                FirewallOutputChainOrigin::AbsentBeforeInstall
            }
            FirewallTableOrigin::Preexisting | FirewallTableOrigin::LegacyUnknown => {
                FirewallOutputChainOrigin::Preexisting
            }
        };
        self.ipv4_journal_resource_with_lifecycle(filter_table_origin, output_chain_origin)
    }

    pub fn ipv4_journal_resource_with_lifecycle(
        self,
        filter_table_origin: FirewallTableOrigin,
        output_chain_origin: FirewallOutputChainOrigin,
    ) -> FirewallResource {
        FirewallResource {
            family: AddressFamily::Ipv4,
            backend: self.backend,
            chain_token: self.ipv4_chain_token,
            filter_table_origin,
            output_chain_origin,
            expected_rule_count: IPV4_STATIC_FIREWALL_RULE_COUNT,
        }
    }

    pub fn ipv6_journal_resource(self) -> FirewallResource {
        self.ipv6_journal_resource_with_origin(FirewallTableOrigin::Preexisting)
    }

    pub fn ipv6_journal_resource_with_origin(
        self,
        filter_table_origin: FirewallTableOrigin,
    ) -> FirewallResource {
        let output_chain_origin = match filter_table_origin {
            FirewallTableOrigin::AbsentBeforeInstall => {
                FirewallOutputChainOrigin::AbsentBeforeInstall
            }
            FirewallTableOrigin::Preexisting | FirewallTableOrigin::LegacyUnknown => {
                FirewallOutputChainOrigin::Preexisting
            }
        };
        self.ipv6_journal_resource_with_lifecycle(filter_table_origin, output_chain_origin)
    }

    pub fn ipv6_journal_resource_with_lifecycle(
        self,
        filter_table_origin: FirewallTableOrigin,
        output_chain_origin: FirewallOutputChainOrigin,
    ) -> FirewallResource {
        FirewallResource {
            family: AddressFamily::Ipv6,
            backend: self.backend,
            chain_token: self.ipv6_chain_token,
            filter_table_origin,
            output_chain_origin,
            expected_rule_count: IPV6_STATIC_FIREWALL_RULE_COUNT,
        }
    }

    pub fn endpoint_journal_resource(self, endpoint: AllowedEndpoint) -> FirewallEndpointResource {
        FirewallEndpointResource {
            family: AddressFamily::Ipv4,
            backend: self.backend,
            chain_token: self.ipv4_chain_token,
            address: IpAddr::V4(*endpoint.address.ip()),
            transport: endpoint.protocol.journal_transport(),
            port: endpoint.address.port(),
        }
    }
}

fn firewall(program: &'static str, parts: &[&str]) -> FirewallCommand {
    let mut args = Vec::with_capacity(parts.len() + 1);
    // Serialize with other iptables/nft-compat users instead of failing a
    // transaction spuriously while the global xtables lock is held.
    args.push("-w".to_string());
    args.extend(parts.iter().map(|part| (*part).to_string()));
    FirewallCommand {
        program,
        args,
        stdin: None,
    }
}

fn owned_rule(
    program: &'static str,
    operation: &str,
    chain: &str,
    insertion_position: Option<&str>,
    match_arguments: impl IntoIterator<Item = String>,
    target: &str,
    identity: KillSwitchIdentity,
) -> FirewallCommand {
    let mut args = vec!["-w".to_string(), operation.to_string(), chain.to_string()];
    if let Some(position) = insertion_position {
        args.push(position.to_string());
    }
    args.extend(match_arguments);
    args.extend([
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        identity.owner_comment(),
        "-j".to_string(),
        target.to_string(),
    ]);
    FirewallCommand {
        program,
        args,
        stdin: None,
    }
}

fn endpoint_rule(
    operation: &str,
    insertion_position: Option<&str>,
    identity: KillSwitchIdentity,
    endpoint: AllowedEndpoint,
) -> FirewallCommand {
    let ip = format!("{}/32", endpoint.address.ip());
    let port = endpoint.address.port().to_string();
    let protocol = endpoint.protocol.iptables_name().to_string();
    owned_rule(
        "iptables",
        operation,
        &identity.ipv4_chain(),
        insertion_position,
        [
            "-d".to_string(),
            ip,
            "-p".to_string(),
            protocol.clone(),
            "-m".to_string(),
            protocol,
            "--dport".to_string(),
            port,
        ],
        "ACCEPT",
        identity,
    )
}

fn validate_allowed_endpoint(endpoint: AllowedEndpoint) -> Result<()> {
    anyhow::ensure!(
        endpoint.address.port() != 0,
        "kill-switch carrier endpoint port must be non-zero"
    );
    Ok(())
}

fn endpoint_journal_snapshot(
    identity: KillSwitchIdentity,
    endpoints: &BTreeSet<AllowedEndpoint>,
) -> Vec<FirewallEndpointResource> {
    debug_assert!(endpoints.len() <= MAX_KILLSWITCH_ENDPOINTS);
    endpoints
        .iter()
        .copied()
        .map(|endpoint| identity.endpoint_journal_resource(endpoint))
        .collect()
}

/// The `iptables` argument lists that install the fail-closed kill-switch.
///
/// Private OUTPUT sub-chains ACCEPT only loopback, the tunnel interface, and the
/// exact server IP/protocol/port tuples needed by the outer carriers, then
/// **DROP everything else**. Both chains are fully built before their OUTPUT
/// jumps are installed.
pub fn killswitch_install_commands(
    tun_iface: &str,
    endpoints: &[AllowedEndpoint],
    identity: KillSwitchIdentity,
) -> Vec<FirewallCommand> {
    let ipv4_chain = identity.ipv4_chain();
    let ipv6_chain = identity.ipv6_chain();
    // Build both private chains before either is reachable from OUTPUT. The
    // current data plane and route/NAT proof are IPv4, so the IPv6 chain is
    // fail-closed and is activated immediately before the IPv4 chain.
    let mut rules = vec![
        firewall("ip6tables", &["-N", &ipv6_chain]),
        owned_rule(
            "ip6tables",
            "-A",
            &ipv6_chain,
            None,
            ["-o".to_string(), "lo".to_string()],
            "ACCEPT",
            identity,
        ),
        owned_rule("ip6tables", "-A", &ipv6_chain, None, [], "DROP", identity),
        firewall("iptables", &["-N", &ipv4_chain]),
        owned_rule(
            "iptables",
            "-A",
            &ipv4_chain,
            None,
            ["-o".to_string(), "lo".to_string()],
            "ACCEPT",
            identity,
        ),
        owned_rule(
            "iptables",
            "-A",
            &ipv4_chain,
            None,
            ["-o".to_string(), tun_iface.to_string()],
            "ACCEPT",
            identity,
        ),
    ];
    let unique_endpoints: BTreeSet<_> = endpoints.iter().copied().collect();
    for endpoint in unique_endpoints {
        rules.push(endpoint_rule("-A", None, identity, endpoint));
    }
    rules.push(owned_rule(
        "iptables",
        "-A",
        &ipv4_chain,
        None,
        [],
        "DROP",
        identity,
    ));
    rules.push(owned_rule(
        "ip6tables",
        "-I",
        "OUTPUT",
        Some("1"),
        [],
        &ipv6_chain,
        identity,
    ));
    rules.push(owned_rule(
        "iptables",
        "-I",
        "OUTPUT",
        Some("1"),
        [],
        &ipv4_chain,
        identity,
    ));
    rules
}

/// Exact inverses only. Dynamic endpoint rules are removed while the fail-closed
/// chain is still hooked; only then are the static OUTPUT jumps, rules, and
/// chains removed. No `-F`, prefix scan, or rule-number deletion is emitted.
pub fn killswitch_teardown_commands(
    tun_iface: &str,
    endpoints: &[AllowedEndpoint],
    identity: KillSwitchIdentity,
) -> Result<Vec<FirewallCommand>> {
    let mut unique_endpoints = BTreeSet::new();
    for endpoint in endpoints {
        validate_allowed_endpoint(*endpoint)?;
        unique_endpoints.insert(*endpoint);
    }
    let resources = endpoint_journal_snapshot(identity, &unique_endpoints);
    Ok(killswitch_recovery_commands(
        tun_iface, identity, &resources,
    )?)
}

/// Pure typed recovery command builder. Callers pass exactly the current
/// non-Removed endpoint resources from the durable journal. Resources are
/// validated and canonicalized before any command is returned; endpoint rules
/// precede the static base teardown.
pub fn killswitch_recovery_commands(
    tun_iface: &str,
    identity: KillSwitchIdentity,
    endpoint_resources: &[FirewallEndpointResource],
) -> std::result::Result<Vec<FirewallCommand>, KillSwitchConflict> {
    let endpoints = validate_endpoint_resources(identity, endpoint_resources)?;
    let mut teardown: Vec<_> = endpoints
        .iter()
        .copied()
        .map(|endpoint| endpoint_rule("-D", None, identity, endpoint))
        .collect();
    let base_install = killswitch_install_commands(tun_iface, &[], identity);
    let base_teardown: Result<Vec<_>> = base_install.iter().rev().map(firewall_undo).collect();
    teardown.extend(
        base_teardown.map_err(|error| KillSwitchConflict::MalformedListing {
            program: "iptables",
            detail: format!("derive exact static firewall teardown: {error:#}"),
        })?,
    );
    Ok(teardown)
}

/// Read-only rule-listing commands needed to assemble a recovery snapshot.
/// Backend identity is inspected separately with `--version`; every ruleset
/// query retains `-w` so it is serialized with concurrent xtables writers.
pub fn killswitch_inspection_commands(identity: KillSwitchIdentity) -> Vec<FirewallCommand> {
    let _ = identity;
    vec![
        firewall("iptables", &["-t", "filter", "-S"]),
        firewall("ip6tables", &["-t", "filter", "-S"]),
    ]
}

fn firewall_undo(command: &FirewallCommand) -> Result<FirewallCommand> {
    let mut args = command.args.clone();
    let operation_index = usize::from(args.first().is_some_and(|arg| arg == "-w"));
    match args.get(operation_index).map(String::as_str) {
        Some("-N") => args[operation_index] = "-X".to_string(),
        Some("-A") => args[operation_index] = "-D".to_string(),
        Some("-I") => {
            args[operation_index] = "-D".to_string();
            // iptables accepts an insertion position for `-I`, but `-D` by
            // rule specification must not contain it.
            let position_index = operation_index + 2;
            if args
                .get(position_index)
                .is_some_and(|position| position == "1")
            {
                args.remove(position_index);
            }
        }
        operation => anyhow::bail!(
            "no transactional inverse for firewall operation {}",
            operation.unwrap_or("<missing>")
        ),
    }
    Ok(FirewallCommand {
        program: command.program,
        args,
        stdin: None,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn apply_firewall_transaction<F>(install: &[FirewallCommand], mut execute: F) -> Result<()>
where
    F: FnMut(&FirewallCommand) -> Result<()>,
{
    let mut rollback = Vec::with_capacity(install.len());
    for command in install {
        // Derive the inverse before mutating the firewall. That way an
        // unsupported command can never be applied without a rollback plan.
        let undo = firewall_undo(command).context("derive kill-switch rollback command")?;
        if let Err(install_error) = execute(command) {
            let mut rollback_errors = Vec::new();
            for undo in rollback.iter().rev() {
                if let Err(error) = execute(undo) {
                    rollback_errors.push(format!(
                        "{} {}: {error:#}",
                        undo.program,
                        undo.args.join(" ")
                    ));
                }
            }
            if rollback_errors.is_empty() {
                return Err(install_error)
                    .context("transactionally install kill-switch (partial state rolled back)");
            }
            return Err(anyhow::anyhow!(
                "transactionally install kill-switch failed: {install_error:#}; rollback also failed: {}",
                rollback_errors.join("; ")
            ));
        }
        rollback.push(undo);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "linux"))]
struct NftFilterTableSnapshot {
    family: AddressFamily,
    /// Canonically sorted complete JSON objects belonging to this exact
    /// family's `filter` table. Empty means the table is absent.
    objects: Vec<serde_json::Value>,
}

#[cfg(any(test, target_os = "linux"))]
impl NftFilterTableSnapshot {
    fn absent(family: AddressFamily) -> Self {
        Self {
            family,
            objects: Vec::new(),
        }
    }

    #[cfg(test)]
    fn synthetic_preexisting(family: AddressFamily) -> Self {
        let nft_family = match family {
            AddressFamily::Ipv4 => "ip",
            AddressFamily::Ipv6 => "ip6",
        };
        Self {
            family,
            objects: vec![serde_json::json!({
                "table": {"family": nft_family, "name": "filter", "handle": 1}
            })],
        }
    }

    fn is_present(&self) -> bool {
        !self.objects.is_empty()
    }

    fn output_chain_is_present(&self) -> std::result::Result<bool, KillSwitchConflict> {
        let count = self
            .objects
            .iter()
            .filter(|entry| {
                entry
                    .get("chain")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|chain| chain.get("name"))
                    .and_then(serde_json::Value::as_str)
                    == Some("OUTPUT")
            })
            .count();
        if count > 1 {
            return Err(KillSwitchConflict::MalformedListing {
                program: "nft",
                detail: "filter table contains duplicate OUTPUT chain declarations".to_string(),
            });
        }
        Ok(count == 1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "linux"))]
struct FirewallSnapshot {
    ipv4_backend: FirewallBackend,
    ipv6_backend: FirewallBackend,
    ipv4_output: Vec<Vec<String>>,
    ipv4_chain: Vec<Vec<String>>,
    ipv4_other: Vec<Vec<String>>,
    ipv6_output: Vec<Vec<String>>,
    ipv6_chain: Vec<Vec<String>>,
    ipv6_other: Vec<Vec<String>>,
    /// `Some` only for iptables-nft. Legacy backends never receive native nft
    /// table lifecycle authority.
    ipv4_nft_filter: Option<NftFilterTableSnapshot>,
    ipv6_nft_filter: Option<NftFilterTableSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KillSwitchConflict {
    UnknownBackend {
        program: &'static str,
        version: String,
    },
    BackendMismatch {
        program: &'static str,
        expected: FirewallBackend,
        actual: FirewallBackend,
    },
    MalformedListing {
        program: &'static str,
        detail: String,
    },
    JumpMismatch {
        program: &'static str,
        exact_count: usize,
        owned_candidate_count: usize,
    },
    ChainRulesMismatch {
        program: &'static str,
        expected_count: usize,
        actual_count: usize,
    },
    EndpointResourceLimit {
        actual: usize,
        maximum: usize,
    },
    EndpointResourceConflict {
        index: usize,
        detail: String,
    },
    BaseResourceConflict {
        index: usize,
        detail: String,
    },
}

impl std::fmt::Display for KillSwitchConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "kill-switch ownership conflict: {self:?}")
    }
}

impl std::error::Error for KillSwitchConflict {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KillSwitchPrepareError {
    Conflict { detail: String },
    Operational { detail: String },
}

impl std::fmt::Display for KillSwitchPrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { detail } => {
                write!(
                    formatter,
                    "kill-switch recovery preflight conflict: {detail}"
                )
            }
            Self::Operational { detail } => {
                write!(formatter, "kill-switch recovery preflight failed: {detail}")
            }
        }
    }
}

impl std::error::Error for KillSwitchPrepareError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KillSwitchConvergeError {
    Conflict { detail: String },
    Operational { detail: String },
}

impl std::fmt::Display for KillSwitchConvergeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { detail } => {
                write!(formatter, "late kill-switch recovery conflict: {detail}")
            }
            Self::Operational { detail } => {
                write!(formatter, "kill-switch recovery operation failed: {detail}")
            }
        }
    }
}

impl std::error::Error for KillSwitchConvergeError {}

#[cfg(any(test, target_os = "linux"))]
fn prepare_inspection_error(error: anyhow::Error) -> KillSwitchPrepareError {
    if let Some(conflict) = error.downcast_ref::<KillSwitchConflict>() {
        KillSwitchPrepareError::Conflict {
            detail: conflict.to_string(),
        }
    } else {
        KillSwitchPrepareError::Operational {
            detail: error.to_string(),
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn converge_inspection_error(error: anyhow::Error) -> KillSwitchConvergeError {
    if let Some(conflict) = error.downcast_ref::<KillSwitchConflict>() {
        KillSwitchConvergeError::Conflict {
            detail: conflict.to_string(),
        }
    } else {
        KillSwitchConvergeError::Operational {
            detail: error.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "linux"))]
enum PreparedFirewallState {
    Pending,
    Removed,
}

#[derive(Clone, Debug)]
struct PreparedEndpointEntry {
    resource: FirewallEndpointResource,
    #[cfg(any(test, target_os = "linux"))]
    endpoint: AllowedEndpoint,
    initial: ResourceObservationKind,
    #[cfg(any(test, target_os = "linux"))]
    state: PreparedFirewallState,
}

#[derive(Clone, Debug)]
struct PreparedBaseEntry {
    resource: FirewallResource,
    initial: ResourceObservationKind,
    #[cfg(any(test, target_os = "linux"))]
    state: PreparedFirewallState,
}

/// Stateful authorization produced by a complete two-family, read-only
/// firewall preflight. Inputs must be the live journal resources in operation
/// order. Endpoint records are converged before base-family records, matching
/// the generic host recovery rank order.
pub struct PreparedKillSwitchRecovery {
    #[cfg(any(test, target_os = "linux"))]
    tun_iface: String,
    #[cfg(any(test, target_os = "linux"))]
    identity: KillSwitchIdentity,
    endpoint_entries: Vec<PreparedEndpointEntry>,
    base_entries: Vec<PreparedBaseEntry>,
    /// Kernel firewall objects cannot survive a reboot.  On a different boot,
    /// even a byte-for-byte matching chain/rule is therefore foreign state and
    /// must never be deleted under the old journal's authority.  An all-absent
    /// census may still be durably acknowledged after a second read-only check.
    #[cfg(any(test, target_os = "linux"))]
    same_boot: bool,
}

impl PreparedKillSwitchRecovery {
    pub fn endpoint_observation(
        &self,
        resource: &FirewallEndpointResource,
    ) -> Option<ResourceObservationKind> {
        self.endpoint_entries
            .iter()
            .find(|entry| &entry.resource == resource)
            .map(|entry| entry.initial)
    }

    pub fn base_observation(&self, resource: &FirewallResource) -> Option<ResourceObservationKind> {
        self.base_entries
            .iter()
            .find(|entry| &entry.resource == resource)
            .map(|entry| entry.initial)
    }

    pub fn endpoint_observations(
        &self,
    ) -> Vec<(FirewallEndpointResource, ResourceObservationKind)> {
        self.endpoint_entries
            .iter()
            .map(|entry| (entry.resource.clone(), entry.initial))
            .collect()
    }

    pub fn base_observations(&self) -> Vec<(FirewallResource, ResourceObservationKind)> {
        self.base_entries
            .iter()
            .map(|entry| (entry.resource.clone(), entry.initial))
            .collect()
    }
}

fn validate_endpoint_resources(
    identity: KillSwitchIdentity,
    resources: &[FirewallEndpointResource],
) -> std::result::Result<BTreeSet<AllowedEndpoint>, KillSwitchConflict> {
    if resources.len() > MAX_KILLSWITCH_ENDPOINTS {
        return Err(KillSwitchConflict::EndpointResourceLimit {
            actual: resources.len(),
            maximum: MAX_KILLSWITCH_ENDPOINTS,
        });
    }
    let mut endpoints = BTreeSet::new();
    for (index, resource) in resources.iter().enumerate() {
        let endpoint = endpoint_from_resource(identity, index, resource)?;
        if !endpoints.insert(endpoint) {
            return Err(KillSwitchConflict::EndpointResourceConflict {
                index,
                detail: "duplicate exact endpoint firewall resource".to_string(),
            });
        }
    }
    Ok(endpoints)
}

fn endpoint_from_resource(
    identity: KillSwitchIdentity,
    index: usize,
    resource: &FirewallEndpointResource,
) -> std::result::Result<AllowedEndpoint, KillSwitchConflict> {
    if resource.backend != identity.backend() {
        return Err(KillSwitchConflict::BackendMismatch {
            program: "iptables",
            expected: identity.backend(),
            actual: resource.backend,
        });
    }
    if resource.family != AddressFamily::Ipv4 {
        return Err(KillSwitchConflict::EndpointResourceConflict {
            index,
            detail: "endpoint firewall resource must use the IPv4 family".to_string(),
        });
    }
    if resource.chain_token != identity.ipv4_chain_token() {
        return Err(KillSwitchConflict::EndpointResourceConflict {
            index,
            detail: "endpoint firewall resource targets a different chain".to_string(),
        });
    }
    let IpAddr::V4(address) = resource.address else {
        return Err(KillSwitchConflict::EndpointResourceConflict {
            index,
            detail: "endpoint firewall resource carries a non-IPv4 address".to_string(),
        });
    };
    if resource.port == 0 {
        return Err(KillSwitchConflict::EndpointResourceConflict {
            index,
            detail: "endpoint firewall resource port is zero".to_string(),
        });
    }
    let protocol = match resource.transport {
        FirewallTransport::Tcp => EndpointProtocol::Tcp,
        FirewallTransport::Udp => EndpointProtocol::Udp,
    };
    Ok(AllowedEndpoint {
        address: SocketAddrV4::new(address, resource.port),
        protocol,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn validate_base_resources(
    identity: KillSwitchIdentity,
    resources: &[FirewallResource],
) -> std::result::Result<(), KillSwitchConflict> {
    if resources.len() > 2 {
        return Err(KillSwitchConflict::BaseResourceConflict {
            index: 2,
            detail: "more than one base firewall resource per address family".to_string(),
        });
    }
    let mut saw_ipv4 = false;
    let mut saw_ipv6 = false;
    for (index, resource) in resources.iter().enumerate() {
        let expected = match resource.family {
            AddressFamily::Ipv4 => {
                if saw_ipv4 {
                    return Err(KillSwitchConflict::BaseResourceConflict {
                        index,
                        detail: "duplicate IPv4 base firewall resource".to_string(),
                    });
                }
                saw_ipv4 = true;
                identity.ipv4_journal_resource_with_lifecycle(
                    resource.filter_table_origin,
                    resource.output_chain_origin,
                )
            }
            AddressFamily::Ipv6 => {
                if saw_ipv6 {
                    return Err(KillSwitchConflict::BaseResourceConflict {
                        index,
                        detail: "duplicate IPv6 base firewall resource".to_string(),
                    });
                }
                saw_ipv6 = true;
                identity.ipv6_journal_resource_with_lifecycle(
                    resource.filter_table_origin,
                    resource.output_chain_origin,
                )
            }
        };
        if *resource != expected {
            return Err(KillSwitchConflict::BaseResourceConflict {
                index,
                detail: format!(
                    "base firewall resource differs from identity-derived {:?} resource",
                    resource.family
                ),
            });
        }
    }
    Ok(())
}

fn validate_tun_iface(tun_iface: &str) -> Result<()> {
    anyhow::ensure!(
        !tun_iface.is_empty()
            && tun_iface.len() <= 15
            && !tun_iface.bytes().any(|byte| byte == 0 || byte == b'/')
            && !tun_iface.chars().any(char::is_whitespace),
        "kill-switch TUN interface name is invalid"
    );
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn parse_backend_output(
    program: &'static str,
    version: &str,
) -> std::result::Result<FirewallBackend, KillSwitchConflict> {
    if version.contains("nf_tables") {
        Ok(FirewallBackend::IptablesNft)
    } else if version.contains("legacy") {
        Ok(FirewallBackend::IptablesLegacy)
    } else {
        Err(KillSwitchConflict::UnknownBackend {
            program,
            version: version.trim().to_string(),
        })
    }
}

#[cfg(any(test, target_os = "linux"))]
fn tokenize_iptables_rule(line: &str) -> std::result::Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            character if character.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if escaped || quote.is_some() {
        return Err("unterminated quote or escape".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    if tokens.is_empty() {
        return Err("empty rule".to_string());
    }
    Ok(tokens)
}

#[cfg(any(test, target_os = "linux"))]
fn parse_iptables_listing(
    program: &'static str,
    listing: &str,
) -> std::result::Result<Vec<Vec<String>>, KillSwitchConflict> {
    listing
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            tokenize_iptables_rule(line).map_err(|detail| KillSwitchConflict::MalformedListing {
                program,
                detail: format!("{detail}: {line:?}"),
            })
        })
        .collect()
}

#[cfg(any(test, target_os = "linux"))]
fn parse_nft_filter_tables(
    listing: &str,
) -> std::result::Result<(NftFilterTableSnapshot, NftFilterTableSnapshot), KillSwitchConflict> {
    let root: serde_json::Value =
        serde_json::from_str(listing).map_err(|error| KillSwitchConflict::MalformedListing {
            program: "nft",
            detail: format!("nft JSON is malformed: {error}"),
        })?;
    let root = root
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| KillSwitchConflict::MalformedListing {
            program: "nft",
            detail: "nft JSON root must contain only `nftables`".to_string(),
        })?;
    let entries = root
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| KillSwitchConflict::MalformedListing {
            program: "nft",
            detail: "nft JSON root has no `nftables` array".to_string(),
        })?;

    let mut ipv4 = NftFilterTableSnapshot::absent(AddressFamily::Ipv4);
    let mut ipv6 = NftFilterTableSnapshot::absent(AddressFamily::Ipv6);
    let mut table_declarations = [0usize; 2];
    for entry in entries {
        let object = entry
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or_else(|| KillSwitchConflict::MalformedListing {
                program: "nft",
                detail: "each nftables entry must contain exactly one object".to_string(),
            })?;
        let (kind, body) = object.iter().next().expect("single-entry object");
        if kind == "metainfo" {
            if !body.is_object() {
                return Err(KillSwitchConflict::MalformedListing {
                    program: "nft",
                    detail: "nft metainfo must be an object".to_string(),
                });
            }
            continue;
        }
        let body_object = body
            .as_object()
            .ok_or_else(|| KillSwitchConflict::MalformedListing {
                program: "nft",
                detail: format!("nft `{kind}` body must be an object"),
            })?;
        let family = body_object
            .get("family")
            .and_then(serde_json::Value::as_str);
        let target_family = match family {
            Some("ip") => Some((0usize, &mut ipv4)),
            Some("ip6") => Some((1usize, &mut ipv6)),
            _ => None,
        };
        let Some((family_index, target)) = target_family else {
            continue;
        };
        let belongs = if kind == "table" {
            body_object.get("name").and_then(serde_json::Value::as_str) == Some("filter")
        } else {
            body_object.get("table").and_then(serde_json::Value::as_str) == Some("filter")
        };
        if !belongs {
            continue;
        }
        if kind == "table" {
            table_declarations[family_index] += 1;
        }
        target.objects.push(entry.clone());
    }

    for (index, snapshot) in [&mut ipv4, &mut ipv6].into_iter().enumerate() {
        if snapshot.objects.is_empty() {
            if table_declarations[index] != 0 {
                return Err(KillSwitchConflict::MalformedListing {
                    program: "nft",
                    detail: "nft table declaration accounting is inconsistent".to_string(),
                });
            }
            continue;
        }
        if table_declarations[index] != 1 {
            return Err(KillSwitchConflict::MalformedListing {
                program: "nft",
                detail: format!(
                    "target filter table has {} declarations",
                    table_declarations[index]
                ),
            });
        }
        snapshot.objects.sort_by(|left, right| {
            serde_json::to_string(left)
                .expect("JSON value serializes")
                .cmp(&serde_json::to_string(right).expect("JSON value serializes"))
        });
    }
    Ok((ipv4, ipv6))
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "linux"))]
enum EmptyCompatShell {
    Absent,
    Exact,
    Drift(String),
}

#[cfg(any(test, target_os = "linux"))]
fn exact_json_keys(object: &serde_json::Map<String, serde_json::Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

#[cfg(any(test, target_os = "linux"))]
fn classify_empty_nft_compat_shell(snapshot: &NftFilterTableSnapshot) -> EmptyCompatShell {
    if snapshot.objects.is_empty() {
        return EmptyCompatShell::Absent;
    }
    let nft_family = match snapshot.family {
        AddressFamily::Ipv4 => "ip",
        AddressFamily::Ipv6 => "ip6",
    };
    let mut table_count = 0usize;
    let mut output_count = 0usize;
    for entry in &snapshot.objects {
        let Some(object) = entry.as_object() else {
            return EmptyCompatShell::Drift("nft entry is not an object".to_string());
        };
        if let Some(table) = object.get("table").and_then(serde_json::Value::as_object) {
            if !exact_json_keys(table, &["family", "name", "handle"])
                || table.get("family").and_then(serde_json::Value::as_str) != Some(nft_family)
                || table.get("name").and_then(serde_json::Value::as_str) != Some("filter")
                || table
                    .get("handle")
                    .and_then(serde_json::Value::as_u64)
                    .is_none()
            {
                return EmptyCompatShell::Drift(
                    "filter table declaration differs from the empty nft compatibility shell"
                        .to_string(),
                );
            }
            table_count += 1;
            continue;
        }
        if let Some(chain) = object.get("chain").and_then(serde_json::Value::as_object) {
            if !exact_json_keys(
                chain,
                &[
                    "family", "table", "name", "handle", "type", "hook", "prio", "policy",
                ],
            ) || chain.get("family").and_then(serde_json::Value::as_str) != Some(nft_family)
                || chain.get("table").and_then(serde_json::Value::as_str) != Some("filter")
                || chain.get("name").and_then(serde_json::Value::as_str) != Some("OUTPUT")
                || chain
                    .get("handle")
                    .and_then(serde_json::Value::as_u64)
                    .is_none()
                || chain.get("type").and_then(serde_json::Value::as_str) != Some("filter")
                || chain.get("hook").and_then(serde_json::Value::as_str) != Some("output")
                || chain.get("prio").and_then(serde_json::Value::as_i64) != Some(0)
                || chain.get("policy").and_then(serde_json::Value::as_str) != Some("accept")
            {
                return EmptyCompatShell::Drift(
                    "OUTPUT chain differs from the empty nft compatibility shell".to_string(),
                );
            }
            output_count += 1;
            continue;
        }
        return EmptyCompatShell::Drift(format!(
            "unexpected object remains in filter table: {entry}"
        ));
    }
    if table_count == 1 && output_count <= 1 && snapshot.objects.len() == 1 + output_count {
        EmptyCompatShell::Exact
    } else {
        EmptyCompatShell::Drift(format!(
            "empty-shell cardinality mismatch: tables={table_count}, OUTPUT={output_count}, objects={}",
            snapshot.objects.len()
        ))
    }
}

#[cfg(any(test, target_os = "linux"))]
fn classify_empty_nft_output_shell(snapshot: &NftFilterTableSnapshot) -> EmptyCompatShell {
    if snapshot.objects.is_empty() {
        return EmptyCompatShell::Absent;
    }
    let nft_family = match snapshot.family {
        AddressFamily::Ipv4 => "ip",
        AddressFamily::Ipv6 => "ip6",
    };
    let mut output_count = 0usize;
    for entry in &snapshot.objects {
        let Some(object) = entry.as_object() else {
            return EmptyCompatShell::Drift("nft entry is not an object".to_string());
        };
        if let Some(chain) = object.get("chain").and_then(serde_json::Value::as_object) {
            if chain.get("name").and_then(serde_json::Value::as_str) != Some("OUTPUT") {
                continue;
            }
            if !exact_json_keys(
                chain,
                &[
                    "family", "table", "name", "handle", "type", "hook", "prio", "policy",
                ],
            ) || chain.get("family").and_then(serde_json::Value::as_str) != Some(nft_family)
                || chain.get("table").and_then(serde_json::Value::as_str) != Some("filter")
                || chain
                    .get("handle")
                    .and_then(serde_json::Value::as_u64)
                    .is_none()
                || chain.get("type").and_then(serde_json::Value::as_str) != Some("filter")
                || chain.get("hook").and_then(serde_json::Value::as_str) != Some("output")
                || chain.get("prio").and_then(serde_json::Value::as_i64) != Some(0)
                || chain.get("policy").and_then(serde_json::Value::as_str) != Some("accept")
            {
                return EmptyCompatShell::Drift(
                    "OUTPUT chain differs from the empty nft compatibility shell".to_string(),
                );
            }
            output_count += 1;
            continue;
        }
        if object.values().any(|body| {
            body.as_object()
                .and_then(|body| body.get("chain"))
                .and_then(serde_json::Value::as_str)
                == Some("OUTPUT")
        }) {
            return EmptyCompatShell::Drift(
                "foreign object or rule remains attached to OUTPUT".to_string(),
            );
        }
    }
    match output_count {
        0 => EmptyCompatShell::Absent,
        1 => EmptyCompatShell::Exact,
        count => EmptyCompatShell::Drift(format!("OUTPUT shell has {count} chain declarations")),
    }
}

#[cfg(test)]
fn inspection_rule_spec(command: &FirewallCommand) -> Option<Vec<String>> {
    let mut args = command.args.clone();
    if args.first().is_some_and(|argument| argument == "-w") {
        args.remove(0);
    }
    match args.first().map(String::as_str) {
        Some("-A") => Some(args),
        Some("-I") => {
            args[0] = "-A".to_string();
            if args.get(2).is_some_and(|position| {
                position.bytes().all(|character| character.is_ascii_digit())
            }) {
                args.remove(2);
            }
            Some(args)
        }
        _ => None,
    }
}

#[cfg(test)]
fn multiset(rules: impl IntoIterator<Item = Vec<String>>) -> BTreeMap<Vec<String>, usize> {
    let mut counts = BTreeMap::new();
    for rule in rules {
        *counts.entry(rule).or_insert(0) += 1;
    }
    counts
}

#[cfg(any(test, target_os = "linux"))]
fn component_listing_spec(command: &FirewallCommand) -> Option<Vec<String>> {
    let mut args = command.args.clone();
    if args.first().is_some_and(|argument| argument == "-w") {
        args.remove(0);
    }
    match args.first().map(String::as_str) {
        Some("-N") | Some("-A") => Some(args),
        Some("-I") => {
            args[0] = "-A".to_string();
            if args
                .get(2)
                .is_some_and(|position| position.bytes().all(|byte| byte.is_ascii_digit()))
            {
                args.remove(2);
            }
            Some(args)
        }
        _ => None,
    }
}

#[cfg(any(test, target_os = "linux"))]
struct PartitionedFamilyListing {
    output: Vec<Vec<String>>,
    chain: Vec<Vec<String>>,
    other: Vec<Vec<String>>,
}

#[cfg(any(test, target_os = "linux"))]
fn partition_family_listing(
    expected_chain: &str,
    rules: Vec<Vec<String>>,
) -> PartitionedFamilyListing {
    let mut output = Vec::new();
    let mut chain = Vec::new();
    let mut other = Vec::new();
    for rule in rules {
        match rule.get(1).map(String::as_str) {
            Some("OUTPUT") => output.push(rule),
            Some(actual) if actual == expected_chain => chain.push(rule),
            _ => other.push(rule),
        }
    }
    PartitionedFamilyListing {
        output,
        chain,
        other,
    }
}

#[cfg(any(test, target_os = "linux"))]
impl FirewallSnapshot {
    fn from_full_listings(
        identity: KillSwitchIdentity,
        ipv4_backend: FirewallBackend,
        ipv6_backend: FirewallBackend,
        ipv4_rules: Vec<Vec<String>>,
        ipv6_rules: Vec<Vec<String>>,
        nft_filter_tables: Option<(NftFilterTableSnapshot, NftFilterTableSnapshot)>,
    ) -> Self {
        let ipv4 = partition_family_listing(&identity.ipv4_chain(), ipv4_rules);
        let ipv6 = partition_family_listing(&identity.ipv6_chain(), ipv6_rules);
        let (ipv4_nft_filter, ipv6_nft_filter) = nft_filter_tables
            .map(|(ipv4, ipv6)| (Some(ipv4), Some(ipv6)))
            .unwrap_or((None, None));
        Self {
            ipv4_backend,
            ipv6_backend,
            ipv4_output: ipv4.output,
            ipv4_chain: ipv4.chain,
            ipv4_other: ipv4.other,
            ipv6_output: ipv6.output,
            ipv6_chain: ipv6.chain,
            ipv6_other: ipv6.other,
            ipv4_nft_filter,
            ipv6_nft_filter,
        }
    }

    fn rules_for(&self, program: &'static str) -> Vec<&Vec<String>> {
        let (output, chain, other) = match program {
            "iptables" => (&self.ipv4_output, &self.ipv4_chain, &self.ipv4_other),
            "ip6tables" => (&self.ipv6_output, &self.ipv6_chain, &self.ipv6_other),
            _ => return Vec::new(),
        };
        output.iter().chain(chain).chain(other).collect()
    }

    fn canonical_rules_for(&self, program: &'static str) -> Vec<Vec<String>> {
        let mut rules: Vec<_> = self.rules_for(program).into_iter().cloned().collect();
        rules.sort();
        rules
    }

    fn same_complete_snapshot(&self, other: &Self) -> bool {
        self.ipv4_backend == other.ipv4_backend
            && self.ipv6_backend == other.ipv6_backend
            && self.canonical_rules_for("iptables") == other.canonical_rules_for("iptables")
            && self.canonical_rules_for("ip6tables") == other.canonical_rules_for("ip6tables")
            && self.ipv4_nft_filter == other.ipv4_nft_filter
            && self.ipv6_nft_filter == other.ipv6_nft_filter
    }

    fn nft_filter_for(&self, family: AddressFamily) -> Option<&NftFilterTableSnapshot> {
        match family {
            AddressFamily::Ipv4 => self.ipv4_nft_filter.as_ref(),
            AddressFamily::Ipv6 => self.ipv6_nft_filter.as_ref(),
        }
    }
}

/// Single-use authorization joining a stable, read-only firewall/table census
/// to the exact journal resources that must be persisted before mutation.
/// Consuming this token at engage time prevents a caller from reusing stale
/// pre-WAL table evidence or silently substituting a different chain identity.
pub struct KillSwitchInstallToken {
    identity: KillSwitchIdentity,
    base_resources: [FirewallResource; 2],
    #[cfg(any(test, target_os = "linux"))]
    #[cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
    baseline: FirewallSnapshot,
}

impl KillSwitchInstallToken {
    pub fn prepare_runtime() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let identity = KillSwitchIdentity::generate(detect_runtime_backend()?)?;
            Self::prepare_with_identity(identity)
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("kill-switch install preflight is available only on Linux")
        }
    }

    /// Lab/embedding variant which retains a caller's already-durable session
    /// identifier while generating fresh chain tokens and table evidence.
    pub fn prepare_runtime_for_session(session_id: SessionId) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let generated = KillSwitchIdentity::generate(detect_runtime_backend()?)?;
            let identity = KillSwitchIdentity::from_parts(
                session_id,
                generated.ipv4_chain_token(),
                generated.ipv6_chain_token(),
                generated.backend(),
            )?;
            Self::prepare_with_identity(identity)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = session_id;
            anyhow::bail!("kill-switch install preflight is available only on Linux")
        }
    }

    #[cfg(target_os = "linux")]
    fn prepare_with_identity(identity: KillSwitchIdentity) -> Result<Self> {
        let before = inspect_firewall(identity).context("capture firewall install preflight")?;
        let after = inspect_firewall(identity).context("repeat firewall install preflight")?;
        install_token_from_stable_snapshots(identity, before, after)
    }

    pub const fn identity(&self) -> KillSwitchIdentity {
        self.identity
    }

    pub fn journal_resources(&self) -> [FirewallResource; 2] {
        self.base_resources.clone()
    }
}

#[cfg(any(test, target_os = "linux"))]
fn install_token_from_stable_snapshots(
    identity: KillSwitchIdentity,
    before: FirewallSnapshot,
    after: FirewallSnapshot,
) -> Result<KillSwitchInstallToken> {
    anyhow::ensure!(
        before.same_complete_snapshot(&after),
        "complete firewall/table state changed across install preflight"
    );
    for (program, actual) in [
        ("iptables", before.ipv4_backend),
        ("ip6tables", before.ipv6_backend),
    ] {
        anyhow::ensure!(
            actual == identity.backend(),
            "{program} backend changed while preparing kill-switch: expected {:?}, found {actual:?}",
            identity.backend()
        );
    }
    let owner = identity.owner_comment();
    for (program, chain) in [
        ("iptables", identity.ipv4_chain()),
        ("ip6tables", identity.ipv6_chain()),
    ] {
        anyhow::ensure!(
            before.rules_for(program).into_iter().all(|rule| {
                !rule_has_owner_comment(rule, &owner) && !rule_mentions_expected_chain(rule, &chain)
            }),
            "fresh kill-switch identity collides with existing {program} state"
        );
    }

    let lifecycle = |family| -> Result<(FirewallTableOrigin, FirewallOutputChainOrigin)> {
        match identity.backend() {
            FirewallBackend::IptablesLegacy => Ok((
                FirewallTableOrigin::Preexisting,
                FirewallOutputChainOrigin::Preexisting,
            )),
            FirewallBackend::IptablesNft => {
                let table = before
                    .nft_filter_for(family)
                    .context("nft backend preflight lacks complete filter-table census")?;
                if table.is_present() {
                    Ok((
                        FirewallTableOrigin::Preexisting,
                        if table.output_chain_is_present()? {
                            FirewallOutputChainOrigin::Preexisting
                        } else {
                            FirewallOutputChainOrigin::AbsentBeforeInstall
                        },
                    ))
                } else {
                    Ok((
                        FirewallTableOrigin::AbsentBeforeInstall,
                        FirewallOutputChainOrigin::AbsentBeforeInstall,
                    ))
                }
            }
        }
    };
    let ipv4 = lifecycle(AddressFamily::Ipv4)?;
    let ipv6 = lifecycle(AddressFamily::Ipv6)?;
    let base_resources = [
        identity.ipv4_journal_resource_with_lifecycle(ipv4.0, ipv4.1),
        identity.ipv6_journal_resource_with_lifecycle(ipv6.0, ipv6.1),
    ];
    Ok(KillSwitchInstallToken {
        identity,
        base_resources,
        baseline: before,
    })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg(any(test, target_os = "linux"))]
enum PreparedFirewallSlot {
    Endpoint(usize),
    Base(usize),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg(any(test, target_os = "linux"))]
struct FirewallComponentKey {
    program: &'static str,
    specification: Vec<String>,
}

#[derive(Clone, Debug)]
#[cfg(any(test, target_os = "linux"))]
struct AuthorizedFirewallComponent {
    slot: PreparedFirewallSlot,
    key: FirewallComponentKey,
    delete: FirewallCommand,
}

#[cfg(any(test, target_os = "linux"))]
fn atomic_base_release_command(
    program: &'static str,
    components: &[&AuthorizedFirewallComponent],
) -> std::result::Result<FirewallCommand, KillSwitchConflict> {
    let restore_program = match program {
        "iptables" => "iptables-restore",
        "ip6tables" => "ip6tables-restore",
        _ => {
            return Err(KillSwitchConflict::MalformedListing {
                program,
                detail: "atomic release requested for unknown firewall family".to_string(),
            })
        }
    };
    let mut deletes = Vec::new();
    let mut release_jump = Vec::new();
    let mut delete_chain = Vec::new();
    for component in components {
        let mut arguments = component.delete.args.clone();
        if arguments.first().is_some_and(|argument| argument == "-w") {
            arguments.remove(0);
        }
        if arguments.iter().any(|argument| {
            argument.is_empty()
                || argument
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'\\' | b'\'' | b'"'))
        }) {
            return Err(KillSwitchConflict::MalformedListing {
                program,
                detail: "atomic restore argument is not safely serializable".to_string(),
            });
        }
        let line = arguments.join(" ");
        match arguments.first().map(String::as_str) {
            Some("-X") => delete_chain.push(line),
            Some("-D") if arguments.get(1).is_some_and(|chain| chain == "OUTPUT") => {
                release_jump.push(line)
            }
            Some("-D") => deletes.push(line),
            operation => {
                return Err(KillSwitchConflict::MalformedListing {
                    program,
                    detail: format!(
                        "atomic release contains unsupported operation {}",
                        operation.unwrap_or("<missing>")
                    ),
                })
            }
        }
    }
    if release_jump.len() > 1 || delete_chain.len() > 1 {
        return Err(KillSwitchConflict::MalformedListing {
            program,
            detail: "atomic base release has duplicate jump or chain deletion".to_string(),
        });
    }
    // These lines are parsed first, but iptables-restore commits the complete
    // table transaction atomically. The OUTPUT jump is deliberately the last
    // rule deletion in the transaction and no later safety mutation exists.
    deletes.extend(release_jump);
    deletes.extend(delete_chain);
    if deletes.is_empty() {
        return Err(KillSwitchConflict::MalformedListing {
            program,
            detail: "atomic base release has no present component".to_string(),
        });
    }
    let mut script = String::from("*filter\n");
    for line in deletes {
        script.push_str(&line);
        script.push('\n');
    }
    script.push_str("COMMIT\n");
    if script.len() > 16 * 1024 {
        return Err(KillSwitchConflict::MalformedListing {
            program,
            detail: "atomic base release script exceeds 16 KiB".to_string(),
        });
    }
    Ok(FirewallCommand {
        program: restore_program,
        args: vec!["-w".to_string(), "5".to_string(), "--noflush".to_string()],
        stdin: Some(script.into_bytes()),
    })
}

#[cfg(any(test, target_os = "linux"))]
fn nft_delete_filter_table_command(family: AddressFamily) -> FirewallCommand {
    let family = match family {
        AddressFamily::Ipv4 => "ip",
        AddressFamily::Ipv6 => "ip6",
    };
    FirewallCommand {
        program: "nft",
        args: vec![
            "delete".to_string(),
            "table".to_string(),
            family.to_string(),
            "filter".to_string(),
        ],
        stdin: None,
    }
}

#[cfg(any(test, target_os = "linux"))]
fn nft_delete_output_chain_command(family: AddressFamily) -> FirewallCommand {
    let family = match family {
        AddressFamily::Ipv4 => "ip",
        AddressFamily::Ipv6 => "ip6",
    };
    FirewallCommand {
        program: "nft",
        args: vec![
            "delete".to_string(),
            "chain".to_string(),
            family.to_string(),
            "filter".to_string(),
            "OUTPUT".to_string(),
        ],
        stdin: None,
    }
}

#[derive(Clone, Debug, Default)]
#[cfg(any(test, target_os = "linux"))]
struct FirewallAnalysis {
    present: BTreeMap<PreparedFirewallSlot, BTreeSet<FirewallComponentKey>>,
}

#[cfg(any(test, target_os = "linux"))]
impl FirewallAnalysis {
    fn slot_is_present(&self, slot: PreparedFirewallSlot) -> bool {
        self.present.get(&slot).is_some_and(|keys| !keys.is_empty())
    }

    fn contains(&self, slot: PreparedFirewallSlot, key: &FirewallComponentKey) -> bool {
        self.present
            .get(&slot)
            .is_some_and(|keys| keys.contains(key))
    }
}

#[cfg(any(test, target_os = "linux"))]
fn rule_has_owner_comment(rule: &[String], owner_comment: &str) -> bool {
    rule.windows(2)
        .any(|pair| pair[0] == "--comment" && pair[1] == owner_comment)
}

#[cfg(any(test, target_os = "linux"))]
fn rule_mentions_expected_chain(rule: &[String], chain: &str) -> bool {
    rule.get(1).is_some_and(|subject| subject == chain) || rule_targets_chain(rule, chain)
}

#[cfg(any(test, target_os = "linux"))]
impl PreparedKillSwitchRecovery {
    fn authorized_components(
        &self,
    ) -> std::result::Result<Vec<AuthorizedFirewallComponent>, KillSwitchConflict> {
        let mut components = Vec::new();
        for (index, entry) in self.endpoint_entries.iter().enumerate() {
            if entry.state == PreparedFirewallState::Removed {
                continue;
            }
            let install = endpoint_rule("-A", None, self.identity, entry.endpoint);
            let specification = component_listing_spec(&install).ok_or_else(|| {
                KillSwitchConflict::MalformedListing {
                    program: "iptables",
                    detail: "could not derive endpoint listing specification".to_string(),
                }
            })?;
            components.push(AuthorizedFirewallComponent {
                slot: PreparedFirewallSlot::Endpoint(index),
                key: FirewallComponentKey {
                    program: install.program,
                    specification,
                },
                delete: endpoint_rule("-D", None, self.identity, entry.endpoint),
            });
        }

        let base_install = killswitch_install_commands(&self.tun_iface, &[], self.identity);
        for (index, entry) in self.base_entries.iter().enumerate() {
            if entry.state == PreparedFirewallState::Removed {
                continue;
            }
            let program = match entry.resource.family {
                AddressFamily::Ipv4 => "iptables",
                AddressFamily::Ipv6 => "ip6tables",
            };
            let family_install: Vec<_> = base_install
                .iter()
                .filter(|command| command.program == program)
                .collect();
            for install in family_install.into_iter().rev() {
                let specification = component_listing_spec(install).ok_or_else(|| {
                    KillSwitchConflict::MalformedListing {
                        program,
                        detail: "could not derive base listing specification".to_string(),
                    }
                })?;
                let delete = firewall_undo(install).map_err(|error| {
                    KillSwitchConflict::MalformedListing {
                        program,
                        detail: format!("derive exact base teardown: {error:#}"),
                    }
                })?;
                components.push(AuthorizedFirewallComponent {
                    slot: PreparedFirewallSlot::Base(index),
                    key: FirewallComponentKey {
                        program,
                        specification,
                    },
                    delete,
                });
            }
        }
        Ok(components)
    }

    fn analyze_snapshot(
        &self,
        snapshot: &FirewallSnapshot,
    ) -> std::result::Result<FirewallAnalysis, KillSwitchConflict> {
        // Backend identity is part of same-boot ownership: deleting an nft
        // object through legacy tooling (or vice versa) is never authorized.
        // Across a reboot, however, the old volatile rules cannot survive. A
        // backend upgrade must not prevent us from proving that *no*
        // journal-shaped object exists and then restoring persistent resources
        // such as DNS. We therefore scan the complete current ruleset first in
        // different-boot mode and accept backend drift only for an all-absent
        // census; any owner comment/expected chain remains a conflict below.
        if self.same_boot {
            for (program, actual) in [
                ("iptables", snapshot.ipv4_backend),
                ("ip6tables", snapshot.ipv6_backend),
            ] {
                if actual != self.identity.backend() {
                    return Err(KillSwitchConflict::BackendMismatch {
                        program,
                        expected: self.identity.backend(),
                        actual,
                    });
                }
            }
        }

        let authorized = self.authorized_components()?;
        let mut by_key = BTreeMap::new();
        for component in &authorized {
            if by_key
                .insert(component.key.clone(), component.slot)
                .is_some()
            {
                return Err(KillSwitchConflict::MalformedListing {
                    program: component.key.program,
                    detail: "journal resources authorize a duplicate firewall component"
                        .to_string(),
                });
            }
        }

        let owner_comment = self.identity.owner_comment();
        let mut analysis = FirewallAnalysis::default();
        for (program, chain) in [
            ("iptables", self.identity.ipv4_chain()),
            ("ip6tables", self.identity.ipv6_chain()),
        ] {
            let mut counts = BTreeMap::new();
            for rule in snapshot.rules_for(program) {
                if !rule_has_owner_comment(rule, &owner_comment)
                    && !rule_mentions_expected_chain(rule, &chain)
                {
                    continue;
                }
                let key = FirewallComponentKey {
                    program,
                    specification: rule.clone(),
                };
                let Some(slot) = by_key.get(&key).copied() else {
                    return Err(KillSwitchConflict::MalformedListing {
                        program,
                        detail: format!(
                            "unknown or modified owner/expected-chain component: {}",
                            rule.join(" ")
                        ),
                    });
                };
                let count = counts.entry(key.clone()).or_insert(0usize);
                *count += 1;
                if *count != 1 {
                    return Err(KillSwitchConflict::MalformedListing {
                        program,
                        detail: format!("duplicate owned component: {}", rule.join(" ")),
                    });
                }
                analysis.present.entry(slot).or_default().insert(key);
            }
        }
        Ok(analysis)
    }

    fn next_endpoint_index(&self) -> Option<usize> {
        self.endpoint_entries
            .iter()
            .position(|entry| entry.state == PreparedFirewallState::Pending)
    }

    fn next_base_index(&self) -> Option<usize> {
        self.base_entries
            .iter()
            .position(|entry| entry.state == PreparedFirewallState::Pending)
    }

    #[cfg(test)]
    fn prepare_with<I>(
        tun_iface: &str,
        identity: KillSwitchIdentity,
        base_resources: &[FirewallResource],
        endpoint_resources: &[FirewallEndpointResource],
        inspect: I,
    ) -> std::result::Result<Self, KillSwitchPrepareError>
    where
        I: FnMut() -> Result<FirewallSnapshot>,
    {
        Self::prepare_with_boot_scope(
            tun_iface,
            identity,
            base_resources,
            endpoint_resources,
            true,
            inspect,
        )
    }

    fn prepare_with_boot_scope<I>(
        tun_iface: &str,
        identity: KillSwitchIdentity,
        base_resources: &[FirewallResource],
        endpoint_resources: &[FirewallEndpointResource],
        same_boot: bool,
        mut inspect: I,
    ) -> std::result::Result<Self, KillSwitchPrepareError>
    where
        I: FnMut() -> Result<FirewallSnapshot>,
    {
        validate_tun_iface(tun_iface).map_err(|error| KillSwitchPrepareError::Conflict {
            detail: error.to_string(),
        })?;
        validate_base_resources(identity, base_resources).map_err(|error| {
            KillSwitchPrepareError::Conflict {
                detail: error.to_string(),
            }
        })?;
        validate_endpoint_resources(identity, endpoint_resources).map_err(|error| {
            KillSwitchPrepareError::Conflict {
                detail: error.to_string(),
            }
        })?;

        let endpoint_entries = endpoint_resources
            .iter()
            .enumerate()
            .map(|(index, resource)| {
                endpoint_from_resource(identity, index, resource).map(|endpoint| {
                    PreparedEndpointEntry {
                        resource: resource.clone(),
                        endpoint,
                        initial: ResourceObservationKind::Absent,
                        state: PreparedFirewallState::Pending,
                    }
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| KillSwitchPrepareError::Conflict {
                detail: error.to_string(),
            })?;
        let base_entries = base_resources
            .iter()
            .cloned()
            .map(|resource| PreparedBaseEntry {
                resource,
                initial: ResourceObservationKind::Absent,
                state: PreparedFirewallState::Pending,
            })
            .collect();
        let mut prepared = Self {
            tun_iface: tun_iface.to_string(),
            identity,
            endpoint_entries,
            base_entries,
            same_boot,
        };

        let before = inspect().map_err(prepare_inspection_error)?;
        let before_analysis = prepared.analyze_snapshot(&before).map_err(|error| {
            KillSwitchPrepareError::Conflict {
                detail: error.to_string(),
            }
        })?;
        let after = inspect().map_err(prepare_inspection_error)?;
        let after_analysis = prepared.analyze_snapshot(&after).map_err(|error| {
            KillSwitchPrepareError::Conflict {
                detail: error.to_string(),
            }
        })?;
        if !before.same_complete_snapshot(&after)
            || before_analysis.present != after_analysis.present
        {
            return Err(KillSwitchPrepareError::Conflict {
                detail: "complete filter ruleset changed across read-only preflight".to_string(),
            });
        }

        for (index, entry) in prepared.endpoint_entries.iter_mut().enumerate() {
            entry.initial =
                if before_analysis.slot_is_present(PreparedFirewallSlot::Endpoint(index)) {
                    if same_boot {
                        ResourceObservationKind::ExactOwnedPresent
                    } else {
                        ResourceObservationKind::Conflict
                    }
                } else {
                    ResourceObservationKind::Absent
                };
        }
        for (index, entry) in prepared.base_entries.iter_mut().enumerate() {
            entry.initial = if before_analysis.slot_is_present(PreparedFirewallSlot::Base(index)) {
                if same_boot {
                    ResourceObservationKind::ExactOwnedPresent
                } else {
                    ResourceObservationKind::Conflict
                }
            } else {
                ResourceObservationKind::Absent
            };
        }
        Ok(prepared)
    }

    fn converge_slot_with<I, E>(
        &mut self,
        slot: PreparedFirewallSlot,
        inspect: &mut I,
        execute: &mut E,
    ) -> std::result::Result<(), KillSwitchConvergeError>
    where
        I: FnMut() -> Result<FirewallSnapshot>,
        E: FnMut(&FirewallCommand) -> Result<()>,
    {
        if !self.same_boot {
            let before = inspect().map_err(converge_inspection_error)?;
            let before_analysis = self.analyze_snapshot(&before).map_err(|error| {
                KillSwitchConvergeError::Conflict {
                    detail: error.to_string(),
                }
            })?;
            let after = inspect().map_err(converge_inspection_error)?;
            let after_analysis = self.analyze_snapshot(&after).map_err(|error| {
                KillSwitchConvergeError::Conflict {
                    detail: error.to_string(),
                }
            })?;
            if !before.same_complete_snapshot(&after)
                || before_analysis.present != after_analysis.present
            {
                return Err(KillSwitchConvergeError::Conflict {
                    detail: "complete filter ruleset changed during different-boot absence proof"
                        .to_string(),
                });
            }
            if !before_analysis.present.is_empty() {
                return Err(KillSwitchConvergeError::Conflict {
                    detail: "journal-shaped firewall state appeared after reboot and is not attributable to the old owner"
                        .to_string(),
                });
            }
            match slot {
                PreparedFirewallSlot::Endpoint(index) => {
                    self.endpoint_entries[index].state = PreparedFirewallState::Removed;
                }
                PreparedFirewallSlot::Base(index) => {
                    self.base_entries[index].state = PreparedFirewallState::Removed;
                }
            }
            return Ok(());
        }

        let target_components: Vec<_> = self
            .authorized_components()
            .map_err(|error| KillSwitchConvergeError::Conflict {
                detail: error.to_string(),
            })?
            .into_iter()
            .filter(|component| component.slot == slot)
            .collect();
        let mut snapshot = inspect().map_err(converge_inspection_error)?;
        let mut analysis = self.analyze_snapshot(&snapshot).map_err(|error| {
            KillSwitchConvergeError::Conflict {
                detail: error.to_string(),
            }
        })?;
        let mut has_post_command_snapshot = false;

        loop {
            let next = target_components
                .iter()
                .find(|component| analysis.contains(slot, &component.key));
            let Some(component) = next else {
                if !has_post_command_snapshot {
                    snapshot = inspect().map_err(converge_inspection_error)?;
                    analysis = self.analyze_snapshot(&snapshot).map_err(|error| {
                        KillSwitchConvergeError::Conflict {
                            detail: error.to_string(),
                        }
                    })?;
                }
                if analysis.slot_is_present(slot) {
                    return Err(KillSwitchConvergeError::Conflict {
                        detail: "target firewall resource remained after exact convergence"
                            .to_string(),
                    });
                }
                match slot {
                    PreparedFirewallSlot::Endpoint(index) => {
                        self.endpoint_entries[index].state = PreparedFirewallState::Removed;
                    }
                    PreparedFirewallSlot::Base(index) => {
                        self.base_entries[index].state = PreparedFirewallState::Removed;
                    }
                }
                return Ok(());
            };

            execute(&component.delete).map_err(|error| KillSwitchConvergeError::Operational {
                detail: format!(
                    "execute exact component delete {} {}: {error:#}",
                    component.delete.program,
                    component.delete.args.join(" ")
                ),
            })?;
            snapshot = inspect().map_err(converge_inspection_error)?;
            analysis = self.analyze_snapshot(&snapshot).map_err(|error| {
                KillSwitchConvergeError::Conflict {
                    detail: error.to_string(),
                }
            })?;
            if analysis.contains(slot, &component.key) {
                return Err(KillSwitchConvergeError::Conflict {
                    detail: format!(
                        "exact component remained after delete: {} {}",
                        component.key.program,
                        component.key.specification.join(" ")
                    ),
                });
            }
            has_post_command_snapshot = true;
        }
    }

    fn converge_endpoint_absent_with<I, E>(
        &mut self,
        resource: &FirewallEndpointResource,
        mut inspect: I,
        mut execute: E,
    ) -> std::result::Result<(), KillSwitchConvergeError>
    where
        I: FnMut() -> Result<FirewallSnapshot>,
        E: FnMut(&FirewallCommand) -> Result<()>,
    {
        let index = self
            .endpoint_entries
            .iter()
            .position(|entry| &entry.resource == resource)
            .ok_or_else(|| KillSwitchConvergeError::Conflict {
                detail: "endpoint resource was not authorized by prepared recovery".to_string(),
            })?;
        if self.endpoint_entries[index].state == PreparedFirewallState::Removed {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "prepared endpoint convergence was replayed".to_string(),
            });
        }
        if self.next_endpoint_index() != Some(index) {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "endpoint convergence is out of journal operation order".to_string(),
            });
        }
        self.converge_slot_with(
            PreparedFirewallSlot::Endpoint(index),
            &mut inspect,
            &mut execute,
        )
    }

    fn converge_base_absent_with<I, E>(
        &mut self,
        resource: &FirewallResource,
        mut inspect: I,
        mut execute: E,
    ) -> std::result::Result<(), KillSwitchConvergeError>
    where
        I: FnMut() -> Result<FirewallSnapshot>,
        E: FnMut(&FirewallCommand) -> Result<()>,
    {
        let index = self
            .base_entries
            .iter()
            .position(|entry| &entry.resource == resource)
            .ok_or_else(|| KillSwitchConvergeError::Conflict {
                detail: "base resource was not authorized by prepared recovery".to_string(),
            })?;
        if self.base_entries[index].state == PreparedFirewallState::Removed {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "prepared base convergence was replayed".to_string(),
            });
        }
        if self.next_endpoint_index().is_some() {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "base convergence preceded a pending endpoint resource".to_string(),
            });
        }
        if self.next_base_index() != Some(index) {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "base convergence is out of journal operation order".to_string(),
            });
        }
        if !self.same_boot {
            return self.converge_slot_with(
                PreparedFirewallSlot::Base(index),
                &mut inspect,
                &mut execute,
            );
        }

        let slot = PreparedFirewallSlot::Base(index);
        let before = inspect().map_err(converge_inspection_error)?;
        let before_analysis =
            self.analyze_snapshot(&before)
                .map_err(|error| KillSwitchConvergeError::Conflict {
                    detail: error.to_string(),
                })?;
        let stable = inspect().map_err(converge_inspection_error)?;
        let stable_analysis =
            self.analyze_snapshot(&stable)
                .map_err(|error| KillSwitchConvergeError::Conflict {
                    detail: error.to_string(),
                })?;
        if !before.same_complete_snapshot(&stable)
            || before_analysis.present != stable_analysis.present
        {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "complete firewall/table state changed before atomic base release"
                    .to_string(),
            });
        }

        let authorized =
            self.authorized_components()
                .map_err(|error| KillSwitchConvergeError::Conflict {
                    detail: error.to_string(),
                })?;
        let present: Vec<_> = authorized
            .iter()
            .filter(|component| {
                component.slot == slot && before_analysis.contains(slot, &component.key)
            })
            .collect();
        if !present.is_empty() {
            let program = match self.base_entries[index].resource.family {
                AddressFamily::Ipv4 => "iptables",
                AddressFamily::Ipv6 => "ip6tables",
            };
            let release = atomic_base_release_command(program, &present).map_err(|error| {
                KillSwitchConvergeError::Conflict {
                    detail: error.to_string(),
                }
            })?;
            execute(&release).map_err(|error| KillSwitchConvergeError::Operational {
                detail: format!(
                    "execute atomic family release {} {}: {error:#}",
                    release.program,
                    release.args.join(" ")
                ),
            })?;
        }

        let after_release = inspect().map_err(converge_inspection_error)?;
        let after_analysis = self.analyze_snapshot(&after_release).map_err(|error| {
            KillSwitchConvergeError::Conflict {
                detail: error.to_string(),
            }
        })?;
        if after_analysis.slot_is_present(slot) {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "base firewall component remained after atomic release".to_string(),
            });
        }

        let resource = self.base_entries[index].resource.clone();
        if resource.filter_table_origin == FirewallTableOrigin::AbsentBeforeInstall {
            if resource.backend != FirewallBackend::IptablesNft {
                return Err(KillSwitchConvergeError::Conflict {
                    detail: "non-nft firewall resource requested filter-table deletion".to_string(),
                });
            }
            let table = after_release
                .nft_filter_for(resource.family)
                .ok_or_else(|| KillSwitchConvergeError::Conflict {
                    detail: "nft lifecycle resource lacks complete table census".to_string(),
                })?;
            match classify_empty_nft_compat_shell(table) {
                EmptyCompatShell::Absent => {}
                EmptyCompatShell::Exact => {
                    // Re-prove the complete shell immediately before deletion.
                    // No delete is issued for a changed or foreign table.
                    let confirmed = inspect().map_err(converge_inspection_error)?;
                    let confirmed_analysis =
                        self.analyze_snapshot(&confirmed).map_err(|error| {
                            KillSwitchConvergeError::Conflict {
                                detail: error.to_string(),
                            }
                        })?;
                    if after_analysis.present != confirmed_analysis.present
                        || after_release.nft_filter_for(resource.family)
                            != confirmed.nft_filter_for(resource.family)
                    {
                        return Err(KillSwitchConvergeError::Conflict {
                            detail: "filter table changed during exact empty-shell proof"
                                .to_string(),
                        });
                    }
                    match classify_empty_nft_compat_shell(
                        confirmed
                            .nft_filter_for(resource.family)
                            .expect("confirmed nft census"),
                    ) {
                        EmptyCompatShell::Exact => {}
                        EmptyCompatShell::Absent => {
                            // Another privileged actor removed it. This caller
                            // performs no mutation and treats absence as the
                            // already-converged idempotent state.
                        }
                        EmptyCompatShell::Drift(detail) => {
                            return Err(KillSwitchConvergeError::Conflict { detail })
                        }
                    }
                    if confirmed
                        .nft_filter_for(resource.family)
                        .is_some_and(NftFilterTableSnapshot::is_present)
                    {
                        let delete = nft_delete_filter_table_command(resource.family);
                        execute(&delete).map_err(|error| KillSwitchConvergeError::Operational {
                            detail: format!(
                                "delete exact owned empty nft compatibility table: {error:#}"
                            ),
                        })?;
                    }
                }
                EmptyCompatShell::Drift(detail) => {
                    return Err(KillSwitchConvergeError::Conflict { detail })
                }
            }

            // Crash-after-delete-before-WAL-ack is idempotent: two complete
            // censuses must now prove absence, whether this call deleted the
            // shell or a prior recovery attempt already did.
            let absent_before = inspect().map_err(converge_inspection_error)?;
            let absent_after = inspect().map_err(converge_inspection_error)?;
            if !absent_before.same_complete_snapshot(&absent_after) {
                return Err(KillSwitchConvergeError::Conflict {
                    detail: "firewall state changed during post-delete absence proof".to_string(),
                });
            }
            for snapshot in [&absent_before, &absent_after] {
                let table = snapshot.nft_filter_for(resource.family).ok_or_else(|| {
                    KillSwitchConvergeError::Conflict {
                        detail: "post-delete nft census is unavailable".to_string(),
                    }
                })?;
                if classify_empty_nft_compat_shell(table) != EmptyCompatShell::Absent {
                    return Err(KillSwitchConvergeError::Conflict {
                        detail: "owned nft compatibility table remained after exact deletion"
                            .to_string(),
                    });
                }
            }
        } else if resource.filter_table_origin == FirewallTableOrigin::LegacyUnknown {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "legacy-unknown filter-table origin cannot be converged".to_string(),
            });
        } else if resource.output_chain_origin == FirewallOutputChainOrigin::AbsentBeforeInstall {
            if resource.backend != FirewallBackend::IptablesNft {
                return Err(KillSwitchConvergeError::Conflict {
                    detail: "non-nft firewall resource requested OUTPUT-chain deletion".to_string(),
                });
            }
            let table = after_release
                .nft_filter_for(resource.family)
                .ok_or_else(|| KillSwitchConvergeError::Conflict {
                    detail: "nft OUTPUT lifecycle lacks complete table census".to_string(),
                })?;
            match classify_empty_nft_output_shell(table) {
                EmptyCompatShell::Absent => {}
                EmptyCompatShell::Exact => {
                    let confirmed = inspect().map_err(converge_inspection_error)?;
                    let confirmed_analysis =
                        self.analyze_snapshot(&confirmed).map_err(|error| {
                            KillSwitchConvergeError::Conflict {
                                detail: error.to_string(),
                            }
                        })?;
                    if after_analysis.present != confirmed_analysis.present
                        || after_release.nft_filter_for(resource.family)
                            != confirmed.nft_filter_for(resource.family)
                    {
                        return Err(KillSwitchConvergeError::Conflict {
                            detail: "filter table changed during exact OUTPUT-shell proof"
                                .to_string(),
                        });
                    }
                    match classify_empty_nft_output_shell(
                        confirmed
                            .nft_filter_for(resource.family)
                            .expect("confirmed nft census"),
                    ) {
                        EmptyCompatShell::Exact => {
                            let delete = nft_delete_output_chain_command(resource.family);
                            execute(&delete).map_err(|error| {
                                KillSwitchConvergeError::Operational {
                                    detail: format!(
                                        "delete exact owned empty nft OUTPUT shell: {error:#}"
                                    ),
                                }
                            })?;
                        }
                        EmptyCompatShell::Absent => {}
                        EmptyCompatShell::Drift(detail) => {
                            return Err(KillSwitchConvergeError::Conflict { detail })
                        }
                    }
                }
                EmptyCompatShell::Drift(detail) => {
                    return Err(KillSwitchConvergeError::Conflict { detail })
                }
            }

            let absent_before = inspect().map_err(converge_inspection_error)?;
            let absent_after = inspect().map_err(converge_inspection_error)?;
            if !absent_before.same_complete_snapshot(&absent_after) {
                return Err(KillSwitchConvergeError::Conflict {
                    detail: "firewall state changed during OUTPUT post-delete absence proof"
                        .to_string(),
                });
            }
            for snapshot in [&absent_before, &absent_after] {
                let table = snapshot.nft_filter_for(resource.family).ok_or_else(|| {
                    KillSwitchConvergeError::Conflict {
                        detail: "post-delete nft OUTPUT census is unavailable".to_string(),
                    }
                })?;
                if classify_empty_nft_output_shell(table) != EmptyCompatShell::Absent {
                    return Err(KillSwitchConvergeError::Conflict {
                        detail: "owned nft OUTPUT shell remained after exact deletion".to_string(),
                    });
                }
            }
        } else if resource.output_chain_origin == FirewallOutputChainOrigin::LegacyUnknown {
            return Err(KillSwitchConvergeError::Conflict {
                detail: "legacy-unknown OUTPUT-chain origin cannot be converged".to_string(),
            });
        }

        self.base_entries[index].state = PreparedFirewallState::Removed;
        Ok(())
    }
}

#[cfg(any(test, target_os = "linux"))]
fn rule_targets_chain(rule: &[String], chain: &str) -> bool {
    rule.windows(2)
        .any(|pair| pair[0] == "-j" && pair[1] == chain)
}

#[cfg(test)]
fn verify_family_snapshot(
    program: &'static str,
    chain: &str,
    owner_comment: &str,
    output_listing: &[Vec<String>],
    chain_listing: &[Vec<String>],
    install: &[FirewallCommand],
) -> std::result::Result<(), KillSwitchConflict> {
    let expected: Vec<Vec<String>> = install
        .iter()
        .filter(|command| command.program == program)
        .filter_map(inspection_rule_spec)
        .collect();
    let expected_jump = expected
        .iter()
        .find(|rule| rule.get(1).is_some_and(|chain| chain == "OUTPUT"))
        .expect("install builder always emits one OUTPUT jump");
    let exact_count = output_listing
        .iter()
        .filter(|rule| *rule == expected_jump)
        .count();
    let owned_candidate_count = output_listing
        .iter()
        .filter(|rule| {
            rule.iter().any(|argument| argument == owner_comment) || rule_targets_chain(rule, chain)
        })
        .count();
    if exact_count != 1 || owned_candidate_count != 1 {
        return Err(KillSwitchConflict::JumpMismatch {
            program,
            exact_count,
            owned_candidate_count,
        });
    }

    let expected_chain_rules = multiset(
        expected
            .into_iter()
            .filter(|rule| rule.get(1).is_some_and(|actual| actual == chain)),
    );
    let actual_chain_rules: Vec<Vec<String>> = chain_listing
        .iter()
        .filter(|rule| !(rule.len() == 2 && rule[0] == "-N" && rule[1] == chain))
        .cloned()
        .collect();
    let actual_multiset = multiset(actual_chain_rules.iter().cloned());
    if actual_multiset != expected_chain_rules {
        return Err(KillSwitchConflict::ChainRulesMismatch {
            program,
            expected_count: expected_chain_rules.values().sum(),
            actual_count: actual_chain_rules.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
fn verify_teardown_snapshot(
    tun_iface: &str,
    endpoint_resources: &[FirewallEndpointResource],
    identity: KillSwitchIdentity,
    snapshot: &FirewallSnapshot,
) -> std::result::Result<Vec<FirewallCommand>, KillSwitchConflict> {
    for (program, actual) in [
        ("iptables", snapshot.ipv4_backend),
        ("ip6tables", snapshot.ipv6_backend),
    ] {
        if actual != identity.backend() {
            return Err(KillSwitchConflict::BackendMismatch {
                program,
                expected: identity.backend(),
                actual,
            });
        }
    }
    let endpoints: Vec<_> = validate_endpoint_resources(identity, endpoint_resources)?
        .into_iter()
        .collect();
    let install = killswitch_install_commands(tun_iface, &endpoints, identity);
    let owner_comment = identity.owner_comment();
    verify_family_snapshot(
        "iptables",
        &identity.ipv4_chain(),
        &owner_comment,
        &snapshot.ipv4_output,
        &snapshot.ipv4_chain,
        &install,
    )?;
    verify_family_snapshot(
        "ip6tables",
        &identity.ipv6_chain(),
        &owner_comment,
        &snapshot.ipv6_output,
        &snapshot.ipv6_chain,
        &install,
    )?;
    killswitch_recovery_commands(tun_iface, identity, endpoint_resources)
}

#[cfg(any(test, target_os = "linux"))]
fn allow_endpoint_with<F>(
    identity: KillSwitchIdentity,
    endpoints: &mut BTreeSet<AllowedEndpoint>,
    endpoint: AllowedEndpoint,
    mut execute: F,
) -> Result<bool>
where
    F: FnMut(&FirewallCommand) -> Result<()>,
{
    validate_allowed_endpoint(endpoint)?;
    if endpoints.contains(&endpoint) {
        return Ok(false);
    }
    anyhow::ensure!(
        endpoints.len() < MAX_KILLSWITCH_ENDPOINTS,
        "kill-switch endpoint set exceeds {MAX_KILLSWITCH_ENDPOINTS}"
    );
    execute(&endpoint_rule("-I", Some("1"), identity, endpoint))?;
    endpoints.insert(endpoint);
    Ok(true)
}

#[cfg(any(test, target_os = "linux"))]
fn deny_endpoint_with<F>(
    identity: KillSwitchIdentity,
    endpoints: &mut BTreeSet<AllowedEndpoint>,
    endpoint: AllowedEndpoint,
    mut execute: F,
) -> Result<bool>
where
    F: FnMut(&FirewallCommand) -> Result<()>,
{
    validate_allowed_endpoint(endpoint)?;
    if !endpoints.contains(&endpoint) {
        return Ok(false);
    }
    execute(&endpoint_rule("-D", None, identity, endpoint))?;
    endpoints.remove(&endpoint);
    Ok(true)
}

#[cfg(test)]
fn teardown_with<I, E>(
    tun_iface: &str,
    endpoint_resources: &[FirewallEndpointResource],
    identity: KillSwitchIdentity,
    inspect: I,
    mut execute: E,
) -> Result<()>
where
    I: FnOnce() -> Result<FirewallSnapshot>,
    E: FnMut(&FirewallCommand) -> Result<()>,
{
    // Inspection and complete ownership verification finish before the first
    // mutating command is made available to the executor.
    let snapshot = inspect()?;
    let teardown = verify_teardown_snapshot(tun_iface, endpoint_resources, identity, &snapshot)?;
    for command in teardown {
        execute(&command).with_context(|| {
            format!(
                "execute exact kill-switch teardown {} {}",
                command.program,
                command.args.join(" ")
            )
        })?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const MAX_FIREWALL_STDOUT_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_FIREWALL_STDERR_BYTES: usize = 32 * 1024;
#[cfg(target_os = "linux")]
const FIREWALL_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(any(target_os = "linux", all(test, unix)))]
fn drain_firewall_pipe<R>(
    mut reader: R,
    limit: usize,
    child_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(Vec<u8>, bool)>
where
    R: std::io::Read + std::os::fd::AsRawFd,
{
    use std::sync::atomic::Ordering;

    let fd = reader.as_raw_fd();
    // SAFETY: `fd` is the live pipe descriptor owned by `reader` for the
    // duration of this function.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A blocking read is unsafe here: a forked descendant may inherit the
    // pipe, outlive the firewall command, and never close its copy.  Keep
    // draining while the direct child is live so it cannot block on a full
    // pipe, then stop at the first empty nonblocking read after it is reaped.
    // SAFETY: `fd` remains live and F_SETFL receives the flags read above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut captured = Vec::with_capacity(limit.min(8 * 1024));
    let mut overflow = false;
    let mut chunk = [0u8; 8 * 1024];
    loop {
        // Once overflow is proven and the direct child has terminated, no
        // further byte can affect the bounded result.  Dropping our pipe end
        // also prevents a malicious pipe-holder from prolonging the join.
        if overflow && child_done.load(Ordering::Acquire) {
            break;
        }
        let read = match std::io::Read::read(&mut reader, &mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if child_done.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            Err(error) => return Err(error),
        };
        let remaining = limit.saturating_sub(captured.len());
        let retained = remaining.min(read);
        captured.extend_from_slice(&chunk[..retained]);
        overflow |= retained != read;
        // Keep draining/discarding excess while the direct child is live.  A
        // fail-closed inspection must not deadlock merely because stderr or a
        // hostile ruleset listing exceeds its retention budget.
    }
    Ok((captured, overflow))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
#[derive(Debug)]
struct BoundedFirewallOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_overflow: bool,
    stderr_overflow: bool,
}

#[cfg(target_os = "linux")]
fn trusted_linux_firewall_executable(program: &str) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let candidates: Vec<std::path::PathBuf> = if std::path::Path::new(program).is_absolute() {
        vec![std::path::PathBuf::from(program)]
    } else {
        let known = matches!(
            program,
            "iptables" | "ip6tables" | "iptables-restore" | "ip6tables-restore" | "nft"
        );
        anyhow::ensure!(known, "untrusted Linux firewall helper {program:?}");
        ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
            .into_iter()
            .map(|directory| std::path::Path::new(directory).join(program))
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
            format!(
                "canonicalize trusted firewall helper {}",
                candidate.display()
            )
        })?;
        let canonical_metadata = std::fs::metadata(&canonical)
            .with_context(|| format!("stat canonical firewall helper {}", canonical.display()))?;
        anyhow::ensure!(
            canonical_metadata.file_type().is_file()
                && canonical_metadata.uid() == 0
                && canonical_metadata.permissions().mode() & 0o022 == 0,
            "canonical firewall helper {} is not root-owned and non-writable",
            canonical.display()
        );
        for ancestor in canonical.ancestors().skip(1) {
            let ancestor_metadata = std::fs::metadata(ancestor).with_context(|| {
                format!(
                    "stat canonical firewall helper ancestor {}",
                    ancestor.display()
                )
            })?;
            anyhow::ensure!(
                ancestor_metadata.file_type().is_dir()
                    && ancestor_metadata.uid() == 0
                    && ancestor_metadata.permissions().mode() & 0o022 == 0,
                "canonical firewall helper ancestor {} is not a root-owned, non-writable directory",
                ancestor.display()
            );
        }
        return Ok(canonical);
    }
    anyhow::bail!("no root-owned, non-writable absolute Linux firewall helper for {program:?}")
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn kill_firewall_process_group(pid: u32) -> Option<String> {
    let process_group = i32::try_from(pid).ok()?;
    // SAFETY: production children are started as leaders of fresh process
    // groups. This remains valid after the direct child has been reaped and is
    // needed to kill a pipe-holding descendant on incomplete stdin delivery.
    if unsafe { libc::kill(-process_group, libc::SIGKILL) } == 0 {
        return None;
    }
    let error = std::io::Error::last_os_error();
    (error.raw_os_error() != Some(libc::ESRCH)).then(|| error.to_string())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn terminate_firewall_process_group_and_reap(
    child: &mut std::process::Child,
) -> (Option<String>, std::io::Result<std::process::ExitStatus>) {
    let pid = child.id();
    let mut kill_error = kill_firewall_process_group(pid);
    // Signal the direct child as well even when the group signal succeeded: a
    // hostile executable can call setsid()/setpgid() after exec and escape the
    // group created by Command. SIGKILL is idempotent for the normal case.
    if let Err(error) = child.kill() {
        if error.kind() != std::io::ErrorKind::InvalidInput
            && error.raw_os_error() != Some(libc::ESRCH)
        {
            kill_error = Some(match kill_error {
                Some(group_error) => {
                    format!("process-group kill: {group_error}; child kill: {error}")
                }
                None => format!("child kill: {error}"),
            });
        }
    }
    // Always wait after a termination attempt.  This is the direct-child
    // zombie-safety boundary; pipe readers are joined only after this returns.
    let wait_result = loop {
        match child.wait() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    (kill_error, wait_result)
}

#[cfg(all(test, unix))]
fn run_bounded_firewall_subprocess(
    program: &'static str,
    args: &[String],
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<BoundedFirewallOutput> {
    run_bounded_firewall_subprocess_with_input(
        program,
        args,
        None,
        timeout,
        stdout_limit,
        stderr_limit,
    )
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn write_firewall_stdin_bounded<W>(
    mut writer: W,
    bytes: &[u8],
    child_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    deadline: std::time::Instant,
) -> std::io::Result<()>
where
    W: std::io::Write + std::os::fd::AsRawFd,
{
    use std::sync::atomic::Ordering;

    let descriptor = writer.as_raw_fd();
    // A helper (or an escaped descendant) may retain stdin without reading it.
    // A blocking `write_all` followed by an unbounded thread join would then
    // outlive both the direct child and the advertised command deadline.
    // SAFETY: `descriptor` is the live pipe owned by `writer`.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor is still live and `flags` came from F_GETFL.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut offset = 0usize;
    while offset < bytes.len() {
        if child_done.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "direct firewall child exited before bounded stdin was consumed",
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "firewall subprocess stdin deadline elapsed",
            ));
        }
        match writer.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "firewall subprocess stdin accepted zero bytes",
                ))
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    writer.flush()
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn run_bounded_firewall_subprocess_with_input(
    program: &'static str,
    args: &[String],
    input: Option<&[u8]>,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<BoundedFirewallOutput> {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[cfg(target_os = "linux")]
    let executable = trusted_linux_firewall_executable(program)?;
    #[cfg(not(target_os = "linux"))]
    let executable = std::path::PathBuf::from(program);
    let mut process = Command::new(&executable);
    process
        // Preserve the validated frontend name as argv[0] even though the
        // executable path is canonicalized for ownership checks.  iptables on
        // distributions such as Arch is a symlink to xtables-nft-multi, which
        // selects its applet exclusively from argv[0]; using the canonical
        // target name makes even `iptables --version` fail closed before TUN
        // creation.
        .arg0(program)
        .args(args)
        // Never let a privileged caller redirect loader/plugin discovery or
        // parser locale through its environment. The helper itself is already
        // an absolute, root-owned canonical path.
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = process
        .spawn()
        .with_context(|| format!("start firewall subprocess {program} {}", args.join(" ")))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = terminate_firewall_process_group_and_reap(&mut child);
            anyhow::bail!("firewall stdout pipe unavailable")
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            let _ = terminate_firewall_process_group_and_reap(&mut child);
            anyhow::bail!("firewall stderr pipe unavailable")
        }
    };
    let child_stdin = if input.is_some() {
        match child.stdin.take() {
            Some(stdin) => Some(stdin),
            None => {
                drop(stdout);
                drop(stderr);
                let _ = terminate_firewall_process_group_and_reap(&mut child);
                anyhow::bail!("firewall stdin pipe unavailable")
            }
        }
    } else {
        None
    };
    let child_done = Arc::new(AtomicBool::new(false));
    let stdout_done = Arc::clone(&child_done);
    let stderr_done = Arc::clone(&child_done);
    let started = Instant::now();

    let (status, stdout, stderr) = std::thread::scope(|scope| -> Result<_> {
        let stdin_writer = child_stdin.map(|stdin| {
            let done = Arc::clone(&child_done);
            let deadline = started + timeout;
            scope.spawn(move || {
                write_firewall_stdin_bounded(
                    stdin,
                    input.expect("stdin exists only with input"),
                    done,
                    deadline,
                )
            })
        });
        let stdout_reader =
            scope.spawn(move || drain_firewall_pipe(stdout, stdout_limit, stdout_done));
        let stderr_reader =
            scope.spawn(move || drain_firewall_pipe(stderr, stderr_limit, stderr_done));
        let mut terminal_error = None;
        let status = loop {
            match child.try_wait() {
                // `try_wait` reaps the direct child when it returns a status.
                Ok(Some(status)) => {
                    if let Some(error) = kill_firewall_process_group(child.id()) {
                        terminal_error = Some(anyhow::anyhow!(
                            "kill firewall subprocess descendants after direct-child exit: {error}"
                        ));
                    }
                    break Some(status);
                }
                Ok(None) if started.elapsed() >= timeout => {
                    let (kill_error, wait_result) =
                        terminate_firewall_process_group_and_reap(&mut child);
                    let wait_detail = wait_result
                        .as_ref()
                        .map(|status| format!("reaped with {status}"))
                        .unwrap_or_else(|error| format!("wait failed: {error}"));
                    terminal_error = Some(anyhow::anyhow!(
                        "firewall subprocess {program} {} timed out after {:?}; kill: {}; {wait_detail}",
                        args.join(" "),
                        timeout,
                        kill_error.as_deref().unwrap_or("ok")
                    ));
                    break wait_result.ok();
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => {
                    let (kill_error, wait_result) =
                        terminate_firewall_process_group_and_reap(&mut child);
                    terminal_error = Some(anyhow::anyhow!(
                        "poll firewall subprocess {program} {}: {error}; kill: {}; wait: {}",
                        args.join(" "),
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
            .map_err(|_| anyhow::anyhow!("firewall stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("firewall stderr reader panicked"))??;
        if let Some(writer) = stdin_writer {
            match writer
                .join()
                .map_err(|_| anyhow::anyhow!("firewall stdin writer panicked"))?
            {
                Ok(()) => {}
                Err(error) => {
                    let descendant_kill = kill_firewall_process_group(child.id());
                    return Err(error).with_context(|| {
                        format!(
                            "write firewall subprocess stdin; descendant-group kill: {}",
                            descendant_kill.as_deref().unwrap_or("ok")
                        )
                    });
                }
            }
        }
        if let Some(error) = terminal_error {
            return Err(error);
        }
        let status = status.ok_or_else(|| anyhow::anyhow!("firewall subprocess had no status"))?;
        Ok((status, stdout, stderr))
    })?;

    Ok(BoundedFirewallOutput {
        status,
        stdout: stdout.0,
        stderr: stderr.0,
        stdout_overflow: stdout.1,
        stderr_overflow: stderr.1,
    })
}

#[cfg(target_os = "linux")]
fn run_bounded_firewall_process(
    program: &'static str,
    args: &[String],
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
    run_bounded_firewall_process_with_input(program, args, None)
}

#[cfg(target_os = "linux")]
fn run_bounded_firewall_process_with_input(
    program: &'static str,
    args: &[String],
    input: Option<&[u8]>,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
    let output = run_bounded_firewall_subprocess_with_input(
        program,
        args,
        input,
        FIREWALL_SUBPROCESS_TIMEOUT,
        MAX_FIREWALL_STDOUT_BYTES,
        MAX_FIREWALL_STDERR_BYTES,
    )?;
    anyhow::ensure!(
        !output.stdout_overflow,
        "firewall stdout exceeded bounded capture"
    );
    anyhow::ensure!(
        !output.stderr_overflow,
        "firewall stderr exceeded bounded capture"
    );
    Ok((output.status, output.stdout, output.stderr))
}

#[cfg(target_os = "linux")]
fn query_firewall(program: &'static str, args: &[&str]) -> Result<String> {
    let owned_args: Vec<_> = args
        .iter()
        .map(|argument| (*argument).to_string())
        .collect();
    let (status, stdout, stderr) = run_bounded_firewall_process(program, &owned_args)?;
    anyhow::ensure!(
        status.success(),
        "read-only firewall inspection {program} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&stderr).trim()
    );
    String::from_utf8(stdout).map_err(|error| {
        KillSwitchConflict::MalformedListing {
            program,
            detail: format!("firewall inspection returned non-UTF-8 output: {error}"),
        }
        .into()
    })
}

#[cfg(target_os = "linux")]
fn query_firewall_command(command: &FirewallCommand) -> Result<String> {
    let arguments: Vec<_> = command.args.iter().map(String::as_str).collect();
    query_firewall(command.program, &arguments)
}

#[cfg(target_os = "linux")]
fn detect_runtime_backend() -> Result<FirewallBackend> {
    let ipv4 = parse_backend_output("iptables", &query_firewall("iptables", &["--version"])?)?;
    let ipv6 = parse_backend_output("ip6tables", &query_firewall("ip6tables", &["--version"])?)?;
    let restore_ipv4 = parse_backend_output(
        "iptables-restore",
        &query_firewall("iptables-restore", &["--version"])?,
    )?;
    let restore_ipv6 = parse_backend_output(
        "ip6tables-restore",
        &query_firewall("ip6tables-restore", &["--version"])?,
    )?;
    anyhow::ensure!(
        ipv4 == ipv6 && ipv4 == restore_ipv4 && ipv4 == restore_ipv6,
        "firewall frontend backend mismatch: iptables={ipv4:?}, ip6tables={ipv6:?}, iptables-restore={restore_ipv4:?}, ip6tables-restore={restore_ipv6:?}"
    );
    Ok(ipv4)
}

#[cfg(target_os = "linux")]
fn inspect_firewall(identity: KillSwitchIdentity) -> Result<FirewallSnapshot> {
    let ipv4_version = query_firewall("iptables", &["--version"])?;
    let ipv6_version = query_firewall("ip6tables", &["--version"])?;
    let ipv4_backend = parse_backend_output("iptables", &ipv4_version)?;
    let ipv6_backend = parse_backend_output("ip6tables", &ipv6_version)?;
    let restore_ipv4 = parse_backend_output(
        "iptables-restore",
        &query_firewall("iptables-restore", &["--version"])?,
    )?;
    let restore_ipv6 = parse_backend_output(
        "ip6tables-restore",
        &query_firewall("ip6tables-restore", &["--version"])?,
    )?;
    anyhow::ensure!(
        ipv4_backend == restore_ipv4 && ipv6_backend == restore_ipv6,
        "firewall inspection found command/restore backend mismatch"
    );
    let commands = killswitch_inspection_commands(identity);
    let ipv4_rules = query_firewall_command(&commands[0])?;
    let ipv6_rules = query_firewall_command(&commands[1])?;
    let nft_filter_tables = if ipv4_backend == FirewallBackend::IptablesNft
        && ipv6_backend == FirewallBackend::IptablesNft
    {
        let listing = query_firewall("nft", &["-j", "list", "ruleset"])?;
        Some(parse_nft_filter_tables(&listing)?)
    } else {
        None
    };
    Ok(FirewallSnapshot::from_full_listings(
        identity,
        ipv4_backend,
        ipv6_backend,
        parse_iptables_listing("iptables", &ipv4_rules)?,
        parse_iptables_listing("ip6tables", &ipv6_rules)?,
        nft_filter_tables,
    ))
}

#[cfg(target_os = "linux")]
impl PreparedKillSwitchRecovery {
    pub fn prepare(
        tun_iface: &str,
        identity: KillSwitchIdentity,
        base_resources: &[FirewallResource],
        endpoint_resources: &[FirewallEndpointResource],
    ) -> std::result::Result<Self, KillSwitchPrepareError> {
        Self::prepare_for_boot(
            tun_iface,
            identity,
            base_resources,
            endpoint_resources,
            true,
        )
    }

    /// Prepare recovery under explicit boot attribution.  `same_boot = false`
    /// is observation-only: matching firewall state is a conflict and an
    /// initially absent resource is only re-proved absent, never deleted.
    pub fn prepare_for_boot(
        tun_iface: &str,
        identity: KillSwitchIdentity,
        base_resources: &[FirewallResource],
        endpoint_resources: &[FirewallEndpointResource],
        same_boot: bool,
    ) -> std::result::Result<Self, KillSwitchPrepareError> {
        Self::prepare_with_boot_scope(
            tun_iface,
            identity,
            base_resources,
            endpoint_resources,
            same_boot,
            || inspect_firewall(identity),
        )
    }

    pub fn converge_endpoint_absent(
        &mut self,
        resource: &FirewallEndpointResource,
    ) -> std::result::Result<(), KillSwitchConvergeError> {
        let identity = self.identity;
        self.converge_endpoint_absent_with(resource, || inspect_firewall(identity), run_firewall)
    }

    pub fn converge_base_absent(
        &mut self,
        resource: &FirewallResource,
    ) -> std::result::Result<(), KillSwitchConvergeError> {
        let identity = self.identity;
        self.converge_base_absent_with(resource, || inspect_firewall(identity), run_firewall)
    }
}

#[cfg(not(target_os = "linux"))]
impl PreparedKillSwitchRecovery {
    pub fn prepare(
        _tun_iface: &str,
        _identity: KillSwitchIdentity,
        _base_resources: &[FirewallResource],
        _endpoint_resources: &[FirewallEndpointResource],
    ) -> std::result::Result<Self, KillSwitchPrepareError> {
        Err(KillSwitchPrepareError::Operational {
            detail: "kill-switch recovery is available only on Linux".to_string(),
        })
    }

    pub fn prepare_for_boot(
        _tun_iface: &str,
        _identity: KillSwitchIdentity,
        _base_resources: &[FirewallResource],
        _endpoint_resources: &[FirewallEndpointResource],
        _same_boot: bool,
    ) -> std::result::Result<Self, KillSwitchPrepareError> {
        Err(KillSwitchPrepareError::Operational {
            detail: "kill-switch recovery is available only on Linux".to_string(),
        })
    }

    pub fn converge_endpoint_absent(
        &mut self,
        _resource: &FirewallEndpointResource,
    ) -> std::result::Result<(), KillSwitchConvergeError> {
        Err(KillSwitchConvergeError::Operational {
            detail: "kill-switch recovery is available only on Linux".to_string(),
        })
    }

    pub fn converge_base_absent(
        &mut self,
        _resource: &FirewallResource,
    ) -> std::result::Result<(), KillSwitchConvergeError> {
        Err(KillSwitchConvergeError::Operational {
            detail: "kill-switch recovery is available only on Linux".to_string(),
        })
    }
}

fn map_killswitch_convergence_error(error: KillSwitchConvergeError) -> RecoveryConvergenceError {
    match error {
        KillSwitchConvergeError::Conflict { detail } => {
            RecoveryConvergenceError::conflict(anyhow::anyhow!(detail))
        }
        KillSwitchConvergeError::Operational { detail } => {
            RecoveryConvergenceError::operational(anyhow::anyhow!(detail))
        }
    }
}

impl PreparedResourceGroup for PreparedKillSwitchRecovery {
    fn observe(&self, resource: &OwnedResource) -> Option<ResourceObservationKind> {
        match resource {
            OwnedResource::FirewallEndpoint(resource) => self.endpoint_observation(resource),
            OwnedResource::Firewall(resource) => self.base_observation(resource),
            _ => None,
        }
    }

    fn converge_absent(
        &mut self,
        resource: &OwnedResource,
    ) -> Option<std::result::Result<(), RecoveryConvergenceError>> {
        match resource {
            OwnedResource::FirewallEndpoint(resource)
                if self.endpoint_observation(resource).is_some() =>
            {
                Some(
                    self.converge_endpoint_absent(resource)
                        .map_err(map_killswitch_convergence_error),
                )
            }
            OwnedResource::Firewall(resource) if self.base_observation(resource).is_some() => Some(
                self.converge_base_absent(resource)
                    .map_err(map_killswitch_convergence_error),
            ),
            _ => None,
        }
    }
}

/// `/etc/resolv.conf` contents pinning DNS to `servers`, so name resolution goes
/// through the tunnel instead of leaking to the LAN/ISP resolver.
pub fn resolv_conf(servers: &[Ipv4Addr]) -> String {
    let mut s =
        String::from("# shadowpipe DNS pin (kill-switch); original restored on tunnel exit\n");
    for ns in servers {
        s.push_str(&format!("nameserver {ns}\n"));
    }
    s
}

// ----------------------------------------------------------------- kill-switch

const MAX_KILLSWITCH_ENDPOINTS: usize = 120;

/// A fail-closed firewall active for the lifetime of the guard; restored on
/// `Drop`. Linux-only; construction fails explicitly elsewhere.
pub struct KillSwitch {
    active: bool,
    identity: KillSwitchIdentity,
    tun_iface: String,
    endpoints: BTreeSet<AllowedEndpoint>,
    base_resources: [FirewallResource; 2],
}

impl KillSwitch {
    /// Engage the kill-switch, allowing only exact outer-carrier tuples outside
    /// the TUN. The current IPv4 tunnel blocks all non-loopback IPv6. Any
    /// partial firewall installation is rolled back before returning an error.
    pub fn engage(tun_iface: &str, endpoints: &[AllowedEndpoint]) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let token = KillSwitchInstallToken::prepare_runtime()?;
            Self::engage_preflighted(tun_iface, endpoints, token)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_iface, endpoints);
            anyhow::bail!("kill-switch runtime is currently implemented only on Linux")
        }
    }

    /// Non-journal compatibility entrypoint. It captures table evidence only
    /// after entry, so a caller must not write a WAL from identity-derived
    /// resources before calling it. Privileged production code must capture a
    /// [`KillSwitchInstallToken`], WAL its exact resources, then call
    /// [`Self::engage_preflighted`].
    #[deprecated(note = "journaled callers must use KillSwitchInstallToken + engage_preflighted")]
    pub fn engage_with_identity(
        tun_iface: &str,
        endpoints: &[AllowedEndpoint],
        identity: KillSwitchIdentity,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let token = KillSwitchInstallToken::prepare_with_identity(identity)?;
            Self::engage_preflighted(tun_iface, endpoints, token)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_iface, endpoints, identity);
            anyhow::bail!("kill-switch runtime is currently implemented only on Linux")
        }
    }

    /// Consume the exact pre-WAL census token and re-check it immediately
    /// before the first `-N`. This is the journal-aware production entrypoint.
    pub fn engage_preflighted(
        tun_iface: &str,
        endpoints: &[AllowedEndpoint],
        token: KillSwitchInstallToken,
    ) -> Result<Self> {
        validate_tun_iface(tun_iface)?;
        let unique_endpoints: BTreeSet<_> = endpoints.iter().copied().collect();
        anyhow::ensure!(
            !unique_endpoints.is_empty(),
            "kill-switch requires at least one exact carrier endpoint"
        );
        anyhow::ensure!(
            unique_endpoints.len() <= MAX_KILLSWITCH_ENDPOINTS,
            "kill-switch endpoint set exceeds {MAX_KILLSWITCH_ENDPOINTS}"
        );
        for endpoint in &unique_endpoints {
            validate_allowed_endpoint(*endpoint)?;
        }
        #[cfg(target_os = "linux")]
        {
            let identity = token.identity;
            let actual_backend = detect_runtime_backend()?;
            anyhow::ensure!(
                actual_backend == identity.backend(),
                "journaled firewall backend {:?} differs from runtime backend {:?}",
                identity.backend(),
                actual_backend
            );
            let before = inspect_firewall(identity)
                .context("recheck complete firewall/table state before first mutation")?;
            let after = inspect_firewall(identity)
                .context("repeat complete firewall/table recheck before first mutation")?;
            anyhow::ensure!(
                token.baseline.same_complete_snapshot(&before)
                    && before.same_complete_snapshot(&after),
                "firewall/table state changed after install token capture; refusing first mutation"
            );
            let endpoints: Vec<_> = unique_endpoints.iter().copied().collect();
            let install = killswitch_install_commands(tun_iface, &endpoints, identity);
            apply_firewall_transaction(&install, run_firewall)?;
            Ok(Self {
                active: true,
                identity,
                tun_iface: tun_iface.to_string(),
                endpoints: unique_endpoints,
                base_resources: token.base_resources,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_iface, endpoints, token, unique_endpoints);
            anyhow::bail!("kill-switch runtime is currently implemented only on Linux")
        }
    }

    pub const fn identity(&self) -> KillSwitchIdentity {
        self.identity
    }

    /// Static v3 base resources, including filter-table origin authority.
    /// Dynamic tuples are returned separately by
    /// [`Self::journal_endpoint_resources`] and never alter these counts.
    pub fn journal_resources(&self) -> [FirewallResource; 2] {
        self.base_resources.clone()
    }

    /// Current non-Removed dynamic endpoint resources in deterministic tuple
    /// order. The guard enforces the same bound as the v3 journal operation
    /// model before any endpoint enters this set.
    pub fn journal_endpoint_resources(&self) -> Vec<FirewallEndpointResource> {
        endpoint_journal_snapshot(self.identity, &self.endpoints)
    }

    pub fn allowed_endpoints(&self) -> impl Iterator<Item = AllowedEndpoint> + '_ {
        self.endpoints.iter().copied()
    }

    pub fn allows_endpoint(&self, endpoint: AllowedEndpoint) -> bool {
        self.endpoints.contains(&endpoint)
    }

    /// Side-effect-free journal preflight. Call this before `begin_add` so an
    /// invalid, duplicate, or over-capacity endpoint never enters the WAL.
    /// `false` means the exact endpoint is already present and needs no add.
    pub fn can_allow_endpoint(&self, endpoint: AllowedEndpoint) -> Result<bool> {
        validate_allowed_endpoint(endpoint)?;
        if self.endpoints.contains(&endpoint) {
            return Ok(false);
        }
        anyhow::ensure!(
            self.endpoints.len() < MAX_KILLSWITCH_ENDPOINTS,
            "kill-switch endpoint set exceeds {MAX_KILLSWITCH_ENDPOINTS}"
        );
        Ok(true)
    }

    /// Stage one exact carrier tuple before publishing it to a dialer snapshot.
    /// The rule is inserted ahead of the terminal DROP; state changes only after
    /// the kernel command succeeds.
    pub fn allow_endpoint(&mut self, endpoint: AllowedEndpoint) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            allow_endpoint_with(self.identity, &mut self.endpoints, endpoint, run_firewall)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = endpoint;
            anyhow::bail!("dynamic kill-switch updates are only available on Linux")
        }
    }

    /// Remove one exact carrier tuple after it has been depublished and all
    /// in-flight dial leases using it have drained.
    pub fn deny_endpoint(&mut self, endpoint: AllowedEndpoint) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            deny_endpoint_with(self.identity, &mut self.endpoints, endpoint, run_firewall)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = endpoint;
            anyhow::bail!("dynamic kill-switch updates are only available on Linux")
        }
    }

    /// Inspect all owned state before the first mutation, then remove only the
    /// exact verified rules and chains. Conflict leaves the firewall untouched.
    pub fn shutdown(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            let endpoint_resources = self.journal_endpoint_resources();
            let base_resources = self.journal_resources();
            let mut prepared = PreparedKillSwitchRecovery::prepare(
                &self.tun_iface,
                self.identity,
                &base_resources,
                &endpoint_resources,
            )?;
            for resource in &endpoint_resources {
                prepared.converge_endpoint_absent(resource)?;
            }
            for resource in &base_resources {
                prepared.converge_base_absent(resource)?;
            }
            self.active = false;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("kill-switch runtime is currently implemented only on Linux")
        }
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Err(error) = self.shutdown() {
            tracing::error!(
                %error,
                owner = %self.identity.owner_comment(),
                ipv4_chain = %self.identity.ipv4_chain(),
                ipv6_chain = %self.identity.ipv6_chain(),
                "kill-switch teardown refused or failed; owned firewall state retained"
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (
            &self.active,
            &self.identity,
            &self.tun_iface,
            &self.endpoints,
            &self.base_resources,
        );
    }
}

// ------------------------------------------------------------------------- DNS

/// Pins `/etc/resolv.conf` to chosen resolvers for the guard's lifetime, restoring
/// the original (file or symlink) on `Drop`. Linux-only; construction fails
/// explicitly elsewhere.
///
/// Known limit (needs host validation): under systemd-resolved this replaces the
/// stub resolver for the session — queries go through the tunnel, but resolved's
/// split-DNS/caching is bypassed until restore. Acceptable for a leak-proof VPN.
pub struct DnsGuard {
    restore: Option<DnsRestore>,
}

#[derive(Clone, Debug)]
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
struct DnsRestore {
    path: std::path::PathBuf,
    symlink_target: Option<std::path::PathBuf>,
    contents: Vec<u8>,
    mode: u32,
}

impl DnsGuard {
    /// Back up `/etc/resolv.conf` and pin it to `servers`. Linux-only; inert guard
    /// elsewhere.
    pub fn apply(servers: &[Ipv4Addr]) -> Result<Self> {
        if servers.is_empty() {
            anyhow::bail!("DNS guard requires at least one resolver");
        }
        #[cfg(target_os = "linux")]
        {
            Self::apply_to_path(std::path::Path::new(RESOLV_CONF), servers)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = servers;
            anyhow::bail!("DNS guard runtime is currently implemented only on Linux")
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    fn apply_to_path(path: &std::path::Path, servers: &[Ipv4Addr]) -> Result<Self> {
        Self::apply_to_path_with(path, servers, atomic_write)
    }

    #[cfg(any(test, target_os = "linux"))]
    fn apply_to_path_with<F>(
        path: &std::path::Path,
        servers: &[Ipv4Addr],
        publish: F,
    ) -> Result<Self>
    where
        F: FnOnce(&std::path::Path, &[u8], u32) -> Result<()>,
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        if servers.is_empty() {
            anyhow::bail!("DNS guard requires at least one resolver");
        }
        let meta = fs::symlink_metadata(path)
            .with_context(|| format!("stat DNS path {}", path.display()))?;
        let (symlink_target, contents, mode) = if meta.file_type().is_symlink() {
            (
                Some(
                    fs::read_link(path)
                        .with_context(|| format!("read DNS symlink {}", path.display()))?,
                ),
                Vec::new(),
                0o644,
            )
        } else if meta.file_type().is_file() {
            (
                None,
                fs::read(path).with_context(|| format!("read DNS file {}", path.display()))?,
                meta.permissions().mode() & 0o777,
            )
        } else {
            anyhow::bail!("DNS path is neither a regular file nor a symlink");
        };
        let restore = DnsRestore {
            path: path.to_path_buf(),
            symlink_target,
            contents,
            mode,
        };
        // Own the rollback state before publication. `rename(2)` may succeed
        // and the following directory fsync may fail; in that case publication
        // returned Err even though the pinned file is already visible.
        let mut guard = Self {
            restore: Some(restore),
        };
        let pinned = resolv_conf(servers);
        if let Err(publish_error) = publish(path, pinned.as_bytes(), 0o644) {
            let restore = guard
                .restore
                .take()
                .expect("DNS guard owns restore state before publication");
            let rollback_error = restore_dns(&restore).err();
            let verification_error = verify_dns_restore(&restore).err();
            if rollback_error.is_none() && verification_error.is_none() {
                return Err(publish_error).context(
                    "atomically publish pinned DNS configuration; original DNS state restored",
                );
            }

            let mut diagnostics = Vec::new();
            if let Some(error) = rollback_error {
                diagnostics.push(format!("restore failed: {error:#}"));
            }
            if let Some(error) = verification_error {
                diagnostics.push(format!("restore verification failed: {error:#}"));
            }
            return Err(anyhow::anyhow!(
                "atomically publish pinned DNS configuration failed: {publish_error:#}; {}",
                diagnostics.join("; ")
            ));
        }
        Ok(guard)
    }

    /// Restore and verify the original resolver object while retaining the
    /// exact rollback state on failure. A higher-level teardown coordinator
    /// can therefore keep the kill-switch armed and retry instead of silently
    /// releasing the firewall after a failed DNS restore.
    pub fn try_restore(&mut self) -> Result<bool> {
        #[cfg(any(test, target_os = "linux"))]
        if let Some(restore) = self.restore.as_ref() {
            restore_dns(restore)?;
            verify_dns_restore(restore)?;
            self.restore = None;
            return Ok(true);
        }
        #[cfg(not(any(test, target_os = "linux")))]
        if self.restore.take().is_some() {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn restore(mut self) -> Result<()> {
        self.try_restore().map(|_| ())
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if let Err(error) = self.try_restore() {
            tracing::error!(%error, "failed to restore and verify DNS configuration");
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn restore_dns(restore: &DnsRestore) -> Result<()> {
    if let Some(target) = &restore.symlink_target {
        atomic_symlink(&restore.path, target).context("restore DNS symlink")
    } else {
        atomic_write(&restore.path, &restore.contents, restore.mode).context("restore DNS file")
    }
}

#[cfg(any(test, target_os = "linux"))]
fn verify_dns_restore(restore: &DnsRestore) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(&restore.path)
        .with_context(|| format!("stat restored DNS path {}", restore.path.display()))?;
    if let Some(expected_target) = &restore.symlink_target {
        anyhow::ensure!(
            metadata.file_type().is_symlink(),
            "restored DNS path is not a symlink"
        );
        let actual_target = std::fs::read_link(&restore.path)
            .with_context(|| format!("read restored DNS symlink {}", restore.path.display()))?;
        anyhow::ensure!(
            actual_target == *expected_target,
            "restored DNS symlink target changed: expected {}, got {}",
            expected_target.display(),
            actual_target.display()
        );
    } else {
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "restored DNS path is not a regular file"
        );
        let actual_contents = std::fs::read(&restore.path)
            .with_context(|| format!("read restored DNS file {}", restore.path.display()))?;
        anyhow::ensure!(
            actual_contents == restore.contents,
            "restored DNS file contents differ from original"
        );
        let actual_mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            actual_mode == restore.mode,
            "restored DNS file mode changed: expected {:o}, got {:o}",
            restore.mode,
            actual_mode
        );
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn sibling_temp(path: &std::path::Path) -> Result<std::path::PathBuf> {
    static NEXT_TEMP_ID: AtomicU32 = AtomicU32::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("DNS path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("DNS path has no UTF-8 filename"))?;
    for _ in 0..64 {
        let n = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.shadowpipe.{}.{n}", std::process::id()));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("could not allocate same-directory DNS temp path")
}

#[cfg(any(test, target_os = "linux"))]
fn sync_parent(path: &std::path::Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("DNS path has no parent"))?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync DNS parent directory {}", parent.display()))
}

#[cfg(any(test, target_os = "linux"))]
fn atomic_write(path: &std::path::Path, contents: &[u8], mode: u32) -> Result<()> {
    atomic_write_with_sync(path, contents, mode, sync_parent)
}

#[cfg(any(test, target_os = "linux"))]
fn atomic_write_with_sync<F>(
    path: &std::path::Path,
    contents: &[u8],
    mode: u32,
    mut sync_directory: F,
) -> Result<()>
where
    F: FnMut(&std::path::Path) -> Result<()>,
{
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let temp = sibling_temp(path)?;
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .with_context(|| format!("create DNS temp {}", temp.display()))?;
        file.write_all(contents).context("write DNS temp")?;
        file.sync_all().context("sync DNS temp")?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))
            .context("set DNS temp permissions")?;
        std::fs::rename(&temp, path).with_context(|| {
            format!("rename DNS temp {} over {}", temp.display(), path.display())
        })?;
        sync_directory(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(any(test, target_os = "linux"))]
fn atomic_symlink(path: &std::path::Path, target: &std::path::Path) -> Result<()> {
    let temp = sibling_temp(path)?;
    let result = (|| -> Result<()> {
        std::os::unix::fs::symlink(target, &temp).with_context(|| {
            format!(
                "create DNS symlink {} -> {}",
                temp.display(),
                target.display()
            )
        })?;
        std::fs::rename(&temp, path).with_context(|| {
            format!(
                "rename DNS symlink {} over {}",
                temp.display(),
                path.display()
            )
        })?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(target_os = "linux")]
fn run_firewall(command: &FirewallCommand) -> Result<()> {
    let (status, _stdout, stderr) = run_bounded_firewall_process_with_input(
        command.program,
        &command.args,
        command.stdin.as_deref(),
    )
    .with_context(|| format!("run {} {}", command.program, command.args.join(" ")))?;
    if status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&stderr);
    Err(anyhow::anyhow!(
        "{} {} failed: {}",
        command.program,
        command.args.join(" "),
        stderr.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_state::{
        HostStateJournalV2, OperationRecord, OperationState, OwnedResource, OwnerIdentity,
        JOURNAL_SCHEMA_VERSION,
    };
    use std::cell::{Cell, RefCell};

    fn endpoint(ip: &str, port: u16, protocol: EndpointProtocol) -> AllowedEndpoint {
        AllowedEndpoint {
            address: SocketAddrV4::new(ip.parse().unwrap(), port),
            protocol,
        }
    }

    fn identity() -> KillSwitchIdentity {
        KillSwitchIdentity::from_parts(
            SessionId::from_bytes([0x11; 16]),
            FirewallChainToken::from_bytes([0x22; 10]),
            FirewallChainToken::from_bytes([0x33; 10]),
            FirewallBackend::IptablesNft,
        )
        .unwrap()
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
        panic!("firewall runner left live descendant pid {pid}");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_firewall_subprocess_timeout_kills_group_reaps_and_closes_inherited_pipes() {
        let args = vec![
            "-c".to_string(),
            // The background child inherits both pipes. Killing only the
            // direct shell would leave the old blocking readers stuck until
            // `sleep` exits; group SIGKILL must make this return promptly.
            "trap '' TERM; sleep 5 & wait".to_string(),
        ];
        let started = std::time::Instant::now();
        let error = run_bounded_firewall_subprocess(
            "/bin/sh",
            &args,
            std::time::Duration::from_millis(80),
            128,
            128,
        )
        .expect_err("hanging firewall process group must time out");
        assert!(error.to_string().contains("timed out"));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "runner waited on a pipe-holding descendant: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_firewall_subprocess_kills_successful_childs_pipe_holder() {
        let args = vec![
            "-c".to_string(),
            // The direct shell exits successfully while `sleep` keeps its
            // inherited stdout/stderr descriptors open. The nonblocking drain
            // must stop after the shell is reaped instead of waiting for EOF.
            "sleep 5 & printf '%s\\n' \"$!\"".to_string(),
        ];
        let started = std::time::Instant::now();
        let output = run_bounded_firewall_subprocess(
            "/bin/sh",
            &args,
            std::time::Duration::from_secs(2),
            128,
            128,
        )
        .unwrap();
        assert!(output.status.success());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "runner waited for descendant EOF: {:?}",
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
    fn bounded_firewall_subprocess_rejects_incomplete_unread_inherited_stdin() {
        let pid_path = std::env::temp_dir().join(format!(
            "shadowpipe-firewall-stdin-holder-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let args = vec![
            "-c".to_string(),
            // The direct shell exits successfully while an escaped background
            // child retains the unread stdin descriptor. A large restore-sized
            // payload fills even a small pipe; the writer must stop when the
            // direct child is reaped rather than wait for descendant EOF/read.
            format!(
                "sleep 5 <&0 >/dev/null 2>&1 & printf '%s\\n' \"$!\" > '{}'",
                pid_path.display()
            ),
        ];
        let input = vec![b'x'; 1024 * 1024];
        let started = std::time::Instant::now();
        let error = run_bounded_firewall_subprocess_with_input(
            "/bin/sh",
            &args,
            Some(&input),
            std::time::Duration::from_secs(2),
            128,
            128,
        )
        .expect_err("a successful child that did not consume its complete ruleset must fail");
        assert!(
            error.to_string().contains("stdin"),
            "unexpected error: {error:#}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "runner waited for an unread inherited stdin pipe: {:?}",
            started.elapsed()
        );
        let pid: libc::pid_t = std::fs::read_to_string(&pid_path)
            .expect("firewall stdin-holder fixture did not publish its pid")
            .trim()
            .parse()
            .expect("firewall stdin-holder fixture published an invalid pid");
        let _ = std::fs::remove_file(pid_path);
        #[cfg(target_os = "linux")]
        assert_linux_process_not_running(pid);
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: pid came from the fixture's `$!`; cleanup is best-effort.
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_firewall_subprocess_sterilizes_privileged_helper_environment() {
        let args = vec![
            "-c".to_string(),
            "test \"$0\" = /bin/sh && \
             test \"$PATH\" = /usr/sbin:/usr/bin:/sbin:/bin && \
             test \"$LC_ALL\" = C && \
             test -z \"${LD_PRELOAD+x}\" && \
             test -z \"${XTABLES_LIBDIR+x}\" && \
             test -z \"${BASH_ENV+x}\""
                .to_string(),
        ];
        let output = run_bounded_firewall_subprocess(
            "/bin/sh",
            &args,
            std::time::Duration::from_secs(2),
            128,
            128,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "sterile firewall helper rejected its environment: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_firewall_resolver_rejects_writable_canonical_ancestor() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let nonce = rand::random::<u64>();
        let unsafe_root = std::env::temp_dir().join(format!(
            "shadowpipe-firewall-unsafe-helper-{}-{nonce}",
            std::process::id()
        ));
        let secure_root = std::path::Path::new("/root").join(format!(
            ".shadowpipe-firewall-secure-helper-{}-{nonce}",
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

        let result = trusted_linux_firewall_executable(candidate.to_str().unwrap());
        std::fs::remove_dir_all(&secure_root).unwrap();
        std::fs::remove_dir_all(&unsafe_root).unwrap();
        assert!(
            result.is_err(),
            "firewall resolver accepted a helper below a writable canonical ancestor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_firewall_subprocess_drains_but_retains_only_configured_limits() {
        let args = vec![
            "-c".to_string(),
            "i=0; while [ $i -lt 2000 ]; do printf 0123456789; printf abcdefghij >&2; i=$((i+1)); done"
                .to_string(),
        ];
        let output = run_bounded_firewall_subprocess(
            "/bin/sh",
            &args,
            std::time::Duration::from_secs(2),
            127,
            131,
        )
        .unwrap();
        assert!(output.status.success());
        assert!(output.stdout_overflow);
        assert!(output.stderr_overflow);
        assert_eq!(output.stdout.len(), 127);
        assert_eq!(output.stderr.len(), 131);
    }

    fn exact_snapshot(
        tun_iface: &str,
        endpoints: &[AllowedEndpoint],
        identity: KillSwitchIdentity,
    ) -> FirewallSnapshot {
        let mut snapshot = FirewallSnapshot {
            ipv4_backend: identity.backend(),
            ipv6_backend: identity.backend(),
            ipv4_output: Vec::new(),
            ipv4_chain: Vec::new(),
            ipv4_other: Vec::new(),
            ipv6_output: Vec::new(),
            ipv6_chain: Vec::new(),
            ipv6_other: Vec::new(),
            ipv4_nft_filter: (identity.backend() == FirewallBackend::IptablesNft)
                .then(|| NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv4)),
            ipv6_nft_filter: (identity.backend() == FirewallBackend::IptablesNft)
                .then(|| NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv6)),
        };
        for command in killswitch_install_commands(tun_iface, endpoints, identity) {
            let Some(specification) = component_listing_spec(&command) else {
                continue;
            };
            let output_rule = specification.get(1).is_some_and(|chain| chain == "OUTPUT");
            match (command.program, output_rule) {
                ("iptables", true) => snapshot.ipv4_output.push(specification),
                ("iptables", false) => snapshot.ipv4_chain.push(specification),
                ("ip6tables", true) => snapshot.ipv6_output.push(specification),
                ("ip6tables", false) => snapshot.ipv6_chain.push(specification),
                (program, _) => panic!("unexpected firewall program {program}"),
            }
        }
        snapshot
    }

    fn empty_firewall_snapshot(
        identity: KillSwitchIdentity,
        nft_filter_tables: Option<(NftFilterTableSnapshot, NftFilterTableSnapshot)>,
    ) -> FirewallSnapshot {
        FirewallSnapshot::from_full_listings(
            identity,
            identity.backend(),
            identity.backend(),
            vec![argv(&["-P", "OUTPUT", "ACCEPT"])],
            vec![argv(&["-P", "OUTPUT", "ACCEPT"])],
            nft_filter_tables,
        )
    }

    fn resources(
        identity: KillSwitchIdentity,
        endpoints: &[AllowedEndpoint],
    ) -> Vec<FirewallEndpointResource> {
        endpoint_journal_snapshot(identity, &endpoints.iter().copied().collect())
    }

    fn base_resources(identity: KillSwitchIdentity) -> Vec<FirewallResource> {
        vec![
            identity.ipv4_journal_resource(),
            identity.ipv6_journal_resource(),
        ]
    }

    fn absent_before_install_base_resources(identity: KillSwitchIdentity) -> Vec<FirewallResource> {
        vec![
            identity.ipv4_journal_resource_with_origin(FirewallTableOrigin::AbsentBeforeInstall),
            identity.ipv6_journal_resource_with_origin(FirewallTableOrigin::AbsentBeforeInstall),
        ]
    }

    fn preexisting_table_absent_output_resources(
        identity: KillSwitchIdentity,
    ) -> Vec<FirewallResource> {
        vec![
            identity.ipv4_journal_resource_with_lifecycle(
                FirewallTableOrigin::Preexisting,
                FirewallOutputChainOrigin::AbsentBeforeInstall,
            ),
            identity.ipv6_journal_resource_with_lifecycle(
                FirewallTableOrigin::Preexisting,
                FirewallOutputChainOrigin::AbsentBeforeInstall,
            ),
        ]
    }

    fn exact_compat_shells() -> (NftFilterTableSnapshot, NftFilterTableSnapshot) {
        parse_nft_filter_tables(
            r#"{"nftables":[
                {"metainfo":{"version":"1.1.6","release_name":"test","json_schema_version":1}},
                {"table":{"family":"ip","name":"filter","handle":1}},
                {"chain":{"family":"ip","table":"filter","name":"OUTPUT","handle":3,"type":"filter","hook":"output","prio":0,"policy":"accept"}},
                {"table":{"family":"ip6","name":"filter","handle":2}},
                {"chain":{"family":"ip6","table":"filter","name":"OUTPUT","handle":3,"type":"filter","hook":"output","prio":0,"policy":"accept"}}
            ]}"#,
        )
        .unwrap()
    }

    #[derive(Clone, Debug)]
    struct SimulatedFirewall {
        identity: KillSwitchIdentity,
        components: BTreeSet<FirewallComponentKey>,
        executed: Vec<FirewallCommand>,
        ipv4_nft_filter: Option<NftFilterTableSnapshot>,
        ipv6_nft_filter: Option<NftFilterTableSnapshot>,
    }

    impl SimulatedFirewall {
        fn full(
            tun_iface: &str,
            endpoints: &[AllowedEndpoint],
            identity: KillSwitchIdentity,
        ) -> Self {
            let components = killswitch_install_commands(tun_iface, endpoints, identity)
                .into_iter()
                .map(|command| FirewallComponentKey {
                    program: command.program,
                    specification: component_listing_spec(&command).unwrap(),
                })
                .collect();
            Self {
                identity,
                components,
                executed: Vec::new(),
                ipv4_nft_filter: (identity.backend() == FirewallBackend::IptablesNft)
                    .then(|| NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv4)),
                ipv6_nft_filter: (identity.backend() == FirewallBackend::IptablesNft)
                    .then(|| NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv6)),
            }
        }

        fn from_components(
            identity: KillSwitchIdentity,
            components: impl IntoIterator<Item = FirewallComponentKey>,
        ) -> Self {
            Self {
                identity,
                components: components.into_iter().collect(),
                executed: Vec::new(),
                ipv4_nft_filter: (identity.backend() == FirewallBackend::IptablesNft)
                    .then(|| NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv4)),
                ipv6_nft_filter: (identity.backend() == FirewallBackend::IptablesNft)
                    .then(|| NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv6)),
            }
        }

        fn snapshot(&self) -> FirewallSnapshot {
            let mut ipv4_rules = vec![
                argv(&["-P", "INPUT", "ACCEPT"]),
                argv(&["-A", "OUTPUT", "-j", "FOREIGN_UNRELATED"]),
            ];
            let mut ipv6_rules = vec![argv(&["-P", "INPUT", "ACCEPT"])];
            for component in &self.components {
                match component.program {
                    "iptables" => ipv4_rules.push(component.specification.clone()),
                    "ip6tables" => ipv6_rules.push(component.specification.clone()),
                    program => panic!("unexpected simulated firewall program {program}"),
                }
            }
            FirewallSnapshot::from_full_listings(
                self.identity,
                self.identity.backend(),
                self.identity.backend(),
                ipv4_rules,
                ipv6_rules,
                match (&self.ipv4_nft_filter, &self.ipv6_nft_filter) {
                    (Some(ipv4), Some(ipv6)) => Some((ipv4.clone(), ipv6.clone())),
                    (None, None) => None,
                    _ => panic!("simulated nft family census is incomplete"),
                },
            )
        }

        fn key_for_delete(command: &FirewallCommand) -> Result<FirewallComponentKey> {
            let mut specification = command.args.clone();
            anyhow::ensure!(specification.first().is_some_and(|arg| arg == "-w"));
            specification.remove(0);
            match specification.first().map(String::as_str) {
                Some("-D") => specification[0] = "-A".to_string(),
                Some("-X") => specification[0] = "-N".to_string(),
                operation => anyhow::bail!(
                    "simulator refuses non-exact teardown operation {:?}",
                    operation
                ),
            }
            Ok(FirewallComponentKey {
                program: command.program,
                specification,
            })
        }

        fn execute(&mut self, command: &FirewallCommand) -> Result<()> {
            assert!(!command.args.iter().any(|argument| argument == "-F"));
            if matches!(command.program, "iptables-restore" | "ip6tables-restore") {
                let program = if command.program == "iptables-restore" {
                    "iptables"
                } else {
                    "ip6tables"
                };
                let script = std::str::from_utf8(
                    command
                        .stdin
                        .as_deref()
                        .context("atomic restore lacks stdin")?,
                )?;
                let mut keys = Vec::new();
                for line in script.lines() {
                    if matches!(line, "*filter" | "COMMIT") {
                        continue;
                    }
                    let delete = FirewallCommand {
                        program,
                        args: std::iter::once("-w".to_string())
                            .chain(line.split_ascii_whitespace().map(str::to_string))
                            .collect(),
                        stdin: None,
                    };
                    keys.push(Self::key_for_delete(&delete)?);
                }
                anyhow::ensure!(
                    keys.iter().all(|key| self.components.contains(key)),
                    "atomic simulated release referenced an absent component"
                );
                for key in keys {
                    self.components.remove(&key);
                }
                self.executed.push(command.clone());
                return Ok(());
            }
            if command.program == "nft" {
                let family = command.args.get(2).map(String::as_str);
                let table = match family {
                    Some("ip") => &mut self.ipv4_nft_filter,
                    Some("ip6") => &mut self.ipv6_nft_filter,
                    _ => anyhow::bail!("simulator received unknown nft family"),
                };
                anyhow::ensure!(table
                    .as_ref()
                    .is_some_and(NftFilterTableSnapshot::is_present));
                match command.args.get(1).map(String::as_str) {
                    Some("table") => {
                        *table = Some(NftFilterTableSnapshot::absent(match family {
                            Some("ip") => AddressFamily::Ipv4,
                            Some("ip6") => AddressFamily::Ipv6,
                            _ => unreachable!(),
                        }));
                    }
                    Some("chain") => {
                        table.as_mut().unwrap().objects.retain(|entry| {
                            entry
                                .get("chain")
                                .and_then(serde_json::Value::as_object)
                                .and_then(|chain| chain.get("name"))
                                .and_then(serde_json::Value::as_str)
                                != Some("OUTPUT")
                        });
                    }
                    operation => anyhow::bail!("unknown simulated nft delete {operation:?}"),
                }
                self.executed.push(command.clone());
                return Ok(());
            }
            let key = Self::key_for_delete(command)?;
            anyhow::ensure!(
                self.components.remove(&key),
                "exact simulated component was already absent"
            );
            self.executed.push(command.clone());
            Ok(())
        }

        fn insert_install(&mut self, command: &FirewallCommand) {
            self.components.insert(FirewallComponentKey {
                program: command.program,
                specification: component_listing_spec(command).unwrap(),
            });
        }
    }

    fn prepare_simulated(
        firewall: &RefCell<SimulatedFirewall>,
        base: &[FirewallResource],
        endpoints: &[FirewallEndpointResource],
    ) -> PreparedKillSwitchRecovery {
        let identity = firewall.borrow().identity;
        PreparedKillSwitchRecovery::prepare_with("sptun0", identity, base, endpoints, || {
            Ok(firewall.borrow().snapshot())
        })
        .unwrap()
    }

    fn converge_endpoint_simulated(
        prepared: &mut PreparedKillSwitchRecovery,
        firewall: &RefCell<SimulatedFirewall>,
        resource: &FirewallEndpointResource,
    ) -> std::result::Result<(), KillSwitchConvergeError> {
        prepared.converge_endpoint_absent_with(
            resource,
            || Ok(firewall.borrow().snapshot()),
            |command| firewall.borrow_mut().execute(command),
        )
    }

    fn converge_base_simulated(
        prepared: &mut PreparedKillSwitchRecovery,
        firewall: &RefCell<SimulatedFirewall>,
        resource: &FirewallResource,
    ) -> std::result::Result<(), KillSwitchConvergeError> {
        prepared.converge_base_absent_with(
            resource,
            || Ok(firewall.borrow().snapshot()),
            |command| firewall.borrow_mut().execute(command),
        )
    }

    fn has_owner_comment(command: &FirewallCommand, owner: &str) -> bool {
        command
            .args
            .windows(2)
            .any(|pair| pair[0] == "--comment" && pair[1] == owner)
    }

    #[test]
    fn random_identity_names_are_bounded_distinct_and_journalable() {
        let mut sessions = BTreeSet::new();
        let mut chain_names = BTreeSet::new();
        for _ in 0..64 {
            let identity = KillSwitchIdentity::generate(FirewallBackend::IptablesNft).unwrap();
            let ipv4_chain = identity.ipv4_chain();
            let ipv6_chain = identity.ipv6_chain();
            assert!(ipv4_chain.starts_with("SP4_"));
            assert!(ipv6_chain.starts_with("SP6_"));
            assert!(ipv4_chain.len() <= 28 && ipv6_chain.len() <= 28);
            assert_ne!(identity.ipv4_chain_token(), identity.ipv6_chain_token());
            assert_eq!(identity.owner_comment(), identity.session_id().owner_tag());
            assert!(identity
                .owner_comment()
                .ends_with(&identity.session_id().to_hex()));
            assert!(sessions.insert(identity.session_id().to_hex()));
            assert!(chain_names.insert(ipv4_chain.clone()));
            assert!(chain_names.insert(ipv6_chain.clone()));

            let ipv4 = identity.ipv4_journal_resource();
            let ipv6 = identity.ipv6_journal_resource();
            assert_eq!(ipv4.chain_name(), ipv4_chain);
            assert_eq!(ipv6.chain_name(), ipv6_chain);
            assert_eq!(ipv4.backend, identity.backend());
            assert_eq!(ipv6.backend, identity.backend());
            assert_eq!(ipv4.expected_rule_count, IPV4_STATIC_FIREWALL_RULE_COUNT);
            assert_eq!(ipv6.expected_rule_count, IPV6_STATIC_FIREWALL_RULE_COUNT);
        }
    }

    #[test]
    fn v3_static_table_origin_and_endpoint_resources_validate_and_round_trip() {
        let identity = identity();
        let endpoints = BTreeSet::from([
            endpoint("203.0.113.9", 8443, EndpointProtocol::Udp),
            endpoint("203.0.113.7", 443, EndpointProtocol::Tcp),
        ]);
        let guard = KillSwitch {
            active: false,
            identity,
            tun_iface: "sptun0".to_string(),
            endpoints,
            base_resources: [
                identity.ipv4_journal_resource(),
                identity.ipv6_journal_resource(),
            ],
        };
        let [ipv4, ipv6] = guard.journal_resources();
        assert_eq!(ipv4.expected_rule_count, IPV4_STATIC_FIREWALL_RULE_COUNT);
        assert_eq!(ipv6.expected_rule_count, IPV6_STATIC_FIREWALL_RULE_COUNT);
        let endpoint_resources = guard.journal_endpoint_resources();
        assert_eq!(endpoint_resources.len(), 2);
        assert_eq!(
            endpoint_resources
                .iter()
                .map(|resource| (resource.address, resource.port, resource.transport))
                .collect::<Vec<_>>(),
            vec![
                ("203.0.113.7".parse().unwrap(), 443, FirewallTransport::Tcp),
                ("203.0.113.9".parse().unwrap(), 8443, FirewallTransport::Udp),
            ]
        );

        let mut operations = vec![
            OperationRecord {
                id: 1,
                state: OperationState::Applied,
                resource: OwnedResource::Firewall(ipv4),
            },
            OperationRecord {
                id: 2,
                state: OperationState::Applied,
                resource: OwnedResource::Firewall(ipv6),
            },
        ];
        operations.extend(
            endpoint_resources
                .into_iter()
                .enumerate()
                .map(|(index, resource)| OperationRecord {
                    id: u32::try_from(index + 3).unwrap(),
                    state: OperationState::Applied,
                    resource: OwnedResource::FirewallEndpoint(resource),
                }),
        );
        let mut journal = HostStateJournalV2::new(
            OwnerIdentity {
                session_id: identity.session_id(),
                boot_id: None,
                uid: 1000,
                pid: 1,
                pid_start_ticks: None,
                network_namespace: None,
                mount_namespace: None,
            },
            operations,
        )
        .unwrap();
        journal
            .transition_phase(crate::host_state::JournalPhase::Active)
            .unwrap();
        assert_eq!(journal.schema_version, JOURNAL_SCHEMA_VERSION);
        let encoded = serde_json::to_vec(&journal).unwrap();
        let decoded: HostStateJournalV2 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, journal);
        decoded.validate().unwrap();
    }

    #[test]
    fn install_is_fail_closed_ordered_deduplicated_and_fully_commented() {
        let identity = identity();
        let repeated = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let rules = killswitch_install_commands("sptun0", &[repeated, repeated], identity);
        let owner = identity.owner_comment();
        assert_eq!(rules.first().unwrap().program, "ip6tables");
        assert_eq!(
            rules.first().unwrap().args,
            argv(&["-w", "-N", &identity.ipv6_chain()])
        );
        assert_eq!(rules.last().unwrap().program, "iptables");
        assert!(rules.last().unwrap().args.contains(&"OUTPUT".to_string()));
        assert!(rules.last().unwrap().args.contains(&identity.ipv4_chain()));
        assert_eq!(rules[rules.len() - 2].program, "ip6tables");
        assert!(rules[rules.len() - 2].args.contains(&identity.ipv6_chain()));
        let ipv4_drop_idx = rules
            .iter()
            .rposition(|command| {
                command.program == "iptables" && command.args.contains(&"DROP".to_string())
            })
            .unwrap();
        assert_eq!(ipv4_drop_idx, rules.len() - 3);
        for command in &rules {
            assert_eq!(command.args.first().map(String::as_str), Some("-w"));
            if !command.args.contains(&"-N".to_string()) {
                assert!(
                    has_owner_comment(command, &owner),
                    "every owned rule and OUTPUT jump needs the full session marker: {command:?}"
                );
            }
        }
        let flat: Vec<String> = rules
            .iter()
            .flat_map(|command| command.args.iter().cloned())
            .collect();
        assert!(flat.contains(&"lo".to_string()), "loopback allowed");
        assert!(flat.contains(&"sptun0".to_string()), "tunnel iface allowed");
        assert!(flat.contains(&"203.0.113.7/32".to_string()));
        assert!(flat.contains(&"443".to_string()));
        assert!(flat.contains(&"tcp".to_string()));
        assert!(!flat.iter().any(|s| s == "ESTABLISHED,RELATED"));
        let endpoint_rule_count = rules
            .iter()
            .filter(|command| {
                command.args.contains(&"203.0.113.7/32".to_string())
                    && command.args.contains(&"443".to_string())
            })
            .count();
        assert_eq!(endpoint_rule_count, 1);
    }

    #[test]
    fn inverse_preserves_wait_and_comments_and_never_flushes() {
        let identity = identity();
        let endpoint = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let install = killswitch_install_commands("sptun0", &[endpoint], identity);
        for command in &install {
            let undo = firewall_undo(command).unwrap();
            assert_eq!(undo.args.first().map(String::as_str), Some("-w"));
            assert!(!undo.args.iter().any(|argument| argument == "-F"));
            if !command.args.contains(&"-N".to_string()) {
                assert!(has_owner_comment(&undo, &identity.owner_comment()));
            }
        }

        let teardown = killswitch_teardown_commands("sptun0", &[endpoint], identity).unwrap();
        assert!(teardown.iter().all(|command| command.args[0] == "-w"));
        assert!(teardown
            .iter()
            .all(|command| !command.args.iter().any(|argument| argument == "-F")));
        assert_eq!(teardown[0].program, "iptables");
        assert_eq!(teardown[0].args[1], "-D");
        assert_eq!(teardown[0].args[2], identity.ipv4_chain());
        assert!(teardown[0].args.contains(&"203.0.113.7/32".to_string()));
        assert_eq!(teardown[1].program, "iptables");
        assert_eq!(teardown[1].args[1], "-D");
        assert_eq!(teardown[1].args[2], "OUTPUT");
        assert_eq!(teardown[2].program, "ip6tables");
        assert_eq!(teardown[2].args[1], "-D");
        assert_eq!(teardown[2].args[2], "OUTPUT");
        let first_delete_chain = teardown
            .iter()
            .position(|command| command.args[1] == "-X")
            .unwrap();
        assert!(
            first_delete_chain > 2,
            "endpoint and both jumps precede chain deletion"
        );
    }

    #[test]
    fn exact_snapshot_yields_exact_ordered_teardown() {
        let identity = identity();
        let endpoints = [
            endpoint("1.1.1.1", 443, EndpointProtocol::Tcp),
            endpoint("2.2.2.2", 8443, EndpointProtocol::Udp),
        ];
        let mut snapshot = exact_snapshot("sptun0", &endpoints, identity);
        snapshot
            .ipv4_output
            .push(argv(&["-A", "OUTPUT", "-j", "FOREIGN_UNRELATED"]));
        let resources = resources(identity, &endpoints);
        let inspections = killswitch_inspection_commands(identity);
        assert_eq!(inspections.len(), 2);
        assert!(inspections.iter().all(|command| {
            command.args[0] == "-w"
                && command.args[1..] == ["-t", "filter", "-S"]
                && !command
                    .args
                    .iter()
                    .any(|argument| matches!(argument.as_str(), "-A" | "-D" | "-F" | "-X"))
        }));
        assert_eq!(inspections[0].program, "iptables");
        assert_eq!(inspections[1].program, "ip6tables");
        let teardown = verify_teardown_snapshot("sptun0", &resources, identity, &snapshot).unwrap();
        assert!(teardown[0].args.contains(&"1.1.1.1/32".to_string()));
        assert!(teardown[1].args.contains(&"2.2.2.2/32".to_string()));
        assert!(teardown[..2]
            .iter()
            .all(|command| command.args[1] == "-D" && command.args[2] != "OUTPUT"));
        assert_eq!(teardown[2].program, "iptables");
        assert_eq!(&teardown[2].args[1..3], ["-D", "OUTPUT"]);
        assert_eq!(teardown[3].program, "ip6tables");
        assert_eq!(&teardown[3].args[1..3], ["-D", "OUTPUT"]);
        assert!(teardown
            .iter()
            .all(|command| command.args[0] == "-w" && !command.args.contains(&"-F".into())));
        assert_eq!(
            teardown
                .iter()
                .filter(|command| command.args[1] == "-X")
                .count(),
            2
        );
        assert!(teardown
            .iter()
            .filter(|command| command.args[1] == "-D")
            .all(|command| has_owner_comment(command, &identity.owner_comment())));
    }

    #[test]
    fn prepared_recovery_enforces_endpoint_then_base_order_replay_and_membership() {
        let identity = identity();
        let endpoints = [
            endpoint("203.0.113.7", 443, EndpointProtocol::Tcp),
            endpoint("203.0.113.9", 8443, EndpointProtocol::Udp),
        ];
        let endpoint_resources = resources(identity, &endpoints);
        let base = base_resources(identity);
        let firewall = RefCell::new(SimulatedFirewall::full("sptun0", &endpoints, identity));
        let mut prepared = prepare_simulated(&firewall, &base, &endpoint_resources);
        assert!(prepared
            .endpoint_observations()
            .iter()
            .all(|(_, kind)| *kind == ResourceObservationKind::ExactOwnedPresent));
        assert!(prepared
            .base_observations()
            .iter()
            .all(|(_, kind)| *kind == ResourceObservationKind::ExactOwnedPresent));
        assert_eq!(
            PreparedResourceGroup::observe(
                &prepared,
                &OwnedResource::FirewallEndpoint(endpoint_resources[0].clone())
            ),
            Some(ResourceObservationKind::ExactOwnedPresent)
        );

        let inspections = Cell::new(0usize);
        assert!(prepared
            .converge_base_absent_with(
                &base[0],
                || {
                    inspections.set(inspections.get() + 1);
                    Ok(firewall.borrow().snapshot())
                },
                |_| panic!("out-of-order base reached mutation"),
            )
            .is_err());
        assert!(prepared
            .converge_endpoint_absent_with(
                &endpoint_resources[1],
                || {
                    inspections.set(inspections.get() + 1);
                    Ok(firewall.borrow().snapshot())
                },
                |_| panic!("out-of-order endpoint reached mutation"),
            )
            .is_err());
        let foreign =
            identity.endpoint_journal_resource(endpoint("192.0.2.99", 9443, EndpointProtocol::Tcp));
        assert!(prepared
            .converge_endpoint_absent_with(
                &foreign,
                || {
                    inspections.set(inspections.get() + 1);
                    Ok(firewall.borrow().snapshot())
                },
                |_| panic!("foreign endpoint reached mutation"),
            )
            .is_err());
        assert_eq!(inspections.get(), 0);

        converge_endpoint_simulated(&mut prepared, &firewall, &endpoint_resources[0]).unwrap();
        let after_first = firewall.borrow().executed.len();
        assert!(
            converge_endpoint_simulated(&mut prepared, &firewall, &endpoint_resources[0]).is_err()
        );
        assert_eq!(firewall.borrow().executed.len(), after_first);
        converge_endpoint_simulated(&mut prepared, &firewall, &endpoint_resources[1]).unwrap();
        converge_base_simulated(&mut prepared, &firewall, &base[0]).unwrap();
        converge_base_simulated(&mut prepared, &firewall, &base[1]).unwrap();
        assert!(firewall.borrow().components.is_empty());
        assert!(firewall.borrow().executed.iter().all(|command| {
            command.args.first().is_some_and(|arg| arg == "-w")
                && !command.args.iter().any(|arg| arg == "-F")
        }));
    }

    #[test]
    fn every_authorized_partial_component_lattice_is_recoverable() {
        let identity = identity();
        let endpoints = [
            endpoint("203.0.113.7", 443, EndpointProtocol::Tcp),
            endpoint("203.0.113.9", 8443, EndpointProtocol::Udp),
        ];
        let endpoint_resources = resources(identity, &endpoints);
        let base = base_resources(identity);
        let full = SimulatedFirewall::full("sptun0", &endpoints, identity);
        let all_components: Vec<_> = full.components.iter().cloned().collect();
        assert_eq!(all_components.len(), 11);

        let endpoint_keys: Vec<_> = endpoints
            .iter()
            .map(|endpoint| {
                let command = endpoint_rule("-A", None, identity, *endpoint);
                FirewallComponentKey {
                    program: command.program,
                    specification: component_listing_spec(&command).unwrap(),
                }
            })
            .collect();
        let base_install = killswitch_install_commands("sptun0", &[], identity);
        let base_keys = |program| {
            base_install
                .iter()
                .filter(|command| command.program == program)
                .map(|command| FirewallComponentKey {
                    program,
                    specification: component_listing_spec(command).unwrap(),
                })
                .collect::<BTreeSet<_>>()
        };
        let ipv4_base_keys = base_keys("iptables");
        let ipv6_base_keys = base_keys("ip6tables");

        for mask in 0usize..(1usize << all_components.len()) {
            let selected: Vec<_> = all_components
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1usize << index) != 0)
                .map(|(_, component)| component.clone())
                .collect();
            let selected_set: BTreeSet<_> = selected.iter().cloned().collect();
            let firewall = RefCell::new(SimulatedFirewall::from_components(identity, selected));
            let mut prepared = prepare_simulated(&firewall, &base, &endpoint_resources);

            for (index, resource) in endpoint_resources.iter().enumerate() {
                let expected = if selected_set.contains(&endpoint_keys[index]) {
                    ResourceObservationKind::ExactOwnedPresent
                } else {
                    ResourceObservationKind::Absent
                };
                assert_eq!(
                    prepared.endpoint_observation(resource),
                    Some(expected),
                    "endpoint observation for lattice mask {mask:#x}"
                );
            }
            for (index, (resource, keys)) in
                [(&base[0], &ipv4_base_keys), (&base[1], &ipv6_base_keys)]
                    .into_iter()
                    .enumerate()
            {
                let expected = if selected_set.iter().any(|key| keys.contains(key)) {
                    ResourceObservationKind::ExactOwnedPresent
                } else {
                    ResourceObservationKind::Absent
                };
                assert_eq!(
                    prepared.base_observation(resource),
                    Some(expected),
                    "base {index} observation for lattice mask {mask:#x}"
                );
            }

            for resource in &endpoint_resources {
                converge_endpoint_simulated(&mut prepared, &firewall, resource).unwrap();
            }
            for resource in &base {
                converge_base_simulated(&mut prepared, &firewall, resource).unwrap();
            }
            assert!(
                firewall.borrow().components.is_empty(),
                "lattice mask {mask:#x} retained components"
            );
            assert_eq!(
                firewall.borrow().executed.len(),
                endpoint_keys
                    .iter()
                    .filter(|key| selected_set.contains(*key))
                    .count()
                    + usize::from(selected_set.iter().any(|key| ipv4_base_keys.contains(key)))
                    + usize::from(selected_set.iter().any(|key| ipv6_base_keys.contains(key))),
                "lattice mask {mask:#x} did not collapse each family into one atomic commit"
            );
        }
    }

    #[test]
    fn fault_after_every_release_transaction_is_retryable_and_never_partially_unhooks() {
        let identity = identity();
        let endpoints = [
            endpoint("203.0.113.7", 443, EndpointProtocol::Tcp),
            endpoint("203.0.113.9", 8443, EndpointProtocol::Udp),
        ];
        let endpoint_resources = resources(identity, &endpoints);
        let base = base_resources(identity);
        let base_install = killswitch_install_commands("sptun0", &[], identity);
        let family_keys = |program| {
            base_install
                .iter()
                .filter(|command| command.program == program)
                .map(|command| FirewallComponentKey {
                    program,
                    specification: component_listing_spec(command).unwrap(),
                })
                .collect::<BTreeSet<_>>()
        };
        let ipv4_keys = family_keys("iptables");
        let ipv6_keys = family_keys("ip6tables");
        let hook_key = |program: &'static str, keys: &BTreeSet<FirewallComponentKey>| {
            keys.iter()
                .find(|key| {
                    key.program == program
                        && key
                            .specification
                            .get(1)
                            .is_some_and(|chain| chain == "OUTPUT")
                })
                .unwrap()
                .clone()
        };
        let ipv4_hook = hook_key("iptables", &ipv4_keys);
        let ipv6_hook = hook_key("ip6tables", &ipv6_keys);
        // Two endpoint deletes plus one atomic commit per address family.
        let total_transactions = endpoints.len() + 2;

        for fail_at in 0..total_transactions {
            let firewall = RefCell::new(SimulatedFirewall::full("sptun0", &endpoints, identity));
            let mut prepared = prepare_simulated(&firewall, &base, &endpoint_resources);
            let call = Cell::new(0usize);
            let injected = Cell::new(false);

            for resource in &endpoint_resources {
                loop {
                    let result = prepared.converge_endpoint_absent_with(
                        resource,
                        || Ok(firewall.borrow().snapshot()),
                        |command| {
                            firewall.borrow_mut().execute(command)?;
                            let current = call.get();
                            call.set(current + 1);
                            if current == fail_at && !injected.replace(true) {
                                anyhow::bail!("injected failure after endpoint delete")
                            }
                            Ok(())
                        },
                    );
                    if result.is_ok() {
                        break;
                    }
                    assert!(matches!(
                        result,
                        Err(KillSwitchConvergeError::Operational { .. })
                    ));
                    assert!(injected.get());
                    let current = &firewall.borrow().components;
                    for (keys, hook) in [(&ipv4_keys, &ipv4_hook), (&ipv6_keys, &ipv6_hook)] {
                        let remaining = current.iter().any(|key| keys.contains(key));
                        assert!(
                            !remaining || current.contains(hook),
                            "a failed transaction left family internals without its OUTPUT hook"
                        );
                    }
                }
            }
            for resource in &base {
                loop {
                    let result = prepared.converge_base_absent_with(
                        resource,
                        || Ok(firewall.borrow().snapshot()),
                        |command| {
                            firewall.borrow_mut().execute(command)?;
                            let current = call.get();
                            call.set(current + 1);
                            if current == fail_at && !injected.replace(true) {
                                anyhow::bail!("injected failure after base delete")
                            }
                            Ok(())
                        },
                    );
                    if result.is_ok() {
                        break;
                    }
                    assert!(matches!(
                        result,
                        Err(KillSwitchConvergeError::Operational { .. })
                    ));
                    assert!(injected.get());
                    let current = &firewall.borrow().components;
                    for (keys, hook) in [(&ipv4_keys, &ipv4_hook), (&ipv6_keys, &ipv6_hook)] {
                        let remaining = current.iter().any(|key| keys.contains(key));
                        assert!(
                            !remaining || current.contains(hook),
                            "atomic family release exposed a partial unhooked state"
                        );
                    }
                }
            }
            assert!(injected.get(), "failure {fail_at} was not reached");
            assert_eq!(call.get(), total_transactions);
            assert!(firewall.borrow().components.is_empty());
            assert_eq!(
                firewall
                    .borrow()
                    .executed
                    .iter()
                    .filter(|command| command.program.ends_with("tables-restore"))
                    .count(),
                2
            );
        }
    }

    #[test]
    fn preflight_and_late_census_reject_unknown_duplicate_modified_and_reappeared_state() {
        let identity = identity();
        let endpoints = [endpoint("203.0.113.7", 443, EndpointProtocol::Tcp)];
        let endpoint_resources = resources(identity, &endpoints);
        let base = base_resources(identity);
        let exact = SimulatedFirewall::full("sptun0", &endpoints, identity).snapshot();

        let mut unknown = exact.clone();
        unknown.ipv4_chain.push(argv(&[
            "-A",
            &identity.ipv4_chain(),
            "-m",
            "comment",
            "--comment",
            &identity.owner_comment(),
            "-j",
            "ACCEPT",
        ]));
        let conflict = PreparedKillSwitchRecovery::prepare_with(
            "sptun0",
            identity,
            &base,
            &endpoint_resources,
            || Ok(unknown.clone()),
        );
        assert!(matches!(
            conflict,
            Err(KillSwitchPrepareError::Conflict { .. })
        ));

        let mut duplicate = exact.clone();
        duplicate.ipv4_chain.push(duplicate.ipv4_chain[0].clone());
        assert!(matches!(
            PreparedKillSwitchRecovery::prepare_with(
                "sptun0",
                identity,
                &base,
                &endpoint_resources,
                || Ok(duplicate.clone()),
            ),
            Err(KillSwitchPrepareError::Conflict { .. })
        ));

        let mut modified = exact.clone();
        let modified_endpoint_rule = modified
            .ipv4_chain
            .iter_mut()
            .find(|rule| rule.iter().any(|part| part == "203.0.113.7/32"))
            .unwrap();
        *modified_endpoint_rule
            .iter_mut()
            .find(|part| part.as_str() == identity.owner_comment())
            .unwrap() = "shadowpipe:ffffffffffffffffffffffffffffffff".to_string();
        assert!(matches!(
            PreparedKillSwitchRecovery::prepare_with(
                "sptun0",
                identity,
                &base,
                &endpoint_resources,
                || Ok(modified.clone()),
            ),
            Err(KillSwitchPrepareError::Conflict { .. })
        ));

        let calls = Cell::new(0usize);
        let bracket_race = PreparedKillSwitchRecovery::prepare_with(
            "sptun0",
            identity,
            &base,
            &endpoint_resources,
            || {
                let call = calls.get();
                calls.set(call + 1);
                Ok(if call == 0 {
                    exact.clone()
                } else {
                    let mut changed = exact.clone();
                    changed.ipv4_other.push(argv(&["-N", "FOREIGN_NEW"]));
                    changed
                })
            },
        );
        assert!(matches!(
            bracket_race,
            Err(KillSwitchPrepareError::Conflict { .. })
        ));
        let operational = PreparedKillSwitchRecovery::prepare_with(
            "sptun0",
            identity,
            &base,
            &endpoint_resources,
            || anyhow::bail!("injected ruleset read failure"),
        );
        assert!(matches!(
            operational,
            Err(KillSwitchPrepareError::Operational { .. })
        ));

        let endpoint_install = endpoint_rule("-A", None, identity, endpoints[0]);
        let mut initially_absent = SimulatedFirewall::full("sptun0", &[], identity);
        initially_absent.components.remove(&FirewallComponentKey {
            program: endpoint_install.program,
            specification: component_listing_spec(&endpoint_install).unwrap(),
        });
        let firewall = RefCell::new(initially_absent);
        let mut prepared = prepare_simulated(&firewall, &base, &endpoint_resources);
        assert_eq!(
            prepared.endpoint_observation(&endpoint_resources[0]),
            Some(ResourceObservationKind::Absent)
        );
        firewall.borrow_mut().insert_install(&endpoint_install);
        converge_endpoint_simulated(&mut prepared, &firewall, &endpoint_resources[0]).unwrap();
        firewall.borrow_mut().insert_install(&endpoint_install);
        let before_base = firewall.borrow().executed.len();
        let late = converge_base_simulated(&mut prepared, &firewall, &base[0]);
        assert!(matches!(
            late,
            Err(KillSwitchConvergeError::Conflict { .. })
        ));
        assert_eq!(firewall.borrow().executed.len(), before_base);
    }

    #[test]
    fn removed_journal_groups_are_excluded_while_remaining_groups_recover() {
        let identity = identity();
        let endpoint = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let endpoint_resource = identity.endpoint_journal_resource(endpoint);
        let base = base_resources(identity);
        let full = SimulatedFirewall::full("sptun0", &[endpoint], identity);
        let endpoint_key = {
            let install = endpoint_rule("-A", None, identity, endpoint);
            FirewallComponentKey {
                program: install.program,
                specification: component_listing_spec(&install).unwrap(),
            }
        };
        let ipv6_only: Vec<_> = full
            .components
            .iter()
            .filter(|key| key.program == "ip6tables")
            .cloned()
            .collect();
        let firewall = RefCell::new(SimulatedFirewall::from_components(identity, ipv6_only));
        let mut prepared = prepare_simulated(&firewall, &base[1..], &[]);
        assert_eq!(
            prepared.base_observation(&base[1]),
            Some(ResourceObservationKind::ExactOwnedPresent)
        );
        converge_base_simulated(&mut prepared, &firewall, &base[1]).unwrap();
        assert!(firewall.borrow().components.is_empty());

        let endpoint_only = RefCell::new(SimulatedFirewall::from_components(
            identity,
            [endpoint_key.clone()],
        ));
        let mut prepared = prepare_simulated(
            &endpoint_only,
            &[],
            std::slice::from_ref(&endpoint_resource),
        );
        assert_eq!(
            prepared.endpoint_observation(&endpoint_resource),
            Some(ResourceObservationKind::ExactOwnedPresent)
        );
        converge_endpoint_simulated(&mut prepared, &endpoint_only, &endpoint_resource).unwrap();
        assert!(endpoint_only.borrow().components.is_empty());

        let stale_removed_base = RefCell::new(SimulatedFirewall::from_components(
            identity,
            full.components
                .iter()
                .filter(|key| key.program == "iptables" && *key != &endpoint_key)
                .cloned(),
        ));
        let conflict =
            PreparedKillSwitchRecovery::prepare_with("sptun0", identity, &[], &[], || {
                Ok(stale_removed_base.borrow().snapshot())
            });
        assert!(matches!(
            conflict,
            Err(KillSwitchPrepareError::Conflict { .. })
        ));
    }

    #[test]
    fn different_boot_firewall_recovery_is_observation_only_across_late_reappearance() {
        let identity = identity();
        let endpoint = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let endpoint_resource = identity.endpoint_journal_resource(endpoint);
        let firewall = RefCell::new(SimulatedFirewall::from_components(identity, []));
        let mut prepared = PreparedKillSwitchRecovery::prepare_with_boot_scope(
            "sptun0",
            identity,
            &base_resources(identity),
            std::slice::from_ref(&endpoint_resource),
            false,
            || Ok(firewall.borrow().snapshot()),
        )
        .unwrap();
        assert_eq!(
            prepared.endpoint_observation(&endpoint_resource),
            Some(ResourceObservationKind::Absent)
        );

        // A reboot may also change the iptables alternatives backend. Volatile
        // old rules cannot survive that boot, so two complete all-absent
        // snapshots remain sufficient proof and must not block DNS recovery.
        let mut drifted_empty = firewall.borrow().snapshot();
        drifted_empty.ipv4_backend = FirewallBackend::IptablesLegacy;
        drifted_empty.ipv6_backend = FirewallBackend::IptablesLegacy;
        let drifted = PreparedKillSwitchRecovery::prepare_with_boot_scope(
            "sptun0",
            identity,
            &base_resources(identity),
            std::slice::from_ref(&endpoint_resource),
            false,
            || Ok(drifted_empty.clone()),
        )
        .unwrap();
        let drifted_endpoint_observations = drifted.endpoint_observations();
        let drifted_base_observations = drifted.base_observations();
        assert!(drifted_endpoint_observations
            .iter()
            .map(|(_, observation)| observation)
            .chain(
                drifted_base_observations
                    .iter()
                    .map(|(_, observation)| observation),
            )
            .all(|observation| *observation == ResourceObservationKind::Absent));
        assert!(matches!(
            PreparedKillSwitchRecovery::prepare_with_boot_scope(
                "sptun0",
                identity,
                &base_resources(identity),
                std::slice::from_ref(&endpoint_resource),
                true,
                || Ok(drifted_empty.clone()),
            ),
            Err(KillSwitchPrepareError::Conflict { .. })
        ));

        firewall
            .borrow_mut()
            .insert_install(&endpoint_rule("-A", None, identity, endpoint));
        let result = converge_endpoint_simulated(&mut prepared, &firewall, &endpoint_resource);
        assert!(matches!(
            result,
            Err(KillSwitchConvergeError::Conflict { .. })
        ));
        assert!(
            firewall.borrow().executed.is_empty(),
            "different-boot recovery must never expose an old-journal delete"
        );

        let exact = RefCell::new(SimulatedFirewall::full("sptun0", &[endpoint], identity));
        let prepared = PreparedKillSwitchRecovery::prepare_with_boot_scope(
            "sptun0",
            identity,
            &base_resources(identity),
            std::slice::from_ref(&endpoint_resource),
            false,
            || Ok(exact.borrow().snapshot()),
        )
        .unwrap();
        assert_eq!(
            prepared.endpoint_observation(&endpoint_resource),
            Some(ResourceObservationKind::Conflict)
        );
        assert!(prepared
            .base_observations()
            .iter()
            .all(|(_, observation)| *observation == ResourceObservationKind::Conflict));

        let mut drifted_exact = exact.borrow().snapshot();
        drifted_exact.ipv4_backend = FirewallBackend::IptablesLegacy;
        drifted_exact.ipv6_backend = FirewallBackend::IptablesLegacy;
        let drifted_present = PreparedKillSwitchRecovery::prepare_with_boot_scope(
            "sptun0",
            identity,
            &base_resources(identity),
            std::slice::from_ref(&endpoint_resource),
            false,
            || Ok(drifted_exact.clone()),
        )
        .unwrap();
        let drifted_present_endpoint_observations = drifted_present.endpoint_observations();
        let drifted_present_base_observations = drifted_present.base_observations();
        assert!(drifted_present_endpoint_observations
            .iter()
            .map(|(_, observation)| observation)
            .chain(
                drifted_present_base_observations
                    .iter()
                    .map(|(_, observation)| observation),
            )
            .all(|observation| *observation == ResourceObservationKind::Conflict));
    }

    #[test]
    fn invalid_resources_fail_before_inspection_and_delete_requires_post_absence() {
        let identity = identity();
        let endpoint = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let endpoint_resource = identity.endpoint_journal_resource(endpoint);
        let base = base_resources(identity);
        let inspections = Cell::new(0usize);
        let duplicate_base = vec![base[0].clone(), base[0].clone()];
        let result = PreparedKillSwitchRecovery::prepare_with(
            "sptun0",
            identity,
            &duplicate_base,
            std::slice::from_ref(&endpoint_resource),
            || {
                inspections.set(inspections.get() + 1);
                anyhow::bail!("invalid resources must fail before inspection")
            },
        );
        assert!(matches!(
            result,
            Err(KillSwitchPrepareError::Conflict { .. })
        ));
        let duplicate_endpoints = vec![endpoint_resource.clone(), endpoint_resource.clone()];
        let result = PreparedKillSwitchRecovery::prepare_with(
            "sptun0",
            identity,
            &base,
            &duplicate_endpoints,
            || {
                inspections.set(inspections.get() + 1);
                anyhow::bail!("invalid resources must fail before inspection")
            },
        );
        assert!(matches!(
            result,
            Err(KillSwitchPrepareError::Conflict { .. })
        ));
        assert_eq!(inspections.get(), 0);

        let firewall = RefCell::new(SimulatedFirewall::full("sptun0", &[endpoint], identity));
        let mut prepared =
            prepare_simulated(&firewall, &base, std::slice::from_ref(&endpoint_resource));
        let mutations = Cell::new(0usize);
        let result = prepared.converge_endpoint_absent_with(
            &endpoint_resource,
            || Ok(firewall.borrow().snapshot()),
            |_| {
                mutations.set(mutations.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(KillSwitchConvergeError::Conflict { .. })
        ));
        assert_eq!(mutations.get(), 1);
    }

    #[test]
    fn extra_missing_modified_foreign_and_backend_state_conflict() {
        let identity = identity();
        let endpoints = [endpoint("203.0.113.7", 443, EndpointProtocol::Tcp)];
        let endpoint_resources = resources(identity, &endpoints);
        let exact = exact_snapshot("sptun0", &endpoints, identity);

        let mut extra = exact.clone();
        extra.ipv4_chain.push(argv(&[
            "-A",
            &identity.ipv4_chain(),
            "-m",
            "comment",
            "--comment",
            &identity.owner_comment(),
            "-j",
            "ACCEPT",
        ]));
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &extra),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let mut missing = exact.clone();
        missing.ipv6_chain.pop();
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &missing),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let mut missing_endpoint = exact.clone();
        missing_endpoint
            .ipv4_chain
            .retain(|rule| !rule.iter().any(|argument| argument == "203.0.113.7/32"));
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &missing_endpoint),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let mut modified = exact.clone();
        let destination = modified
            .ipv4_chain
            .iter_mut()
            .flatten()
            .find(|argument| argument.as_str() == "203.0.113.7/32")
            .unwrap();
        *destination = "203.0.113.8/32".to_string();
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &modified),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let mut wrong_comment = exact.clone();
        let endpoint_rule = wrong_comment
            .ipv4_chain
            .iter_mut()
            .find(|rule| rule.iter().any(|argument| argument == "203.0.113.7/32"))
            .unwrap();
        let comment = endpoint_rule
            .iter_mut()
            .find(|argument| argument.as_str() == identity.owner_comment())
            .unwrap();
        *comment = "shadowpipe:ffffffffffffffffffffffffffffffff".to_string();
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &wrong_comment),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let mut duplicate_endpoint = exact.clone();
        let exact_endpoint_rule = duplicate_endpoint
            .ipv4_chain
            .iter()
            .find(|rule| rule.iter().any(|argument| argument == "203.0.113.7/32"))
            .unwrap()
            .clone();
        duplicate_endpoint.ipv4_chain.push(exact_endpoint_rule);
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &duplicate_endpoint),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let mut foreign = exact.clone();
        foreign.ipv4_chain.push(argv(&[
            "-A",
            &identity.ipv4_chain(),
            "-j",
            "FOREIGN_TARGET",
        ]));
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &foreign),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let mut duplicate_jump = exact.clone();
        duplicate_jump
            .ipv4_output
            .push(duplicate_jump.ipv4_output[0].clone());
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &duplicate_jump),
            Err(KillSwitchConflict::JumpMismatch { .. })
        ));

        let mut wrong_backend = exact;
        wrong_backend.ipv6_backend = FirewallBackend::IptablesLegacy;
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &endpoint_resources, identity, &wrong_backend),
            Err(KillSwitchConflict::BackendMismatch {
                program: "ip6tables",
                ..
            })
        ));
    }

    #[test]
    fn any_conflict_performs_zero_teardown_mutations() {
        let identity = identity();
        let endpoints = [endpoint("203.0.113.7", 443, EndpointProtocol::Tcp)];
        let endpoint_resources = resources(identity, &endpoints);
        let mut conflict = exact_snapshot("sptun0", &endpoints, identity);
        conflict.ipv4_chain.push(argv(&[
            "-A",
            &identity.ipv4_chain(),
            "-j",
            "FOREIGN_TARGET",
        ]));
        let mut mutations = 0;
        let result = teardown_with(
            "sptun0",
            &endpoint_resources,
            identity,
            || Ok(conflict),
            |_| {
                mutations += 1;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(mutations, 0);
    }

    #[test]
    fn typed_endpoint_resource_conflicts_are_rejected_before_mutation() {
        let identity = identity();
        let endpoints = [endpoint("203.0.113.7", 443, EndpointProtocol::Tcp)];
        let snapshot = exact_snapshot("sptun0", &endpoints, identity);
        let exact = resources(identity, &endpoints);

        let mut duplicate = exact.clone();
        duplicate.push(exact[0].clone());
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &duplicate, identity, &snapshot),
            Err(KillSwitchConflict::EndpointResourceConflict { .. })
        ));

        let mut wrong_backend = exact.clone();
        wrong_backend[0].backend = FirewallBackend::IptablesLegacy;
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &wrong_backend, identity, &snapshot),
            Err(KillSwitchConflict::BackendMismatch {
                program: "iptables",
                ..
            })
        ));

        let mut wrong_chain = exact.clone();
        wrong_chain[0].chain_token = FirewallChainToken::from_bytes([0x44; 10]);
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &wrong_chain, identity, &snapshot),
            Err(KillSwitchConflict::EndpointResourceConflict { .. })
        ));

        let mut changed_tuple = exact.clone();
        changed_tuple[0].port = 8443;
        assert!(matches!(
            verify_teardown_snapshot("sptun0", &changed_tuple, identity, &snapshot),
            Err(KillSwitchConflict::ChainRulesMismatch { .. })
        ));

        let over_limit = vec![exact[0].clone(); MAX_KILLSWITCH_ENDPOINTS + 1];
        assert!(matches!(
            killswitch_recovery_commands("sptun0", identity, &over_limit),
            Err(KillSwitchConflict::EndpointResourceLimit { .. })
        ));

        let mut mutations = 0;
        assert!(teardown_with(
            "sptun0",
            &duplicate,
            identity,
            || Ok(snapshot),
            |_| {
                mutations += 1;
                Ok(())
            },
        )
        .is_err());
        assert_eq!(mutations, 0);
    }

    #[test]
    fn dynamic_set_tracks_only_successful_exact_commented_updates() {
        let identity = identity();
        let existing = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let staged = endpoint("203.0.113.9", 8443, EndpointProtocol::Udp);
        let rejected = endpoint("203.0.113.10", 9443, EndpointProtocol::Tcp);
        let mut endpoints = BTreeSet::from([existing]);
        let mut commands = Vec::new();
        assert_eq!(
            endpoint_journal_snapshot(identity, &endpoints),
            resources(identity, &[existing])
        );

        assert!(
            allow_endpoint_with(identity, &mut endpoints, staged, |command| {
                commands.push(command.clone());
                Ok(())
            })
            .unwrap()
        );
        assert!(endpoints.contains(&staged));
        let staged_resources = endpoint_journal_snapshot(identity, &endpoints);
        assert_eq!(staged_resources, resources(identity, &[existing, staged]));
        assert_eq!(staged_resources[1].family, AddressFamily::Ipv4);
        assert_eq!(staged_resources[1].backend, identity.backend());
        assert_eq!(staged_resources[1].chain_token, identity.ipv4_chain_token());
        assert_eq!(staged_resources[1].transport, FirewallTransport::Udp);
        assert_eq!(staged_resources[1].port, 8443);
        let allow = commands.last().unwrap();
        assert_eq!(allow.args[0], "-w");
        assert_eq!(allow.args[1], "-I");
        assert_eq!(allow.args[2], identity.ipv4_chain());
        assert_eq!(allow.args[3], "1");
        assert!(allow.args.contains(&"203.0.113.9/32".to_string()));
        assert!(allow.args.contains(&"udp".to_string()));
        assert!(allow.args.contains(&"8443".to_string()));
        assert!(has_owner_comment(allow, &identity.owner_comment()));

        let command_count = commands.len();
        assert!(
            !allow_endpoint_with(identity, &mut endpoints, staged, |command| {
                commands.push(command.clone());
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(commands.len(), command_count);

        let rejected_result = allow_endpoint_with(identity, &mut endpoints, rejected, |_| {
            anyhow::bail!("injected add failure")
        });
        assert!(rejected_result.is_err());
        assert!(!endpoints.contains(&rejected));
        assert_eq!(
            endpoint_journal_snapshot(identity, &endpoints),
            staged_resources
        );

        let failed_remove = deny_endpoint_with(identity, &mut endpoints, staged, |_| {
            anyhow::bail!("injected delete failure")
        });
        assert!(failed_remove.is_err());
        assert!(endpoints.contains(&staged));
        assert_eq!(
            endpoint_journal_snapshot(identity, &endpoints),
            staged_resources
        );

        assert!(
            deny_endpoint_with(identity, &mut endpoints, staged, |command| {
                commands.push(command.clone());
                Ok(())
            })
            .unwrap()
        );
        assert!(!endpoints.contains(&staged));
        let deny = commands.last().unwrap();
        assert_eq!(deny.args[0], "-w");
        assert_eq!(deny.args[1], "-D");
        assert!(deny.args.contains(&"203.0.113.9/32".to_string()));
        assert!(has_owner_comment(deny, &identity.owner_comment()));
        assert_eq!(
            endpoint_journal_snapshot(identity, &endpoints),
            resources(identity, &[existing])
        );
        assert_eq!(
            identity.ipv4_journal_resource().expected_rule_count,
            IPV4_STATIC_FIREWALL_RULE_COUNT
        );
    }

    #[test]
    fn endpoint_capacity_preflight_is_side_effect_free_and_wal_ready() {
        let identity = identity();
        let existing = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let mut guard = KillSwitch {
            active: false,
            identity,
            tun_iface: "sptun0".to_string(),
            endpoints: BTreeSet::from([existing]),
            base_resources: [
                identity.ipv4_journal_resource(),
                identity.ipv6_journal_resource(),
            ],
        };
        assert!(!guard.can_allow_endpoint(existing).unwrap());
        let candidate = endpoint("203.0.113.8", 8443, EndpointProtocol::Udp);
        assert!(guard.can_allow_endpoint(candidate).unwrap());
        assert!(!guard.endpoints.contains(&candidate));

        guard.endpoints.clear();
        for port in 1..=u16::try_from(MAX_KILLSWITCH_ENDPOINTS).unwrap() {
            guard
                .endpoints
                .insert(endpoint("198.51.100.1", port, EndpointProtocol::Tcp));
        }
        let before = guard.endpoints.clone();
        assert!(guard
            .can_allow_endpoint(endpoint("198.51.100.2", 9443, EndpointProtocol::Tcp))
            .is_err());
        assert_eq!(guard.endpoints, before);
        assert!(guard
            .can_allow_endpoint(endpoint("198.51.100.2", 0, EndpointProtocol::Tcp))
            .is_err());
        assert_eq!(guard.endpoints, before);
    }

    #[test]
    fn quoted_listing_comments_parse_to_the_exact_owned_jump() {
        let identity = identity();
        let listing = format!(
            "-A OUTPUT -m comment --comment \"{}\" -j {}\n",
            identity.owner_comment(),
            identity.ipv4_chain()
        );
        let parsed = parse_iptables_listing("iptables", &listing).unwrap();
        let install = killswitch_install_commands(
            "sptun0",
            &[endpoint("203.0.113.7", 443, EndpointProtocol::Tcp)],
            identity,
        );
        let expected = install
            .iter()
            .filter(|command| command.program == "iptables")
            .filter_map(inspection_rule_spec)
            .find(|rule| rule.get(1).is_some_and(|chain| chain == "OUTPUT"))
            .unwrap();
        assert_eq!(parsed, vec![expected]);
    }

    #[test]
    fn nft_ruleset_parser_accepts_only_exact_empty_compatibility_shells() {
        let absent = parse_nft_filter_tables(
            r#"{"nftables":[{"metainfo":{"version":"1","release_name":"x","json_schema_version":1}}]}"#,
        )
        .unwrap();
        assert_eq!(
            classify_empty_nft_compat_shell(&absent.0),
            EmptyCompatShell::Absent
        );
        assert_eq!(
            classify_empty_nft_compat_shell(&absent.1),
            EmptyCompatShell::Absent
        );

        let (ipv4, ipv6) = exact_compat_shells();
        assert_eq!(
            classify_empty_nft_compat_shell(&ipv4),
            EmptyCompatShell::Exact
        );
        assert_eq!(
            classify_empty_nft_compat_shell(&ipv6),
            EmptyCompatShell::Exact
        );
        assert_eq!(
            classify_empty_nft_output_shell(&ipv4),
            EmptyCompatShell::Exact
        );

        let mut drift = ipv4;
        drift.objects.push(serde_json::json!({
            "rule": {
                "family": "ip", "table": "filter", "chain": "OUTPUT", "handle": 9,
                "expr": [{"counter": {"packets": 0, "bytes": 0}}]
            }
        }));
        assert!(matches!(
            classify_empty_nft_compat_shell(&drift),
            EmptyCompatShell::Drift(_)
        ));
        assert!(matches!(
            classify_empty_nft_output_shell(&drift),
            EmptyCompatShell::Drift(_)
        ));

        assert_eq!(
            classify_empty_nft_output_shell(&NftFilterTableSnapshot::synthetic_preexisting(
                AddressFamily::Ipv4
            )),
            EmptyCompatShell::Absent
        );

        assert!(parse_nft_filter_tables(
            r#"{"nftables":[
                {"table":{"family":"ip","name":"filter","handle":1}},
                {"table":{"family":"ip","name":"filter","handle":2}}
            ]}"#
        )
        .is_err());
    }

    #[test]
    fn install_token_binds_stable_pre_wal_table_state_and_rejects_drift() {
        let identity = identity();
        let absent = (
            NftFilterTableSnapshot::absent(AddressFamily::Ipv4),
            NftFilterTableSnapshot::absent(AddressFamily::Ipv6),
        );
        let baseline = empty_firewall_snapshot(identity, Some(absent));
        let token =
            install_token_from_stable_snapshots(identity, baseline.clone(), baseline.clone())
                .unwrap();
        assert_eq!(token.identity(), identity);
        assert_eq!(token.baseline, baseline);
        assert!(token.journal_resources().iter().all(
            |resource| resource.filter_table_origin == FirewallTableOrigin::AbsentBeforeInstall
        ));
        assert!(token.journal_resources().iter().all(|resource| {
            resource.output_chain_origin == FirewallOutputChainOrigin::AbsentBeforeInstall
        }));

        let mut changed = baseline.clone();
        changed
            .ipv4_other
            .push(argv(&["-A", "OUTPUT", "-j", "FOREIGN"]));
        assert!(install_token_from_stable_snapshots(identity, baseline.clone(), changed).is_err());

        let preexisting = empty_firewall_snapshot(identity, Some(exact_compat_shells()));
        let token = install_token_from_stable_snapshots(identity, preexisting.clone(), preexisting)
            .unwrap();
        assert!(token
            .journal_resources()
            .iter()
            .all(|resource| resource.filter_table_origin == FirewallTableOrigin::Preexisting));
        assert!(token.journal_resources().iter().all(|resource| {
            resource.output_chain_origin == FirewallOutputChainOrigin::Preexisting
        }));

        let table_only = empty_firewall_snapshot(
            identity,
            Some((
                NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv4),
                NftFilterTableSnapshot::synthetic_preexisting(AddressFamily::Ipv6),
            )),
        );
        let token =
            install_token_from_stable_snapshots(identity, table_only.clone(), table_only).unwrap();
        assert!(token.journal_resources().iter().all(|resource| {
            resource.filter_table_origin == FirewallTableOrigin::Preexisting
                && resource.output_chain_origin == FirewallOutputChainOrigin::AbsentBeforeInstall
        }));

        let mut collision = baseline.clone();
        collision.ipv4_output.push(argv(&[
            "-A",
            "OUTPUT",
            "-m",
            "comment",
            "--comment",
            &identity.owner_comment(),
            "-j",
            &identity.ipv4_chain(),
        ]));
        assert!(
            install_token_from_stable_snapshots(identity, collision.clone(), collision).is_err()
        );
    }

    #[test]
    fn family_base_release_is_one_atomic_commit_with_output_jump_last() {
        let identity = identity();
        let base = base_resources(identity);
        let firewall = RefCell::new(SimulatedFirewall::full("sptun0", &[], identity));
        let prepared = prepare_simulated(&firewall, &base, &[]);
        let components = prepared.authorized_components().unwrap();
        let ipv4: Vec<_> = components
            .iter()
            .filter(|component| component.slot == PreparedFirewallSlot::Base(0))
            .collect();
        let release = atomic_base_release_command("iptables", &ipv4).unwrap();
        assert_eq!(release.program, "iptables-restore");
        assert_eq!(release.args, argv(&["-w", "5", "--noflush"]));
        let script = std::str::from_utf8(release.stdin.as_deref().unwrap()).unwrap();
        let lines: Vec<_> = script.lines().collect();
        assert_eq!(lines.first(), Some(&"*filter"));
        assert_eq!(lines.last(), Some(&"COMMIT"));
        let jump = lines
            .iter()
            .position(|line| line.starts_with("-D OUTPUT "))
            .unwrap();
        let delete_chain = lines
            .iter()
            .position(|line| line.starts_with("-X SP4_"))
            .unwrap();
        assert!(lines[..jump]
            .iter()
            .filter(|line| line.starts_with("-D "))
            .all(|line| !line.starts_with("-D OUTPUT ")));
        assert!(jump < delete_chain);
        assert!(!lines[jump + 1..delete_chain]
            .iter()
            .any(|line| line.starts_with("-D ")));
    }

    #[test]
    fn absent_before_install_tables_are_deleted_and_post_delete_retry_is_idempotent() {
        let identity = identity();
        let endpoint = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let endpoint_resources = resources(identity, &[endpoint]);
        let base = absent_before_install_base_resources(identity);
        let mut simulated = SimulatedFirewall::full("sptun0", &[endpoint], identity);
        let (ipv4, ipv6) = exact_compat_shells();
        simulated.ipv4_nft_filter = Some(ipv4);
        simulated.ipv6_nft_filter = Some(ipv6);
        let firewall = RefCell::new(simulated);
        let mut prepared = prepare_simulated(&firewall, &base, &endpoint_resources);
        converge_endpoint_simulated(&mut prepared, &firewall, &endpoint_resources[0]).unwrap();

        let injected = Cell::new(false);
        let first = prepared.converge_base_absent_with(
            &base[0],
            || Ok(firewall.borrow().snapshot()),
            |command| {
                firewall.borrow_mut().execute(command)?;
                if command.program == "nft" && !injected.replace(true) {
                    anyhow::bail!("injected crash-equivalent after nft delete commit")
                }
                Ok(())
            },
        );
        assert!(matches!(
            first,
            Err(KillSwitchConvergeError::Operational { .. })
        ));
        assert!(injected.get());
        assert_eq!(
            classify_empty_nft_compat_shell(firewall.borrow().ipv4_nft_filter.as_ref().unwrap()),
            EmptyCompatShell::Absent
        );

        // Same prepared authorization retries without another deletion; this
        // is the exact crash-after-table-delete-before-WAL-ack state.
        converge_base_simulated(&mut prepared, &firewall, &base[0]).unwrap();
        converge_base_simulated(&mut prepared, &firewall, &base[1]).unwrap();
        assert!(firewall.borrow().components.is_empty());
        assert_eq!(
            firewall
                .borrow()
                .executed
                .iter()
                .filter(|command| command.program == "nft")
                .count(),
            2
        );
        assert!(firewall.borrow().executed.iter().all(|command| {
            command.program != "nft"
                || command.args == argv(&["delete", "table", command.args[2].as_str(), "filter"])
        }));
    }

    #[test]
    fn preexisting_or_drifted_tables_are_never_deleted() {
        let identity = identity();
        let endpoint = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let endpoint_resources = resources(identity, &[endpoint]);

        let mut preexisting_firewall = SimulatedFirewall::full("sptun0", &[endpoint], identity);
        let (ipv4, ipv6) = exact_compat_shells();
        preexisting_firewall.ipv4_nft_filter = Some(ipv4.clone());
        preexisting_firewall.ipv6_nft_filter = Some(ipv6);
        let preexisting_firewall = RefCell::new(preexisting_firewall);
        let preexisting = base_resources(identity);
        let mut prepared =
            prepare_simulated(&preexisting_firewall, &preexisting, &endpoint_resources);
        converge_endpoint_simulated(&mut prepared, &preexisting_firewall, &endpoint_resources[0])
            .unwrap();
        for resource in &preexisting {
            converge_base_simulated(&mut prepared, &preexisting_firewall, resource).unwrap();
        }
        assert!(preexisting_firewall
            .borrow()
            .executed
            .iter()
            .all(|command| command.program != "nft"));
        assert!(preexisting_firewall
            .borrow()
            .ipv4_nft_filter
            .as_ref()
            .unwrap()
            .is_present());

        let mut drifted_firewall = SimulatedFirewall::full("sptun0", &[endpoint], identity);
        let mut drifted = ipv4;
        drifted.objects.push(serde_json::json!({
            "chain": {
                "family": "ip", "table": "filter", "name": "FOREIGN", "handle": 99
            }
        }));
        drifted_firewall.ipv4_nft_filter = Some(drifted);
        drifted_firewall.ipv6_nft_filter = Some(exact_compat_shells().1);
        let drifted_firewall = RefCell::new(drifted_firewall);
        let absent = absent_before_install_base_resources(identity);
        let mut prepared = prepare_simulated(&drifted_firewall, &absent, &endpoint_resources);
        converge_endpoint_simulated(&mut prepared, &drifted_firewall, &endpoint_resources[0])
            .unwrap();
        assert!(matches!(
            converge_base_simulated(&mut prepared, &drifted_firewall, &absent[0]),
            Err(KillSwitchConvergeError::Conflict { .. })
        ));
        assert!(drifted_firewall
            .borrow()
            .executed
            .iter()
            .all(|command| command.program != "nft"));
        assert!(drifted_firewall
            .borrow()
            .ipv4_nft_filter
            .as_ref()
            .unwrap()
            .is_present());
    }

    #[test]
    fn session_created_output_shell_is_removed_from_preexisting_foreign_table() {
        let identity = identity();
        let endpoint = endpoint("203.0.113.7", 443, EndpointProtocol::Tcp);
        let endpoint_resources = resources(identity, &[endpoint]);
        let baseline = parse_nft_filter_tables(
            r#"{"nftables":[
                {"table":{"family":"ip","name":"filter","handle":1}},
                {"chain":{"family":"ip","table":"filter","name":"FOREIGN4","handle":2}},
                {"table":{"family":"ip6","name":"filter","handle":3}},
                {"chain":{"family":"ip6","table":"filter","name":"FOREIGN6","handle":4}}
            ]}"#,
        )
        .unwrap();
        let installed = parse_nft_filter_tables(
            r#"{"nftables":[
                {"table":{"family":"ip","name":"filter","handle":1}},
                {"chain":{"family":"ip","table":"filter","name":"FOREIGN4","handle":2}},
                {"chain":{"family":"ip","table":"filter","name":"OUTPUT","handle":5,"type":"filter","hook":"output","prio":0,"policy":"accept"}},
                {"table":{"family":"ip6","name":"filter","handle":3}},
                {"chain":{"family":"ip6","table":"filter","name":"FOREIGN6","handle":4}},
                {"chain":{"family":"ip6","table":"filter","name":"OUTPUT","handle":6,"type":"filter","hook":"output","prio":0,"policy":"accept"}}
            ]}"#,
        )
        .unwrap();
        let mut simulated = SimulatedFirewall::full("sptun0", &[endpoint], identity);
        simulated.ipv4_nft_filter = Some(installed.0);
        simulated.ipv6_nft_filter = Some(installed.1);
        let firewall = RefCell::new(simulated);
        let base = preexisting_table_absent_output_resources(identity);
        let mut prepared = prepare_simulated(&firewall, &base, &endpoint_resources);
        converge_endpoint_simulated(&mut prepared, &firewall, &endpoint_resources[0]).unwrap();
        for resource in &base {
            converge_base_simulated(&mut prepared, &firewall, resource).unwrap();
        }
        let firewall = firewall.borrow();
        assert_eq!(firewall.ipv4_nft_filter.as_ref(), Some(&baseline.0));
        assert_eq!(firewall.ipv6_nft_filter.as_ref(), Some(&baseline.1));
        assert_eq!(
            firewall
                .executed
                .iter()
                .filter(|command| command.program == "nft")
                .count(),
            2
        );
        assert!(firewall
            .executed
            .iter()
            .filter(|command| command.program == "nft")
            .all(
                |command| command.args.get(1).map(String::as_str) == Some("chain")
                    && command.args.last().map(String::as_str) == Some("OUTPUT")
            ));
    }

    #[test]
    fn different_boot_never_spends_old_absent_before_install_table_authority() {
        let identity = identity();
        let base = absent_before_install_base_resources(identity);
        let mut simulated = SimulatedFirewall::from_components(identity, []);
        let (ipv4, ipv6) = exact_compat_shells();
        simulated.ipv4_nft_filter = Some(ipv4);
        simulated.ipv6_nft_filter = Some(ipv6);
        let firewall = RefCell::new(simulated);
        let mut prepared = PreparedKillSwitchRecovery::prepare_with_boot_scope(
            "sptun0",
            identity,
            &base,
            &[],
            false,
            || Ok(firewall.borrow().snapshot()),
        )
        .unwrap();
        for resource in &base {
            converge_base_simulated(&mut prepared, &firewall, resource).unwrap();
        }
        assert!(firewall.borrow().executed.is_empty());
        assert!(firewall
            .borrow()
            .ipv4_nft_filter
            .as_ref()
            .unwrap()
            .is_present());
        assert!(firewall
            .borrow()
            .ipv6_nft_filter
            .as_ref()
            .unwrap()
            .is_present());
    }

    #[test]
    fn backend_detection_is_explicit_and_rejects_unknown_variants() {
        assert_eq!(
            parse_backend_output("iptables", "iptables v1.8.10 (nf_tables)").unwrap(),
            FirewallBackend::IptablesNft
        );
        assert_eq!(
            parse_backend_output("iptables", "iptables v1.8.10 (legacy)").unwrap(),
            FirewallBackend::IptablesLegacy
        );
        assert!(matches!(
            parse_backend_output("iptables", "iptables v1.8.10"),
            Err(KillSwitchConflict::UnknownBackend {
                program: "iptables",
                ..
            })
        ));
    }

    #[test]
    fn killswitch_partial_install_rolls_back_exact_applied_prefix_in_reverse() {
        let install = killswitch_install_commands(
            "sptun0",
            &[endpoint("203.0.113.7", 443, EndpointProtocol::Tcp)],
            identity(),
        );

        for fail_at in 0..install.len() {
            let mut calls = Vec::new();
            let mut call_index = 0;
            let result = apply_firewall_transaction(&install, |command| {
                let current = call_index;
                call_index += 1;
                calls.push(command.clone());
                if current == fail_at {
                    anyhow::bail!("injected firewall failure at command {fail_at}");
                }
                Ok(())
            });

            assert!(result.is_err(), "failure index {fail_at} must propagate");
            assert_eq!(
                &calls[..=fail_at],
                &install[..=fail_at],
                "installation must stop at injected failure {fail_at}"
            );
            let expected_rollback: Vec<_> = install[..fail_at]
                .iter()
                .rev()
                .map(|command| firewall_undo(command).unwrap())
                .collect();
            assert_eq!(
                &calls[fail_at + 1..],
                expected_rollback.as_slice(),
                "only successfully applied commands must be undone, in reverse order"
            );
        }
    }

    #[test]
    fn resolv_conf_pins_each_nameserver() {
        let s = resolv_conf(&["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()]);
        assert!(s.contains("nameserver 1.1.1.1\n"));
        assert!(s.contains("nameserver 9.9.9.9\n"));
        assert!(s.starts_with("# shadowpipe"), "marked as ours for clarity");
    }

    #[test]
    fn dns_guard_atomically_restores_regular_file() {
        let dir = std::env::temp_dir().join(format!(
            "shadowpipe-dns-regular-{}-{}",
            std::process::id(),
            NEXT_CHAIN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("resolv.conf");
        std::fs::write(&path, b"nameserver 192.0.2.53\n").unwrap();
        {
            let _guard = DnsGuard::apply_to_path(&path, &["1.1.1.1".parse().unwrap()]).unwrap();
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                resolv_conf(&["1.1.1.1".parse().unwrap()])
            );
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"nameserver 192.0.2.53\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dns_guard_retains_rollback_state_until_restore_is_verified() {
        let dir = std::env::temp_dir().join(format!(
            "shadowpipe-dns-retry-{}-{}",
            std::process::id(),
            NEXT_CHAIN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("resolv.conf");
        let original = b"nameserver 192.0.2.57\n";
        std::fs::write(&path, original).unwrap();
        let mut guard = DnsGuard::apply_to_path(&path, &["1.1.1.1".parse().unwrap()]).unwrap();

        // A foreign directory at the resolver pathname makes atomic restore
        // fail after the guard has already captured the exact original state.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(guard.try_restore().is_err());
        assert!(
            guard.restore.is_some(),
            "failed restore must retain rollback authority for a safe retry"
        );

        std::fs::remove_dir(&path).unwrap();
        assert!(guard.try_restore().unwrap());
        assert!(guard.restore.is_none());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dns_guard_rolls_back_regular_file_after_post_rename_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "shadowpipe-dns-rollback-regular-{}-{}",
            std::process::id(),
            NEXT_CHAIN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("resolv.conf");
        let original = b"nameserver 192.0.2.55\n";
        std::fs::write(&path, original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let result = DnsGuard::apply_to_path_with(
            &path,
            &["1.1.1.1".parse().unwrap()],
            |publish_path, contents, mode| {
                atomic_write_with_sync(publish_path, contents, mode, |renamed_path| {
                    assert_eq!(
                        std::fs::read(renamed_path).unwrap(),
                        contents,
                        "failure is injected only after rename made pinned DNS visible"
                    );
                    anyhow::bail!("injected DNS parent fsync failure after rename")
                })
            },
        );

        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_file());
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dns_guard_restores_original_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "shadowpipe-dns-symlink-{}-{}",
            std::process::id(),
            NEXT_CHAIN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("real-resolv.conf");
        let path = dir.join("resolv.conf");
        std::fs::write(&target, b"nameserver 192.0.2.54\n").unwrap();
        std::os::unix::fs::symlink("real-resolv.conf", &path).unwrap();
        {
            let _guard = DnsGuard::apply_to_path(&path, &["9.9.9.9".parse().unwrap()]).unwrap();
            assert!(!std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink());
        }
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_link(&path).unwrap(),
            std::path::Path::new("real-resolv.conf")
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"nameserver 192.0.2.54\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dns_guard_rolls_back_symlink_after_post_rename_failure() {
        let dir = std::env::temp_dir().join(format!(
            "shadowpipe-dns-rollback-symlink-{}-{}",
            std::process::id(),
            NEXT_CHAIN_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("real-resolv.conf");
        let path = dir.join("resolv.conf");
        let original_target_contents = b"nameserver 192.0.2.56\n";
        std::fs::write(&target, original_target_contents).unwrap();
        std::os::unix::fs::symlink("real-resolv.conf", &path).unwrap();

        let result = DnsGuard::apply_to_path_with(
            &path,
            &["9.9.9.9".parse().unwrap()],
            |publish_path, contents, mode| {
                atomic_write_with_sync(publish_path, contents, mode, |renamed_path| {
                    assert!(
                        !std::fs::symlink_metadata(renamed_path)
                            .unwrap()
                            .file_type()
                            .is_symlink(),
                        "rename must already have replaced the original symlink"
                    );
                    assert_eq!(std::fs::read(renamed_path).unwrap(), contents);
                    anyhow::bail!("injected DNS parent fsync failure after rename")
                })
            },
        );

        assert!(result.is_err());
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_link(&path).unwrap(),
            std::path::Path::new("real-resolv.conf"),
            "relative symlink target must be restored exactly"
        );
        assert_eq!(std::fs::read(&target).unwrap(), original_target_contents);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
