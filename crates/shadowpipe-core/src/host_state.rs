//! Durable, fail-safe host-state primitives for the Linux full-tunnel client.
//!
//! This module intentionally contains no route, firewall, DNS, TUN, or process
//! mutation. It provides the typed journal, secure persistence, lease, identity
//! capture, and pure recovery planner that a privileged coordinator can build
//! on. Recovery is deliberately two-phase: callers must inspect every pending
//! resource first, then ask [`decide_recovery`] for a complete ordered plan.
//! No removal plan is returned when an observation is missing or conflicts.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::fmt;
#[cfg(any(test, not(unix)))]
use std::fs::OpenOptions;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::{Arc, OnceLock};

/// Hard limit applied before JSON deserialization.
/// Sized to contain every schema-valid `MAX_OPERATIONS` journal, including
/// maximally JSON-escaped Linux interface names, while retaining a strict
/// pre-deserialization allocation bound.
pub const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
/// Version 3 additionally binds each firewall family to the read-only observed
/// lifecycle of its nftables compatibility table.  Version 2 is intentionally
/// rejected: it cannot distinguish a pre-existing `filter` table from one
/// lazily created by this session, so recovery has no authority to remove the
/// otherwise-empty compatibility shell.  Version 1 is likewise unsafe because
/// its mutable aggregate firewall count cannot be interpreted after a crash
/// during endpoint rotation.
pub const JOURNAL_SCHEMA_VERSION: u16 = 3;
pub const MAX_OPERATIONS: usize = 256;
pub const LINUX_MAIN_ROUTE_TABLE: u32 = 254;
pub const SHADOWPIPE_ROUTE_PROTOCOL: u8 = 186;
pub const IPV4_STATIC_FIREWALL_RULE_COUNT: u16 = 4;
pub const IPV6_STATIC_FIREWALL_RULE_COUNT: u16 = 3;
const JOURNAL_MODE: u32 = 0o600;
#[cfg(unix)]
const STATE_DIRECTORY_MODE: u32 = 0o700;

macro_rules! hex_identifier {
    ($name:ident, $length:expr) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            pub fn to_hex(self) -> String {
                hex::encode(self.0)
            }

            fn parse_hex(value: &str) -> Result<Self, String> {
                if value.len() != $length * 2
                    || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(format!(
                        "expected exactly {} hexadecimal characters",
                        $length * 2
                    ));
                }
                let mut bytes = [0u8; $length];
                hex::decode_to_slice(value, &mut bytes)
                    .map_err(|error| format!("invalid hexadecimal identifier: {error}"))?;
                Ok(Self(bytes))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.to_hex())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse_hex(&value).map_err(de::Error::custom)
            }
        }
    };
}

hex_identifier!(SessionId, 16);
hex_identifier!(BootId, 16);
hex_identifier!(FirewallChainToken, 10);
hex_identifier!(Sha256Digest, 32);

impl SessionId {
    /// Generate a non-zero 128-bit identifier directly from the operating
    /// system CSPRNG.
    pub fn generate() -> Result<Self, HostStateError> {
        loop {
            let mut bytes = [0u8; 16];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|error| HostStateError::Entropy(error.to_string()))?;
            if bytes != [0u8; 16] {
                return Ok(Self(bytes));
            }
        }
    }

    /// Full ownership marker used in firewall comments and the TUN alias.
    pub fn owner_tag(self) -> String {
        format!("shadowpipe:{self}")
    }

    /// Fixed, path-component-only name for the resolver exchange object.
    pub fn resolver_exchange_file_name(self) -> String {
        format!(".resolv.conf.shadowpipe.{self}")
    }
}

impl FirewallChainToken {
    pub fn generate() -> Result<Self, HostStateError> {
        loop {
            let mut bytes = [0u8; 10];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|error| HostStateError::Entropy(error.to_string()))?;
            if bytes != [0u8; 10] {
                return Ok(Self(bytes));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerIdentity {
    pub session_id: SessionId,
    pub boot_id: Option<BootId>,
    pub uid: u32,
    pub pid: u32,
    pub pid_start_ticks: Option<u64>,
    pub network_namespace: Option<NamespaceIdentity>,
    pub mount_namespace: Option<NamespaceIdentity>,
}

impl OwnerIdentity {
    /// Capture the strongest owner identity currently available. `/proc`
    /// attributes are optional so hardened or non-Linux environments fail into
    /// an ambiguous recovery decision rather than fabricating liveness proof.
    pub fn capture() -> Result<Self, HostStateError> {
        Self::capture_with_session(SessionId::generate()?)
    }

    pub fn capture_with_session(session_id: SessionId) -> Result<Self, HostStateError> {
        if session_id.as_bytes() == &[0u8; 16] {
            return Err(HostStateError::Entropy(
                "caller-provided session identity is zero".to_string(),
            ));
        }
        Ok(Self {
            session_id,
            boot_id: capture_boot_id(),
            uid: effective_uid(),
            pid: std::process::id(),
            pid_start_ticks: capture_pid_start_ticks(std::process::id()),
            // Namespace membership is per-thread on Linux. `/proc/self` names
            // the thread-group leader and can lie after a caller-thread setns;
            // `thread-self` binds the identity to the thread doing capture.
            network_namespace: capture_namespace_identity("/proc/thread-self/ns/net"),
            mount_namespace: capture_namespace_identity("/proc/thread-self/ns/mnt"),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalPhase {
    Preparing,
    Active,
    Cleaning,
    Conflict,
}

impl JournalPhase {
    pub fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Preparing, Self::Active)
                    | (Self::Preparing, Self::Cleaning)
                    | (Self::Preparing, Self::Conflict)
                    | (Self::Active, Self::Preparing)
                    | (Self::Active, Self::Cleaning)
                    | (Self::Active, Self::Conflict)
                    | (Self::Cleaning, Self::Conflict)
            )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Planned,
    Applied,
    Removed,
}

impl OperationState {
    pub fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Planned, Self::Applied)
                    | (Self::Planned, Self::Removed)
                    | (Self::Applied, Self::Removed)
            )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn matches(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceIdentity {
    pub name: String,
    pub ifindex: u32,
}

impl InterfaceIdentity {
    fn validate(&self) -> Result<(), JournalValidationError> {
        if self.ifindex == 0 {
            return Err(JournalValidationError::new(
                "interface ifindex must be non-zero",
            ));
        }
        if self.name.is_empty()
            || self.name.len() > 15
            || self.name.bytes().any(|byte| byte == 0 || byte == b'/')
        {
            return Err(JournalValidationError::new(
                "interface name must be 1..=15 bytes and contain neither NUL nor '/'",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePurpose {
    SplitDefault,
    EndpointBypass,
    SshBypass,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpPrefix {
    fn validate(&self, family: AddressFamily) -> Result<(), JournalValidationError> {
        let maximum = match family {
            AddressFamily::Ipv4 => 32,
            AddressFamily::Ipv6 => 128,
        };
        if !family.matches(self.address) || self.prefix_len > maximum {
            return Err(JournalValidationError::new(
                "route destination family/prefix length is inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteResource {
    pub purpose: RoutePurpose,
    pub family: AddressFamily,
    pub table: u32,
    pub destination: IpPrefix,
    pub gateway: Option<IpAddr>,
    pub output: InterfaceIdentity,
    pub protocol: u8,
    pub metric: u32,
}

impl RouteResource {
    fn validate(&self) -> Result<(), JournalValidationError> {
        if self.table != LINUX_MAIN_ROUTE_TABLE {
            return Err(JournalValidationError::new(format!(
                "route table must be Linux main table {LINUX_MAIN_ROUTE_TABLE}"
            )));
        }
        if self.protocol != SHADOWPIPE_ROUTE_PROTOCOL {
            return Err(JournalValidationError::new(format!(
                "route protocol must be the reserved ShadowPipe value {SHADOWPIPE_ROUTE_PROTOCOL}"
            )));
        }
        if self.metric == 0 {
            return Err(JournalValidationError::new(
                "owned route metric must be non-zero",
            ));
        }
        self.destination.validate(self.family)?;
        if self
            .gateway
            .is_some_and(|gateway| !self.family.matches(gateway))
        {
            return Err(JournalValidationError::new(
                "route gateway family differs from destination family",
            ));
        }
        self.output.validate()?;
        match self.purpose {
            RoutePurpose::SplitDefault => {
                if self.destination.prefix_len != 1
                    || self.gateway.is_some()
                    || !is_split_default_prefix(self.destination.address)
                {
                    return Err(JournalValidationError::new(
                        "split-default route must be one canonical /1 through an interface without a gateway",
                    ));
                }
            }
            RoutePurpose::EndpointBypass | RoutePurpose::SshBypass => {
                let host_prefix = match self.family {
                    AddressFamily::Ipv4 => 32,
                    AddressFamily::Ipv6 => 128,
                };
                if self.destination.prefix_len != host_prefix {
                    return Err(JournalValidationError::new(
                        "bypass route must be an exact host prefix",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn is_split_default_prefix(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            matches!(octets[0], 0 | 128) && octets[1..] == [0, 0, 0]
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            matches!(octets[0], 0 | 128) && octets[1..] == [0; 15]
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    IptablesNft,
    IptablesLegacy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallTransport {
    Tcp,
    Udp,
}

/// Durable authority for the lifecycle of one family's `filter` table.
///
/// `AbsentBeforeInstall` is deliberately narrower than generic ownership: it
/// authorizes deletion only on the same boot, only through the nft backend,
/// and only after a complete read-only census proves the table is the exact
/// empty compatibility shell left by iptables-nft.  `LegacyUnknown` exists
/// solely so an old v2 JSON object can be deserialized and rejected by the
/// schema-version check instead of being silently upgraded.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallTableOrigin {
    Preexisting,
    AbsentBeforeInstall,
    #[default]
    LegacyUnknown,
}

/// Durable lifecycle authority for the iptables-nft compatibility OUTPUT
/// base chain. A pre-existing `filter` table may still lack this chain, and
/// iptables will lazily create it when the owned jump is inserted.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallOutputChainOrigin {
    Preexisting,
    AbsentBeforeInstall,
    #[default]
    LegacyUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallResource {
    pub family: AddressFamily,
    pub backend: FirewallBackend,
    pub chain_token: FirewallChainToken,
    /// Read-only table state captured before the WAL and before the first
    /// firewall mutation. Missing values deserialize as `LegacyUnknown` only
    /// to make old journals fail closed during validation.
    #[serde(default)]
    pub filter_table_origin: FirewallTableOrigin,
    #[serde(default)]
    pub output_chain_origin: FirewallOutputChainOrigin,
    /// Number of deterministic static rules owned with the chain, including
    /// its exact OUTPUT jump. Dynamic carrier tuples are separate
    /// [`FirewallEndpointResource`] records and never alter this value.
    pub expected_rule_count: u16,
}

impl FirewallResource {
    pub fn chain_name(&self) -> String {
        let prefix = match self.family {
            AddressFamily::Ipv4 => "SP4_",
            AddressFamily::Ipv6 => "SP6_",
        };
        format!("{prefix}{}", self.chain_token)
    }

    fn validate(&self) -> Result<(), JournalValidationError> {
        let expected = match self.family {
            AddressFamily::Ipv4 => IPV4_STATIC_FIREWALL_RULE_COUNT,
            AddressFamily::Ipv6 => IPV6_STATIC_FIREWALL_RULE_COUNT,
        };
        if self.expected_rule_count != expected {
            return Err(JournalValidationError::new(format!(
                "firewall static rule count for {:?} must be {expected}, found {}",
                self.family, self.expected_rule_count
            )));
        }
        if self.chain_token.as_bytes() == &[0u8; 10] {
            return Err(JournalValidationError::new(
                "firewall chain token must be non-zero",
            ));
        }
        match (self.backend, self.filter_table_origin) {
            (_, FirewallTableOrigin::LegacyUnknown) => {
                return Err(JournalValidationError::new(
                    "firewall filter-table origin is missing or legacy-unknown",
                ));
            }
            (FirewallBackend::IptablesLegacy, FirewallTableOrigin::AbsentBeforeInstall) => {
                return Err(JournalValidationError::new(
                    "legacy iptables cannot own nft filter-table lifecycle",
                ));
            }
            _ => {}
        }
        match (self.backend, self.output_chain_origin) {
            (_, FirewallOutputChainOrigin::LegacyUnknown) => {
                return Err(JournalValidationError::new(
                    "firewall OUTPUT-chain origin is missing or legacy-unknown",
                ));
            }
            (FirewallBackend::IptablesLegacy, FirewallOutputChainOrigin::AbsentBeforeInstall) => {
                return Err(JournalValidationError::new(
                    "legacy iptables cannot own nft OUTPUT-chain lifecycle",
                ));
            }
            _ => {}
        }
        if self.filter_table_origin == FirewallTableOrigin::AbsentBeforeInstall
            && self.output_chain_origin != FirewallOutputChainOrigin::AbsentBeforeInstall
        {
            return Err(JournalValidationError::new(
                "an absent-before-install filter table must also have an absent OUTPUT chain",
            ));
        }
        debug_assert!(self.chain_name().len() <= 28);
        Ok(())
    }
}

/// One exact dynamically managed firewall ACCEPT rule. The full rule is
/// recoverable without DNS or policy input: family/backend/chain select the
/// owned chain and address/transport/port select the carrier tuple. The owner
/// comment is derived from the enclosing journal's session identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallEndpointResource {
    pub family: AddressFamily,
    pub backend: FirewallBackend,
    pub chain_token: FirewallChainToken,
    pub address: IpAddr,
    pub transport: FirewallTransport,
    pub port: u16,
}

impl FirewallEndpointResource {
    fn validate(&self) -> Result<(), JournalValidationError> {
        if self.chain_token.as_bytes() == &[0u8; 10] {
            return Err(JournalValidationError::new(
                "firewall endpoint chain token must be non-zero",
            ));
        }
        if !self.family.matches(self.address) {
            return Err(JournalValidationError::new(
                "firewall endpoint address does not match its address family",
            ));
        }
        if self.port == 0 {
            return Err(JournalValidationError::new(
                "firewall endpoint port must be non-zero",
            ));
        }
        Ok(())
    }

    fn chain_key(&self) -> (AddressFamily, FirewallBackend, FirewallChainToken) {
        (self.family, self.backend, self.chain_token)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Regular,
    Symlink,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub link_count: u64,
    pub kind: FileKind,
}

#[cfg(unix)]
impl FileIdentity {
    /// Build an identity from `symlink_metadata`; callers must not pass
    /// metadata obtained by following the resolver symlink.
    pub fn from_symlink_metadata(metadata: &Metadata) -> Result<Self, JournalValidationError> {
        use std::os::unix::fs::MetadataExt;

        let kind = if metadata.file_type().is_file() {
            FileKind::Regular
        } else if metadata.file_type().is_symlink() {
            FileKind::Symlink
        } else {
            return Err(JournalValidationError::new(
                "DNS identity must describe a regular file or symlink",
            ));
        };
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            link_count: metadata.nlink(),
            kind,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverTarget {
    EtcResolvConf,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsResource {
    pub target: ResolverTarget,
    pub original: FileIdentity,
    /// Digest of the original regular-file contents. A symlink is immutable in
    /// place and is instead bound by its inode identity, so it carries `None`.
    pub original_sha256: Option<Sha256Digest>,
    pub pinned: FileIdentity,
    pub pinned_sha256: Sha256Digest,
}

impl DnsResource {
    pub(crate) fn validate(&self) -> Result<(), JournalValidationError> {
        for (label, identity) in [("original", self.original), ("pinned", self.pinned)] {
            if identity.device == 0 || identity.inode == 0 || identity.link_count == 0 {
                return Err(JournalValidationError::new(format!(
                    "DNS {label} identity must have non-zero device, inode, and link count"
                )));
            }
            let expected_type = match identity.kind {
                FileKind::Regular => 0o100000,
                FileKind::Symlink => 0o120000,
            };
            if identity.mode & 0o170000 != expected_type {
                return Err(JournalValidationError::new(format!(
                    "DNS {label} mode does not match its file kind"
                )));
            }
        }
        if self.pinned.kind != FileKind::Regular {
            return Err(JournalValidationError::new(
                "DNS pinned identity must be a regular file",
            ));
        }
        if (self.original.device, self.original.inode) == (self.pinned.device, self.pinned.inode) {
            return Err(JournalValidationError::new(
                "DNS original and pinned identities must be distinct",
            ));
        }
        match (self.original.kind, self.original_sha256) {
            (FileKind::Regular, Some(_)) | (FileKind::Symlink, None) => {}
            (FileKind::Regular, None) => {
                return Err(JournalValidationError::new(
                    "DNS original regular file requires a SHA-256 digest",
                ))
            }
            (FileKind::Symlink, Some(_)) => {
                return Err(JournalValidationError::new(
                    "DNS original symlink must not carry a regular-file digest",
                ))
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunResource {
    pub interface: InterfaceIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "resource",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OwnedResource {
    Route(RouteResource),
    Dns(DnsResource),
    Tun(TunResource),
    Firewall(FirewallResource),
    FirewallEndpoint(FirewallEndpointResource),
}

impl OwnedResource {
    fn validate(&self) -> Result<(), JournalValidationError> {
        match self {
            Self::Route(route) => route.validate(),
            Self::Dns(dns) => dns.validate(),
            Self::Tun(tun) => tun.interface.validate(),
            Self::Firewall(firewall) => firewall.validate(),
            Self::FirewallEndpoint(endpoint) => endpoint.validate(),
        }
    }

    fn removal_rank(&self) -> u8 {
        match self {
            Self::Route(route) if route.purpose == RoutePurpose::SplitDefault => 0,
            Self::Dns(_) => 1,
            Self::Route(_) => 2,
            Self::Tun(_) => 3,
            // Endpoint ACCEPT rules are removed while the fail-closed chain is
            // still hooked. The static rules, OUTPUT jump, and chain itself are
            // deliberately the final firewall recovery resource.
            Self::FirewallEndpoint(_) => 4,
            Self::Firewall(_) => 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub id: u32,
    pub state: OperationState,
    pub resource: OwnedResource,
}

/// Durable journal representation. The historical Rust type name is retained
/// for source compatibility; `schema_version` is authoritative and this build
/// accepts only [`JOURNAL_SCHEMA_VERSION`] (wire schema v3).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostStateJournalV1 {
    pub schema_version: u16,
    pub generation: u64,
    pub phase: JournalPhase,
    pub owner: OwnerIdentity,
    pub operations: Vec<OperationRecord>,
}

pub type HostStateJournalV2 = HostStateJournalV1;

impl HostStateJournalV1 {
    pub fn new(
        owner: OwnerIdentity,
        operations: Vec<OperationRecord>,
    ) -> Result<Self, JournalValidationError> {
        let journal = Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            generation: 1,
            phase: JournalPhase::Preparing,
            owner,
            operations,
        };
        journal.validate()?;
        Ok(journal)
    }

    pub fn validate(&self) -> Result<(), JournalValidationError> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalValidationError::new(format!(
                "unsupported host-state schema version {}",
                self.schema_version
            )));
        }
        if self.generation == 0 {
            return Err(JournalValidationError::new(
                "journal generation must be non-zero",
            ));
        }
        if self.owner.pid == 0 {
            return Err(JournalValidationError::new("owner PID must be non-zero"));
        }
        if self.owner.session_id.as_bytes() == &[0u8; 16] {
            return Err(JournalValidationError::new(
                "owner session identifier must be non-zero",
            ));
        }
        if self.operations.len() > MAX_OPERATIONS {
            return Err(JournalValidationError::new(format!(
                "journal contains {} operations; maximum is {MAX_OPERATIONS}",
                self.operations.len()
            )));
        }

        let mut latest_resource_states = HashMap::with_capacity(self.operations.len());
        let mut dns_count = 0usize;
        let mut tun_count = 0usize;
        let mut firewall_families = HashSet::new();
        let mut live_firewall_chains = HashMap::new();
        let mut live_firewall_endpoints = Vec::new();
        let mut live_route_keys = HashSet::new();
        for (index, operation) in self.operations.iter().enumerate() {
            let expected_id = u32::try_from(index + 1)
                .expect("MAX_OPERATIONS is smaller than the operation identifier range");
            if operation.id != expected_id {
                return Err(JournalValidationError::new(format!(
                    "operation IDs must be contiguous and chronological: expected {expected_id}, found {}",
                    operation.id
                )));
            }
            operation.resource.validate()?;
            if let Some(previous_state) =
                latest_resource_states.insert(&operation.resource, operation.state)
            {
                if previous_state != OperationState::Removed {
                    return Err(JournalValidationError::new(format!(
                        "owned resource recurs at operation {} before its prior record is removed",
                        operation.id
                    )));
                }
            }
            let live = operation.state != OperationState::Removed;
            match &operation.resource {
                OwnedResource::Dns(dns) => {
                    if live {
                        dns_count += 1;
                    }
                    if dns.pinned.uid != self.owner.uid {
                        return Err(JournalValidationError::new(
                            "DNS pinned file owner must match journal owner UID",
                        ));
                    }
                }
                OwnedResource::Tun(_) if live => tun_count += 1,
                OwnedResource::Tun(_) => {}
                OwnedResource::Firewall(firewall) if live => {
                    if !firewall_families.insert(firewall.family) {
                        return Err(JournalValidationError::new(
                            "only one live firewall resource per address family is allowed",
                        ));
                    }
                    live_firewall_chains.insert(
                        (firewall.family, firewall.backend, firewall.chain_token),
                        operation.id,
                    );
                }
                OwnedResource::Firewall(_) => {}
                OwnedResource::FirewallEndpoint(endpoint) if live => {
                    live_firewall_endpoints.push((operation.id, endpoint.chain_key()));
                }
                OwnedResource::Route(route) if live => {
                    let kernel_key = (
                        route.family,
                        route.table,
                        route.destination.clone(),
                        route.gateway,
                        route.output.clone(),
                        route.protocol,
                        route.metric,
                    );
                    if !live_route_keys.insert(kernel_key) {
                        return Err(JournalValidationError::new(
                            "live route resources duplicate one normalized kernel tuple",
                        ));
                    }
                }
                OwnedResource::FirewallEndpoint(_) | OwnedResource::Route(_) => {}
            }
        }
        for (endpoint_operation_id, chain_key) in live_firewall_endpoints {
            let Some(chain_operation_id) = live_firewall_chains.get(&chain_key) else {
                return Err(JournalValidationError::new(
                    "live firewall endpoint requires a matching live base firewall resource",
                ));
            };
            if chain_operation_id >= &endpoint_operation_id {
                return Err(JournalValidationError::new(
                    "base firewall resource must chronologically precede its endpoint records",
                ));
            }
        }
        if dns_count > 1 || tun_count > 1 {
            return Err(JournalValidationError::new(
                "journal permits at most one DNS resource and one TUN resource",
            ));
        }
        if self.phase == JournalPhase::Active
            && self
                .operations
                .iter()
                .any(|operation| operation.state == OperationState::Planned)
        {
            return Err(JournalValidationError::new(
                "active journal cannot contain a planned operation",
            ));
        }
        Ok(())
    }

    /// Validate an append-only, monotonic durable update. Existing operation
    /// identities and resource specifications are immutable: otherwise a
    /// compromised or buggy writer could retarget later cleanup at an object
    /// that was never owned by this session.
    pub fn validate_successor(&self, next: &Self) -> Result<(), JournalValidationError> {
        self.validate()?;
        next.validate()?;
        let expected_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| JournalValidationError::new("journal generation overflow"))?;
        if next.generation != expected_generation {
            return Err(JournalValidationError::new(format!(
                "successor generation must be {expected_generation}, found {}",
                next.generation
            )));
        }
        if next.owner != self.owner {
            return Err(JournalValidationError::new(
                "successor cannot change owner identity",
            ));
        }
        if !self.phase.can_transition_to(next.phase) {
            return Err(JournalValidationError::new(format!(
                "illegal journal phase transition {:?} -> {:?}",
                self.phase, next.phase
            )));
        }
        if next.operations.len() < self.operations.len() {
            // Active checkpoints may discard only already-Removed history and
            // densely renumber the still-live Applied vocabulary. This is the
            // sole compaction form; it cannot retarget or drop a live resource.
            let compacted: Vec<OperationRecord> = self
                .operations
                .iter()
                .filter(|operation| operation.state != OperationState::Removed)
                .enumerate()
                .map(|(index, operation)| OperationRecord {
                    id: u32::try_from(index + 1)
                        .expect("MAX_OPERATIONS fits operation identifiers"),
                    state: operation.state,
                    resource: operation.resource.clone(),
                })
                .collect();
            if self.phase == JournalPhase::Active
                && next.phase == JournalPhase::Active
                && next.operations == compacted
            {
                return Ok(());
            }
            return Err(JournalValidationError::new(
                "successor cannot remove operation records except exact Active compaction of Removed history",
            ));
        }

        for (previous, candidate) in self.operations.iter().zip(&next.operations) {
            if candidate.id != previous.id || candidate.resource != previous.resource {
                return Err(JournalValidationError::new(
                    "successor cannot reorder, replace, or retarget an existing operation",
                ));
            }
            if !previous.state.can_transition_to(candidate.state) {
                return Err(JournalValidationError::new(format!(
                    "illegal operation {} transition {:?} -> {:?}",
                    previous.id, previous.state, candidate.state
                )));
            }

            let state_change_allowed = match (self.phase, next.phase) {
                (JournalPhase::Preparing, JournalPhase::Preparing) => true,
                (JournalPhase::Cleaning, JournalPhase::Cleaning) => {
                    candidate.state == previous.state || candidate.state == OperationState::Removed
                }
                // Every phase edge is a durable checkpoint of its own. Enter
                // Preparing before appending/changing operations and publish
                // Active only after the Applied/Removed acknowledgement was
                // persisted in an earlier Preparing generation. Cleaning and
                // Conflict edges likewise cannot smuggle a state change.
                _ => candidate.state == previous.state,
            };
            if !state_change_allowed {
                return Err(JournalValidationError::new(format!(
                    "operation {} state change is not allowed during phase transition {:?} -> {:?}",
                    previous.id, self.phase, next.phase
                )));
            }
        }

        let appended = &next.operations[self.operations.len()..];
        if !appended.is_empty()
            && !matches!(
                (self.phase, next.phase),
                (JournalPhase::Preparing, JournalPhase::Preparing)
            )
        {
            return Err(JournalValidationError::new(
                "operations may be appended only while remaining in preparing phase",
            ));
        }
        if appended
            .iter()
            .any(|operation| operation.state != OperationState::Planned)
        {
            return Err(JournalValidationError::new(
                "new operations must first be durably recorded as planned",
            ));
        }
        Ok(())
    }

    pub fn transition_phase(&mut self, next: JournalPhase) -> Result<(), TransitionError> {
        if !self.phase.can_transition_to(next) {
            return Err(TransitionError::IllegalPhase {
                from: self.phase,
                to: next,
            });
        }
        if next == JournalPhase::Active
            && self
                .operations
                .iter()
                .any(|operation| operation.state == OperationState::Planned)
        {
            return Err(TransitionError::ActiveWithIncompleteOperations);
        }
        self.phase = next;
        Ok(())
    }

    pub fn transition_operation(
        &mut self,
        operation_id: u32,
        next: OperationState,
    ) -> Result<(), TransitionError> {
        let operation = self
            .operations
            .iter_mut()
            .find(|operation| operation.id == operation_id)
            .ok_or(TransitionError::UnknownOperation(operation_id))?;
        if operation.state == next {
            return Ok(());
        }
        if !operation.state.can_transition_to(next) {
            return Err(TransitionError::IllegalOperation {
                operation_id,
                from: operation.state,
                to: next,
            });
        }
        let phase_allows = match self.phase {
            JournalPhase::Preparing => matches!(
                (operation.state, next),
                (OperationState::Planned, OperationState::Applied)
                    | (OperationState::Planned, OperationState::Removed)
                    | (OperationState::Applied, OperationState::Removed)
            ),
            JournalPhase::Cleaning => next == OperationState::Removed,
            JournalPhase::Active | JournalPhase::Conflict => false,
        };
        if !phase_allows {
            return Err(TransitionError::OperationNotAllowedInPhase {
                operation_id,
                phase: self.phase,
                to: next,
            });
        }
        operation.state = next;
        Ok(())
    }

    pub fn next_generation(&mut self) -> Result<(), TransitionError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(TransitionError::GenerationOverflow)?;
        Ok(())
    }

    pub fn is_fully_removed(&self) -> bool {
        self.phase == JournalPhase::Cleaning
            && self
                .operations
                .iter()
                .all(|operation| operation.state == OperationState::Removed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalValidationError {
    message: String,
}

impl JournalValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JournalValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JournalValidationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionError {
    IllegalPhase {
        from: JournalPhase,
        to: JournalPhase,
    },
    ActiveWithIncompleteOperations,
    UnknownOperation(u32),
    IllegalOperation {
        operation_id: u32,
        from: OperationState,
        to: OperationState,
    },
    OperationNotAllowedInPhase {
        operation_id: u32,
        phase: JournalPhase,
        to: OperationState,
    },
    GenerationOverflow,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid host-state transition: {self:?}")
    }
}

impl std::error::Error for TransitionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseEvidence {
    Held,
    Available,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootEvidence {
    Same,
    Different,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessEvidence {
    MatchingStartTime,
    Missing,
    PidReused,
    Unknown,
}

/// Whether the recovery process is looking at the same kernel namespaces as
/// the journal owner. Namespace inode identities are meaningful only within a
/// boot: after a reboot the volatile network namespace is gone and persistent
/// resources (notably resolver state) must instead be authorized solely by
/// their exact journaled identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceEvidence {
    Same,
    Different,
    Unknown,
    NotApplicableAfterReboot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerEvidence {
    pub lease: LeaseEvidence,
    pub boot: BootEvidence,
    pub process: ProcessEvidence,
    pub namespaces: NamespaceEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerDisposition {
    Active,
    Stale,
    Ambiguous,
}

pub fn classify_owner(evidence: OwnerEvidence) -> OwnerDisposition {
    if evidence.lease == LeaseEvidence::Held {
        return OwnerDisposition::Active;
    }
    match (evidence.boot, evidence.namespaces, evidence.process) {
        (BootEvidence::Different, NamespaceEvidence::NotApplicableAfterReboot, _) => {
            OwnerDisposition::Stale
        }
        (
            BootEvidence::Same,
            NamespaceEvidence::Same,
            ProcessEvidence::Missing | ProcessEvidence::PidReused,
        ) => OwnerDisposition::Stale,
        (BootEvidence::Same, _, _)
        | (BootEvidence::Unknown, _, _)
        | (BootEvidence::Different, _, _) => OwnerDisposition::Ambiguous,
    }
}

pub fn observe_owner(owner: &OwnerIdentity, lease: LeaseEvidence) -> OwnerEvidence {
    let current_boot = capture_boot_id();
    let boot = match (owner.boot_id, current_boot) {
        (Some(expected), Some(actual)) if expected == actual => BootEvidence::Same,
        (Some(_), Some(_)) => BootEvidence::Different,
        _ => BootEvidence::Unknown,
    };
    let process = match owner.pid_start_ticks {
        Some(expected) => match capture_pid_start_ticks(owner.pid) {
            Some(actual) if actual == expected => ProcessEvidence::MatchingStartTime,
            Some(_) => ProcessEvidence::PidReused,
            None if !Path::new(&format!("/proc/{}", owner.pid)).exists() => {
                ProcessEvidence::Missing
            }
            None => ProcessEvidence::Unknown,
        },
        None => ProcessEvidence::Unknown,
    };
    let namespaces = match boot {
        BootEvidence::Different => NamespaceEvidence::NotApplicableAfterReboot,
        BootEvidence::Unknown => NamespaceEvidence::Unknown,
        BootEvidence::Same => match (
            owner.network_namespace,
            capture_namespace_identity("/proc/thread-self/ns/net"),
            owner.mount_namespace,
            capture_namespace_identity("/proc/thread-self/ns/mnt"),
        ) {
            (Some(expected_net), Some(actual_net), Some(expected_mnt), Some(actual_mnt))
                if expected_net == actual_net && expected_mnt == actual_mnt =>
            {
                NamespaceEvidence::Same
            }
            (Some(_), Some(_), Some(_), Some(_)) => NamespaceEvidence::Different,
            _ => NamespaceEvidence::Unknown,
        },
    };
    OwnerEvidence {
        lease,
        boot,
        process,
        namespaces,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceObservationKind {
    ExactOwnedPresent,
    Absent,
    Conflict,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceObservation {
    pub operation_id: u32,
    pub kind: ResourceObservationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    RemoveExactOwned,
    MarkAlreadyAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryStep {
    pub operation_id: u32,
    pub action: RecoveryAction,
    pub resource: OwnedResource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    pub source_generation: u64,
    /// Must be persisted before executing the first step.
    pub required_phase: JournalPhase,
    pub steps: Vec<RecoveryStep>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryRefusal {
    AmbiguousOwner,
    JournalAlreadyInConflict,
    ResourceConflict { operation_ids: Vec<u32> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    LeaveActive,
    Refuse(RecoveryRefusal),
    Execute(RecoveryPlan),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryDecisionError {
    InvalidJournal(JournalValidationError),
    DuplicateObservation(u32),
    UnknownObservation(u32),
    ObservationForRemovedOperation(u32),
    MissingObservations(Vec<u32>),
}

impl fmt::Display for RecoveryDecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cannot construct recovery plan: {self:?}")
    }
}

impl std::error::Error for RecoveryDecisionError {}

/// Pure all-or-nothing recovery decision. This function performs no I/O and
/// never invokes a caller-provided mutation callback. A complete plan exists
/// only after every non-removed operation has one unambiguous observation.
pub fn decide_recovery(
    journal: &HostStateJournalV1,
    owner: OwnerDisposition,
    observations: &[ResourceObservation],
) -> Result<RecoveryDecision, RecoveryDecisionError> {
    journal
        .validate()
        .map_err(RecoveryDecisionError::InvalidJournal)?;
    match owner {
        OwnerDisposition::Active => return Ok(RecoveryDecision::LeaveActive),
        OwnerDisposition::Ambiguous => {
            return Ok(RecoveryDecision::Refuse(RecoveryRefusal::AmbiguousOwner))
        }
        OwnerDisposition::Stale => {}
    }
    if journal.phase == JournalPhase::Conflict {
        return Ok(RecoveryDecision::Refuse(
            RecoveryRefusal::JournalAlreadyInConflict,
        ));
    }

    let pending: HashMap<u32, &OperationRecord> = journal
        .operations
        .iter()
        .filter(|operation| operation.state != OperationState::Removed)
        .map(|operation| (operation.id, operation))
        .collect();
    let all_operations: HashMap<u32, &OperationRecord> = journal
        .operations
        .iter()
        .map(|operation| (operation.id, operation))
        .collect();
    let mut inspected = HashMap::with_capacity(observations.len());
    for observation in observations {
        let Some(operation) = all_operations.get(&observation.operation_id) else {
            return Err(RecoveryDecisionError::UnknownObservation(
                observation.operation_id,
            ));
        };
        if operation.state == OperationState::Removed {
            return Err(RecoveryDecisionError::ObservationForRemovedOperation(
                observation.operation_id,
            ));
        }
        if inspected
            .insert(observation.operation_id, observation.kind)
            .is_some()
        {
            return Err(RecoveryDecisionError::DuplicateObservation(
                observation.operation_id,
            ));
        }
    }

    let mut missing: Vec<u32> = pending
        .keys()
        .filter(|operation_id| !inspected.contains_key(operation_id))
        .copied()
        .collect();
    missing.sort_unstable();
    if !missing.is_empty() {
        return Err(RecoveryDecisionError::MissingObservations(missing));
    }

    let mut conflicts: Vec<u32> = inspected
        .iter()
        .filter_map(|(operation_id, kind)| {
            (*kind == ResourceObservationKind::Conflict).then_some(*operation_id)
        })
        .collect();
    conflicts.sort_unstable();
    if !conflicts.is_empty() {
        return Ok(RecoveryDecision::Refuse(
            RecoveryRefusal::ResourceConflict {
                operation_ids: conflicts,
            },
        ));
    }

    let mut steps: Vec<RecoveryStep> = pending
        .values()
        .map(|operation| {
            let action = match inspected[&operation.id] {
                ResourceObservationKind::ExactOwnedPresent => RecoveryAction::RemoveExactOwned,
                ResourceObservationKind::Absent => RecoveryAction::MarkAlreadyAbsent,
                ResourceObservationKind::Conflict => unreachable!("conflicts returned above"),
            };
            RecoveryStep {
                operation_id: operation.id,
                action,
                resource: operation.resource.clone(),
            }
        })
        .collect();
    steps.sort_by_key(|step| (step.resource.removal_rank(), step.operation_id));
    Ok(RecoveryDecision::Execute(RecoveryPlan {
        source_generation: journal.generation,
        required_phase: JournalPhase::Cleaning,
        steps,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnsafeFileReason {
    NotRegular,
    WrongOwner {
        expected: u32,
        actual: u32,
    },
    WrongMode {
        expected: u32,
        actual: u32,
    },
    MultipleHardLinks {
        actual: u64,
    },
    ParentNotDirectory,
    UnsafeParentMode {
        actual: u32,
    },
    /// A directory entry no longer names the inode that was opened and
    /// validated for the pending operation.
    IdentityChanged,
}

#[derive(Debug)]
pub enum HostStateError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    UnsafeFile {
        path: PathBuf,
        reason: UnsafeFileReason,
    },
    TooLarge {
        actual: u64,
        maximum: u64,
    },
    Json(serde_json::Error),
    InvalidJournal(JournalValidationError),
    Entropy(String),
    AlreadyExists(PathBuf),
    Missing(PathBuf),
    SessionMismatch {
        expected: SessionId,
        actual: SessionId,
    },
    GenerationMismatch {
        expected: u64,
        actual: u64,
    },
    JournalNotFullyRemoved,
}

impl HostStateError {
    fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for HostStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} {}: {source}", path.display()),
            Self::UnsafeFile { path, reason } => {
                write!(
                    formatter,
                    "unsafe host-state file {}: {reason:?}",
                    path.display()
                )
            }
            Self::TooLarge { actual, maximum } => {
                write!(formatter, "journal is {actual} bytes; maximum is {maximum}")
            }
            Self::Json(error) => write!(formatter, "invalid journal JSON: {error}"),
            Self::InvalidJournal(error) => write!(formatter, "invalid host-state journal: {error}"),
            Self::Entropy(error) => {
                write!(formatter, "operating-system entropy unavailable: {error}")
            }
            Self::AlreadyExists(path) => {
                write!(formatter, "journal already exists: {}", path.display())
            }
            Self::Missing(path) => write!(formatter, "journal does not exist: {}", path.display()),
            Self::SessionMismatch { expected, actual } => {
                write!(
                    formatter,
                    "journal session mismatch: expected {expected}, found {actual}"
                )
            }
            Self::GenerationMismatch { expected, actual } => write!(
                formatter,
                "journal generation mismatch: expected {expected}, found {actual}"
            ),
            Self::JournalNotFullyRemoved => formatter.write_str(
                "journal can be removed only in cleaning phase after every operation is removed",
            ),
        }
    }
}

impl std::error::Error for HostStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(source) => Some(source),
            Self::InvalidJournal(source) => Some(source),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for HostStateError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<JournalValidationError> for HostStateError {
    fn from(error: JournalValidationError) -> Self {
        Self::InvalidJournal(error)
    }
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

#[cfg(unix)]
fn opened_metadata_values(metadata: &Metadata) -> (u32, u32, u64) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    (
        metadata.uid(),
        metadata.permissions().mode() & 0o777,
        metadata.nlink(),
    )
}

#[cfg(not(unix))]
fn opened_metadata_values(_metadata: &Metadata) -> (u32, u32, u64) {
    (0, JOURNAL_MODE, 1)
}

fn validate_opened_regular_file(
    path: &Path,
    metadata: &Metadata,
    expected_uid: u32,
    expected_mode: u32,
) -> Result<(), HostStateError> {
    if !metadata.file_type().is_file() {
        return Err(HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::NotRegular,
        });
    }
    let (actual_uid, actual_mode, link_count) = opened_metadata_values(metadata);
    validate_security_values(
        path,
        expected_uid,
        actual_uid,
        expected_mode,
        actual_mode,
        link_count,
    )
}

fn validate_security_values(
    path: &Path,
    expected_uid: u32,
    actual_uid: u32,
    expected_mode: u32,
    actual_mode: u32,
    link_count: u64,
) -> Result<(), HostStateError> {
    if actual_uid != expected_uid {
        return Err(HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::WrongOwner {
                expected: expected_uid,
                actual: actual_uid,
            },
        });
    }
    if actual_mode != expected_mode {
        return Err(HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::WrongMode {
                expected: expected_mode,
                actual: actual_mode,
            },
        });
    }
    if link_count != 1 {
        return Err(HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::MultipleHardLinks { actual: link_count },
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_state_directory(path: &Path, _expected_uid: u32) -> Result<(), HostStateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| HostStateError::io("stat state directory", path, error))?;
    if !metadata.file_type().is_dir() {
        return Err(HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::ParentNotDirectory,
        });
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileObjectIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileObjectIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn from_stat(stat: &libc::stat) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            device: stat.st_dev,
            #[cfg(not(target_os = "linux"))]
            device: stat.st_dev as u64,
            inode: stat.st_ino,
        }
    }
}

/// Metadata fields that must remain stable while a bounded journal is read.
/// The inode check alone does not detect an in-place truncate/rewrite by a
/// second writer.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileReadVersion {
    identity: FileObjectIdentity,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl FileReadVersion {
    fn from_metadata(metadata: &Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            identity: FileObjectIdentity::from_metadata(metadata),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[cfg(unix)]
fn c_component(
    value: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<std::ffi::CString, HostStateError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(HostStateError::UnsafeFile {
            path: display_path.to_path_buf(),
            reason: UnsafeFileReason::NotRegular,
        });
    }
    std::ffi::CString::new(bytes).map_err(|_| {
        HostStateError::io(
            "validate state component",
            display_path,
            io::Error::new(io::ErrorKind::InvalidInput, "component contains NUL"),
        )
    })
}

/// One opened, validated state directory. All journal namespace operations use
/// this descriptor, so renaming or replacing the pathname cannot redirect a
/// running store into a different directory.
#[cfg(unix)]
#[derive(Debug)]
struct StateDirectoryAnchor {
    directory: File,
    display_path: PathBuf,
    identity: FileObjectIdentity,
    expected_uid: u32,
}

#[cfg(unix)]
impl StateDirectoryAnchor {
    fn open(path: &Path, expected_uid: u32) -> Result<Self, HostStateError> {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        #[cfg(target_os = "linux")]
        let directory = {
            use std::os::fd::AsRawFd;
            use std::path::Component;

            // Walk every component through an already opened directory
            // descriptor. A final-component O_NOFOLLOW alone is insufficient:
            // an intermediate symlink could otherwise redirect privileged
            // state. ParentDir is rejected so traversal cannot escape the
            // descriptor chain.
            let start = if path.is_absolute() { b"/\0" } else { b".\0" };
            // SAFETY: start is a static NUL-terminated path and a successful
            // call returns one newly owned descriptor.
            let descriptor = unsafe {
                libc::open(
                    start.as_ptr().cast(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(HostStateError::io(
                    "open state-directory traversal root",
                    path,
                    io::Error::last_os_error(),
                ));
            }
            // SAFETY: descriptor is newly owned and non-negative.
            let mut directory = unsafe { File::from_raw_fd(descriptor) };
            for component in path.components() {
                let value = match component {
                    Component::RootDir | Component::CurDir => continue,
                    Component::Normal(value) => value,
                    Component::ParentDir | Component::Prefix(_) => {
                        return Err(HostStateError::UnsafeFile {
                            path: path.to_path_buf(),
                            reason: UnsafeFileReason::ParentNotDirectory,
                        })
                    }
                };
                let component = c_component(value, path)?;
                // SAFETY: directory is live and component is a single
                // NUL-terminated name. O_NOFOLLOW applies at every hop.
                let next = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        component.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next < 0 {
                    return Err(HostStateError::io(
                        "open state-directory path component",
                        path,
                        io::Error::last_os_error(),
                    ));
                }
                // SAFETY: next is newly owned and non-negative.
                directory = unsafe { File::from_raw_fd(next) };
            }
            directory
        };

        #[cfg(not(target_os = "linux"))]
        let directory = {
            use std::os::unix::ffi::OsStrExt;
            let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                HostStateError::io(
                    "encode state directory",
                    path,
                    io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"),
                )
            })?;
            // Non-Linux Unix is a development fallback. It pins and validates
            // the final directory inode but lacks the Linux component-walk
            // guarantee for intermediate symlinks.
            let descriptor = unsafe {
                libc::open(
                    path_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(HostStateError::io(
                    "open anchored state directory",
                    path,
                    io::Error::last_os_error(),
                ));
            }
            // SAFETY: descriptor is newly owned and non-negative.
            unsafe { File::from_raw_fd(descriptor) }
        };
        let metadata = directory
            .metadata()
            .map_err(|error| HostStateError::io("stat anchored state directory", path, error))?;
        if !metadata.file_type().is_dir() {
            return Err(HostStateError::UnsafeFile {
                path: path.to_path_buf(),
                reason: UnsafeFileReason::ParentNotDirectory,
            });
        }
        if metadata.uid() != expected_uid {
            return Err(HostStateError::UnsafeFile {
                path: path.to_path_buf(),
                reason: UnsafeFileReason::WrongOwner {
                    expected: expected_uid,
                    actual: metadata.uid(),
                },
            });
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != STATE_DIRECTORY_MODE {
            return Err(HostStateError::UnsafeFile {
                path: path.to_path_buf(),
                reason: UnsafeFileReason::UnsafeParentMode { actual: mode },
            });
        }
        Ok(Self {
            identity: FileObjectIdentity::from_metadata(&metadata),
            directory,
            display_path: path.to_path_buf(),
            expected_uid,
        })
    }

    fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.directory.as_raw_fd()
    }

    fn verify(&self) -> Result<(), HostStateError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = self.directory.metadata().map_err(|error| {
            HostStateError::io("restat anchored state directory", &self.display_path, error)
        })?;
        if !metadata.file_type().is_dir()
            || FileObjectIdentity::from_metadata(&metadata) != self.identity
        {
            return Err(HostStateError::UnsafeFile {
                path: self.display_path.clone(),
                reason: UnsafeFileReason::IdentityChanged,
            });
        }
        if metadata.uid() != self.expected_uid {
            return Err(HostStateError::UnsafeFile {
                path: self.display_path.clone(),
                reason: UnsafeFileReason::WrongOwner {
                    expected: self.expected_uid,
                    actual: metadata.uid(),
                },
            });
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != STATE_DIRECTORY_MODE {
            return Err(HostStateError::UnsafeFile {
                path: self.display_path.clone(),
                reason: UnsafeFileReason::UnsafeParentMode { actual: mode },
            });
        }
        Ok(())
    }

    fn open_component(
        &self,
        name: &std::ffi::CStr,
        display_path: &Path,
        flags: libc::c_int,
        mode: u32,
        action: &'static str,
    ) -> Result<File, HostStateError> {
        use std::os::fd::FromRawFd;
        self.verify()?;
        // SAFETY: the directory descriptor and name are live; a successful call
        // returns one newly owned descriptor.
        let descriptor = unsafe {
            libc::openat(
                self.fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if descriptor < 0 {
            return Err(HostStateError::io(
                action,
                display_path,
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: descriptor is newly owned and non-negative.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn component_identity(
        &self,
        name: &std::ffi::CStr,
        display_path: &Path,
    ) -> Result<Option<FileObjectIdentity>, HostStateError> {
        use std::mem::MaybeUninit;
        self.verify()?;
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat points to writable storage and name is NUL terminated.
        let result = unsafe {
            libc::fstatat(
                self.fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(HostStateError::io(
                "stat anchored state component",
                display_path,
                error,
            ));
        }
        // SAFETY: successful fstatat initialized stat.
        Ok(Some(FileObjectIdentity::from_stat(unsafe {
            &stat.assume_init()
        })))
    }

    fn ensure_name_identity(
        &self,
        name: &std::ffi::CStr,
        display_path: &Path,
        expected: FileObjectIdentity,
    ) -> Result<(), HostStateError> {
        if self.component_identity(name, display_path)? == Some(expected) {
            Ok(())
        } else {
            Err(HostStateError::UnsafeFile {
                path: display_path.to_path_buf(),
                reason: UnsafeFileReason::IdentityChanged,
            })
        }
    }

    fn reopen_verified_regular(
        &self,
        name: &std::ffi::CStr,
        display_path: &Path,
        expected: FileObjectIdentity,
        expected_mode: u32,
    ) -> Result<File, HostStateError> {
        let file = self.open_component(
            name,
            display_path,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
            "reopen anchored state component",
        )?;
        let metadata = file.metadata().map_err(|error| {
            HostStateError::io("stat reopened state component", display_path, error)
        })?;
        validate_opened_regular_file(display_path, &metadata, self.expected_uid, expected_mode)?;
        if FileObjectIdentity::from_metadata(&metadata) != expected {
            return Err(HostStateError::UnsafeFile {
                path: display_path.to_path_buf(),
                reason: UnsafeFileReason::IdentityChanged,
            });
        }
        self.ensure_name_identity(name, display_path, expected)?;
        Ok(file)
    }

    #[cfg(not(target_os = "linux"))]
    fn rename_component(
        &self,
        from: &std::ffi::CStr,
        to: &std::ffi::CStr,
        display_path: &Path,
    ) -> Result<(), HostStateError> {
        self.verify()?;
        // SAFETY: both components are NUL terminated and relative to the same
        // live directory descriptor.
        let result = unsafe { libc::renameat(self.fd(), from.as_ptr(), self.fd(), to.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(HostStateError::io(
                "atomically replace anchored journal",
                display_path,
                io::Error::last_os_error(),
            ))
        }
    }

    fn unlink_component(
        &self,
        name: &std::ffi::CStr,
        display_path: &Path,
    ) -> Result<(), HostStateError> {
        self.verify()?;
        // SAFETY: name is NUL terminated and relative to a live directory fd.
        let result = unsafe { libc::unlinkat(self.fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(HostStateError::io(
                "unlink anchored state component",
                display_path,
                io::Error::last_os_error(),
            ))
        }
    }

    fn sync(&self) -> Result<(), HostStateError> {
        self.verify()?;
        self.directory.sync_all().map_err(|error| {
            HostStateError::io("fsync anchored state directory", &self.display_path, error)
        })
    }
}

#[cfg(not(unix))]
fn open_readonly_nofollow(path: &Path) -> Result<File, HostStateError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|error| HostStateError::io("open journal", path, error))
}

pub fn read_journal(path: &Path) -> Result<HostStateJournalV1, HostStateError> {
    #[cfg(unix)]
    {
        let (anchor, name) = open_anchor_for_path(path, effective_uid())?;
        read_journal_anchored(&anchor, &name, path, effective_uid()).map(|(journal, _)| journal)
    }
    #[cfg(not(unix))]
    read_journal_for_uid(path, effective_uid())
}

#[cfg(not(unix))]
fn read_journal_for_uid(
    path: &Path,
    expected_uid: u32,
) -> Result<HostStateJournalV1, HostStateError> {
    let file = open_readonly_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| HostStateError::io("stat opened journal", path, error))?;
    validate_opened_regular_file(path, &metadata, expected_uid, JOURNAL_MODE)?;
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(HostStateError::TooLarge {
            actual: metadata.len(),
            maximum: MAX_JOURNAL_BYTES,
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| HostStateError::io("read journal", path, error))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(HostStateError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    let journal: HostStateJournalV1 = serde_json::from_slice(&bytes)?;
    journal.validate()?;
    if journal.owner.uid != expected_uid {
        return Err(HostStateError::InvalidJournal(JournalValidationError::new(
            format!(
                "journal owner UID {} differs from file owner UID {expected_uid}",
                journal.owner.uid
            ),
        )));
    }
    Ok(journal)
}

#[cfg(unix)]
fn open_anchor_for_path(
    path: &Path,
    expected_uid: u32,
) -> Result<(Arc<StateDirectoryAnchor>, std::ffi::CString), HostStateError> {
    let parent = state_parent(path)?;
    let name = c_component(
        path.file_name().ok_or_else(|| HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::NotRegular,
        })?,
        path,
    )?;
    Ok((
        Arc::new(StateDirectoryAnchor::open(parent, expected_uid)?),
        name,
    ))
}

#[cfg(unix)]
fn read_journal_anchored(
    anchor: &StateDirectoryAnchor,
    name: &std::ffi::CStr,
    path: &Path,
    expected_uid: u32,
) -> Result<(HostStateJournalV1, FileObjectIdentity), HostStateError> {
    let mut file = anchor.open_component(
        name,
        path,
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
        "open anchored journal",
    )?;
    let before = file
        .metadata()
        .map_err(|error| HostStateError::io("stat opened anchored journal", path, error))?;
    validate_opened_regular_file(path, &before, expected_uid, JOURNAL_MODE)?;
    if before.len() > MAX_JOURNAL_BYTES {
        return Err(HostStateError::TooLarge {
            actual: before.len(),
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    let version = FileReadVersion::from_metadata(&before);
    anchor.ensure_name_identity(name, path, version.identity)?;

    let mut bytes = Vec::with_capacity(before.len() as usize);
    {
        let mut bounded = (&mut file).take(MAX_JOURNAL_BYTES + 1);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|error| HostStateError::io("read anchored journal", path, error))?;
    }
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(HostStateError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    let after = file
        .metadata()
        .map_err(|error| HostStateError::io("restat opened anchored journal", path, error))?;
    validate_opened_regular_file(path, &after, expected_uid, JOURNAL_MODE)?;
    if FileReadVersion::from_metadata(&after) != version {
        return Err(HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::IdentityChanged,
        });
    }
    anchor.ensure_name_identity(name, path, version.identity)?;

    let journal: HostStateJournalV1 = serde_json::from_slice(&bytes)?;
    journal.validate()?;
    if journal.owner.uid != expected_uid {
        return Err(HostStateError::InvalidJournal(JournalValidationError::new(
            format!(
                "journal owner UID {} differs from file owner UID {expected_uid}",
                journal.owner.uid
            ),
        )));
    }
    Ok((journal, version.identity))
}

#[cfg(not(unix))]
struct PendingTemp {
    path: PathBuf,
    published: bool,
}

#[cfg(not(unix))]
impl Drop for PendingTemp {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
struct PendingTemp {
    anchor: Arc<StateDirectoryAnchor>,
    name: std::ffi::CString,
    display_path: PathBuf,
    file: File,
    identity: FileObjectIdentity,
    published: bool,
}

#[cfg(unix)]
impl PendingTemp {
    fn verify_name(&self) -> Result<(), HostStateError> {
        let metadata = self.file.metadata().map_err(|error| {
            HostStateError::io("restat open journal temp", &self.display_path, error)
        })?;
        if FileObjectIdentity::from_metadata(&metadata) != self.identity {
            return Err(HostStateError::UnsafeFile {
                path: self.display_path.clone(),
                reason: UnsafeFileReason::IdentityChanged,
            });
        }
        self.anchor
            .ensure_name_identity(&self.name, &self.display_path, self.identity)?;
        validate_opened_regular_file(
            &self.display_path,
            &metadata,
            self.anchor.expected_uid,
            JOURNAL_MODE,
        )
    }
}

#[cfg(unix)]
impl Drop for PendingTemp {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Never unlink a name that no longer refers to the exact staged inode.
        if self
            .anchor
            .ensure_name_identity(&self.name, &self.display_path, self.identity)
            .is_ok()
        {
            let _ = self.anchor.unlink_component(&self.name, &self.display_path);
        }
    }
}

fn state_parent(path: &Path) -> Result<&Path, HostStateError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::ParentNotDirectory,
        })
}

#[cfg(not(unix))]
fn stage_journal(
    path: &Path,
    bytes: &[u8],
    expected_uid: u32,
) -> Result<PendingTemp, HostStateError> {
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(HostStateError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    let parent = state_parent(path)?;
    validate_state_directory(parent, expected_uid)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| HostStateError::UnsafeFile {
            path: path.to_path_buf(),
            reason: UnsafeFileReason::NotRegular,
        })?
        .to_string_lossy();

    for _ in 0..32 {
        let nonce = SessionId::generate()?;
        let temp_path = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(JOURNAL_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(&temp_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(HostStateError::io(
                    "create same-directory journal temp",
                    temp_path,
                    error,
                ))
            }
        };
        let pending = PendingTemp {
            path: temp_path.clone(),
            published: false,
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(JOURNAL_MODE))
                .map_err(|error| HostStateError::io("chmod journal temp", &temp_path, error))?;
        }
        let metadata = file
            .metadata()
            .map_err(|error| HostStateError::io("stat journal temp", &temp_path, error))?;
        validate_opened_regular_file(&temp_path, &metadata, expected_uid, JOURNAL_MODE)?;
        file.write_all(bytes)
            .map_err(|error| HostStateError::io("write journal temp", &temp_path, error))?;
        file.sync_all()
            .map_err(|error| HostStateError::io("fsync journal temp", &temp_path, error))?;
        drop(file);
        return Ok(pending);
    }
    Err(HostStateError::io(
        "allocate unique journal temp",
        path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary-name collision limit reached",
        ),
    ))
}

#[cfg(unix)]
fn stage_journal_anchored(
    anchor: Arc<StateDirectoryAnchor>,
    bytes: &[u8],
    journal_path: &Path,
) -> Result<PendingTemp, HostStateError> {
    use std::os::unix::fs::PermissionsExt;

    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(HostStateError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    for _ in 0..32 {
        let nonce = SessionId::generate()?;
        let file_name = format!(".shadowpipe-journal.{}.{}.tmp", std::process::id(), nonce);
        let name = std::ffi::CString::new(file_name.as_bytes())
            .expect("ASCII journal temp name contains no NUL");
        let display_path = anchor.display_path.join(&file_name);
        let mut file = match anchor.open_component(
            &name,
            &display_path,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            JOURNAL_MODE,
            "create anchored journal temp",
        ) {
            Ok(file) => file,
            Err(HostStateError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
        file.set_permissions(fs::Permissions::from_mode(JOURNAL_MODE))
            .map_err(|error| {
                HostStateError::io("chmod anchored journal temp", &display_path, error)
            })?;
        let metadata = file.metadata().map_err(|error| {
            HostStateError::io("stat anchored journal temp", &display_path, error)
        })?;
        validate_opened_regular_file(&display_path, &metadata, anchor.expected_uid, JOURNAL_MODE)?;
        let identity = FileObjectIdentity::from_metadata(&metadata);
        anchor.ensure_name_identity(&name, &display_path, identity)?;
        file.write_all(bytes).map_err(|error| {
            HostStateError::io("write anchored journal temp", &display_path, error)
        })?;
        file.sync_all().map_err(|error| {
            HostStateError::io("fsync anchored journal temp", &display_path, error)
        })?;
        let pending = PendingTemp {
            anchor,
            name,
            display_path,
            file,
            identity,
            published: false,
        };
        pending.verify_name()?;
        return Ok(pending);
    }
    Err(HostStateError::io(
        "allocate anchored journal temp",
        journal_path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary-name collision limit reached",
        ),
    ))
}

#[cfg(not(unix))]
fn sync_parent_directory(path: &Path) -> Result<(), HostStateError> {
    let parent = state_parent(path)?;
    let directory = File::open(parent)
        .map_err(|error| HostStateError::io("open journal directory", parent, error))?;
    directory
        .sync_all()
        .map_err(|error| HostStateError::io("fsync journal directory", parent, error))
}

#[cfg(target_os = "linux")]
fn publish_noreplace_at(
    anchor: &StateDirectoryAnchor,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> io::Result<()> {
    // SAFETY: both pointers refer to live NUL-terminated byte strings for the
    // duration of the call; flags and directory descriptors are kernel-defined.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            anchor.fd(),
            from.as_ptr(),
            anchor.fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn exchange_at(
    anchor: &StateDirectoryAnchor,
    first: &std::ffi::CStr,
    second: &std::ffi::CStr,
) -> io::Result<()> {
    // RENAME_EXCHANGE keeps both directory entries present and gives replace
    // a post-syscall comparison point: the displaced inode is available under
    // the pending name instead of being destroyed by a plain renameat.
    // SAFETY: both names are live NUL-terminated components and both directory
    // descriptors refer to the same anchored directory.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            anchor.fd(),
            first.as_ptr(),
            anchor.fd(),
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn publish_noreplace_at(
    anchor: &StateDirectoryAnchor,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> io::Result<()> {
    // linkat is an atomic no-clobber publication on Unix development hosts.
    // The source is unlinked only after the target link exists.
    let linked = unsafe { libc::linkat(anchor.fd(), from.as_ptr(), anchor.fd(), to.as_ptr(), 0) };
    if linked != 0 {
        return Err(io::Error::last_os_error());
    }
    let unlinked = unsafe { libc::unlinkat(anchor.fd(), from.as_ptr(), 0) };
    if unlinked == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn publish_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    // Atomic no-clobber publication fallback for development hosts. Linux uses
    // renameat2(RENAME_NOREPLACE), the production primitive.
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}

fn serialize_journal(journal: &HostStateJournalV1) -> Result<Vec<u8>, HostStateError> {
    journal.validate()?;
    let mut bytes = serde_json::to_vec(journal)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(HostStateError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    Ok(bytes)
}

#[derive(Clone, Debug)]
pub struct JournalStore {
    path: PathBuf,
    expected_uid: u32,
    #[cfg(unix)]
    anchor: Arc<OnceLock<Arc<StateDirectoryAnchor>>>,
}

impl JournalStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            expected_uid: effective_uid(),
            #[cfg(unix)]
            anchor: Arc::new(OnceLock::new()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<HostStateJournalV1, HostStateError> {
        #[cfg(unix)]
        {
            self.load_with_identity().map(|(journal, _)| journal)
        }
        #[cfg(not(unix))]
        read_journal_for_uid(&self.path, self.expected_uid)
    }

    #[cfg(unix)]
    fn anchored(&self) -> Result<(Arc<StateDirectoryAnchor>, std::ffi::CString), HostStateError> {
        let parent = state_parent(&self.path)?;
        let name = c_component(
            self.path
                .file_name()
                .ok_or_else(|| HostStateError::UnsafeFile {
                    path: self.path.clone(),
                    reason: UnsafeFileReason::NotRegular,
                })?,
            &self.path,
        )?;
        let anchor = if let Some(anchor) = self.anchor.get() {
            Arc::clone(anchor)
        } else {
            let candidate = Arc::new(StateDirectoryAnchor::open(parent, self.expected_uid)?);
            match self.anchor.set(Arc::clone(&candidate)) {
                Ok(()) => candidate,
                Err(_) => Arc::clone(
                    self.anchor
                        .get()
                        .expect("another thread initialized the state-directory anchor"),
                ),
            }
        };
        anchor.verify()?;
        Ok((anchor, name))
    }

    #[cfg(unix)]
    fn load_with_identity(
        &self,
    ) -> Result<(HostStateJournalV1, FileObjectIdentity), HostStateError> {
        let (anchor, name) = self.anchored()?;
        read_journal_anchored(&anchor, &name, &self.path, self.expected_uid)
    }

    /// Atomically create generation one without replacing any existing name.
    pub fn create(&self, journal: &HostStateJournalV1) -> Result<(), HostStateError> {
        if journal.generation != 1 {
            return Err(HostStateError::GenerationMismatch {
                expected: 1,
                actual: journal.generation,
            });
        }
        if journal.owner.uid != self.expected_uid {
            return Err(HostStateError::InvalidJournal(JournalValidationError::new(
                format!(
                    "journal owner UID {} differs from writer UID {}",
                    journal.owner.uid, self.expected_uid
                ),
            )));
        }
        let bytes = serialize_journal(journal)?;
        #[cfg(unix)]
        {
            let (anchor, name) = self.anchored()?;
            let mut pending = stage_journal_anchored(Arc::clone(&anchor), &bytes, &self.path)?;
            pending.verify_name()?;
            match publish_noreplace_at(&anchor, &pending.name, &name) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(HostStateError::AlreadyExists(self.path.clone()))
                }
                Err(error) => {
                    return Err(HostStateError::io(
                        "atomically create anchored journal",
                        &self.path,
                        error,
                    ))
                }
            }
            pending.published = true;
            anchor.ensure_name_identity(&name, &self.path, pending.identity)?;
            anchor.sync()
        }
        #[cfg(not(unix))]
        {
            let mut pending = stage_journal(&self.path, &bytes, self.expected_uid)?;
            match publish_noreplace(&pending.path, &self.path) {
                Ok(()) => pending.published = true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(HostStateError::AlreadyExists(self.path.clone()))
                }
                Err(error) => {
                    return Err(HostStateError::io(
                        "atomically create journal",
                        &self.path,
                        error,
                    ))
                }
            }
            sync_parent_directory(&self.path)
        }
    }

    /// Replace a validated journal with exactly the next generation. The
    /// existing session identity cannot be changed through this operation.
    pub fn replace(&self, journal: &HostStateJournalV1) -> Result<(), HostStateError> {
        #[cfg(unix)]
        {
            self.replace_anchored_with_hook(journal, || {})
        }
        #[cfg(not(unix))]
        {
            let current = match self.load() {
                Ok(current) => current,
                Err(HostStateError::Io { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    return Err(HostStateError::Missing(self.path.clone()))
                }
                Err(error) => return Err(error),
            };
            if current.owner.session_id != journal.owner.session_id {
                return Err(HostStateError::SessionMismatch {
                    expected: current.owner.session_id,
                    actual: journal.owner.session_id,
                });
            }
            let expected_generation =
                current
                    .generation
                    .checked_add(1)
                    .ok_or(HostStateError::GenerationMismatch {
                        expected: u64::MAX,
                        actual: journal.generation,
                    })?;
            if journal.generation != expected_generation {
                return Err(HostStateError::GenerationMismatch {
                    expected: expected_generation,
                    actual: journal.generation,
                });
            }
            current.validate_successor(journal)?;
            let bytes = serialize_journal(journal)?;
            let mut pending = stage_journal(&self.path, &bytes, self.expected_uid)?;
            fs::rename(&pending.path, &self.path).map_err(|error| {
                HostStateError::io("atomically replace journal", &self.path, error)
            })?;
            pending.published = true;
            sync_parent_directory(&self.path)
        }
    }

    #[cfg(unix)]
    fn replace_anchored_with_hook<F>(
        &self,
        journal: &HostStateJournalV1,
        before_namespace_mutation: F,
    ) -> Result<(), HostStateError>
    where
        F: FnOnce(),
    {
        let (current, current_identity) = match self.load_with_identity() {
            Ok(current) => current,
            Err(HostStateError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(HostStateError::Missing(self.path.clone()))
            }
            Err(error) => return Err(error),
        };
        if current.owner.session_id != journal.owner.session_id {
            return Err(HostStateError::SessionMismatch {
                expected: current.owner.session_id,
                actual: journal.owner.session_id,
            });
        }
        let expected_generation =
            current
                .generation
                .checked_add(1)
                .ok_or(HostStateError::GenerationMismatch {
                    expected: u64::MAX,
                    actual: journal.generation,
                })?;
        if journal.generation != expected_generation {
            return Err(HostStateError::GenerationMismatch {
                expected: expected_generation,
                actual: journal.generation,
            });
        }
        current.validate_successor(journal)?;
        let bytes = serialize_journal(journal)?;
        let (anchor, name) = self.anchored()?;
        let mut pending = stage_journal_anchored(Arc::clone(&anchor), &bytes, &self.path)?;

        // Retain both descriptors through publication. The test hook is
        // deliberately after revalidation so Linux tests exercise the atomic
        // exchange comparison, not merely the earlier pathname check.
        let _current_guard =
            anchor.reopen_verified_regular(&name, &self.path, current_identity, JOURNAL_MODE)?;
        before_namespace_mutation();
        pending.verify_name()?;

        #[cfg(target_os = "linux")]
        {
            exchange_at(&anchor, &pending.name, &name).map_err(|error| {
                HostStateError::io("exchange anchored journal generations", &self.path, error)
            })?;
            let installed = anchor.component_identity(&name, &self.path)?;
            let displaced = anchor.component_identity(&pending.name, &pending.display_path)?;
            if installed != Some(pending.identity) || displaced != Some(current_identity) {
                // A writer changed the target after our read. RENAME_EXCHANGE
                // preserved that inode under the pending name, so roll back
                // only while both exchange results are still exactly known.
                if installed == Some(pending.identity) {
                    let Some(displaced) = displaced else {
                        return Err(HostStateError::UnsafeFile {
                            path: self.path.clone(),
                            reason: UnsafeFileReason::IdentityChanged,
                        });
                    };
                    match exchange_at(&anchor, &pending.name, &name) {
                        Ok(()) => {
                            anchor.ensure_name_identity(
                                &pending.name,
                                &pending.display_path,
                                pending.identity,
                            )?;
                            anchor.ensure_name_identity(&name, &self.path, displaced)?;
                            anchor.sync()?;
                        }
                        Err(error) => {
                            // Do not unlink either name on failed rollback: the
                            // candidate and displaced inode remain recoverable.
                            pending.published = true;
                            return Err(HostStateError::io(
                                "roll back conflicted journal exchange",
                                &self.path,
                                error,
                            ));
                        }
                    }
                }
                return Err(HostStateError::UnsafeFile {
                    path: self.path.clone(),
                    reason: UnsafeFileReason::IdentityChanged,
                });
            }

            pending.published = true;
            anchor.ensure_name_identity(&name, &self.path, pending.identity)?;
            // The old generation is deleted only from the private pending
            // name and only while it is still the inode observed at load.
            let _displaced_guard = anchor.reopen_verified_regular(
                &pending.name,
                &pending.display_path,
                current_identity,
                JOURNAL_MODE,
            )?;
            anchor.unlink_component(&pending.name, &pending.display_path)?;
            if anchor
                .component_identity(&pending.name, &pending.display_path)?
                .is_some()
            {
                return Err(HostStateError::UnsafeFile {
                    path: pending.display_path.clone(),
                    reason: UnsafeFileReason::IdentityChanged,
                });
            }
            anchor.sync()
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Development Unix targets lack Linux's renameat2 exchange/CAS
            // pattern. The descriptor and immediate identity checks reject a
            // staged swap, but a hostile same-UID process remains outside this
            // fallback's threat boundary.
            anchor.rename_component(&pending.name, &name, &self.path)?;
            pending.published = true;
            anchor.ensure_name_identity(&name, &self.path, pending.identity)?;
            anchor.sync()
        }
    }

    pub fn remove_completed(&self, expected_session: SessionId) -> Result<(), HostStateError> {
        #[cfg(unix)]
        {
            self.remove_completed_anchored_with_hook(expected_session, || {})
        }
        #[cfg(not(unix))]
        {
            let current = self.load()?;
            if current.owner.session_id != expected_session {
                return Err(HostStateError::SessionMismatch {
                    expected: expected_session,
                    actual: current.owner.session_id,
                });
            }
            if !current.is_fully_removed() {
                return Err(HostStateError::JournalNotFullyRemoved);
            }
            fs::remove_file(&self.path).map_err(|error| {
                HostStateError::io("remove completed journal", &self.path, error)
            })?;
            sync_parent_directory(&self.path)
        }
    }

    #[cfg(unix)]
    fn remove_completed_anchored_with_hook<F>(
        &self,
        expected_session: SessionId,
        before_namespace_mutation: F,
    ) -> Result<(), HostStateError>
    where
        F: FnOnce(),
    {
        let (current, current_identity) = self.load_with_identity()?;
        if current.owner.session_id != expected_session {
            return Err(HostStateError::SessionMismatch {
                expected: expected_session,
                actual: current.owner.session_id,
            });
        }
        if !current.is_fully_removed() {
            return Err(HostStateError::JournalNotFullyRemoved);
        }
        let (anchor, name) = self.anchored()?;
        let _current_guard =
            anchor.reopen_verified_regular(&name, &self.path, current_identity, JOURNAL_MODE)?;
        before_namespace_mutation();

        #[cfg(target_os = "linux")]
        {
            // unlinkat cannot compare an inode. First move the name into a
            // unique quarantine with RENAME_NOREPLACE, then inspect the inode
            // actually selected by that atomic namespace operation. A swapped
            // foreign entry is restored, never unlinked.
            let (quarantine, quarantine_path) = {
                let mut selected = None;
                for _ in 0..32 {
                    let nonce = SessionId::generate()?;
                    let file_name = format!(
                        ".shadowpipe-journal-remove.{}.{}.tmp",
                        std::process::id(),
                        nonce
                    );
                    let candidate = std::ffi::CString::new(file_name.as_bytes())
                        .expect("ASCII quarantine name contains no NUL");
                    let candidate_path = anchor.display_path.join(&file_name);
                    match publish_noreplace_at(&anchor, &name, &candidate) {
                        Ok(()) => {
                            selected = Some((candidate, candidate_path));
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            return Err(HostStateError::io(
                                "quarantine completed anchored journal",
                                &self.path,
                                error,
                            ))
                        }
                    }
                }
                selected.ok_or_else(|| {
                    HostStateError::io(
                        "allocate completed-journal quarantine",
                        &self.path,
                        io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "quarantine-name collision limit reached",
                        ),
                    )
                })?
            };
            let quarantined = anchor.component_identity(&quarantine, &quarantine_path)?;
            if quarantined != Some(current_identity) {
                // Restore without clobbering a new target. If another writer
                // populated the journal name, leave both entries recoverable.
                match publish_noreplace_at(&anchor, &quarantine, &name) {
                    Ok(()) => anchor.sync()?,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        anchor.sync()?;
                    }
                    Err(error) => {
                        anchor.sync()?;
                        return Err(HostStateError::io(
                            "restore conflicted completed journal",
                            &self.path,
                            error,
                        ));
                    }
                }
                return Err(HostStateError::UnsafeFile {
                    path: self.path.clone(),
                    reason: UnsafeFileReason::IdentityChanged,
                });
            }
            let _quarantine_guard = anchor.reopen_verified_regular(
                &quarantine,
                &quarantine_path,
                current_identity,
                JOURNAL_MODE,
            )?;
            anchor.unlink_component(&quarantine, &quarantine_path)?;
            if anchor.component_identity(&name, &self.path)?.is_some()
                || anchor
                    .component_identity(&quarantine, &quarantine_path)?
                    .is_some()
            {
                return Err(HostStateError::UnsafeFile {
                    path: self.path.clone(),
                    reason: UnsafeFileReason::IdentityChanged,
                });
            }
            anchor.sync()
        }

        #[cfg(not(target_os = "linux"))]
        {
            // As with replacement, non-Linux Unix is a development fallback:
            // immediate identity checks are strong against accidental races,
            // not an actively hostile writer with the same directory rights.
            anchor.unlink_component(&name, &self.path)?;
            if anchor.component_identity(&name, &self.path)?.is_some() {
                return Err(HostStateError::UnsafeFile {
                    path: self.path.clone(),
                    reason: UnsafeFileReason::IdentityChanged,
                });
            }
            anchor.sync()
        }
    }
}

#[derive(Debug)]
pub enum DurableJournalError {
    Store(HostStateError),
    Transition(TransitionError),
    InvalidPhase {
        expected: &'static str,
        actual: JournalPhase,
    },
    OperationCapacity,
    MissingLiveResource,
    OperationState {
        operation_id: u32,
        expected: OperationState,
        actual: OperationState,
    },
}

impl fmt::Display for DurableJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Transition(error) => error.fmt(formatter),
            Self::InvalidPhase { expected, actual } => {
                write!(
                    formatter,
                    "durable journal expected {expected}, found {actual:?}"
                )
            }
            Self::OperationCapacity => write!(
                formatter,
                "durable journal exhausted its {MAX_OPERATIONS}-operation capacity"
            ),
            Self::MissingLiveResource => {
                formatter.write_str("durable journal has no matching live owned resource")
            }
            Self::OperationState {
                operation_id,
                expected,
                actual,
            } => write!(
                formatter,
                "durable journal operation {operation_id} expected {expected:?}, found {actual:?}"
            ),
        }
    }
}

impl std::error::Error for DurableJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Transition(error) => Some(error),
            _ => None,
        }
    }
}

impl From<HostStateError> for DurableJournalError {
    fn from(error: HostStateError) -> Self {
        Self::Store(error)
    }
}

impl From<TransitionError> for DurableJournalError {
    fn from(error: TransitionError) -> Self {
        Self::Transition(error)
    }
}

impl From<JournalValidationError> for DurableJournalError {
    fn from(error: JournalValidationError) -> Self {
        Self::Store(HostStateError::InvalidJournal(error))
    }
}

/// Small write-ahead state machine around [`JournalStore`]. Every method that
/// changes the in-memory journal first publishes exactly one validated next
/// generation. Callers therefore cannot accidentally acknowledge a privileged
/// mutation only in RAM.
#[derive(Debug)]
pub struct DurableHostJournal {
    store: JournalStore,
    journal: HostStateJournalV2,
}

impl DurableHostJournal {
    /// Create an empty Preparing journal before the first host mutation.
    pub fn create(store: JournalStore, owner: OwnerIdentity) -> Result<Self, DurableJournalError> {
        let journal = HostStateJournalV2::new(owner, Vec::new())?;
        store.create(&journal)?;
        Ok(Self { store, journal })
    }

    pub fn load(store: JournalStore) -> Result<Self, DurableJournalError> {
        let journal = store.load()?;
        Ok(Self { store, journal })
    }

    pub fn journal(&self) -> &HostStateJournalV2 {
        &self.journal
    }

    pub fn store(&self) -> &JournalStore {
        &self.store
    }

    fn commit<F>(&mut self, mutate: F) -> Result<(), DurableJournalError>
    where
        F: FnOnce(&mut HostStateJournalV2) -> Result<(), DurableJournalError>,
    {
        let mut next = self.journal.clone();
        mutate(&mut next)?;
        next.next_generation()?;
        self.store.replace(&next)?;
        self.journal = next;
        Ok(())
    }

    fn ensure_preparing(&mut self) -> Result<(), DurableJournalError> {
        match self.journal.phase {
            JournalPhase::Preparing => Ok(()),
            JournalPhase::Active => self.commit(|journal| {
                journal.transition_phase(JournalPhase::Preparing)?;
                Ok(())
            }),
            actual => Err(DurableJournalError::InvalidPhase {
                expected: "active or preparing phase",
                actual,
            }),
        }
    }

    pub fn compact_removed(&mut self) -> Result<bool, DurableJournalError> {
        if self.journal.phase != JournalPhase::Active {
            return Err(DurableJournalError::InvalidPhase {
                expected: "active phase",
                actual: self.journal.phase,
            });
        }
        if !self
            .journal
            .operations
            .iter()
            .any(|operation| operation.state == OperationState::Removed)
        {
            return Ok(false);
        }
        self.commit(|journal| {
            journal
                .operations
                .retain(|operation| operation.state != OperationState::Removed);
            for (index, operation) in journal.operations.iter_mut().enumerate() {
                operation.id =
                    u32::try_from(index + 1).expect("MAX_OPERATIONS fits operation identifiers");
            }
            journal.validate().map_err(HostStateError::from)?;
            Ok(())
        })?;
        Ok(true)
    }

    /// WAL an exact resource as Planned. The returned ID must be acknowledged
    /// only after the corresponding host command has a definite success result.
    pub fn begin_add(&mut self, resource: OwnedResource) -> Result<u32, DurableJournalError> {
        self.begin_add_batch(vec![resource])?
            .into_iter()
            .next()
            .ok_or(DurableJournalError::OperationCapacity)
    }

    fn preflight_add_batch(
        &self,
        resources: &[OwnedResource],
    ) -> Result<Vec<u32>, DurableJournalError> {
        if !matches!(
            self.journal.phase,
            JournalPhase::Active | JournalPhase::Preparing
        ) {
            return Err(DurableJournalError::InvalidPhase {
                expected: "active or preparing phase",
                actual: self.journal.phase,
            });
        }
        if resources.len() > MAX_OPERATIONS.saturating_sub(self.journal.operations.len()) {
            return Err(DurableJournalError::OperationCapacity);
        }
        let first = self.journal.operations.len() + 1;
        let ids: Vec<u32> = (first..first + resources.len())
            .map(|value| u32::try_from(value).map_err(|_| DurableJournalError::OperationCapacity))
            .collect::<Result<_, _>>()?;

        // Simulate every durable generation that the real operation will write.
        // This ensures a byte-capacity failure is returned while the live journal
        // is still Active, before a caller can perform any external mutation.
        let mut projected = self.journal.clone();
        if projected.phase == JournalPhase::Active {
            projected.transition_phase(JournalPhase::Preparing)?;
            projected.next_generation()?;
        }
        projected
            .operations
            .extend(
                ids.iter()
                    .copied()
                    .zip(resources.iter().cloned())
                    .map(|(id, resource)| OperationRecord {
                        id,
                        state: OperationState::Planned,
                        resource,
                    }),
            );
        projected.validate().map_err(HostStateError::from)?;
        projected.next_generation()?;
        serialize_journal(&projected)?;
        Ok(ids)
    }

    /// Append one complete multi-resource intent in a single durable
    /// generation. Recovery can therefore reconstruct the whole typed identity
    /// (for example both firewall chain tokens) before the first host command.
    pub fn begin_add_batch(
        &mut self,
        resources: Vec<OwnedResource>,
    ) -> Result<Vec<u32>, DurableJournalError> {
        if resources.is_empty() {
            return Ok(Vec::new());
        }
        if self.journal.phase == JournalPhase::Active
            && (self.journal.operations.len() + resources.len() > MAX_OPERATIONS
                || self
                    .journal
                    .operations
                    .iter()
                    .filter(|operation| operation.state == OperationState::Removed)
                    .count()
                    >= 64)
        {
            self.compact_removed()?;
        }
        let ids = match self.preflight_add_batch(&resources) {
            Err(DurableJournalError::Store(HostStateError::TooLarge { .. }))
                if self.journal.phase == JournalPhase::Active
                    && self
                        .journal
                        .operations
                        .iter()
                        .any(|operation| operation.state == OperationState::Removed) =>
            {
                self.compact_removed()?;
                self.preflight_add_batch(&resources)?
            }
            result => result?,
        };
        self.ensure_preparing()?;
        let returned_ids = ids.clone();
        self.commit(move |journal| {
            journal
                .operations
                .extend(
                    ids.into_iter()
                        .zip(resources)
                        .map(|(id, resource)| OperationRecord {
                            id,
                            state: OperationState::Planned,
                            resource,
                        }),
                );
            journal.validate().map_err(HostStateError::from)?;
            Ok(())
        })?;
        Ok(returned_ids)
    }

    pub fn acknowledge_add(&mut self, operation_id: u32) -> Result<(), DurableJournalError> {
        self.expect_state(operation_id, OperationState::Planned)?;
        self.commit(|journal| {
            journal.transition_operation(operation_id, OperationState::Applied)?;
            Ok(())
        })
    }

    /// Prove that a command which never applied left no resource, then close its
    /// Planned record without pretending it was Applied.
    pub fn acknowledge_add_absent(&mut self, operation_id: u32) -> Result<(), DurableJournalError> {
        self.expect_state(operation_id, OperationState::Planned)?;
        self.commit(|journal| {
            journal.transition_operation(operation_id, OperationState::Removed)?;
            Ok(())
        })
    }

    /// Persist the Active checkpoint only when no operation remains ambiguous.
    pub fn publish_active(&mut self) -> Result<(), DurableJournalError> {
        if self.journal.phase != JournalPhase::Preparing {
            return Err(DurableJournalError::InvalidPhase {
                expected: "preparing phase",
                actual: self.journal.phase,
            });
        }
        self.commit(|journal| {
            journal.transition_phase(JournalPhase::Active)?;
            Ok(())
        })
    }

    /// Enter Preparing before removing one previously Applied exact resource.
    /// The phase edge is itself durable; a crash before the command simply
    /// leaves the resource eligible for whole-journal recovery.
    pub fn begin_remove(&mut self, resource: &OwnedResource) -> Result<u32, DurableJournalError> {
        let operation = self
            .journal
            .operations
            .iter()
            .rev()
            .find(|operation| {
                operation.resource == *resource && operation.state != OperationState::Removed
            })
            .ok_or(DurableJournalError::MissingLiveResource)?;
        if operation.state != OperationState::Applied {
            return Err(DurableJournalError::OperationState {
                operation_id: operation.id,
                expected: OperationState::Applied,
                actual: operation.state,
            });
        }
        let operation_id = operation.id;
        self.ensure_preparing()?;
        Ok(operation_id)
    }

    pub fn acknowledge_remove(&mut self, operation_id: u32) -> Result<(), DurableJournalError> {
        self.expect_state(operation_id, OperationState::Applied)?;
        self.commit(|journal| {
            journal.transition_operation(operation_id, OperationState::Removed)?;
            Ok(())
        })
    }

    pub fn begin_cleaning(&mut self) -> Result<(), DurableJournalError> {
        match self.journal.phase {
            JournalPhase::Cleaning => Ok(()),
            JournalPhase::Preparing | JournalPhase::Active => self.commit(|journal| {
                journal.transition_phase(JournalPhase::Cleaning)?;
                Ok(())
            }),
            actual => Err(DurableJournalError::InvalidPhase {
                expected: "preparing, active, or cleaning phase",
                actual,
            }),
        }
    }

    pub fn mark_conflict(&mut self) -> Result<(), DurableJournalError> {
        match self.journal.phase {
            JournalPhase::Conflict => Ok(()),
            JournalPhase::Preparing | JournalPhase::Active | JournalPhase::Cleaning => {
                self.commit(|journal| {
                    journal.transition_phase(JournalPhase::Conflict)?;
                    Ok(())
                })
            }
        }
    }

    /// Mark one inspected recovery step removed while already Cleaning.
    pub fn acknowledge_recovery_step(
        &mut self,
        operation_id: u32,
    ) -> Result<(), DurableJournalError> {
        if self.journal.phase != JournalPhase::Cleaning {
            return Err(DurableJournalError::InvalidPhase {
                expected: "cleaning phase",
                actual: self.journal.phase,
            });
        }
        let actual = self.operation_state(operation_id)?;
        if actual == OperationState::Removed {
            return Ok(());
        }
        self.commit(|journal| {
            journal.transition_operation(operation_id, OperationState::Removed)?;
            Ok(())
        })
    }

    pub fn remove_completed(self) -> Result<(), DurableJournalError> {
        self.store
            .remove_completed(self.journal.owner.session_id)
            .map_err(Into::into)
    }

    pub fn remove_completed_file(&mut self) -> Result<(), DurableJournalError> {
        self.store
            .remove_completed(self.journal.owner.session_id)
            .map_err(Into::into)
    }

    fn operation_state(&self, operation_id: u32) -> Result<OperationState, DurableJournalError> {
        self.journal
            .operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .map(|operation| operation.state)
            .ok_or(DurableJournalError::MissingLiveResource)
    }

    fn expect_state(
        &self,
        operation_id: u32,
        expected: OperationState,
    ) -> Result<(), DurableJournalError> {
        let actual = self.operation_state(operation_id)?;
        if actual == expected {
            Ok(())
        } else {
            Err(DurableJournalError::OperationState {
                operation_id,
                expected,
                actual,
            })
        }
    }
}

#[derive(Debug)]
pub enum LeaseError {
    Busy { path: PathBuf },
    HostState(HostStateError),
    Unsupported,
}

impl fmt::Display for LeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy { path } => {
                write!(formatter, "host-state lease is busy: {}", path.display())
            }
            Self::HostState(error) => error.fmt(formatter),
            Self::Unsupported => formatter.write_str("host-state flock lease is unsupported"),
        }
    }
}

impl std::error::Error for LeaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HostState(error) => Some(error),
            _ => None,
        }
    }
}

impl From<HostStateError> for LeaseError {
    fn from(error: HostStateError) -> Self {
        Self::HostState(error)
    }
}

pub struct HostStateLease {
    #[cfg(unix)]
    file: File,
    path: PathBuf,
    #[cfg(unix)]
    _anchor: Arc<StateDirectoryAnchor>,
}

impl fmt::Debug for HostStateLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostStateLease")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl HostStateLease {
    /// Acquire an exclusive process-lifetime lease without waiting. Busy is a
    /// distinct typed result so callers can map it to EX_TEMPFAIL (75) without
    /// mistaking it for an unsafe journal that should trigger recovery.
    #[cfg(unix)]
    pub fn try_acquire(path: impl Into<PathBuf>) -> Result<Self, LeaseError> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;

        let path = path.into();
        let expected_uid = effective_uid();
        let parent = state_parent(&path).map_err(LeaseError::HostState)?;
        let anchor = Arc::new(
            StateDirectoryAnchor::open(parent, expected_uid).map_err(LeaseError::HostState)?,
        );
        let name = c_component(
            path.file_name().ok_or_else(|| {
                LeaseError::HostState(HostStateError::UnsafeFile {
                    path: path.clone(),
                    reason: UnsafeFileReason::NotRegular,
                })
            })?,
            &path,
        )
        .map_err(LeaseError::HostState)?;

        let mut created = false;
        let file = match anchor.open_component(
            &name,
            &path,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            JOURNAL_MODE,
            "create anchored lease",
        ) {
            Ok(file) => {
                created = true;
                file.set_permissions(fs::Permissions::from_mode(JOURNAL_MODE))
                    .map_err(|error| {
                        LeaseError::HostState(HostStateError::io(
                            "chmod newly-created lease",
                            &path,
                            error,
                        ))
                    })?;
                file
            }
            Err(HostStateError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                anchor
                    .open_component(
                        &name,
                        &path,
                        libc::O_RDWR | libc::O_NONBLOCK,
                        0,
                        "open existing anchored lease",
                    )
                    .map_err(LeaseError::HostState)?
            }
            Err(error) => return Err(LeaseError::HostState(error)),
        };
        let metadata = file.metadata().map_err(|error| {
            LeaseError::HostState(HostStateError::io("stat opened lease", &path, error))
        })?;
        validate_opened_regular_file(&path, &metadata, expected_uid, JOURNAL_MODE)
            .map_err(LeaseError::HostState)?;
        let identity = FileObjectIdentity::from_metadata(&metadata);
        anchor
            .ensure_name_identity(&name, &path, identity)
            .map_err(LeaseError::HostState)?;

        // SAFETY: fd is valid for the call; flock has no pointer arguments.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Err(LeaseError::Busy { path });
            }
            return Err(LeaseError::HostState(HostStateError::io(
                "acquire lease",
                &path,
                error,
            )));
        }
        // Close the open-before-flock race: after the lock is held, the anchored
        // pathname must still resolve to the exact locked inode.
        anchor
            .ensure_name_identity(&name, &path, identity)
            .map_err(LeaseError::HostState)?;
        let after = file.metadata().map_err(|error| {
            LeaseError::HostState(HostStateError::io("restat locked lease", &path, error))
        })?;
        validate_opened_regular_file(&path, &after, expected_uid, JOURNAL_MODE)
            .map_err(LeaseError::HostState)?;
        if FileObjectIdentity::from_metadata(&after) != identity {
            return Err(LeaseError::HostState(HostStateError::UnsafeFile {
                path,
                reason: UnsafeFileReason::IdentityChanged,
            }));
        }
        if created {
            anchor.sync().map_err(LeaseError::HostState)?;
        }
        Ok(Self {
            file,
            path,
            _anchor: anchor,
        })
    }

    #[cfg(not(unix))]
    pub fn try_acquire(_path: impl Into<PathBuf>) -> Result<Self, LeaseError> {
        Err(LeaseError::Unsupported)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HostStateLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: fd remains valid throughout Drop; close would also release
            // the lock, but an explicit unlock makes the lifetime obvious.
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn capture_boot_id() -> Option<BootId> {
    #[cfg(target_os = "linux")]
    {
        let value = read_small_text(Path::new("/proc/sys/kernel/random/boot_id"), 128)?;
        let compact: String = value
            .trim()
            .chars()
            .filter(|character| *character != '-')
            .collect();
        BootId::parse_hex(&compact).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn capture_pid_start_ticks(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let path = PathBuf::from(format!("/proc/{pid}/stat"));
        let stat = read_small_text(&path, 16 * 1024)?;
        let close = stat.rfind(')')?;
        // The first token after the comm field is field 3 (state), therefore
        // zero-based token 19 is field 22 (starttime).
        stat.get(close + 1..)?
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn capture_namespace_identity(path: &str) -> Option<NamespaceIdentity> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).ok()?;
        Some(NamespaceIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

#[cfg(target_os = "linux")]
fn read_small_text(path: &Path, maximum: u64) -> Option<String> {
    let file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > maximum {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "shadowpipe-host-state-test-{}-{}",
                std::process::id(),
                SessionId::generate().expect("test entropy")
            ));
            fs::create_dir(&path).expect("create test directory");
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))
                .expect("chmod test directory");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn owner() -> OwnerIdentity {
        OwnerIdentity {
            session_id: SessionId::from_bytes([7; 16]),
            boot_id: Some(BootId::from_bytes([8; 16])),
            uid: effective_uid(),
            pid: 1234,
            pid_start_ticks: Some(9876),
            network_namespace: Some(NamespaceIdentity {
                device: 1,
                inode: 2,
            }),
            mount_namespace: Some(NamespaceIdentity {
                device: 1,
                inode: 3,
            }),
        }
    }

    fn interface() -> InterfaceIdentity {
        InterfaceIdentity {
            name: "sp0".into(),
            ifindex: 42,
        }
    }

    fn route(purpose: RoutePurpose) -> OwnedResource {
        let (address, prefix_len, gateway) = match purpose {
            RoutePurpose::SplitDefault => (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1, None),
            RoutePurpose::EndpointBypass | RoutePurpose::SshBypass => (
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                32,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            ),
        };
        OwnedResource::Route(RouteResource {
            purpose,
            family: AddressFamily::Ipv4,
            table: LINUX_MAIN_ROUTE_TABLE,
            destination: IpPrefix {
                address,
                prefix_len,
            },
            gateway,
            output: interface(),
            protocol: SHADOWPIPE_ROUTE_PROTOCOL,
            metric: 40_000,
        })
    }

    fn file_identity(inode: u64) -> FileIdentity {
        FileIdentity {
            device: 1,
            inode,
            uid: effective_uid(),
            gid: 0,
            mode: 0o100644,
            link_count: 1,
            kind: FileKind::Regular,
        }
    }

    fn dns() -> OwnedResource {
        OwnedResource::Dns(DnsResource {
            target: ResolverTarget::EtcResolvConf,
            original: file_identity(10),
            original_sha256: Some(Sha256Digest::from_bytes([8; 32])),
            pinned: file_identity(11),
            pinned_sha256: Sha256Digest::from_bytes([9; 32]),
        })
    }

    fn tun() -> OwnedResource {
        OwnedResource::Tun(TunResource {
            interface: interface(),
        })
    }

    fn firewall_with_token(family: AddressFamily, token: u8) -> OwnedResource {
        OwnedResource::Firewall(FirewallResource {
            family,
            backend: FirewallBackend::IptablesNft,
            chain_token: FirewallChainToken::from_bytes([token; 10]),
            filter_table_origin: FirewallTableOrigin::Preexisting,
            output_chain_origin: FirewallOutputChainOrigin::Preexisting,
            expected_rule_count: match family {
                AddressFamily::Ipv4 => IPV4_STATIC_FIREWALL_RULE_COUNT,
                AddressFamily::Ipv6 => IPV6_STATIC_FIREWALL_RULE_COUNT,
            },
        })
    }

    fn firewall(family: AddressFamily) -> OwnedResource {
        firewall_with_token(family, 4)
    }

    fn firewall_endpoint(address: &str, port: u16, transport: FirewallTransport) -> OwnedResource {
        let address: IpAddr = address.parse().expect("test IP address");
        OwnedResource::FirewallEndpoint(FirewallEndpointResource {
            family: if address.is_ipv4() {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            },
            backend: FirewallBackend::IptablesNft,
            chain_token: FirewallChainToken::from_bytes([4; 10]),
            address,
            transport,
            port,
        })
    }

    fn operation(id: u32, resource: OwnedResource) -> OperationRecord {
        OperationRecord {
            id,
            state: OperationState::Planned,
            resource,
        }
    }

    fn operation_in(id: u32, state: OperationState, resource: OwnedResource) -> OperationRecord {
        OperationRecord {
            id,
            state,
            resource,
        }
    }

    fn recovery_steps(
        journal: &HostStateJournalV1,
        observations: &[ResourceObservation],
    ) -> Vec<(u32, RecoveryAction)> {
        let RecoveryDecision::Execute(plan) =
            decide_recovery(journal, OwnerDisposition::Stale, observations)
                .expect("valid recovery decision")
        else {
            panic!("expected executable recovery plan")
        };
        plan.steps
            .into_iter()
            .map(|step| (step.operation_id, step.action))
            .collect()
    }

    fn sample_journal() -> HostStateJournalV1 {
        HostStateJournalV1::new(
            owner(),
            vec![operation(1, route(RoutePurpose::SplitDefault))],
        )
        .expect("valid journal")
    }

    fn write_secure(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(JOURNAL_MODE);
        }
        let mut file = options.open(path).expect("create fixture");
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(JOURNAL_MODE))
            .expect("chmod fixture");
        file.write_all(bytes).expect("write fixture");
        file.sync_all().expect("sync fixture");
    }

    #[test]
    fn schema_rejects_unknown_fields_at_top_and_nested_levels() {
        let mut value = serde_json::to_value(sample_journal()).expect("serialize fixture");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostStateJournalV1>(value).is_err());

        let mut value = serde_json::to_value(sample_journal()).expect("serialize fixture");
        value["owner"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostStateJournalV1>(value).is_err());

        let mut value = serde_json::to_value(sample_journal()).expect("serialize fixture");
        value["operations"][0]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostStateJournalV1>(value).is_err());

        let mut value = serde_json::to_value(sample_journal()).expect("serialize fixture");
        value["operations"][0]["resource"]["resource"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostStateJournalV1>(value).is_err());

        let endpoint = operation(
            2,
            firewall_endpoint("203.0.113.8", 8443, FirewallTransport::Udp),
        );
        let mut value = serde_json::to_value(endpoint).expect("serialize firewall endpoint");
        value["resource"]["resource"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<OperationRecord>(value).is_err());
    }

    #[test]
    fn schema_v3_round_trips_table_origin_and_explicitly_rejects_v1_v2() {
        assert_eq!(JOURNAL_SCHEMA_VERSION, 3);
        let journal = HostStateJournalV1::new(
            owner(),
            vec![
                operation(1, firewall(AddressFamily::Ipv4)),
                operation(
                    2,
                    firewall_endpoint("203.0.113.8", 8443, FirewallTransport::Udp),
                ),
            ],
        )
        .expect("valid endpoint journal");
        let encoded = serde_json::to_vec(&journal).expect("serialize v3 journal");
        let decoded: HostStateJournalV1 =
            serde_json::from_slice(&encoded).expect("deserialize v3 journal");
        assert_eq!(decoded, journal);
        decoded.validate().expect("validate v3 round trip");

        let mut obsolete_v2: serde_json::Value =
            serde_json::from_slice(&encoded).expect("decode v3 fixture");
        obsolete_v2["schema_version"] = serde_json::json!(2);
        let legacy_firewall = obsolete_v2["operations"][0]["resource"]["resource"]
            .as_object_mut()
            .unwrap();
        legacy_firewall.remove("filter_table_origin");
        legacy_firewall.remove("output_chain_origin");
        let obsolete_v2: HostStateJournalV1 =
            serde_json::from_value(obsolete_v2).expect("legacy v2 parses with unknown origin");
        let error = obsolete_v2.validate().expect_err("v2 must fail closed");
        assert!(error
            .to_string()
            .contains("unsupported host-state schema version 2"));

        let mut obsolete = journal;
        obsolete.schema_version = 1;
        let error = obsolete.validate().expect_err("v1 must fail closed");
        assert!(error
            .to_string()
            .contains("unsupported host-state schema version 1"));

        let directory = TestDirectory::new();
        let path = directory.join("obsolete-v1.json");
        write_secure(
            &path,
            &serde_json::to_vec(&obsolete).expect("serialize obsolete fixture"),
        );
        assert!(matches!(
            read_journal(&path),
            Err(HostStateError::InvalidJournal(_))
        ));
    }

    #[test]
    fn bounded_reader_rejects_truncated_and_oversized_input() {
        let directory = TestDirectory::new();
        let truncated = directory.join("truncated.json");
        write_secure(&truncated, br#"{"schema_version":1,"#);
        assert!(matches!(
            read_journal(&truncated),
            Err(HostStateError::Json(_))
        ));

        let oversized = directory.join("oversized.json");
        write_secure(&oversized, &vec![b' '; MAX_JOURNAL_BYTES as usize + 1]);
        assert!(matches!(
            read_journal(&oversized),
            Err(HostStateError::TooLarge { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reader_rejects_symlink_and_wrong_mode() {
        let directory = TestDirectory::new();
        let target = directory.join("target.json");
        write_secure(
            &target,
            &serde_json::to_vec(&sample_journal()).expect("serialize fixture"),
        );
        let link = directory.join("link.json");
        symlink(&target, &link).expect("create symlink");
        assert!(read_journal(&link).is_err());

        let wrong_mode = directory.join("wrong-mode.json");
        write_secure(
            &wrong_mode,
            &serde_json::to_vec(&sample_journal()).expect("serialize fixture"),
        );
        fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o644))
            .expect("set unsafe mode");
        assert!(matches!(
            read_journal(&wrong_mode),
            Err(HostStateError::UnsafeFile {
                reason: UnsafeFileReason::WrongMode { .. },
                ..
            })
        ));
    }

    #[test]
    fn metadata_validation_rejects_wrong_owner() {
        assert!(matches!(
            validate_security_values(Path::new("journal"), 1000, 0, 0o600, 0o600, 1),
            Err(HostStateError::UnsafeFile {
                reason: UnsafeFileReason::WrongOwner { .. },
                ..
            })
        ));
    }

    #[test]
    fn firewall_resources_require_static_counts_and_exact_chain_binding() {
        let mut bad_count = firewall(AddressFamily::Ipv4);
        let OwnedResource::Firewall(resource) = &mut bad_count else {
            unreachable!()
        };
        resource.expected_rule_count += 1;
        assert!(HostStateJournalV1::new(owner(), vec![operation(1, bad_count)]).is_err());

        let mut legacy_claims_absent = firewall(AddressFamily::Ipv4);
        let OwnedResource::Firewall(resource) = &mut legacy_claims_absent else {
            unreachable!()
        };
        resource.backend = FirewallBackend::IptablesLegacy;
        resource.filter_table_origin = FirewallTableOrigin::AbsentBeforeInstall;
        assert!(
            HostStateJournalV1::new(owner(), vec![operation(1, legacy_claims_absent)]).is_err()
        );

        HostStateJournalV1::new(owner(), vec![operation(1, firewall(AddressFamily::Ipv6))])
            .expect("IPv6 base uses its exact static count");

        let endpoint = firewall_endpoint("203.0.113.8", 443, FirewallTransport::Tcp);
        assert!(HostStateJournalV1::new(owner(), vec![operation(1, endpoint.clone())]).is_err());

        let mut wrong_chain = endpoint.clone();
        let OwnedResource::FirewallEndpoint(resource) = &mut wrong_chain else {
            unreachable!()
        };
        resource.chain_token = FirewallChainToken::from_bytes([9; 10]);
        assert!(HostStateJournalV1::new(
            owner(),
            vec![
                operation(1, firewall(AddressFamily::Ipv4)),
                operation(2, wrong_chain),
            ],
        )
        .is_err());

        let mut legacy_claims_output_absent = firewall(AddressFamily::Ipv4);
        let OwnedResource::Firewall(resource) = &mut legacy_claims_output_absent else {
            unreachable!()
        };
        resource.backend = FirewallBackend::IptablesLegacy;
        resource.output_chain_origin = FirewallOutputChainOrigin::AbsentBeforeInstall;
        assert!(
            HostStateJournalV1::new(owner(), vec![operation(1, legacy_claims_output_absent)])
                .is_err()
        );

        let mut wrong_family = endpoint.clone();
        let OwnedResource::FirewallEndpoint(resource) = &mut wrong_family else {
            unreachable!()
        };
        resource.family = AddressFamily::Ipv6;
        assert!(HostStateJournalV1::new(
            owner(),
            vec![
                operation(1, firewall(AddressFamily::Ipv4)),
                operation(2, wrong_family),
            ],
        )
        .is_err());

        let mut zero_port = endpoint;
        let OwnedResource::FirewallEndpoint(resource) = &mut zero_port else {
            unreachable!()
        };
        resource.port = 0;
        assert!(HostStateJournalV1::new(
            owner(),
            vec![
                operation(1, firewall(AddressFamily::Ipv4)),
                operation(2, zero_port),
            ],
        )
        .is_err());
    }

    #[test]
    fn operation_ids_are_contiguous_and_capacity_exhaustion_is_fail_closed() {
        assert!(HostStateJournalV1::new(
            owner(),
            vec![operation(2, route(RoutePurpose::SplitDefault))],
        )
        .is_err());
        assert!(HostStateJournalV1::new(
            owner(),
            vec![
                operation(1, route(RoutePurpose::SplitDefault)),
                operation(3, route(RoutePurpose::EndpointBypass)),
            ],
        )
        .is_err());

        let repeated = route(RoutePurpose::EndpointBypass);
        let operations: Vec<_> = (1..=(MAX_OPERATIONS + 1))
            .map(|id| {
                operation_in(
                    u32::try_from(id).unwrap(),
                    OperationState::Removed,
                    repeated.clone(),
                )
            })
            .collect();
        let error = HostStateJournalV1::new(owner(), operations)
            .expect_err("journal must not compact or reuse operation IDs");
        assert!(error.to_string().contains("maximum is 256"));
    }

    #[test]
    fn transition_rules_are_forward_only_and_phase_aware() {
        let mut journal = sample_journal();
        assert_eq!(
            journal.transition_phase(JournalPhase::Active),
            Err(TransitionError::ActiveWithIncompleteOperations)
        );
        journal
            .transition_operation(1, OperationState::Applied)
            .expect("apply planned operation");
        assert!(matches!(
            journal.transition_operation(1, OperationState::Planned),
            Err(TransitionError::IllegalOperation { .. })
        ));
        journal
            .transition_phase(JournalPhase::Active)
            .expect("activate complete journal");
        assert!(matches!(
            journal.transition_operation(1, OperationState::Removed),
            Err(TransitionError::OperationNotAllowedInPhase { .. })
        ));
        journal
            .transition_phase(JournalPhase::Cleaning)
            .expect("begin cleanup");
        journal
            .transition_operation(1, OperationState::Removed)
            .expect("remove while cleaning");
        assert!(matches!(
            journal.transition_operation(1, OperationState::Applied),
            Err(TransitionError::IllegalOperation { .. })
        ));
        assert!(!JournalPhase::Cleaning.can_transition_to(JournalPhase::Active));
        assert!(JournalPhase::Active.can_transition_to(JournalPhase::Preparing));
    }

    #[test]
    fn runtime_phase_edges_are_strict_durable_checkpoints() {
        let planned = sample_journal();
        let mut combined_activation = planned.clone();
        combined_activation.generation += 1;
        combined_activation.operations[0].state = OperationState::Applied;
        combined_activation.phase = JournalPhase::Active;
        assert!(
            planned.validate_successor(&combined_activation).is_err(),
            "Applied acknowledgement and Active checkpoint require separate generations"
        );

        let mut active = planned.clone();
        active.operations[0].state = OperationState::Applied;
        active.phase = JournalPhase::Active;
        active.validate().expect("valid active starting point");

        let mut smuggled_entry = active.clone();
        smuggled_entry.generation += 1;
        smuggled_entry.phase = JournalPhase::Preparing;
        smuggled_entry.operations[0].state = OperationState::Removed;
        assert!(active.validate_successor(&smuggled_entry).is_err());

        let mut appended_on_entry = active.clone();
        appended_on_entry.generation += 1;
        appended_on_entry.phase = JournalPhase::Preparing;
        appended_on_entry
            .operations
            .push(operation(2, route(RoutePurpose::EndpointBypass)));
        assert!(active.validate_successor(&appended_on_entry).is_err());

        let mut preparing = active.clone();
        preparing.generation += 1;
        preparing.phase = JournalPhase::Preparing;
        active
            .validate_successor(&preparing)
            .expect("Active to Preparing is a phase-only checkpoint");

        let mut removed = preparing.clone();
        removed.generation += 1;
        removed.operations[0].state = OperationState::Removed;
        preparing
            .validate_successor(&removed)
            .expect("runtime removal is acknowledged while Preparing");

        let mut active_removed = removed.clone();
        active_removed.generation += 1;
        active_removed.phase = JournalPhase::Active;
        removed
            .validate_successor(&active_removed)
            .expect("Removed history is valid at the later Active checkpoint");
        active_removed
            .validate()
            .expect("Active permits Removed records");

        let mut planned_active = active_removed;
        planned_active
            .operations
            .push(operation(2, route(RoutePurpose::EndpointBypass)));
        assert!(planned_active.validate().is_err());
    }

    #[test]
    fn durable_successor_cannot_retarget_or_smuggle_applied_operations() {
        let current = sample_journal();

        let mut retargeted = current.clone();
        retargeted.generation += 1;
        let OwnedResource::Route(route_spec) = &mut retargeted.operations[0].resource else {
            panic!("route fixture")
        };
        route_spec.metric += 1;
        assert!(current.validate_successor(&retargeted).is_err());

        let mut changed_owner = current.clone();
        changed_owner.generation += 1;
        changed_owner.owner.pid_start_ticks = Some(123);
        assert!(current.validate_successor(&changed_owner).is_err());

        let mut smuggled = current.clone();
        smuggled.generation += 1;
        smuggled.operations.push(OperationRecord {
            id: 2,
            state: OperationState::Applied,
            resource: route(RoutePurpose::EndpointBypass),
        });
        assert!(current.validate_successor(&smuggled).is_err());

        let mut planned = current.clone();
        planned.generation += 1;
        planned
            .operations
            .push(operation(2, route(RoutePurpose::EndpointBypass)));
        current
            .validate_successor(&planned)
            .expect("append-only planned operation is legal");
    }

    #[test]
    fn exact_resource_recurrence_requires_removed_history_and_allows_a_b_a() {
        let endpoint_a = firewall_endpoint("203.0.113.7", 443, FirewallTransport::Tcp);
        let endpoint_b = firewall_endpoint("203.0.113.8", 8443, FirewallTransport::Udp);

        let duplicate_live = HostStateJournalV1::new(
            owner(),
            vec![
                operation_in(1, OperationState::Applied, firewall(AddressFamily::Ipv4)),
                operation_in(2, OperationState::Applied, endpoint_a.clone()),
                operation(3, endpoint_a.clone()),
            ],
        );
        assert!(duplicate_live.is_err());

        let history = HostStateJournalV1::new(
            owner(),
            vec![
                operation_in(1, OperationState::Applied, firewall(AddressFamily::Ipv4)),
                operation_in(2, OperationState::Removed, endpoint_a.clone()),
                operation_in(3, OperationState::Removed, endpoint_b),
            ],
        )
        .expect("removed A and B history");
        let mut a_b_a = history.clone();
        a_b_a.generation += 1;
        a_b_a.operations.push(operation(4, endpoint_a));
        history
            .validate_successor(&a_b_a)
            .expect("an exact tuple may recur only through a fresh later record");
        assert_eq!(a_b_a.operations[3].id, 4);

        let mut nonchronological = a_b_a;
        nonchronological.operations[3].id = 3;
        assert!(nonchronological.validate().is_err());
    }

    #[test]
    fn singleton_limits_count_only_live_records() {
        let old_dns = dns();
        let mut new_dns = dns();
        let OwnedResource::Dns(resource) = &mut new_dns else {
            unreachable!()
        };
        resource.original = file_identity(20);
        resource.pinned = file_identity(21);
        resource.pinned_sha256 = Sha256Digest::from_bytes([10; 32]);

        let mut journal = HostStateJournalV1::new(
            owner(),
            vec![
                operation_in(1, OperationState::Removed, old_dns),
                operation_in(2, OperationState::Applied, new_dns.clone()),
                operation_in(
                    3,
                    OperationState::Removed,
                    firewall_with_token(AddressFamily::Ipv4, 3),
                ),
                operation_in(
                    4,
                    OperationState::Applied,
                    firewall_with_token(AddressFamily::Ipv4, 4),
                ),
            ],
        )
        .expect("historical singleton records do not consume live slots");
        journal.phase = JournalPhase::Active;
        journal
            .validate()
            .expect("Active accepts Applied and Removed records");

        let mut another_dns = new_dns;
        let OwnedResource::Dns(resource) = &mut another_dns else {
            unreachable!()
        };
        resource.original = file_identity(30);
        resource.pinned = file_identity(31);
        resource.pinned_sha256 = Sha256Digest::from_bytes([11; 32]);
        journal.operations.push(operation(5, another_dns));
        journal.phase = JournalPhase::Preparing;
        assert!(
            journal.validate().is_err(),
            "a second live DNS target is still rejected"
        );
    }

    #[test]
    fn recovery_requires_complete_inspection_and_orders_firewall_last() {
        let journal = HostStateJournalV1::new(
            owner(),
            vec![
                operation(1, firewall(AddressFamily::Ipv4)),
                operation(2, route(RoutePurpose::EndpointBypass)),
                operation(3, dns()),
                operation(4, route(RoutePurpose::SplitDefault)),
                operation(5, tun()),
                operation(
                    6,
                    firewall_endpoint("203.0.113.7", 443, FirewallTransport::Tcp),
                ),
            ],
        )
        .expect("valid journal");
        let incomplete = [ResourceObservation {
            operation_id: 1,
            kind: ResourceObservationKind::ExactOwnedPresent,
        }];
        assert_eq!(
            decide_recovery(&journal, OwnerDisposition::Stale, &incomplete),
            Err(RecoveryDecisionError::MissingObservations(vec![
                2, 3, 4, 5, 6
            ]))
        );

        let observations: Vec<_> = (1..=6)
            .map(|operation_id| ResourceObservation {
                operation_id,
                kind: ResourceObservationKind::ExactOwnedPresent,
            })
            .collect();
        let RecoveryDecision::Execute(plan) =
            decide_recovery(&journal, OwnerDisposition::Stale, &observations)
                .expect("complete decision")
        else {
            panic!("expected executable plan")
        };
        assert_eq!(plan.required_phase, JournalPhase::Cleaning);
        assert_eq!(
            plan.steps
                .iter()
                .map(|step| step.operation_id)
                .collect::<Vec<_>>(),
            vec![4, 3, 2, 5, 6, 1]
        );
    }

    #[test]
    fn dynamic_endpoint_wal_crash_boundaries_have_unambiguous_recovery() {
        let endpoint = firewall_endpoint("203.0.113.7", 443, FirewallTransport::Tcp);
        let mut active = HostStateJournalV1::new(
            owner(),
            vec![operation_in(
                1,
                OperationState::Applied,
                firewall(AddressFamily::Ipv4),
            )],
        )
        .expect("base firewall journal");
        active.phase = JournalPhase::Active;
        active.validate().expect("active base checkpoint");

        // Durable phase entry happens before either the planned record or the
        // kernel add. A crash here knows only about the base chain.
        let mut add_preparing = active.clone();
        add_preparing.generation += 1;
        add_preparing.phase = JournalPhase::Preparing;
        active
            .validate_successor(&add_preparing)
            .expect("persist add transaction entry");
        assert_eq!(
            recovery_steps(
                &add_preparing,
                &[ResourceObservation {
                    operation_id: 1,
                    kind: ResourceObservationKind::ExactOwnedPresent,
                }],
            ),
            vec![(1, RecoveryAction::RemoveExactOwned)]
        );

        let mut add_planned = add_preparing.clone();
        add_planned.generation += 1;
        add_planned.operations.push(operation(2, endpoint));
        add_preparing
            .validate_successor(&add_planned)
            .expect("persist exact endpoint before kernel add");

        // Before the add, Planned+Absent is safe. After a successful add but
        // before its acknowledgement, the same Planned record observes exact
        // presence and owns the inverse. Both plans are endpoint-before-base.
        let base_present = ResourceObservation {
            operation_id: 1,
            kind: ResourceObservationKind::ExactOwnedPresent,
        };
        assert_eq!(
            recovery_steps(
                &add_planned,
                &[
                    base_present,
                    ResourceObservation {
                        operation_id: 2,
                        kind: ResourceObservationKind::Absent,
                    },
                ],
            ),
            vec![
                (2, RecoveryAction::MarkAlreadyAbsent),
                (1, RecoveryAction::RemoveExactOwned),
            ]
        );
        assert_eq!(
            recovery_steps(
                &add_planned,
                &[
                    base_present,
                    ResourceObservation {
                        operation_id: 2,
                        kind: ResourceObservationKind::ExactOwnedPresent,
                    },
                ],
            ),
            vec![
                (2, RecoveryAction::RemoveExactOwned),
                (1, RecoveryAction::RemoveExactOwned),
            ]
        );

        let mut add_applied = add_planned.clone();
        add_applied.generation += 1;
        add_applied.operations[1].state = OperationState::Applied;
        add_planned
            .validate_successor(&add_applied)
            .expect("persist successful kernel add");
        let mut active_with_endpoint = add_applied.clone();
        active_with_endpoint.generation += 1;
        active_with_endpoint.phase = JournalPhase::Active;
        add_applied
            .validate_successor(&active_with_endpoint)
            .expect("publish separate Active checkpoint");

        // Removal starts only after depublish/drain in the coordinator. A crash
        // after exact kernel delete but before Removed persistence is represented
        // by Applied+Absent and therefore cannot resurrect the tuple.
        let mut remove_preparing = active_with_endpoint.clone();
        remove_preparing.generation += 1;
        remove_preparing.phase = JournalPhase::Preparing;
        active_with_endpoint
            .validate_successor(&remove_preparing)
            .expect("persist remove transaction entry");
        assert_eq!(
            recovery_steps(
                &remove_preparing,
                &[
                    base_present,
                    ResourceObservation {
                        operation_id: 2,
                        kind: ResourceObservationKind::Absent,
                    },
                ],
            ),
            vec![
                (2, RecoveryAction::MarkAlreadyAbsent),
                (1, RecoveryAction::RemoveExactOwned),
            ]
        );

        let mut removed = remove_preparing.clone();
        removed.generation += 1;
        removed.operations[1].state = OperationState::Removed;
        remove_preparing
            .validate_successor(&removed)
            .expect("persist exact endpoint removal");
        assert_eq!(
            recovery_steps(&removed, &[base_present]),
            vec![(1, RecoveryAction::RemoveExactOwned)]
        );
        assert_eq!(
            decide_recovery(
                &removed,
                OwnerDisposition::Stale,
                &[
                    base_present,
                    ResourceObservation {
                        operation_id: 2,
                        kind: ResourceObservationKind::Absent,
                    },
                ],
            ),
            Err(RecoveryDecisionError::ObservationForRemovedOperation(2))
        );

        let mut active_removed = removed.clone();
        active_removed.generation += 1;
        active_removed.phase = JournalPhase::Active;
        removed
            .validate_successor(&active_removed)
            .expect("publish removal Active checkpoint");
        active_removed
            .validate()
            .expect("Removed record remains durable and non-live");
    }

    #[test]
    fn one_conflict_suppresses_the_entire_removal_plan() {
        let journal = HostStateJournalV1::new(
            owner(),
            vec![
                operation(1, route(RoutePurpose::SplitDefault)),
                operation(2, firewall(AddressFamily::Ipv4)),
            ],
        )
        .expect("valid journal");
        let decision = decide_recovery(
            &journal,
            OwnerDisposition::Stale,
            &[
                ResourceObservation {
                    operation_id: 1,
                    kind: ResourceObservationKind::ExactOwnedPresent,
                },
                ResourceObservation {
                    operation_id: 2,
                    kind: ResourceObservationKind::Conflict,
                },
            ],
        )
        .expect("decision");
        assert_eq!(
            decision,
            RecoveryDecision::Refuse(RecoveryRefusal::ResourceConflict {
                operation_ids: vec![2]
            })
        );
    }

    #[test]
    fn free_lease_with_matching_process_is_ambiguous() {
        assert_eq!(
            classify_owner(OwnerEvidence {
                lease: LeaseEvidence::Available,
                boot: BootEvidence::Same,
                process: ProcessEvidence::MatchingStartTime,
                namespaces: NamespaceEvidence::Same,
            }),
            OwnerDisposition::Ambiguous
        );
        assert_eq!(
            classify_owner(OwnerEvidence {
                lease: LeaseEvidence::Available,
                boot: BootEvidence::Same,
                process: ProcessEvidence::PidReused,
                namespaces: NamespaceEvidence::Same,
            }),
            OwnerDisposition::Stale
        );
        assert_eq!(
            classify_owner(OwnerEvidence {
                lease: LeaseEvidence::Held,
                boot: BootEvidence::Different,
                process: ProcessEvidence::Missing,
                namespaces: NamespaceEvidence::NotApplicableAfterReboot,
            }),
            OwnerDisposition::Active
        );
        assert_eq!(
            classify_owner(OwnerEvidence {
                lease: LeaseEvidence::Available,
                boot: BootEvidence::Same,
                process: ProcessEvidence::Missing,
                namespaces: NamespaceEvidence::Different,
            }),
            OwnerDisposition::Ambiguous,
            "a dead same-boot PID cannot authorize recovery in another namespace"
        );
        assert_eq!(
            classify_owner(OwnerEvidence {
                lease: LeaseEvidence::Available,
                boot: BootEvidence::Different,
                process: ProcessEvidence::Unknown,
                namespaces: NamespaceEvidence::NotApplicableAfterReboot,
            }),
            OwnerDisposition::Stale,
            "namespace inode identities are intentionally ignored after reboot"
        );
    }

    #[test]
    fn journal_store_round_trip_is_atomic_and_generation_bound() {
        let directory = TestDirectory::new();
        let path = directory.join("host-state-v1.json");
        let store = JournalStore::new(&path);
        let mut journal = sample_journal();

        let mut wrong_writer = journal.clone();
        wrong_writer.owner.uid ^= 1;
        assert!(matches!(
            store.create(&wrong_writer),
            Err(HostStateError::InvalidJournal(_))
        ));
        assert!(!path.exists());

        store.create(&journal).expect("create journal");
        assert_eq!(store.load().expect("load journal"), journal);
        assert!(matches!(
            store.create(&journal),
            Err(HostStateError::AlreadyExists(_))
        ));

        journal
            .transition_operation(1, OperationState::Applied)
            .expect("apply operation");
        journal.next_generation().expect("advance generation");
        store.replace(&journal).expect("replace journal");
        assert_eq!(store.load().expect("load replacement"), journal);

        #[cfg(unix)]
        {
            let mode = fs::metadata(&path)
                .expect("stat journal")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, JOURNAL_MODE);
        }
    }

    #[test]
    fn maximal_operation_journals_fit_the_bounded_store() {
        use std::net::Ipv6Addr;

        let directory = TestDirectory::new();
        let maximally_escaped_name = "\u{1}".repeat(15);
        let maximal_route = OwnedResource::Route(RouteResource {
            purpose: RoutePurpose::EndpointBypass,
            family: AddressFamily::Ipv6,
            table: LINUX_MAIN_ROUTE_TABLE,
            destination: IpPrefix {
                address: IpAddr::V6(Ipv6Addr::from([0xff; 16])),
                prefix_len: 128,
            },
            gateway: Some(IpAddr::V6(Ipv6Addr::from([0xff; 16]))),
            output: InterfaceIdentity {
                name: maximally_escaped_name,
                ifindex: u32::MAX,
            },
            protocol: SHADOWPIPE_ROUTE_PROTOCOL,
            metric: u32::MAX,
        });
        let regular_mode_with_maximal_numeric_width = !0o170000u32 | 0o100000;
        let maximal_dns = OwnedResource::Dns(DnsResource {
            target: ResolverTarget::EtcResolvConf,
            original: FileIdentity {
                device: u64::MAX,
                inode: u64::MAX - 1,
                uid: u32::MAX,
                gid: u32::MAX,
                mode: regular_mode_with_maximal_numeric_width,
                link_count: u64::MAX,
                kind: FileKind::Regular,
            },
            original_sha256: Some(Sha256Digest::from_bytes([0xff; 32])),
            pinned: FileIdentity {
                device: u64::MAX,
                inode: u64::MAX,
                uid: effective_uid(),
                gid: u32::MAX,
                mode: regular_mode_with_maximal_numeric_width,
                link_count: u64::MAX,
                kind: FileKind::Regular,
            },
            pinned_sha256: Sha256Digest::from_bytes([0xff; 32]),
        });

        for (index, resource) in [maximal_route, maximal_dns].into_iter().enumerate() {
            let operations = (1..=MAX_OPERATIONS)
                .map(|id| OperationRecord {
                    id: u32::try_from(id).unwrap(),
                    state: OperationState::Removed,
                    resource: resource.clone(),
                })
                .collect();
            let mut maximal_owner = owner();
            maximal_owner.pid = u32::MAX;
            maximal_owner.pid_start_ticks = Some(u64::MAX);
            maximal_owner.network_namespace = Some(NamespaceIdentity {
                device: u64::MAX,
                inode: u64::MAX,
            });
            maximal_owner.mount_namespace = maximal_owner.network_namespace;
            let journal = HostStateJournalV1::new(maximal_owner, operations).unwrap();
            let mut capacity_probe = journal.clone();
            if !matches!(&resource, OwnedResource::Dns(_)) {
                capacity_probe.owner.uid = u32::MAX;
            }
            capacity_probe.generation = u64::MAX;
            let encoded =
                serialize_journal(&capacity_probe).expect("maximal journal must fit bounded store");
            assert!(
                encoded.len() > 64 * 1024,
                "fixture must cover the old undersized 64-KiB limit"
            );
            assert!(encoded.len() as u64 <= MAX_JOURNAL_BYTES);

            let store = JournalStore::new(directory.join(&format!("maximal-{index}-v2.json")));
            store.create(&journal).expect("persist maximal journal");
            let mut successor = journal.clone();
            successor.next_generation().unwrap();
            store
                .replace(&successor)
                .expect("replace maximal journal generation");
            assert_eq!(store.load().unwrap(), successor);
        }
    }

    #[cfg(unix)]
    #[test]
    fn journal_store_remains_bound_to_the_opened_directory_inode() {
        let root = TestDirectory::new();
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(STATE_DIRECTORY_MODE)).unwrap();
        let path = state.join("host-state-v2.json");
        let store = JournalStore::new(&path);
        let journal = sample_journal();
        store.create(&journal).unwrap();

        let moved = root.join("state-moved");
        fs::rename(&state, &moved).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(STATE_DIRECTORY_MODE)).unwrap();

        assert_eq!(store.load().unwrap(), journal);
        assert!(moved.join("host-state-v2.json").exists());
        assert!(
            !path.exists(),
            "replacement directory must not redirect the store"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn state_directory_walk_rejects_an_intermediate_symlink() {
        let root = TestDirectory::new();
        let real = root.join("real-state");
        let redirected = root.join("redirected-state");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(STATE_DIRECTORY_MODE)).unwrap();
        symlink(&real, &redirected).unwrap();

        let store = JournalStore::new(redirected.join("host-state-v2.json"));
        assert!(matches!(
            store.create(&sample_journal()),
            Err(HostStateError::Io { .. })
        ));
        assert!(
            !real.join("host-state-v2.json").exists(),
            "intermediate symlink must never redirect journal creation"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replace_refuses_a_swapped_target_without_clobbering_it() {
        let directory = TestDirectory::new();
        let path = directory.join("replace-swap-v2.json");
        let original = directory.join("replace-swap-original.json");
        let store = JournalStore::new(&path);
        let journal = sample_journal();
        store.create(&journal).unwrap();
        let mut successor = journal.clone();
        successor.next_generation().unwrap();
        let foreign = b"foreign replacement must survive";

        let error = store
            .replace_anchored_with_hook(&successor, || {
                fs::rename(&path, &original).unwrap();
                write_secure(&path, foreign);
            })
            .expect_err("swapped journal target must be refused");
        assert!(matches!(
            error,
            HostStateError::UnsafeFile {
                reason: UnsafeFileReason::IdentityChanged,
                ..
            }
        ));
        assert_eq!(fs::read(&path).unwrap(), foreign);
        assert_eq!(read_journal(&original).unwrap(), journal);
    }

    #[cfg(unix)]
    #[test]
    fn pending_temp_drop_never_unlinks_a_swapped_foreign_name() {
        let directory = TestDirectory::new();
        let path = directory.join("temp-swap-v2.json");
        let store = JournalStore::new(&path);
        let journal = sample_journal();
        store.create(&journal).unwrap();
        let mut successor = journal.clone();
        successor.next_generation().unwrap();
        let foreign = b"foreign temp must survive";
        let mut swapped_temp = None;

        let error = store
            .replace_anchored_with_hook(&successor, || {
                let temp = fs::read_dir(&directory.path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|candidate| {
                        candidate
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.starts_with(".shadowpipe-journal."))
                    })
                    .expect("staged journal temp");
                fs::remove_file(&temp).unwrap();
                write_secure(&temp, foreign);
                swapped_temp = Some(temp);
            })
            .expect_err("swapped temp target must be refused");
        assert!(matches!(
            error,
            HostStateError::UnsafeFile {
                reason: UnsafeFileReason::IdentityChanged,
                ..
            }
        ));
        let swapped_temp = swapped_temp.unwrap();
        assert_eq!(fs::read(swapped_temp).unwrap(), foreign);
        assert_eq!(store.load().unwrap(), journal);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completed_remove_refuses_a_swapped_target_without_unlinking_it() {
        let directory = TestDirectory::new();
        let path = directory.join("remove-swap-v2.json");
        let original = directory.join("remove-swap-original.json");
        let store = JournalStore::new(&path);
        let mut journal = sample_journal();
        journal
            .transition_operation(1, OperationState::Removed)
            .unwrap();
        journal.transition_phase(JournalPhase::Cleaning).unwrap();
        store.create(&journal).unwrap();
        let foreign = b"foreign completed target must survive";

        let error = store
            .remove_completed_anchored_with_hook(journal.owner.session_id, || {
                fs::rename(&path, &original).unwrap();
                write_secure(&path, foreign);
            })
            .expect_err("swapped completed journal must be refused");
        assert!(matches!(
            error,
            HostStateError::UnsafeFile {
                reason: UnsafeFileReason::IdentityChanged,
                ..
            }
        ));
        assert_eq!(fs::read(&path).unwrap(), foreign);
        assert_eq!(read_journal(&original).unwrap(), journal);
    }

    #[test]
    fn durable_runtime_wals_add_and_remove_before_acknowledgement() {
        let directory = TestDirectory::new();
        let path = directory.join("runtime-v2.json");
        let store = JournalStore::new(&path);
        let resource = route(RoutePurpose::EndpointBypass);
        let mut runtime = DurableHostJournal::create(store.clone(), owner()).unwrap();
        assert_eq!(runtime.journal().phase, JournalPhase::Preparing);
        assert!(runtime.journal().operations.is_empty());

        let id = runtime.begin_add(resource.clone()).unwrap();
        let persisted = store.load().unwrap();
        assert_eq!(persisted.operations[0].state, OperationState::Planned);
        assert_eq!(persisted.phase, JournalPhase::Preparing);

        runtime.acknowledge_add(id).unwrap();
        assert_eq!(
            store.load().unwrap().operations[0].state,
            OperationState::Applied
        );
        runtime.publish_active().unwrap();
        assert_eq!(store.load().unwrap().phase, JournalPhase::Active);

        let remove_id = runtime.begin_remove(&resource).unwrap();
        assert_eq!(remove_id, id);
        assert_eq!(store.load().unwrap().phase, JournalPhase::Preparing);
        runtime.acknowledge_remove(id).unwrap();
        runtime.publish_active().unwrap();
        let persisted = store.load().unwrap();
        assert_eq!(persisted.operations[0].state, OperationState::Removed);
        assert_eq!(persisted.phase, JournalPhase::Active);

        runtime.begin_cleaning().unwrap();
        runtime.remove_completed().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn durable_runtime_reload_preserves_every_crash_boundary() {
        let directory = TestDirectory::new();
        let path = directory.join("crash-boundaries-v2.json");
        let store = JournalStore::new(&path);
        let resource = route(RoutePurpose::EndpointBypass);
        let mut first = DurableHostJournal::create(store.clone(), owner()).unwrap();
        let id = first.begin_add(resource.clone()).unwrap();
        drop(first);

        let mut after_planned = DurableHostJournal::load(store.clone()).unwrap();
        assert_eq!(
            after_planned.journal().operations[0].state,
            OperationState::Planned
        );
        after_planned.acknowledge_add(id).unwrap();
        drop(after_planned);

        let mut after_applied = DurableHostJournal::load(store.clone()).unwrap();
        assert_eq!(after_applied.journal().phase, JournalPhase::Preparing);
        assert_eq!(
            after_applied.journal().operations[0].state,
            OperationState::Applied
        );
        after_applied.publish_active().unwrap();
        after_applied.begin_remove(&resource).unwrap();
        drop(after_applied);

        let after_remove_intent = DurableHostJournal::load(store).unwrap();
        assert_eq!(after_remove_intent.journal().phase, JournalPhase::Preparing);
        assert_eq!(
            after_remove_intent.journal().operations[0].state,
            OperationState::Applied
        );
    }

    #[test]
    fn durable_runtime_rejects_duplicate_live_resource_and_false_ack() {
        let directory = TestDirectory::new();
        let store = JournalStore::new(directory.join("reject-v2.json"));
        let resource = route(RoutePurpose::EndpointBypass);
        let mut runtime = DurableHostJournal::create(store.clone(), owner()).unwrap();
        let id = runtime.begin_add(resource.clone()).unwrap();
        assert!(runtime.acknowledge_remove(id).is_err());
        runtime.acknowledge_add(id).unwrap();
        runtime.publish_active().unwrap();
        assert!(runtime.begin_add(resource.clone()).is_err());
        assert_eq!(runtime.journal().phase, JournalPhase::Active);
        assert_eq!(store.load().unwrap().phase, JournalPhase::Active);
        assert!(runtime
            .begin_remove(&route(RoutePurpose::SshBypass))
            .is_err());
    }

    #[test]
    fn active_compaction_discards_only_removed_history() {
        let directory = TestDirectory::new();
        let store = JournalStore::new(directory.join("compact-v2.json"));
        let first = route(RoutePurpose::EndpointBypass);
        let second = route(RoutePurpose::SshBypass);
        let mut runtime = DurableHostJournal::create(store, owner()).unwrap();
        let first_id = runtime.begin_add(first.clone()).unwrap();
        runtime.acknowledge_add(first_id).unwrap();
        runtime.publish_active().unwrap();
        runtime.begin_remove(&first).unwrap();
        runtime.acknowledge_remove(first_id).unwrap();
        runtime.publish_active().unwrap();
        let second_id = runtime.begin_add(second.clone()).unwrap();
        runtime.acknowledge_add(second_id).unwrap();
        runtime.publish_active().unwrap();

        assert!(runtime.compact_removed().unwrap());
        assert_eq!(runtime.journal().operations.len(), 1);
        assert_eq!(runtime.journal().operations[0].id, 1);
        assert_eq!(runtime.journal().operations[0].resource, second);
        assert_eq!(
            runtime.journal().operations[0].state,
            OperationState::Applied
        );
    }

    #[test]
    fn repeated_dynamic_reappearance_compacts_before_capacity_exhaustion() {
        let directory = TestDirectory::new();
        let store = JournalStore::new(directory.join("churn-v2.json"));
        let resource = route(RoutePurpose::EndpointBypass);
        let mut runtime = DurableHostJournal::create(store, owner()).unwrap();
        for _ in 0..(MAX_OPERATIONS + 20) {
            let id = runtime.begin_add(resource.clone()).unwrap();
            runtime.acknowledge_add(id).unwrap();
            runtime.publish_active().unwrap();
            runtime.begin_remove(&resource).unwrap();
            runtime.acknowledge_remove(id).unwrap();
            runtime.publish_active().unwrap();
        }
        assert!(runtime.journal().operations.len() < MAX_OPERATIONS);
        assert!(runtime
            .journal()
            .operations
            .iter()
            .all(|operation| operation.state == OperationState::Removed));
    }

    #[cfg(unix)]
    #[test]
    fn lease_is_nonblocking_and_busy_is_typed() {
        let directory = TestDirectory::new();
        let path = directory.join("host.lock");
        let first = HostStateLease::try_acquire(&path).expect("first lease");
        assert!(matches!(
            HostStateLease::try_acquire(&path),
            Err(LeaseError::Busy { .. })
        ));
        drop(first);
        HostStateLease::try_acquire(&path).expect("lease after release");
    }
}
