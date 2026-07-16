//! Bounded network-change triggers and a read-only Linux event source.
//!
//! Notifications in this module are deliberately **not authoritative host
//! state**. A consumer must treat every returned change as a wake-up trigger,
//! discard any cached observation, and freshly observe interfaces, addresses,
//! routes, and DNS before asking the platform reconciliation contract for a
//! decision.
//!
//! The Linux decoder and socket adapter are a clean-room implementation based
//! only on the public Linux UAPI in `<linux/netlink.h>` and
//! `<linux/rtnetlink.h>`. It does not copy implementation code from sing-box,
//! Xray, or another userspace network stack.

use std::error::Error;
use std::fmt;

use crate::platform::NetworkChangeKind;
use crate::routes::SHADOWPIPE_ROUTE_PROTOCOL;

/// Hard cap for one kernel netlink datagram.
///
/// The Linux reader owns exactly one buffer of this size and never allocates
/// based on a length supplied by the kernel.
pub const MAX_NETLINK_DATAGRAM_BYTES: usize = 64 * 1024;

const NLMSG_ALIGN_TO: usize = 4;
const NLMSG_HEADER_BYTES: usize = 16;
const RTATTR_HEADER_BYTES: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;
const IFINFO_MESSAGE_BYTES: usize = 16;
const IFINFO_CHANGE_OFFSET: usize = 12;
const IFADDR_MESSAGE_BYTES: usize = 8;
const ROUTE_MESSAGE_BYTES: usize = 12;
const FIB_RULE_HEADER_BYTES: usize = 12;
const RTA_TABLE: u16 = 15;
const RT_TABLE_COMPAT: u32 = 252;
const RT_TABLE_MAIN: u32 = 254;

// Public Linux UAPI message values from <linux/netlink.h> and
// <linux/rtnetlink.h>. They remain local constants so the pure decoder is
// testable on non-Linux hosts.
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const LINUX_AF_INET: u8 = 2;
const LINUX_AF_INET6: u8 = 10;
// Public IFF_PROMISC bit from <linux/if.h>. AF_PACKET observers such as
// tcpdump temporarily change only this flag when entering/leaving promiscuous
// mode. Linux emits RTM_NEWLINK for that observer refcount transition even
// though interface membership, carrier, addresses, and routing are unchanged.
const LINUX_IFF_PROMISC: u32 = 0x0100;

// Public multicast masks from <linux/rtnetlink.h>. Linux exposes IPv6 rule
// notifications as RTNLGRP_IPV6_RULE (group 19) but does not define a legacy
// RTMGRP_IPV6_RULE macro, so its nl_groups bit is derived from that public UAPI
// group number.
#[cfg(any(test, target_os = "linux"))]
const RTMGRP_LINK: u32 = 0x0001;
#[cfg(any(test, target_os = "linux"))]
const RTMGRP_IPV4_IFADDR: u32 = 0x0010;
#[cfg(any(test, target_os = "linux"))]
const RTMGRP_IPV4_ROUTE: u32 = 0x0040;
#[cfg(any(test, target_os = "linux"))]
const RTMGRP_IPV4_RULE: u32 = 0x0080;
#[cfg(any(test, target_os = "linux"))]
const RTMGRP_IPV6_IFADDR: u32 = 0x0100;
#[cfg(any(test, target_os = "linux"))]
const RTMGRP_IPV6_ROUTE: u32 = 0x0400;
#[cfg(any(test, target_os = "linux"))]
const RTNLGRP_IPV6_RULE: u32 = 19;
#[cfg(any(test, target_os = "linux"))]
const RTMGRP_IPV6_RULE: u32 = 1 << (RTNLGRP_IPV6_RULE - 1);

/// Address-family scope for Linux underlay invalidation notifications.
///
/// IPv4-only clients deliberately avoid subscribing to IPv6 address, route,
/// and policy-rule groups. A future dual-stack underlay can opt into all three
/// IPv6 groups without changing decoder semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxNetworkEventInterest {
    Ipv4UnderlayOnly,
    DualStack,
}

#[cfg(any(test, target_os = "linux"))]
const fn rtnetlink_subscription_groups(interest: LinuxNetworkEventInterest) -> u32 {
    let ipv4 = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE;
    match interest {
        LinuxNetworkEventInterest::Ipv4UnderlayOnly => ipv4,
        LinuxNetworkEventInterest::DualStack => {
            ipv4 | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_RULE
        }
    }
}

const NETWORK_CHANGE_KINDS: [NetworkChangeKind; 10] = [
    NetworkChangeKind::InitialObservation,
    NetworkChangeKind::InterfaceSetChanged,
    NetworkChangeKind::InterfaceAddressChanged,
    NetworkChangeKind::DefaultRouteChanged,
    NetworkChangeKind::RoutingPolicyChanged,
    NetworkChangeKind::OwnedRouteChanged,
    NetworkChangeKind::DnsConfigurationChanged,
    NetworkChangeKind::ConnectivityChanged,
    NetworkChangeKind::Suspend,
    NetworkChangeKind::Resume,
];

const fn kind_bit(kind: NetworkChangeKind) -> u16 {
    match kind {
        NetworkChangeKind::InitialObservation => 1 << 0,
        NetworkChangeKind::InterfaceSetChanged => 1 << 1,
        NetworkChangeKind::InterfaceAddressChanged => 1 << 2,
        NetworkChangeKind::DefaultRouteChanged => 1 << 3,
        NetworkChangeKind::RoutingPolicyChanged => 1 << 4,
        NetworkChangeKind::OwnedRouteChanged => 1 << 5,
        NetworkChangeKind::DnsConfigurationChanged => 1 << 6,
        NetworkChangeKind::ConnectivityChanged => 1 << 7,
        NetworkChangeKind::Suspend => 1 << 8,
        NetworkChangeKind::Resume => 1 << 9,
    }
}

/// Fixed-capacity set of coalesced change triggers.
///
/// Its storage is always two bytes. Repeated notifications set an existing bit
/// instead of creating an unbounded queue.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NetworkChangeSet {
    bits: u16,
}

impl NetworkChangeSet {
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    pub const fn one(kind: NetworkChangeKind) -> Self {
        Self {
            bits: kind_bit(kind),
        }
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    pub const fn len(self) -> usize {
        self.bits.count_ones() as usize
    }

    pub const fn contains(self, kind: NetworkChangeKind) -> bool {
        self.bits & kind_bit(kind) != 0
    }

    pub fn insert(&mut self, kind: NetworkChangeKind) -> bool {
        let bit = kind_bit(kind);
        let was_absent = self.bits & bit == 0;
        self.bits |= bit;
        was_absent
    }

    pub fn union_with(&mut self, other: Self) {
        self.bits |= other.bits;
    }

    pub fn iter(self) -> impl Iterator<Item = NetworkChangeKind> {
        NETWORK_CHANGE_KINDS
            .into_iter()
            .filter(move |kind| self.contains(*kind))
    }
}

impl From<NetworkChangeKind> for NetworkChangeSet {
    fn from(value: NetworkChangeKind) -> Self {
        Self::one(value)
    }
}

impl FromIterator<NetworkChangeKind> for NetworkChangeSet {
    fn from_iter<T: IntoIterator<Item = NetworkChangeKind>>(iter: T) -> Self {
        let mut changes = Self::new();
        for kind in iter {
            changes.insert(kind);
        }
        changes
    }
}

/// Monotonic generation assigned to accepted network-change triggers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkEventGeneration(u64);

impl NetworkEventGeneration {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A bounded batch of wake-up triggers.
///
/// This value is evidence that a prior host observation may be stale. It is
/// never evidence that a specific interface, address, or route currently
/// exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoalescedNetworkChanges {
    generation: NetworkEventGeneration,
    changes: NetworkChangeSet,
}

impl CoalescedNetworkChanges {
    pub const fn generation(self) -> NetworkEventGeneration {
        self.generation
    }

    pub const fn changes(self) -> NetworkChangeSet {
        self.changes
    }
}

/// Terminal error for a coalescer whose generation can no longer advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkChangeAccumulatorError {
    GenerationOverflow,
}

impl fmt::Display for NetworkChangeAccumulatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationOverflow => formatter.write_str("network event generation overflow"),
        }
    }
}

impl Error for NetworkChangeAccumulatorError {}

/// Fixed-capacity dirty accumulator.
///
/// Each non-empty [`mark_dirty`](Self::mark_dirty) call advances the
/// generation exactly once, even if every kind was already pending. Overflow
/// permanently poisons the accumulator so callers cannot accidentally process
/// an ambiguous generation.
#[derive(Debug, Default)]
pub struct NetworkChangeAccumulator {
    generation: NetworkEventGeneration,
    pending: NetworkChangeSet,
    poisoned: bool,
}

impl NetworkChangeAccumulator {
    pub const fn new() -> Self {
        Self {
            generation: NetworkEventGeneration::new(0),
            pending: NetworkChangeSet::new(),
            poisoned: false,
        }
    }

    pub const fn with_generation(generation: NetworkEventGeneration) -> Self {
        Self {
            generation,
            pending: NetworkChangeSet::new(),
            poisoned: false,
        }
    }

    pub const fn generation(&self) -> NetworkEventGeneration {
        self.generation
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Coalesce a non-empty group of triggers and advance its generation.
    ///
    /// Passing an empty set is a no-op. A source can therefore decode an
    /// irrelevant but valid datagram without causing unnecessary observation.
    pub fn mark_dirty(
        &mut self,
        changes: NetworkChangeSet,
    ) -> Result<NetworkEventGeneration, NetworkChangeAccumulatorError> {
        if self.poisoned {
            return Err(NetworkChangeAccumulatorError::GenerationOverflow);
        }
        if changes.is_empty() {
            return Ok(self.generation);
        }

        let Some(next) = self.generation.get().checked_add(1) else {
            self.poisoned = true;
            return Err(NetworkChangeAccumulatorError::GenerationOverflow);
        };
        self.generation = NetworkEventGeneration::new(next);
        self.pending.union_with(changes);
        Ok(self.generation)
    }

    pub fn mark(
        &mut self,
        kind: NetworkChangeKind,
    ) -> Result<NetworkEventGeneration, NetworkChangeAccumulatorError> {
        self.mark_dirty(NetworkChangeSet::one(kind))
    }

    /// Drain the current dirty set without resetting the monotonic generation.
    pub fn take_pending(
        &mut self,
    ) -> Result<Option<CoalescedNetworkChanges>, NetworkChangeAccumulatorError> {
        if self.poisoned {
            return Err(NetworkChangeAccumulatorError::GenerationOverflow);
        }
        if self.pending.is_empty() {
            return Ok(None);
        }

        let changes = std::mem::take(&mut self.pending);
        Ok(Some(CoalescedNetworkChanges {
            generation: self.generation,
            changes,
        }))
    }
}

/// Structural error in one Linux rtnetlink notification datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkDecodeError {
    EmptyDatagram,
    DatagramTooLarge {
        length: usize,
        maximum: usize,
    },
    TruncatedHeader {
        offset: usize,
        remaining: usize,
    },
    InvalidMessageLength {
        offset: usize,
        length: usize,
    },
    TruncatedMessage {
        offset: usize,
        declared: usize,
        remaining: usize,
    },
    TruncatedPayload {
        message_type: u16,
        expected: usize,
        actual: usize,
    },
    InvalidAttributeLength {
        message_type: u16,
        offset: usize,
        length: usize,
    },
    TruncatedAttribute {
        message_type: u16,
        offset: usize,
        declared: usize,
        remaining: usize,
    },
    DuplicateAttribute {
        message_type: u16,
        attribute_type: u16,
    },
    ConflictingRouteTable {
        header_table: u32,
        attribute_table: u32,
    },
    KernelError(i32),
    KernelOverrun,
}

impl fmt::Display for NetlinkDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatagram => formatter.write_str("empty rtnetlink datagram"),
            Self::DatagramTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "rtnetlink datagram is {length} bytes, maximum is {maximum}"
                )
            }
            Self::TruncatedHeader { offset, remaining } => write!(
                formatter,
                "truncated rtnetlink header at byte {offset}: {remaining} bytes remain"
            ),
            Self::InvalidMessageLength { offset, length } => write!(
                formatter,
                "invalid rtnetlink message length {length} at byte {offset}"
            ),
            Self::TruncatedMessage {
                offset,
                declared,
                remaining,
            } => write!(
                formatter,
                "truncated rtnetlink message at byte {offset}: declares {declared} bytes, {remaining} remain"
            ),
            Self::TruncatedPayload {
                message_type,
                expected,
                actual,
            } => write!(
                formatter,
                "rtnetlink type {message_type} payload is {actual} bytes, expected at least {expected}"
            ),
            Self::InvalidAttributeLength {
                message_type,
                offset,
                length,
            } => write!(
                formatter,
                "rtnetlink type {message_type} attribute at byte {offset} has invalid length {length}"
            ),
            Self::TruncatedAttribute {
                message_type,
                offset,
                declared,
                remaining,
            } => write!(
                formatter,
                "rtnetlink type {message_type} attribute at byte {offset} declares {declared} bytes, {remaining} remain"
            ),
            Self::DuplicateAttribute {
                message_type,
                attribute_type,
            } => write!(
                formatter,
                "rtnetlink type {message_type} repeats attribute type {attribute_type}"
            ),
            Self::ConflictingRouteTable {
                header_table,
                attribute_table,
            } => write!(
                formatter,
                "rtnetlink route table differs between rtmsg ({header_table}) and RTA_TABLE ({attribute_table})"
            ),
            Self::KernelError(code) => {
                write!(formatter, "kernel returned rtnetlink error {code}")
            }
            Self::KernelOverrun => formatter.write_str("kernel reported rtnetlink overrun"),
        }
    }
}

impl Error for NetlinkDecodeError {}

fn read_u16_ne(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

fn read_u32_ne(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_i32_ne(bytes: &[u8]) -> i32 {
    i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn link_notification_is_promiscuity_only(message_type: u16, payload: &[u8]) -> bool {
    // struct ifinfomsg stores ifi_change at bytes 12..16. Do not use the
    // IFLA_PROMISCUITY attribute as a delta: it reports the current refcount.
    // RTM_DELLINK is always significant, and zero, all-ones, or mixed change
    // masks remain conservative invalidations.
    message_type == RTM_NEWLINK
        && read_u32_ne(&payload[IFINFO_CHANGE_OFFSET..IFINFO_CHANGE_OFFSET + size_of::<u32>()])
            == LINUX_IFF_PROMISC
}

fn align4(length: usize) -> Option<usize> {
    length
        .checked_add(NLMSG_ALIGN_TO - 1)
        .map(|value| value & !(NLMSG_ALIGN_TO - 1))
}

fn validate_attributes(
    message_type: u16,
    payload: &[u8],
    fixed_bytes: usize,
) -> Result<(), NetlinkDecodeError> {
    if payload.len() < fixed_bytes {
        return Err(NetlinkDecodeError::TruncatedPayload {
            message_type,
            expected: fixed_bytes,
            actual: payload.len(),
        });
    }

    let mut offset = fixed_bytes;
    while offset < payload.len() {
        let remaining = payload.len() - offset;
        if remaining < RTATTR_HEADER_BYTES {
            return Err(NetlinkDecodeError::TruncatedAttribute {
                message_type,
                offset,
                declared: RTATTR_HEADER_BYTES,
                remaining,
            });
        }

        let length = usize::from(read_u16_ne(&payload[offset..offset + 2]));
        if length < RTATTR_HEADER_BYTES {
            return Err(NetlinkDecodeError::InvalidAttributeLength {
                message_type,
                offset,
                length,
            });
        }
        if length > remaining {
            return Err(NetlinkDecodeError::TruncatedAttribute {
                message_type,
                offset,
                declared: length,
                remaining,
            });
        }

        let Some(aligned) = align4(length) else {
            return Err(NetlinkDecodeError::InvalidAttributeLength {
                message_type,
                offset,
                length,
            });
        };
        let Some(next) = offset.checked_add(aligned) else {
            return Err(NetlinkDecodeError::InvalidAttributeLength {
                message_type,
                offset,
                length,
            });
        };
        if next > payload.len() {
            // The final attribute may omit alignment padding because its
            // declared length still provides an unambiguous endpoint.
            if offset + length == payload.len() {
                return Ok(());
            }
            return Err(NetlinkDecodeError::TruncatedAttribute {
                message_type,
                offset,
                declared: aligned,
                remaining,
            });
        }
        offset = next;
    }
    Ok(())
}

fn route_table_id(message_type: u16, payload: &[u8]) -> Result<u32, NetlinkDecodeError> {
    let header_table = u32::from(payload[4]);
    let mut attribute_table = None;
    let mut offset = ROUTE_MESSAGE_BYTES;

    while offset < payload.len() {
        let length = usize::from(read_u16_ne(&payload[offset..offset + 2]));
        let attribute_type = read_u16_ne(&payload[offset + 2..offset + 4]) & NLA_TYPE_MASK;
        if attribute_type == RTA_TABLE {
            if length != RTATTR_HEADER_BYTES + size_of::<u32>() {
                return Err(NetlinkDecodeError::InvalidAttributeLength {
                    message_type,
                    offset,
                    length,
                });
            }
            let table = read_u32_ne(
                &payload
                    [offset + RTATTR_HEADER_BYTES..offset + RTATTR_HEADER_BYTES + size_of::<u32>()],
            );
            if attribute_table.replace(table).is_some() {
                return Err(NetlinkDecodeError::DuplicateAttribute {
                    message_type,
                    attribute_type,
                });
            }
        }

        let aligned = align4(length).expect("validated route attribute length aligns");
        if offset + aligned > payload.len() {
            break;
        }
        offset += aligned;
    }

    if let Some(attribute_table) = attribute_table {
        if header_table != 0 && header_table != RT_TABLE_COMPAT && header_table != attribute_table {
            return Err(NetlinkDecodeError::ConflictingRouteTable {
                header_table,
                attribute_table,
            });
        }
        Ok(attribute_table)
    } else {
        Ok(header_table)
    }
}

/// Decode one Linux `NETLINK_ROUTE` multicast datagram into bounded triggers.
///
/// This is pure and portable so malformed-input tests run on macOS and
/// Windows. Link and address messages trigger fresh observation except for an
/// exact `RTM_NEWLINK` `IFF_PROMISC`-only observer transition. Every IPv4/IPv6
/// route change invalidates cached routing state: external `/0` changes are
/// classified as default-route changes, external non-default prefixes as
/// connectivity changes, and protocol-186 routes separately so a caller may
/// suppress only an exactly revalidated owned mutation. Policy-rule messages
/// have their own invalidation class.
pub fn decode_rtnetlink_datagram(datagram: &[u8]) -> Result<NetworkChangeSet, NetlinkDecodeError> {
    if datagram.is_empty() {
        return Err(NetlinkDecodeError::EmptyDatagram);
    }
    if datagram.len() > MAX_NETLINK_DATAGRAM_BYTES {
        return Err(NetlinkDecodeError::DatagramTooLarge {
            length: datagram.len(),
            maximum: MAX_NETLINK_DATAGRAM_BYTES,
        });
    }

    let mut changes = NetworkChangeSet::new();
    let mut offset = 0usize;
    while offset < datagram.len() {
        let remaining = datagram.len() - offset;
        if remaining < NLMSG_HEADER_BYTES {
            return Err(NetlinkDecodeError::TruncatedHeader { offset, remaining });
        }

        let message_length = read_u32_ne(&datagram[offset..offset + 4]) as usize;
        if message_length < NLMSG_HEADER_BYTES {
            return Err(NetlinkDecodeError::InvalidMessageLength {
                offset,
                length: message_length,
            });
        }
        if message_length > remaining {
            return Err(NetlinkDecodeError::TruncatedMessage {
                offset,
                declared: message_length,
                remaining,
            });
        }
        let message_type = read_u16_ne(&datagram[offset + 4..offset + 6]);
        let message_end = offset + message_length;
        let payload = &datagram[offset + NLMSG_HEADER_BYTES..message_end];

        match message_type {
            NLMSG_NOOP | NLMSG_DONE => {}
            NLMSG_ERROR => {
                if payload.len() < size_of::<i32>() {
                    return Err(NetlinkDecodeError::TruncatedPayload {
                        message_type,
                        expected: size_of::<i32>(),
                        actual: payload.len(),
                    });
                }
                let code = read_i32_ne(&payload[..size_of::<i32>()]);
                if code != 0 {
                    return Err(NetlinkDecodeError::KernelError(code));
                }
            }
            NLMSG_OVERRUN => return Err(NetlinkDecodeError::KernelOverrun),
            RTM_NEWLINK | RTM_DELLINK => {
                validate_attributes(message_type, payload, IFINFO_MESSAGE_BYTES)?;
                if !link_notification_is_promiscuity_only(message_type, payload) {
                    changes.insert(NetworkChangeKind::InterfaceSetChanged);
                }
            }
            RTM_NEWADDR | RTM_DELADDR => {
                validate_attributes(message_type, payload, IFADDR_MESSAGE_BYTES)?;
                changes.insert(NetworkChangeKind::InterfaceAddressChanged);
            }
            RTM_NEWROUTE | RTM_DELROUTE => {
                validate_attributes(message_type, payload, ROUTE_MESSAGE_BYTES)?;
                let family = payload[0];
                let destination_prefix_length = payload[1];
                let protocol = payload[5];
                let table = route_table_id(message_type, payload)?;
                if matches!(family, LINUX_AF_INET | LINUX_AF_INET6) {
                    if family == LINUX_AF_INET
                        && table == RT_TABLE_MAIN
                        && protocol == SHADOWPIPE_ROUTE_PROTOCOL
                    {
                        changes.insert(NetworkChangeKind::OwnedRouteChanged);
                    } else if destination_prefix_length == 0 {
                        changes.insert(NetworkChangeKind::DefaultRouteChanged);
                    } else {
                        changes.insert(NetworkChangeKind::ConnectivityChanged);
                    }
                }
            }
            RTM_NEWRULE | RTM_DELRULE => {
                validate_attributes(message_type, payload, FIB_RULE_HEADER_BYTES)?;
                changes.insert(NetworkChangeKind::RoutingPolicyChanged);
            }
            _ => {
                // A valid message outside the subscribed change classes is
                // irrelevant. It is not converted into host-state authority.
            }
        }

        if message_end == datagram.len() {
            break;
        }
        let Some(aligned_length) = align4(message_length) else {
            return Err(NetlinkDecodeError::InvalidMessageLength {
                offset,
                length: message_length,
            });
        };
        let Some(next) = offset.checked_add(aligned_length) else {
            return Err(NetlinkDecodeError::InvalidMessageLength {
                offset,
                length: message_length,
            });
        };
        if next > datagram.len() {
            return Err(NetlinkDecodeError::TruncatedMessage {
                offset,
                declared: aligned_length,
                remaining,
            });
        }
        offset = next;
    }

    Ok(changes)
}

/// Read-only Linux rtnetlink multicast source.
#[cfg(target_os = "linux")]
pub mod linux {
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    pub use super::LinuxNetworkEventInterest;
    use super::{
        decode_rtnetlink_datagram, rtnetlink_subscription_groups, NetlinkDecodeError,
        NetworkChangeSet, MAX_NETLINK_DATAGRAM_BYTES,
    };
    const RECEIVE_BUFFER_BYTES: libc::c_int = (MAX_NETLINK_DATAGRAM_BYTES * 4) as libc::c_int;

    #[derive(Debug)]
    pub enum LinuxNetworkEventSourceError {
        Io(io::Error),
        UnexpectedSender { port_id: u32 },
        Decode(NetlinkDecodeError),
    }

    impl std::fmt::Display for LinuxNetworkEventSourceError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(error) => write!(formatter, "rtnetlink event source I/O error: {error}"),
                Self::UnexpectedSender { port_id } => {
                    write!(formatter, "rtnetlink datagram came from port id {port_id}")
                }
                Self::Decode(error) => write!(formatter, "invalid rtnetlink event: {error}"),
            }
        }
    }

    impl std::error::Error for LinuxNetworkEventSourceError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Io(error) => Some(error),
                Self::Decode(error) => Some(error),
                Self::UnexpectedSender { .. } => None,
            }
        }
    }

    /// Nonblocking, read-only listener for kernel network-change triggers.
    ///
    /// The socket reports receive overflow instead of suppressing `ENOBUFS`.
    /// Such an error must make the caller fail closed and perform a complete
    /// observation before privileged reconciliation.
    #[derive(Debug)]
    pub struct LinuxNetworkEventSource {
        socket: OwnedFd,
        buffer: Box<[u8; MAX_NETLINK_DATAGRAM_BYTES]>,
    }

    impl LinuxNetworkEventSource {
        pub fn open(
            interest: LinuxNetworkEventInterest,
        ) -> Result<Self, LinuxNetworkEventSourceError> {
            // SAFETY: socket has no pointer arguments and returns a fresh fd.
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                )
            };
            if raw < 0 {
                return Err(LinuxNetworkEventSourceError::Io(io::Error::last_os_error()));
            }
            // SAFETY: raw is a newly owned non-negative descriptor.
            let socket = unsafe { OwnedFd::from_raw_fd(raw) };

            // A fixed receive buffer bounds the kernel-side queue. We
            // intentionally do not enable NETLINK_NO_ENOBUFS: lost events must
            // remain visible as a fail-closed error.
            // SAFETY: RECEIVE_BUFFER_BYTES is initialized and its size is
            // supplied exactly.
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&RECEIVE_BUFFER_BYTES as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(LinuxNetworkEventSourceError::Io(io::Error::last_os_error()));
            }

            // Zero initialization is the Linux ABI's canonical initialization
            // for sockaddr_nl, including libc's private padding.
            let mut local = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
            local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            local.nl_groups = rtnetlink_subscription_groups(interest);
            // SAFETY: local is initialized and the exact sockaddr_nl size is
            // provided to bind.
            let result = unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&local as *const libc::sockaddr_nl).cast(),
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(LinuxNetworkEventSourceError::Io(io::Error::last_os_error()));
            }

            Ok(Self {
                socket,
                buffer: Box::new([0; MAX_NETLINK_DATAGRAM_BYTES]),
            })
        }

        /// Read and decode at most one datagram.
        ///
        /// `Ok(None)` means the nonblocking socket had no queued datagram.
        /// Every non-empty returned set is only a trigger for fresh host
        /// observation.
        pub fn try_read(
            &mut self,
        ) -> Result<Option<NetworkChangeSet>, LinuxNetworkEventSourceError> {
            loop {
                let mut sender =
                    unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
                let mut sender_length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
                // MSG_TRUNC makes Linux return the full datagram length. An
                // oversized datagram is consumed and rejected without
                // allocating from its declared size.
                // SAFETY: buffer and sender are writable for the supplied
                // lengths, and the owned descriptor remains open.
                let received = unsafe {
                    libc::recvfrom(
                        self.socket.as_raw_fd(),
                        self.buffer.as_mut_ptr().cast(),
                        self.buffer.len(),
                        libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                        (&mut sender as *mut libc::sockaddr_nl).cast(),
                        &mut sender_length,
                    )
                };
                if received < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.kind() == io::ErrorKind::WouldBlock {
                        return Ok(None);
                    }
                    return Err(LinuxNetworkEventSourceError::Io(error));
                }

                let received = received as usize;
                if received > self.buffer.len() {
                    return Err(LinuxNetworkEventSourceError::Decode(
                        NetlinkDecodeError::DatagramTooLarge {
                            length: received,
                            maximum: self.buffer.len(),
                        },
                    ));
                }
                if sender_length < size_of::<libc::sockaddr_nl>() as libc::socklen_t
                    || sender.nl_family != libc::AF_NETLINK as libc::sa_family_t
                    || sender.nl_pid != 0
                {
                    return Err(LinuxNetworkEventSourceError::UnexpectedSender {
                        port_id: sender.nl_pid,
                    });
                }

                let changes = decode_rtnetlink_datagram(&self.buffer[..received])
                    .map_err(LinuxNetworkEventSourceError::Decode)?;
                return Ok(Some(changes));
            }
        }
    }

    impl AsRawFd for LinuxNetworkEventSource {
        fn as_raw_fd(&self) -> RawFd {
            self.socket.as_raw_fd()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[ignore = "opens a read-only NETLINK_ROUTE socket on a Linux host"]
        fn socket_smoke_test_is_non_mutating() {
            let mut source =
                LinuxNetworkEventSource::open(LinuxNetworkEventInterest::Ipv4UnderlayOnly).unwrap();
            assert!(source.as_raw_fd() >= 0);
            let _ = source.try_read().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn netlink_message(message_type: u16, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_BYTES + payload.len();
        let aligned = align4(length).unwrap();
        let mut message = vec![0u8; aligned];
        message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&message_type.to_ne_bytes());
        message[NLMSG_HEADER_BYTES..length].copy_from_slice(payload);
        message
    }

    fn route_payload(family: u8, destination_prefix_length: u8) -> [u8; ROUTE_MESSAGE_BYTES] {
        route_payload_with_protocol(family, destination_prefix_length, 0)
    }

    fn route_payload_with_protocol(
        family: u8,
        destination_prefix_length: u8,
        protocol: u8,
    ) -> [u8; ROUTE_MESSAGE_BYTES] {
        route_payload_with_protocol_and_table(family, destination_prefix_length, protocol, 0)
    }

    fn route_payload_with_protocol_and_table(
        family: u8,
        destination_prefix_length: u8,
        protocol: u8,
        table: u8,
    ) -> [u8; ROUTE_MESSAGE_BYTES] {
        let mut payload = [0u8; ROUTE_MESSAGE_BYTES];
        payload[0] = family;
        payload[1] = destination_prefix_length;
        payload[4] = table;
        payload[5] = protocol;
        payload
    }

    fn route_payload_with_table_attribute(
        family: u8,
        destination_prefix_length: u8,
        protocol: u8,
        table: u32,
    ) -> Vec<u8> {
        let mut payload =
            route_payload_with_protocol_and_table(family, destination_prefix_length, protocol, 0)
                .to_vec();
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&RTA_TABLE.to_ne_bytes());
        payload.extend_from_slice(&table.to_ne_bytes());
        payload
    }

    fn rule_payload(family: u8) -> [u8; FIB_RULE_HEADER_BYTES] {
        let mut payload = [0u8; FIB_RULE_HEADER_BYTES];
        payload[0] = family;
        payload
    }

    fn link_payload(change: u32) -> [u8; IFINFO_MESSAGE_BYTES] {
        let mut payload = [0u8; IFINFO_MESSAGE_BYTES];
        payload[12..16].copy_from_slice(&change.to_ne_bytes());
        payload
    }

    #[test]
    fn change_set_is_fixed_and_iterates_in_canonical_order() {
        let changes: NetworkChangeSet = [
            NetworkChangeKind::Resume,
            NetworkChangeKind::OwnedRouteChanged,
            NetworkChangeKind::DefaultRouteChanged,
            NetworkChangeKind::Resume,
            NetworkChangeKind::InterfaceSetChanged,
        ]
        .into_iter()
        .collect();

        assert_eq!(std::mem::size_of::<NetworkChangeSet>(), 2);
        assert_eq!(changes.len(), 4);
        assert!(changes.contains(NetworkChangeKind::Resume));
        assert_eq!(
            changes.iter().collect::<Vec<_>>(),
            vec![
                NetworkChangeKind::InterfaceSetChanged,
                NetworkChangeKind::DefaultRouteChanged,
                NetworkChangeKind::OwnedRouteChanged,
                NetworkChangeKind::Resume,
            ]
        );
    }

    #[test]
    fn accumulator_coalesces_duplicates_but_advances_per_trigger_group() {
        let mut accumulator = NetworkChangeAccumulator::new();
        assert_eq!(
            accumulator.mark(NetworkChangeKind::InterfaceSetChanged),
            Ok(NetworkEventGeneration::new(1))
        );
        assert_eq!(
            accumulator.mark(NetworkChangeKind::InterfaceSetChanged),
            Ok(NetworkEventGeneration::new(2))
        );
        assert_eq!(
            accumulator.mark(NetworkChangeKind::DefaultRouteChanged),
            Ok(NetworkEventGeneration::new(3))
        );

        let batch = accumulator.take_pending().unwrap().unwrap();
        assert_eq!(batch.generation(), NetworkEventGeneration::new(3));
        assert_eq!(batch.changes().len(), 2);
        assert!(batch
            .changes()
            .contains(NetworkChangeKind::InterfaceSetChanged));
        assert!(batch
            .changes()
            .contains(NetworkChangeKind::DefaultRouteChanged));
        assert_eq!(accumulator.take_pending(), Ok(None));
        assert_eq!(accumulator.generation(), NetworkEventGeneration::new(3));
    }

    #[test]
    fn empty_trigger_group_is_a_noop() {
        let mut accumulator = NetworkChangeAccumulator::new();
        assert_eq!(
            accumulator.mark_dirty(NetworkChangeSet::new()),
            Ok(NetworkEventGeneration::new(0))
        );
        assert_eq!(accumulator.take_pending(), Ok(None));
    }

    #[test]
    fn generation_overflow_permanently_fails_closed() {
        let mut accumulator =
            NetworkChangeAccumulator::with_generation(NetworkEventGeneration::new(u64::MAX));
        assert_eq!(
            accumulator.mark(NetworkChangeKind::Resume),
            Err(NetworkChangeAccumulatorError::GenerationOverflow)
        );
        assert!(accumulator.is_poisoned());
        assert_eq!(
            accumulator.mark(NetworkChangeKind::InitialObservation),
            Err(NetworkChangeAccumulatorError::GenerationOverflow)
        );
        assert_eq!(
            accumulator.take_pending(),
            Err(NetworkChangeAccumulatorError::GenerationOverflow)
        );
    }

    #[test]
    fn decoder_coalesces_link_address_and_default_route_messages() {
        let mut datagram = netlink_message(RTM_NEWLINK, &[0; IFINFO_MESSAGE_BYTES]);
        datagram.extend(netlink_message(RTM_DELADDR, &[0; IFADDR_MESSAGE_BYTES]));
        datagram.extend(netlink_message(
            RTM_NEWROUTE,
            &route_payload(LINUX_AF_INET, 0),
        ));
        datagram.extend(netlink_message(
            RTM_DELROUTE,
            &route_payload(LINUX_AF_INET6, 0),
        ));

        let changes = decode_rtnetlink_datagram(&datagram).unwrap();
        assert_eq!(changes.len(), 3);
        assert!(changes.contains(NetworkChangeKind::InterfaceSetChanged));
        assert!(changes.contains(NetworkChangeKind::InterfaceAddressChanged));
        assert!(changes.contains(NetworkChangeKind::DefaultRouteChanged));
    }

    #[test]
    fn decoder_ignores_exact_promiscuity_only_newlink_observer_transition() {
        let datagram = netlink_message(RTM_NEWLINK, &link_payload(LINUX_IFF_PROMISC));

        assert!(decode_rtnetlink_datagram(&datagram).unwrap().is_empty());
    }

    #[test]
    fn promiscuity_only_notification_does_not_mask_a_default_route_change() {
        let mut datagram = netlink_message(RTM_NEWLINK, &link_payload(LINUX_IFF_PROMISC));
        datagram.extend(netlink_message(
            RTM_NEWROUTE,
            &route_payload(LINUX_AF_INET, 0),
        ));

        assert_eq!(
            decode_rtnetlink_datagram(&datagram).unwrap(),
            NetworkChangeKind::DefaultRouteChanged.into()
        );
    }

    #[test]
    fn decoder_keeps_mixed_or_non_newlink_promiscuity_changes_fail_closed() {
        let mut datagram = netlink_message(RTM_NEWLINK, &link_payload(LINUX_IFF_PROMISC | 0x0001));
        datagram.extend(netlink_message(
            RTM_DELLINK,
            &link_payload(LINUX_IFF_PROMISC),
        ));

        let changes = decode_rtnetlink_datagram(&datagram).unwrap();
        assert_eq!(changes, NetworkChangeKind::InterfaceSetChanged.into());
    }

    #[test]
    fn promiscuity_only_notification_still_requires_structurally_valid_attributes() {
        let mut payload = link_payload(LINUX_IFF_PROMISC).to_vec();
        payload.extend_from_slice(&3u16.to_ne_bytes());
        payload.extend_from_slice(&1u16.to_ne_bytes());

        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWLINK, &payload)),
            Err(NetlinkDecodeError::InvalidAttributeLength {
                message_type: RTM_NEWLINK,
                ..
            })
        ));
    }

    #[test]
    fn decoder_classifies_ipv4_24_and_32_routes_as_connectivity_changes() {
        let mut datagram = netlink_message(RTM_NEWROUTE, &route_payload(LINUX_AF_INET, 24));
        datagram.extend(netlink_message(
            RTM_DELROUTE,
            &route_payload(LINUX_AF_INET, 32),
        ));

        let changes = decode_rtnetlink_datagram(&datagram).unwrap();
        assert_eq!(changes, NetworkChangeKind::ConnectivityChanged.into());
    }

    #[test]
    fn decoder_classifies_ipv6_non_default_route_as_connectivity_change() {
        let datagram = netlink_message(RTM_NEWROUTE, &route_payload(LINUX_AF_INET6, 128));

        let changes = decode_rtnetlink_datagram(&datagram).unwrap();
        assert_eq!(changes, NetworkChangeKind::ConnectivityChanged.into());
    }

    #[test]
    fn decoder_classifies_protocol_186_routes_without_suppressing_them() {
        let mut datagram = netlink_message(
            RTM_NEWROUTE,
            &route_payload_with_protocol_and_table(
                LINUX_AF_INET,
                0,
                SHADOWPIPE_ROUTE_PROTOCOL,
                RT_TABLE_MAIN as u8,
            ),
        );
        datagram.extend(netlink_message(
            RTM_DELROUTE,
            &route_payload_with_table_attribute(
                LINUX_AF_INET,
                32,
                SHADOWPIPE_ROUTE_PROTOCOL,
                RT_TABLE_MAIN,
            ),
        ));

        let changes = decode_rtnetlink_datagram(&datagram).unwrap();
        assert_eq!(changes, NetworkChangeKind::OwnedRouteChanged.into());
        assert!(!changes.contains(NetworkChangeKind::DefaultRouteChanged));
        assert!(!changes.contains(NetworkChangeKind::ConnectivityChanged));
    }

    #[test]
    fn protocol_186_is_owned_only_for_ipv4_main_table() {
        let mut datagram = netlink_message(
            RTM_NEWROUTE,
            &route_payload_with_protocol_and_table(
                LINUX_AF_INET,
                32,
                SHADOWPIPE_ROUTE_PROTOCOL,
                100,
            ),
        );
        datagram.extend(netlink_message(
            RTM_NEWROUTE,
            &route_payload_with_protocol_and_table(
                LINUX_AF_INET6,
                128,
                SHADOWPIPE_ROUTE_PROTOCOL,
                RT_TABLE_MAIN as u8,
            ),
        ));

        let changes = decode_rtnetlink_datagram(&datagram).unwrap();
        assert_eq!(changes, NetworkChangeKind::ConnectivityChanged.into());
        assert!(!changes.contains(NetworkChangeKind::OwnedRouteChanged));
    }

    #[test]
    fn route_table_attribute_is_exact_and_cannot_conflict_or_repeat() {
        let owned = netlink_message(
            RTM_NEWROUTE,
            &route_payload_with_table_attribute(
                LINUX_AF_INET,
                32,
                SHADOWPIPE_ROUTE_PROTOCOL,
                RT_TABLE_MAIN,
            ),
        );
        assert_eq!(
            decode_rtnetlink_datagram(&owned).unwrap(),
            NetworkChangeKind::OwnedRouteChanged.into()
        );

        let mut conflicting = route_payload_with_protocol_and_table(
            LINUX_AF_INET,
            32,
            SHADOWPIPE_ROUTE_PROTOCOL,
            100,
        )
        .to_vec();
        conflicting.extend_from_slice(&8u16.to_ne_bytes());
        conflicting.extend_from_slice(&RTA_TABLE.to_ne_bytes());
        conflicting.extend_from_slice(&RT_TABLE_MAIN.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWROUTE, &conflicting)),
            Err(NetlinkDecodeError::ConflictingRouteTable { .. })
        ));

        let mut extended = route_payload_with_protocol_and_table(
            LINUX_AF_INET,
            32,
            SHADOWPIPE_ROUTE_PROTOCOL,
            RT_TABLE_COMPAT as u8,
        )
        .to_vec();
        extended.extend_from_slice(&8u16.to_ne_bytes());
        extended.extend_from_slice(&RTA_TABLE.to_ne_bytes());
        extended.extend_from_slice(&1000u32.to_ne_bytes());
        assert_eq!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWROUTE, &extended)).unwrap(),
            NetworkChangeKind::ConnectivityChanged.into()
        );

        let mut duplicate = route_payload_with_table_attribute(
            LINUX_AF_INET,
            32,
            SHADOWPIPE_ROUTE_PROTOCOL,
            RT_TABLE_MAIN,
        );
        duplicate.extend_from_slice(&8u16.to_ne_bytes());
        duplicate.extend_from_slice(&RTA_TABLE.to_ne_bytes());
        duplicate.extend_from_slice(&RT_TABLE_MAIN.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWROUTE, &duplicate)),
            Err(NetlinkDecodeError::DuplicateAttribute {
                attribute_type: RTA_TABLE,
                ..
            })
        ));
    }

    #[test]
    fn decoder_classifies_rule_add_and_delete_as_routing_policy_changes() {
        let mut datagram = netlink_message(RTM_NEWRULE, &rule_payload(LINUX_AF_INET));
        datagram.extend(netlink_message(RTM_DELRULE, &rule_payload(LINUX_AF_INET6)));

        let changes = decode_rtnetlink_datagram(&datagram).unwrap();
        assert_eq!(changes, NetworkChangeKind::RoutingPolicyChanged.into());
    }

    #[test]
    fn decoder_ignores_unknown_valid_messages() {
        let mut datagram = netlink_message(99, &[1, 2, 3, 4]);
        datagram.extend(netlink_message(99, &[1, 2, 3, 4]));

        assert!(decode_rtnetlink_datagram(&datagram).unwrap().is_empty());
    }

    #[test]
    fn decoder_accepts_valid_attributes_and_unpadded_final_message() {
        let mut payload = vec![0u8; IFADDR_MESSAGE_BYTES];
        payload.extend_from_slice(&5u16.to_ne_bytes());
        payload.extend_from_slice(&1u16.to_ne_bytes());
        payload.push(7);
        let mut message = netlink_message(RTM_NEWADDR, &payload);
        message.truncate(NLMSG_HEADER_BYTES + payload.len());

        let changes = decode_rtnetlink_datagram(&message).unwrap();
        assert!(changes.contains(NetworkChangeKind::InterfaceAddressChanged));
    }

    #[test]
    fn malformed_datagram_shapes_are_rejected() {
        assert_eq!(
            decode_rtnetlink_datagram(&[]),
            Err(NetlinkDecodeError::EmptyDatagram)
        );
        assert!(matches!(
            decode_rtnetlink_datagram(&vec![0; MAX_NETLINK_DATAGRAM_BYTES + 1]),
            Err(NetlinkDecodeError::DatagramTooLarge { .. })
        ));
        assert!(matches!(
            decode_rtnetlink_datagram(&[0; NLMSG_HEADER_BYTES - 1]),
            Err(NetlinkDecodeError::TruncatedHeader { .. })
        ));

        let mut too_short = vec![0u8; NLMSG_HEADER_BYTES];
        too_short[..4].copy_from_slice(&8u32.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&too_short),
            Err(NetlinkDecodeError::InvalidMessageLength { .. })
        ));

        let mut truncated = vec![0u8; NLMSG_HEADER_BYTES];
        truncated[..4].copy_from_slice(&32u32.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&truncated),
            Err(NetlinkDecodeError::TruncatedMessage { .. })
        ));
    }

    #[test]
    fn truncated_fixed_payload_and_attributes_are_rejected() {
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWLINK, &[0; 15])),
            Err(NetlinkDecodeError::TruncatedPayload { .. })
        ));

        let mut invalid_length = vec![0u8; IFADDR_MESSAGE_BYTES];
        invalid_length.extend_from_slice(&0u16.to_ne_bytes());
        invalid_length.extend_from_slice(&1u16.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWADDR, &invalid_length)),
            Err(NetlinkDecodeError::InvalidAttributeLength { .. })
        ));

        let mut truncated = vec![0u8; ROUTE_MESSAGE_BYTES];
        truncated.extend_from_slice(&8u16.to_ne_bytes());
        truncated.extend_from_slice(&1u16.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWROUTE, &truncated)),
            Err(NetlinkDecodeError::TruncatedAttribute { .. })
        ));
    }

    #[test]
    fn malformed_rule_payload_and_attributes_are_rejected() {
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(
                RTM_NEWRULE,
                &[0; FIB_RULE_HEADER_BYTES - 1]
            )),
            Err(NetlinkDecodeError::TruncatedPayload { .. })
        ));

        let mut invalid_length = vec![0u8; FIB_RULE_HEADER_BYTES];
        invalid_length.extend_from_slice(&3u16.to_ne_bytes());
        invalid_length.extend_from_slice(&1u16.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_DELRULE, &invalid_length)),
            Err(NetlinkDecodeError::InvalidAttributeLength { .. })
        ));

        let mut truncated = vec![0u8; FIB_RULE_HEADER_BYTES];
        truncated.extend_from_slice(&8u16.to_ne_bytes());
        truncated.extend_from_slice(&1u16.to_ne_bytes());
        assert!(matches!(
            decode_rtnetlink_datagram(&netlink_message(RTM_NEWRULE, &truncated)),
            Err(NetlinkDecodeError::TruncatedAttribute { .. })
        ));
    }

    #[test]
    fn subscription_masks_are_mode_aware_and_exact() {
        assert_eq!(
            rtnetlink_subscription_groups(LinuxNetworkEventInterest::Ipv4UnderlayOnly),
            0x00d1
        );
        assert_eq!(
            rtnetlink_subscription_groups(LinuxNetworkEventInterest::DualStack),
            0x405d1
        );
        assert_eq!(RTMGRP_IPV6_RULE, 0x40000);
    }

    #[test]
    fn kernel_errors_and_overruns_are_fail_closed() {
        assert_eq!(
            decode_rtnetlink_datagram(&netlink_message(NLMSG_ERROR, &(-105i32).to_ne_bytes())),
            Err(NetlinkDecodeError::KernelError(-105))
        );
        assert_eq!(
            decode_rtnetlink_datagram(&netlink_message(NLMSG_OVERRUN, &[])),
            Err(NetlinkDecodeError::KernelOverrun)
        );
        assert!(
            decode_rtnetlink_datagram(&netlink_message(NLMSG_ERROR, &0i32.to_ne_bytes()))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn trailing_fragment_after_aligned_message_is_rejected() {
        let mut datagram = netlink_message(NLMSG_NOOP, &[]);
        datagram.push(0);
        assert!(matches!(
            decode_rtnetlink_datagram(&datagram),
            Err(NetlinkDecodeError::TruncatedHeader { .. })
        ));
    }
}
