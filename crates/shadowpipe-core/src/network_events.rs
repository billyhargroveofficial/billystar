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

/// Hard cap for one kernel netlink datagram.
///
/// The Linux reader owns exactly one buffer of this size and never allocates
/// based on a length supplied by the kernel.
pub const MAX_NETLINK_DATAGRAM_BYTES: usize = 64 * 1024;

const NLMSG_ALIGN_TO: usize = 4;
const NLMSG_HEADER_BYTES: usize = 16;
const RTATTR_HEADER_BYTES: usize = 4;
const IFINFO_MESSAGE_BYTES: usize = 16;
const IFADDR_MESSAGE_BYTES: usize = 8;
const ROUTE_MESSAGE_BYTES: usize = 12;

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
const LINUX_AF_INET: u8 = 2;
const LINUX_AF_INET6: u8 = 10;

const NETWORK_CHANGE_KINDS: [NetworkChangeKind; 8] = [
    NetworkChangeKind::InitialObservation,
    NetworkChangeKind::InterfaceSetChanged,
    NetworkChangeKind::InterfaceAddressChanged,
    NetworkChangeKind::DefaultRouteChanged,
    NetworkChangeKind::DnsConfigurationChanged,
    NetworkChangeKind::ConnectivityChanged,
    NetworkChangeKind::Suspend,
    NetworkChangeKind::Resume,
];

const fn kind_bit(kind: NetworkChangeKind) -> u8 {
    match kind {
        NetworkChangeKind::InitialObservation => 1 << 0,
        NetworkChangeKind::InterfaceSetChanged => 1 << 1,
        NetworkChangeKind::InterfaceAddressChanged => 1 << 2,
        NetworkChangeKind::DefaultRouteChanged => 1 << 3,
        NetworkChangeKind::DnsConfigurationChanged => 1 << 4,
        NetworkChangeKind::ConnectivityChanged => 1 << 5,
        NetworkChangeKind::Suspend => 1 << 6,
        NetworkChangeKind::Resume => 1 << 7,
    }
}

/// Fixed-capacity set of coalesced change triggers.
///
/// Its storage is always one byte. Repeated notifications set an existing bit
/// instead of creating an unbounded queue.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NetworkChangeSet {
    bits: u8,
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

/// Decode one Linux `NETLINK_ROUTE` multicast datagram into bounded triggers.
///
/// This is pure and portable so malformed-input tests run on macOS and
/// Windows. Link and address messages always trigger fresh observation.
/// Route messages trigger only when their destination prefix length is zero
/// for IPv4 or IPv6; other routes cannot directly replace a default route.
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
                changes.insert(NetworkChangeKind::InterfaceSetChanged);
            }
            RTM_NEWADDR | RTM_DELADDR => {
                validate_attributes(message_type, payload, IFADDR_MESSAGE_BYTES)?;
                changes.insert(NetworkChangeKind::InterfaceAddressChanged);
            }
            RTM_NEWROUTE | RTM_DELROUTE => {
                validate_attributes(message_type, payload, ROUTE_MESSAGE_BYTES)?;
                let family = payload[0];
                let destination_prefix_length = payload[1];
                if matches!(family, LINUX_AF_INET | LINUX_AF_INET6)
                    && destination_prefix_length == 0
                {
                    changes.insert(NetworkChangeKind::DefaultRouteChanged);
                }
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

    use super::{
        decode_rtnetlink_datagram, NetlinkDecodeError, NetworkChangeSet, MAX_NETLINK_DATAGRAM_BYTES,
    };

    // Public multicast masks from <linux/rtnetlink.h>. Only link, IPv4/IPv6
    // address, and IPv4/IPv6 route notifications are subscribed.
    const RTMGRP_LINK: u32 = 0x0001;
    const RTMGRP_IPV4_IFADDR: u32 = 0x0010;
    const RTMGRP_IPV4_ROUTE: u32 = 0x0040;
    const RTMGRP_IPV6_IFADDR: u32 = 0x0100;
    const RTMGRP_IPV6_ROUTE: u32 = 0x0400;
    const SUBSCRIBED_GROUPS: u32 = RTMGRP_LINK
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_IFADDR
        | RTMGRP_IPV6_ROUTE;
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
        pub fn open() -> Result<Self, LinuxNetworkEventSourceError> {
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
            local.nl_groups = SUBSCRIBED_GROUPS;
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
        fn subscription_mask_contains_only_documented_change_groups() {
            assert_eq!(SUBSCRIBED_GROUPS, 0x0551);
        }

        #[test]
        #[ignore = "opens a read-only NETLINK_ROUTE socket on a Linux host"]
        fn socket_smoke_test_is_non_mutating() {
            let mut source = LinuxNetworkEventSource::open().unwrap();
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
        let mut payload = [0u8; ROUTE_MESSAGE_BYTES];
        payload[0] = family;
        payload[1] = destination_prefix_length;
        payload
    }

    #[test]
    fn change_set_is_fixed_and_iterates_in_canonical_order() {
        let changes: NetworkChangeSet = [
            NetworkChangeKind::Resume,
            NetworkChangeKind::DefaultRouteChanged,
            NetworkChangeKind::Resume,
            NetworkChangeKind::InterfaceSetChanged,
        ]
        .into_iter()
        .collect();

        assert_eq!(changes.len(), 3);
        assert!(changes.contains(NetworkChangeKind::Resume));
        assert_eq!(
            changes.iter().collect::<Vec<_>>(),
            vec![
                NetworkChangeKind::InterfaceSetChanged,
                NetworkChangeKind::DefaultRouteChanged,
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
    fn decoder_ignores_non_default_and_unknown_valid_messages() {
        let mut datagram = netlink_message(RTM_NEWROUTE, &route_payload(LINUX_AF_INET, 24));
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
