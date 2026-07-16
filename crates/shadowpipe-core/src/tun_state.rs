//! Exact ownership and crash observation for the Linux TUN interface.
//!
//! The journal binds both interface name and ifindex. Runtime ownership is
//! additionally marked with the full random session tag in Linux `ifalias`.
//! Production TUNs are non-persistent and disappear when their last exact file
//! descriptor closes. Crash recovery therefore never issues `RTM_DELLINK`: a
//! reused name/ifindex, modified alias, or unexpectedly surviving interface is
//! a conflict and produces no mutating request.

use anyhow::Result;

use crate::host_state::{ResourceObservationKind, SessionId, TunResource};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunObservation {
    pub name: String,
    pub ifindex: u32,
    pub alias: String,
}

#[derive(Debug)]
pub enum TunConvergenceError {
    Conflict(anyhow::Error),
    Operational(anyhow::Error),
}

impl TunConvergenceError {
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
    }
}

impl std::fmt::Display for TunConvergenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(error) => write!(formatter, "TUN ownership conflict: {error:#}"),
            Self::Operational(error) => write!(formatter, "TUN recovery failed: {error:#}"),
        }
    }
}

impl std::error::Error for TunConvergenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Conflict(error) | Self::Operational(error) => Some(error.as_ref()),
        }
    }
}

pub fn classify_tun(
    resource: &TunResource,
    session: SessionId,
    observation: Option<&TunObservation>,
) -> ResourceObservationKind {
    let Some(observation) = observation else {
        return ResourceObservationKind::Absent;
    };
    if observation.name == resource.interface.name
        && observation.ifindex == resource.interface.ifindex
        && observation.alias == session.owner_tag()
    {
        ResourceObservationKind::ExactOwnedPresent
    } else {
        ResourceObservationKind::Conflict
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::host_state::InterfaceIdentity;

    const NETLINK_TIMEOUT_SECONDS: libc::time_t = 3;
    const MAX_NETLINK_DATAGRAM_BYTES: usize = 64 * 1024;
    const MAX_NETLINK_REPLY_DATAGRAMS: usize = 4;
    const NLA_TYPE_MASK: u16 = 0x3fff;
    const TUN_ALIAS_VISIBILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
    const TUN_ALIAS_VISIBILITY_POLL: std::time::Duration = std::time::Duration::from_millis(2);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RtAttribute {
        length: u16,
        kind: u16,
    }

    static NETLINK_SEQUENCE: AtomicU32 = AtomicU32::new(1);

    const fn align4(length: usize) -> usize {
        (length + 3) & !3
    }

    fn netlink_socket() -> Result<OwnedFd> {
        // SAFETY: socket has no pointer arguments and returns a fresh fd.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error()).context("open NETLINK_ROUTE socket");
        }
        // SAFETY: raw is a newly owned non-negative descriptor.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let timeout = libc::timeval {
            tv_sec: NETLINK_TIMEOUT_SECONDS,
            tv_usec: 0,
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            // SAFETY: timeout is initialized and the supplied size is exact.
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&timeout as *const libc::timeval).cast(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error()).context("set NETLINK_ROUTE socket timeout");
            }
        }
        // Zero initialization is the kernel ABI's canonical way to initialize
        // the private padding fields exposed by libc.
        let mut local = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: local points to an initialized sockaddr_nl of the exact size.
        let result = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&local as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("bind NETLINK_ROUTE socket");
        }
        let mut kernel = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // nl_pid=0 addresses the kernel.
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&kernel as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("connect NETLINK_ROUTE kernel peer");
        }
        Ok(socket)
    }

    fn link_request(message_type: u16, ifindex: u32, alias: Option<&str>) -> Result<()> {
        anyhow::ensure!(
            ifindex > 0 && ifindex <= i32::MAX as u32,
            "invalid link ifindex"
        );
        // Match iproute2's canonical IFLA_IFALIAS mutation encoding: the exact
        // UTF-8 byte string without a trailing NUL. ACK alone is deliberately
        // not accepted as ownership proof; a current-netns GET verifies it.
        let alias_payload = alias.map(|value| value.as_bytes().to_vec());
        if let Some(payload) = &alias_payload {
            anyhow::ensure!(
                payload.len() <= u16::MAX as usize - size_of::<RtAttribute>(),
                "interface alias exceeds netlink attribute capacity"
            );
        }
        let base = size_of::<libc::nlmsghdr>() + size_of::<libc::ifinfomsg>();
        let attribute_size = alias_payload.as_ref().map_or(0, |payload| {
            align4(size_of::<RtAttribute>() + payload.len())
        });
        let total = base
            .checked_add(attribute_size)
            .context("netlink link request length overflow")?;
        let sequence = NETLINK_SEQUENCE.fetch_add(1, Ordering::Relaxed).max(1);
        let header = libc::nlmsghdr {
            nlmsg_len: total.try_into().context("netlink request is too large")?,
            nlmsg_type: message_type,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            nlmsg_seq: sequence,
            nlmsg_pid: 0,
        };
        let mut info = unsafe { MaybeUninit::<libc::ifinfomsg>::zeroed().assume_init() };
        info.ifi_family = libc::AF_UNSPEC as u8;
        info.ifi_index = ifindex as i32;
        let mut request = vec![0u8; total];
        // SAFETY: the destination ranges are sized and aligned-independent;
        // write_unaligned initializes them without creating references.
        unsafe {
            std::ptr::write_unaligned(request.as_mut_ptr().cast::<libc::nlmsghdr>(), header);
            std::ptr::write_unaligned(
                request
                    .as_mut_ptr()
                    .add(size_of::<libc::nlmsghdr>())
                    .cast::<libc::ifinfomsg>(),
                info,
            );
        }
        if let Some(payload) = alias_payload {
            let offset = base;
            let attribute = RtAttribute {
                length: (size_of::<RtAttribute>() + payload.len())
                    .try_into()
                    .context("netlink alias attribute is too large")?,
                kind: libc::IFLA_IFALIAS,
            };
            // SAFETY: offset and payload were included in total above.
            unsafe {
                std::ptr::write_unaligned(
                    request.as_mut_ptr().add(offset).cast::<RtAttribute>(),
                    attribute,
                );
            }
            let payload_start = offset + size_of::<RtAttribute>();
            request[payload_start..payload_start + payload.len()].copy_from_slice(&payload);
        }

        let socket = netlink_socket()?;
        // SAFETY: request is a valid initialized byte buffer.
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error()).context("send rtnetlink link request");
        }
        anyhow::ensure!(
            sent as usize == request.len(),
            "short rtnetlink request write"
        );

        let mut response = [0u8; 4096];
        loop {
            // SAFETY: response is writable for its complete length.
            let received = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    response.as_mut_ptr().cast(),
                    response.len(),
                    0,
                )
            };
            if received < 0 {
                return Err(io::Error::last_os_error())
                    .context("receive rtnetlink acknowledgement");
            }
            anyhow::ensure!(received > 0, "rtnetlink acknowledgement stream closed");
            let received = received as usize;
            let mut offset = 0usize;
            while offset + size_of::<libc::nlmsghdr>() <= received {
                // SAFETY: the bounds check above covers the complete header.
                let reply = unsafe {
                    std::ptr::read_unaligned(response.as_ptr().add(offset).cast::<libc::nlmsghdr>())
                };
                let length = reply.nlmsg_len as usize;
                anyhow::ensure!(
                    length >= size_of::<libc::nlmsghdr>() && offset + length <= received,
                    "malformed rtnetlink acknowledgement length"
                );
                if reply.nlmsg_seq == sequence && reply.nlmsg_type == libc::NLMSG_ERROR as u16 {
                    anyhow::ensure!(
                        length >= size_of::<libc::nlmsghdr>() + size_of::<libc::nlmsgerr>(),
                        "truncated rtnetlink NLMSG_ERROR acknowledgement"
                    );
                    // SAFETY: the message length check covers nlmsgerr.
                    let acknowledgement = unsafe {
                        std::ptr::read_unaligned(
                            response
                                .as_ptr()
                                .add(offset + size_of::<libc::nlmsghdr>())
                                .cast::<libc::nlmsgerr>(),
                        )
                    };
                    if acknowledgement.error == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-acknowledgement.error))
                        .context("kernel rejected rtnetlink link request");
                }
                offset = offset
                    .checked_add(align4(length))
                    .context("rtnetlink acknowledgement offset overflow")?;
            }
        }
    }

    fn validate_name(name: &str) -> Result<()> {
        anyhow::ensure!(
            !name.is_empty()
                && name.len() <= 15
                && !name
                    .bytes()
                    .any(|byte| byte == 0 || byte == b'/' || byte.is_ascii_whitespace()),
            "invalid Linux interface name {name:?}"
        );
        Ok(())
    }

    fn receive_bounded_datagram(socket: &OwnedFd) -> Result<Vec<u8>> {
        let mut probe = 0u8;
        // Linux returns the complete datagram length with MSG_TRUNC even when
        // the supplied buffer is shorter. Peeking first lets us reject an
        // oversized response before allocating or consuming it.
        let length = loop {
            // SAFETY: probe is writable for one byte and MSG_PEEK leaves the
            // datagram queued for the bounded receive below.
            let result = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    (&mut probe as *mut u8).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_TRUNC,
                )
            };
            if result >= 0 {
                break result as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("peek rtnetlink response length");
            }
        };
        anyhow::ensure!(length > 0, "rtnetlink response stream closed");
        anyhow::ensure!(
            length <= MAX_NETLINK_DATAGRAM_BYTES,
            "rtnetlink response exceeds {MAX_NETLINK_DATAGRAM_BYTES} bytes"
        );
        let mut response = vec![0u8; length];
        let received = loop {
            // SAFETY: response is writable for its complete allocated length.
            let result = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    response.as_mut_ptr().cast(),
                    response.len(),
                    0,
                )
            };
            if result >= 0 {
                break result as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("receive rtnetlink response");
            }
        };
        anyhow::ensure!(
            received == length,
            "rtnetlink response length changed between peek and receive"
        );
        Ok(response)
    }

    fn parse_nla_string(payload: &[u8], field: &str) -> Result<String> {
        anyhow::ensure!(!payload.is_empty(), "empty {field} attribute");
        let value = payload.strip_suffix(&[0]).unwrap_or(payload);
        anyhow::ensure!(!value.contains(&0), "embedded NUL in {field} attribute");
        String::from_utf8(value.to_vec()).with_context(|| format!("non-UTF-8 {field} attribute"))
    }

    fn parse_link_observation(message: &[u8], requested_name: &str) -> Result<TunObservation> {
        let base = size_of::<libc::nlmsghdr>() + size_of::<libc::ifinfomsg>();
        anyhow::ensure!(message.len() >= base, "truncated RTM_NEWLINK response");
        // SAFETY: the length check above covers the complete ifinfomsg.
        let info = unsafe {
            std::ptr::read_unaligned(
                message
                    .as_ptr()
                    .add(size_of::<libc::nlmsghdr>())
                    .cast::<libc::ifinfomsg>(),
            )
        };
        anyhow::ensure!(info.ifi_index > 0, "invalid RTM_NEWLINK ifindex");

        let mut name = None::<String>;
        let mut alias = None::<String>;
        let mut offset = base;
        while offset < message.len() {
            anyhow::ensure!(
                message.len() - offset >= size_of::<RtAttribute>(),
                "truncated rtnetlink attribute header"
            );
            // SAFETY: the remaining bytes cover the complete attribute header.
            let attribute = unsafe {
                std::ptr::read_unaligned(message.as_ptr().add(offset).cast::<RtAttribute>())
            };
            let length = attribute.length as usize;
            anyhow::ensure!(
                length >= size_of::<RtAttribute>(),
                "invalid zero-length rtnetlink attribute"
            );
            let end = offset
                .checked_add(length)
                .context("rtnetlink attribute end overflow")?;
            anyhow::ensure!(end <= message.len(), "truncated rtnetlink attribute");
            let aligned_end = offset
                .checked_add(align4(length))
                .context("rtnetlink attribute alignment overflow")?;
            anyhow::ensure!(
                aligned_end <= message.len(),
                "truncated rtnetlink attribute padding"
            );
            let payload = &message[offset + size_of::<RtAttribute>()..end];
            match attribute.kind & NLA_TYPE_MASK {
                kind if kind == libc::IFLA_IFNAME => {
                    anyhow::ensure!(name.is_none(), "duplicate IFLA_IFNAME attribute");
                    name = Some(parse_nla_string(payload, "IFLA_IFNAME")?);
                }
                kind if kind == libc::IFLA_IFALIAS => {
                    anyhow::ensure!(alias.is_none(), "duplicate IFLA_IFALIAS attribute");
                    alias = Some(parse_nla_string(payload, "IFLA_IFALIAS")?);
                }
                _ => {}
            }
            offset = aligned_end;
        }
        let name = name.context("RTM_NEWLINK response lacks IFLA_IFNAME")?;
        anyhow::ensure!(
            name == requested_name,
            "RTM_GETLINK returned unexpected interface {name:?}"
        );
        Ok(TunObservation {
            name,
            ifindex: info.ifi_index as u32,
            alias: alias.unwrap_or_default(),
        })
    }

    /// Query name, ifindex and alias in one RTM_GETLINK response from the
    /// caller's current network namespace. In particular, do not consult
    /// `/sys/class/net`: a process can unshare its network namespace without
    /// remounting sysfs, in which case sysfs still describes the parent
    /// namespace and turns a valid alias into a false empty observation.
    fn inspect_name(name: &str) -> Result<Option<TunObservation>> {
        validate_name(name)?;
        let mut name_payload = name.as_bytes().to_vec();
        name_payload.push(0); // IFLA_IFNAME query strings are NUL-terminated.
        let base = size_of::<libc::nlmsghdr>() + size_of::<libc::ifinfomsg>();
        let attribute_size = align4(size_of::<RtAttribute>() + name_payload.len());
        let total = base
            .checked_add(attribute_size)
            .context("RTM_GETLINK request length overflow")?;
        let sequence = NETLINK_SEQUENCE.fetch_add(1, Ordering::Relaxed).max(1);
        let header = libc::nlmsghdr {
            nlmsg_len: total
                .try_into()
                .context("RTM_GETLINK request is too large")?,
            nlmsg_type: libc::RTM_GETLINK,
            nlmsg_flags: libc::NLM_F_REQUEST as u16,
            nlmsg_seq: sequence,
            nlmsg_pid: 0,
        };
        let mut info = unsafe { MaybeUninit::<libc::ifinfomsg>::zeroed().assume_init() };
        info.ifi_family = libc::AF_UNSPEC as u8;
        let mut request = vec![0u8; total];
        // SAFETY: both destination ranges are present in the sized request.
        unsafe {
            std::ptr::write_unaligned(request.as_mut_ptr().cast::<libc::nlmsghdr>(), header);
            std::ptr::write_unaligned(
                request
                    .as_mut_ptr()
                    .add(size_of::<libc::nlmsghdr>())
                    .cast::<libc::ifinfomsg>(),
                info,
            );
            std::ptr::write_unaligned(
                request.as_mut_ptr().add(base).cast::<RtAttribute>(),
                RtAttribute {
                    length: (size_of::<RtAttribute>() + name_payload.len())
                        .try_into()
                        .context("IFLA_IFNAME query attribute is too large")?,
                    kind: libc::IFLA_IFNAME,
                },
            );
        }
        let payload_start = base + size_of::<RtAttribute>();
        request[payload_start..payload_start + name_payload.len()].copy_from_slice(&name_payload);

        let socket = netlink_socket()?;
        // SAFETY: request is a valid initialized byte buffer.
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error()).context("send RTM_GETLINK request");
        }
        anyhow::ensure!(sent as usize == request.len(), "short RTM_GETLINK write");

        for _ in 0..MAX_NETLINK_REPLY_DATAGRAMS {
            let response = receive_bounded_datagram(&socket)?;
            let mut offset = 0usize;
            while offset < response.len() {
                anyhow::ensure!(
                    response.len() - offset >= size_of::<libc::nlmsghdr>(),
                    "truncated rtnetlink response header"
                );
                // SAFETY: the remaining response covers the complete header.
                let reply = unsafe {
                    std::ptr::read_unaligned(response.as_ptr().add(offset).cast::<libc::nlmsghdr>())
                };
                let length = reply.nlmsg_len as usize;
                anyhow::ensure!(
                    length >= size_of::<libc::nlmsghdr>(),
                    "invalid rtnetlink response length"
                );
                let end = offset
                    .checked_add(length)
                    .context("rtnetlink response end overflow")?;
                anyhow::ensure!(end <= response.len(), "truncated rtnetlink response");
                let aligned_end = offset
                    .checked_add(align4(length))
                    .context("rtnetlink response alignment overflow")?;
                anyhow::ensure!(
                    aligned_end <= response.len(),
                    "truncated rtnetlink response padding"
                );
                if reply.nlmsg_seq == sequence {
                    match reply.nlmsg_type {
                        kind if kind == libc::RTM_NEWLINK => {
                            return parse_link_observation(&response[offset..end], name).map(Some);
                        }
                        kind if kind == libc::NLMSG_ERROR as u16 => {
                            anyhow::ensure!(
                                length >= size_of::<libc::nlmsghdr>() + size_of::<libc::nlmsgerr>(),
                                "truncated RTM_GETLINK NLMSG_ERROR"
                            );
                            // SAFETY: the checked message length covers nlmsgerr.
                            let acknowledgement = unsafe {
                                std::ptr::read_unaligned(
                                    response
                                        .as_ptr()
                                        .add(offset + size_of::<libc::nlmsghdr>())
                                        .cast::<libc::nlmsgerr>(),
                                )
                            };
                            if acknowledgement.error == 0 {
                                anyhow::bail!("RTM_GETLINK returned ACK without link state");
                            }
                            let errno = acknowledgement
                                .error
                                .checked_neg()
                                .context("invalid RTM_GETLINK errno")?;
                            if errno == libc::ENODEV || errno == libc::ENXIO {
                                return Ok(None);
                            }
                            return Err(io::Error::from_raw_os_error(errno))
                                .context("kernel rejected RTM_GETLINK request");
                        }
                        other => anyhow::bail!(
                            "unexpected rtnetlink response type {other} for RTM_GETLINK"
                        ),
                    }
                }
                offset = aligned_end;
            }
        }
        anyhow::bail!(
            "RTM_GETLINK produced no matching response within {MAX_NETLINK_REPLY_DATAGRAMS} datagrams"
        )
    }

    fn inspect(resource: &TunResource) -> Result<Option<TunObservation>> {
        inspect_name(&resource.interface.name)
    }

    pub fn capture(name: &str) -> Result<TunResource> {
        let actual = inspect_name(name)?.context("new TUN interface is absent")?;
        Ok(TunResource {
            interface: InterfaceIdentity {
                name: name.to_string(),
                ifindex: actual.ifindex,
            },
        })
    }

    /// Mark a newly-created interface after its TunResource has been durably
    /// journaled as Planned.
    pub fn mark_owned(resource: &TunResource, session: SessionId) -> Result<()> {
        let before = inspect(resource)?.context("TUN disappeared before ownership marking")?;
        anyhow::ensure!(
            before.name == resource.interface.name && before.ifindex == resource.interface.ifindex,
            "TUN identity changed before ownership marking"
        );
        anyhow::ensure!(
            before.alias.is_empty() || before.alias == session.owner_tag(),
            "TUN already has a foreign interface alias"
        );
        if before.alias.is_empty() {
            link_request(
                libc::RTM_NEWLINK,
                resource.interface.ifindex,
                Some(&session.owner_tag()),
            )
            .context("mark TUN ownership by exact ifindex")?;
        }
        let deadline = std::time::Instant::now()
            .checked_add(TUN_ALIAS_VISIBILITY_TIMEOUT)
            .context("TUN alias verification deadline overflow")?;
        loop {
            let after = inspect(resource)?;
            let classified = classify_tun(resource, session, after.as_ref());
            if classified == ResourceObservationKind::ExactOwnedPresent {
                return Ok(());
            }
            // A successful mutation ACK can theoretically precede visibility
            // to a subsequent RTM_GETLINK query. Retry only the exact same
            // interface with an as-yet-empty alias. Absence, reuse, or any
            // foreign alias is an immediate conflict, never an
            // eventual-consistency retry.
            let retryable_empty_alias = after.as_ref().is_some_and(|observation| {
                observation.name == resource.interface.name
                    && observation.ifindex == resource.interface.ifindex
                    && observation.alias.is_empty()
            });
            if !retryable_empty_alias || std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "TUN ownership marker did not verify; classified {classified:?}, observed {after:?}"
                );
            }
            std::thread::sleep(TUN_ALIAS_VISIBILITY_POLL);
        }
    }

    pub fn inspect_kind(
        resource: &TunResource,
        session: SessionId,
    ) -> Result<ResourceObservationKind> {
        let observation = inspect(resource)?;
        Ok(classify_tun(resource, session, observation.as_ref()))
    }

    /// Prove stable absence without deleting by ifindex. There is no rtnetlink
    /// compare-and-delete primitive for name+ifindex+alias; an inspect→delete
    /// sequence could delete a foreign interface after ifindex reuse. The
    /// production TUN is non-persistent, so presence after owner death instead
    /// means a leaked descriptor, persistence, or identity race and must fail
    /// closed for operator inspection.
    pub fn converge_absent(
        resource: &TunResource,
        session: SessionId,
    ) -> std::result::Result<(), TunConvergenceError> {
        for boundary in ["first", "immediate"] {
            match inspect_kind(resource, session).map_err(TunConvergenceError::Operational)? {
                ResourceObservationKind::Absent => {}
                ResourceObservationKind::Conflict => {
                    return Err(TunConvergenceError::Conflict(anyhow::anyhow!(
                        "{boundary} TUN absence census observed a foreign/reused interface"
                    )))
                }
                ResourceObservationKind::ExactOwnedPresent => {
                    return Err(TunConvergenceError::Conflict(anyhow::anyhow!(
                        "{boundary} TUN absence census observed a surviving owned interface; refusing non-atomic RTM_DELLINK"
                    )))
                }
            }
        }
        Ok(())
    }

    pub fn remove_exact(resource: &TunResource, session: SessionId) -> Result<()> {
        converge_absent(resource, session).map_err(anyhow::Error::new)
    }

    #[cfg(test)]
    mod parser_tests {
        use super::*;

        fn push_attribute(message: &mut Vec<u8>, kind: u16, payload: &[u8]) {
            let offset = message.len();
            let length = size_of::<RtAttribute>() + payload.len();
            message.resize(offset + align4(length), 0);
            // SAFETY: resize above reserved the complete header and payload.
            unsafe {
                std::ptr::write_unaligned(
                    message.as_mut_ptr().add(offset).cast::<RtAttribute>(),
                    RtAttribute {
                        length: length.try_into().unwrap(),
                        kind,
                    },
                );
            }
            let payload_start = offset + size_of::<RtAttribute>();
            message[payload_start..payload_start + payload.len()].copy_from_slice(payload);
        }

        fn link_message(attributes: &[(u16, &[u8])]) -> Vec<u8> {
            let base = size_of::<libc::nlmsghdr>() + size_of::<libc::ifinfomsg>();
            let mut message = vec![0u8; base];
            let mut info = unsafe { MaybeUninit::<libc::ifinfomsg>::zeroed().assume_init() };
            info.ifi_index = 17;
            // SAFETY: the base allocation covers the complete ifinfomsg.
            unsafe {
                std::ptr::write_unaligned(
                    message
                        .as_mut_ptr()
                        .add(size_of::<libc::nlmsghdr>())
                        .cast::<libc::ifinfomsg>(),
                    info,
                );
            }
            for (kind, payload) in attributes {
                push_attribute(&mut message, *kind, payload);
            }
            message
        }

        #[test]
        fn parses_atomic_name_index_and_alias_observation() {
            let message = link_message(&[
                (libc::IFLA_IFNAME, b"sptun0\0"),
                (libc::IFLA_IFALIAS, b"shadowpipe:001122\0"),
            ]);
            assert_eq!(
                parse_link_observation(&message, "sptun0").unwrap(),
                TunObservation {
                    name: "sptun0".to_string(),
                    ifindex: 17,
                    alias: "shadowpipe:001122".to_string(),
                }
            );
        }

        #[test]
        fn missing_alias_is_observed_as_empty_but_duplicate_identity_is_rejected() {
            let message = link_message(&[(libc::IFLA_IFNAME, b"sptun0\0")]);
            assert_eq!(
                parse_link_observation(&message, "sptun0").unwrap().alias,
                ""
            );

            let duplicate = link_message(&[
                (libc::IFLA_IFNAME, b"sptun0\0"),
                (libc::IFLA_IFNAME, b"sptun0\0"),
            ]);
            assert!(parse_link_observation(&duplicate, "sptun0")
                .unwrap_err()
                .to_string()
                .contains("duplicate IFLA_IFNAME"));
        }

        #[test]
        fn malformed_or_ambiguous_string_attributes_are_rejected() {
            let embedded_nul = link_message(&[(libc::IFLA_IFNAME, b"sp\0tun0\0")]);
            assert!(parse_link_observation(&embedded_nul, "sptun0")
                .unwrap_err()
                .to_string()
                .contains("embedded NUL"));

            let mut truncated = link_message(&[(libc::IFLA_IFNAME, b"sptun0\0")]);
            truncated.pop();
            assert!(parse_link_observation(&truncated, "sptun0")
                .unwrap_err()
                .to_string()
                .contains("padding"));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    capture as capture_tun_resource, converge_absent as converge_tun_absent,
    inspect_kind as inspect_tun, mark_owned as mark_tun_owned, remove_exact as remove_tun_exact,
};

#[cfg(not(target_os = "linux"))]
pub fn capture_tun_resource(_name: &str) -> Result<TunResource> {
    anyhow::bail!("journaled TUN ownership is Linux-only")
}

#[cfg(not(target_os = "linux"))]
pub fn inspect_tun(
    _resource: &TunResource,
    _session: SessionId,
) -> Result<ResourceObservationKind> {
    anyhow::bail!("journaled TUN inspection is Linux-only")
}

#[cfg(not(target_os = "linux"))]
pub fn mark_tun_owned(_resource: &TunResource, _session: SessionId) -> Result<()> {
    anyhow::bail!("journaled TUN ownership is Linux-only")
}

#[cfg(not(target_os = "linux"))]
pub fn remove_tun_exact(_resource: &TunResource, _session: SessionId) -> Result<()> {
    anyhow::bail!("journaled TUN recovery is Linux-only")
}

#[cfg(not(target_os = "linux"))]
pub fn converge_tun_absent(
    _resource: &TunResource,
    _session: SessionId,
) -> std::result::Result<(), TunConvergenceError> {
    Err(TunConvergenceError::Operational(anyhow::anyhow!(
        "journaled TUN recovery is Linux-only"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_state::InterfaceIdentity;

    fn resource() -> TunResource {
        TunResource {
            interface: InterfaceIdentity {
                name: "sptun0".to_string(),
                ifindex: 17,
            },
        }
    }

    #[test]
    fn exact_name_index_and_full_alias_are_required() {
        let resource = resource();
        let session = SessionId::from_bytes([7; 16]);
        let exact = TunObservation {
            name: "sptun0".to_string(),
            ifindex: 17,
            alias: session.owner_tag(),
        };
        assert_eq!(
            classify_tun(&resource, session, Some(&exact)),
            ResourceObservationKind::ExactOwnedPresent
        );
        assert_eq!(
            classify_tun(&resource, session, None),
            ResourceObservationKind::Absent
        );

        for foreign in [
            TunObservation {
                name: "sptun1".to_string(),
                ..exact.clone()
            },
            TunObservation {
                ifindex: 18,
                ..exact.clone()
            },
            TunObservation {
                alias: "shadowpipe:foreign".to_string(),
                ..exact
            },
        ] {
            assert_eq!(
                classify_tun(&resource, session, Some(&foreign)),
                ResourceObservationKind::Conflict
            );
        }
    }
}
