use anyhow::{Context, Result};
#[cfg(any(test, feature = "test-util"))] // VecDeque is only used by the test-only MemTun
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tun::AbstractDevice;
use tun::{AsyncDevice, Configuration};

pub type TunDevice = AsyncDevice;

/// TUN I/O surface used by `run_tunnel` (OS device or in-memory test double).
#[derive(Clone)]
pub enum TunnelIo {
    Os(SharedTun),
    #[cfg(any(test, feature = "test-util"))]
    Mem(MemTun),
}

impl TunnelIo {
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        match self {
            TunnelIo::Os(t) => t.read_packet(buf).await,
            #[cfg(any(test, feature = "test-util"))]
            TunnelIo::Mem(t) => t.read_packet(buf).await,
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        match self {
            TunnelIo::Os(t) => t.write_packet(packet).await,
            #[cfg(any(test, feature = "test-util"))]
            TunnelIo::Mem(t) => t.write_packet(packet).await,
        }
    }
}

impl From<SharedTun> for TunnelIo {
    fn from(t: SharedTun) -> Self {
        TunnelIo::Os(t)
    }
}

/// In-memory TUN for integration tests (`test-util` feature).
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone)]
pub struct MemTun {
    inner: Arc<MemTunInner>,
}

#[cfg(any(test, feature = "test-util"))]
struct MemTunInner {
    read_q: Mutex<VecDeque<Vec<u8>>>,
    read_notify: tokio::sync::Notify,
    written: Mutex<Vec<Vec<u8>>>,
}

#[cfg(any(test, feature = "test-util"))]
impl Default for MemTun {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl MemTun {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MemTunInner {
                read_q: Mutex::new(VecDeque::new()),
                read_notify: tokio::sync::Notify::new(),
                written: Mutex::new(Vec::new()),
            }),
        }
    }

    pub async fn inject_packet(&self, packet: Vec<u8>) {
        self.inner.read_q.lock().await.push_back(packet);
        self.inner.read_notify.notify_waiters();
    }

    pub async fn drain_written(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.inner.written.lock().await)
    }

    pub async fn total_written_bytes(&self) -> usize {
        self.inner
            .written
            .lock()
            .await
            .iter()
            .map(|p| p.len())
            .sum()
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            {
                let mut q = self.inner.read_q.lock().await;
                if let Some(pkt) = q.pop_front() {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    if n < pkt.len() {
                        q.push_front(pkt[n..].to_vec());
                    }
                    return Ok(n);
                }
            }
            self.inner.read_notify.notified().await;
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        self.inner.written.lock().await.push(packet.to_vec());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: Option<String>,
    pub address: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            address: Ipv4Addr::new(10, 8, 0, 2),
            peer: Ipv4Addr::new(10, 8, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1280,
        }
    }
}

impl TunConfig {
    pub fn server_default() -> Self {
        Self {
            address: Ipv4Addr::new(10, 8, 0, 1),
            peer: Ipv4Addr::new(10, 8, 0, 2),
            ..Self::default()
        }
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// Split TUN read/write halves so concurrent tunnel tasks do not deadlock.
#[derive(Clone)]
pub struct SharedTun {
    read: Arc<Mutex<tokio::io::ReadHalf<AsyncDevice>>>,
    write: Arc<Mutex<tokio::io::WriteHalf<AsyncDevice>>>,
}

impl SharedTun {
    pub fn new(dev: AsyncDevice) -> Self {
        let (read, write) = tokio::io::split(dev);
        Self {
            read: Arc::new(Mutex::new(read)),
            write: Arc::new(Mutex::new(write)),
        }
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        self.read.lock().await.read(buf).await.context("tun read")
    }

    pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        self.write
            .lock()
            .await
            .write_all(packet)
            .await
            .context("tun write")
    }
}

pub async fn open_async(cfg: &TunConfig) -> Result<AsyncDevice> {
    let config = tun_configuration(cfg);
    tun::create_as_async(&config).context("create tun device (needs root/CAP_NET_ADMIN)")
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxClientTunOpenMode {
    KernelAllocated,
    ExclusiveNamed,
}

#[cfg(any(target_os = "linux", test))]
fn linux_client_tun_open_mode(cfg: &TunConfig) -> LinuxClientTunOpenMode {
    if cfg.name.is_some() {
        LinuxClientTunOpenMode::ExclusiveNamed
    } else {
        LinuxClientTunOpenMode::KernelAllocated
    }
}

/// Open a client TUN without allowing an explicit Linux name to attach to an
/// existing interface.
///
/// An empty Linux `ifr_name` asks the kernel to atomically allocate a fresh
/// `tunN`, so that path may use the portable `tun` crate opener. An explicit
/// name must use `IFF_TUN_EXCL`; otherwise `TUNSETIFF` may attach this process
/// to a foreign persistent TUN before ownership journaling can inspect it.
pub async fn open_async_client(cfg: &TunConfig) -> Result<AsyncDevice> {
    #[cfg(target_os = "linux")]
    match linux_client_tun_open_mode(cfg) {
        LinuxClientTunOpenMode::ExclusiveNamed => {
            return open_async_exclusive_named(cfg).await;
        }
        LinuxClientTunOpenMode::KernelAllocated => {}
    }

    open_async(cfg).await
}

fn tun_configuration(cfg: &TunConfig) -> Configuration {
    let mut config = Configuration::default();
    config
        .address(cfg.address)
        .destination(cfg.peer)
        .netmask(cfg.netmask)
        .mtu(cfg.mtu)
        .up();

    if let Some(name) = &cfg.name {
        config.tun_name(name);
    }
    config
}

/// Create a named, non-persistent Linux TUN without ever attaching to an
/// interface that already exists.
///
/// `tun::create_as_async` normally issues `TUNSETIFF` without `IFF_TUN_EXCL`.
/// For a fixed name that allows an attach-to-existing race between a userspace
/// preflight and the ioctl. Neither endpoint can prove such an interface is its
/// own, so named Linux client and server startup paths use the kernel's atomic
/// exclusion flag instead: a collision fails closed and the existing link is
/// left untouched.
#[cfg(target_os = "linux")]
pub async fn open_async_exclusive_named(cfg: &TunConfig) -> Result<AsyncDevice> {
    use std::ffi::{CStr, CString};
    use std::fs::OpenOptions;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    let requested = cfg
        .name
        .as_deref()
        .context("exclusive Linux TUN creation requires an explicit interface name")?;
    validate_linux_iface_name(requested)?;
    let requested_c =
        CString::new(requested).context("validated Linux interface name contains NUL")?;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .context("open /dev/net/tun (needs root/CAP_NET_ADMIN)")?;

    // Zero initialization is the kernel ABI's canonical initialization for
    // `ifreq`, including its union and padding bytes.
    let mut request = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };
    let name_bytes = requested_c.as_bytes_with_nul();
    anyhow::ensure!(
        name_bytes.len() <= request.ifr_name.len(),
        "Linux interface name exceeds IFNAMSIZ"
    );
    // SAFETY: both pointers are live and the bound above proves the destination
    // has room for the complete NUL-terminated name.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr().cast::<libc::c_char>(),
            request.ifr_name.as_mut_ptr(),
            name_bytes.len(),
        );
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
    }

    // SAFETY: `file` is an open /dev/net/tun descriptor and `request` has the
    // exact kernel `ifreq` layout. IFF_TUN_EXCL makes collision handling atomic.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &mut request) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        return Err(error).with_context(|| {
            format!(
                "create Linux TUN {requested:?} exclusively; an existing interface is never attached or deleted"
            )
        });
    }

    // SAFETY: a successful TUNSETIFF writes a NUL-terminated name into ifr_name.
    let actual = unsafe { CStr::from_ptr(request.ifr_name.as_ptr()) }
        .to_str()
        .context("kernel returned a non-UTF-8 TUN interface name")?;
    anyhow::ensure!(
        actual == requested,
        "kernel created unexpected TUN interface {actual:?} instead of {requested:?}"
    );

    // Transfer the already-bound exclusive descriptor into `tun`, then apply
    // addressing while the non-persistent descriptor remains owned. Any error
    // drops it, so the newly-created interface disappears without name-based
    // cleanup.
    let raw_fd = file.into_raw_fd();
    let mut wrapper = Configuration::default();
    wrapper
        .tun_name(actual)
        .mtu(cfg.mtu)
        .raw_fd(raw_fd)
        .close_fd_on_drop(true);
    // A valid raw fd is owned by `tun` from this call onward, including its
    // error paths; closing it again here could race with descriptor reuse.
    let mut device =
        tun::create_as_async(&wrapper).context("wrap exclusively-created Linux TUN descriptor")?;
    let config = tun_configuration(cfg);
    device
        .configure(&config)
        .context("configure exclusively-created Linux TUN")?;
    Ok(device)
}

/// Refuse named TUN startup on platforms where this module cannot provide an
/// atomic create-only primitive. Silent fallback would reintroduce
/// attach-to-existing semantics on at least some supported platforms.
#[cfg(not(target_os = "linux"))]
pub async fn open_async_exclusive_named(_cfg: &TunConfig) -> Result<AsyncDevice> {
    anyhow::bail!("atomic exclusive named TUN creation is currently supported only on Linux")
}

#[cfg(any(target_os = "linux", test))]
fn validate_linux_iface_name(name: &str) -> Result<()> {
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

pub fn iface_name(dev: &AsyncDevice) -> Result<String> {
    dev.tun_name().context("read tun interface name")
}

pub fn nat_setup_hint(tun_addr: Ipv4Addr, egress_iface: &str) {
    let octets = tun_addr.octets();
    let network = Ipv4Addr::new(octets[0], octets[1], octets[2], 0);
    eprintln!(
        "\n--- Linux NAT setup (run as root on server) ---\n\
         sysctl -w net.ipv4.ip_forward=1\n\
         iptables -t nat -A POSTROUTING -s {network}/24 -o {egress_iface} -j MASQUERADE\n\
         iptables -A FORWARD -i shadowpipe0 -j ACCEPT\n\
         iptables -A FORWARD -o shadowpipe0 -m state --state RELATED,ESTABLISHED -j ACCEPT\n\
         ---\n"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        linux_client_tun_open_mode, validate_linux_iface_name, LinuxClientTunOpenMode, TunConfig,
    };

    #[test]
    fn linux_client_uses_exclusive_creation_for_every_explicit_name() {
        let named = TunConfig {
            name: Some("sptunc".to_string()),
            ..TunConfig::default()
        };
        assert_eq!(
            linux_client_tun_open_mode(&named),
            LinuxClientTunOpenMode::ExclusiveNamed
        );

        let unnamed = TunConfig::default();
        assert_eq!(
            linux_client_tun_open_mode(&unnamed),
            LinuxClientTunOpenMode::KernelAllocated
        );
    }

    #[test]
    fn exclusive_linux_name_validation_accepts_a_normal_fixed_name() {
        validate_linux_iface_name("shadowpipe0").expect("normal Linux interface name");
    }

    #[test]
    fn exclusive_linux_name_validation_rejects_ambiguous_or_oversized_names() {
        for invalid in [
            "",
            "0123456789abcdef",
            "../shadowpipe0",
            "shadow pipe",
            "bad\0name",
        ] {
            assert!(
                validate_linux_iface_name(invalid).is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }
}
