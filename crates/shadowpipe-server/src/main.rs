use anyhow::{Context, Result};
use clap::Parser;
use shadowpipe_core::carrier::server_accept;
use shadowpipe_core::client_auth::{parse_client_key_id, AuthorizedClients};
use shadowpipe_core::mux::MuxConfig;
use shadowpipe_core::pacing::{
    build_ping_reply, build_ping_request, parse_ping, PacerConfig, PingMsg,
};
use shadowpipe_core::proto::{CamouflageMode, FrameFlags};
use shadowpipe_core::session::{AuthenticatedSession, ServerState};
use shadowpipe_core::tun_dev::{nat_setup_hint, open_async_exclusive_named, SharedTun};
use shadowpipe_core::tunnel::{
    pacer_from_config, run_tunnel_guarded_with_liveness, server_tun_config, CarrierLivenessConfig,
    DeadCarrier,
};
use shadowpipe_core::volume_guard::VolumeGuard;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tracing::{info, warn};

struct ActiveTunnel {
    gen: u64,
    handle: JoinHandle<()>,
}

/// Admission slot for the single shared TUN. At most one tunnel task may own the
/// TUN at a time. A newcomer is rejected while the current task is live instead
/// of evicting it. Mandatory v3 device authentication has already completed
/// before this type is reachable; authenticated liveness eventually clears a
/// dead owner and permits a reconnect.
struct TunnelSlot {
    active: Mutex<Option<ActiveTunnel>>,
    generation: AtomicU64,
}

impl TunnelSlot {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(None),
            generation: AtomicU64::new(0),
        })
    }

    /// Install a task iff the TUN is currently idle. `make_task` runs while the
    /// slot lock is held and receives the generation plus an `Arc` to this slot
    /// so the task can clear its own entry when it ends. A busy slot returns
    /// `None` without invoking the closure or disturbing the active task.
    async fn install_if_idle<F>(self: &Arc<Self>, make_task: F) -> Option<u64>
    where
        F: FnOnce(u64, Arc<TunnelSlot>) -> JoinHandle<()>,
    {
        let mut slot = self.active.lock().await;
        // A panic occurs before the task's normal clear path. Reap only a handle
        // Tokio has already marked finished; never use this as a reason to abort
        // or replace a still-running owner.
        if slot
            .as_ref()
            .is_some_and(|active| active.handle.is_finished())
        {
            let finished = slot.take().expect("finished slot entry disappeared");
            if let Err(error) = finished.handle.await {
                warn!(gen = finished.gen, %error, "reaped failed tunnel owner");
            }
        }
        if slot.is_some() {
            return None;
        }
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let handle = make_task(gen, Arc::clone(self));
        *slot = Some(ActiveTunnel { gen, handle });
        Some(gen)
    }

    /// Clear the slot iff it still holds `gen` (the task ended on its own and a
    /// newer client hasn't already taken over — never stomp the newcomer).
    async fn clear_if_current(&self, gen: u64) {
        let mut slot = self.active.lock().await;
        if slot.as_ref().is_some_and(|s| s.gen == gen) {
            *slot = None;
        }
    }
}

struct SharedTunnel {
    tun: SharedTun,
    slot: Arc<TunnelSlot>,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "shadowpipe-server", about = "shadowpipe tunnel server")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:47843")]
    listen: String,

    #[arg(long)]
    tunnel: bool,

    #[arg(long, default_value = "shadowpipe0")]
    tun_name: String,

    #[arg(long, default_value = "10.8.0.1")]
    tun_addr: Ipv4Addr,

    #[arg(long, default_value = "10.8.0.2")]
    tun_peer: Ipv4Addr,

    #[arg(long, default_value = "1280")]
    mtu: u16,

    #[arg(long, default_value = "24")]
    mux_streams: u32,

    #[arg(long, default_value = "4096")]
    mux_chunk: usize,

    #[arg(long)]
    nat_hint: bool,

    #[arg(long, default_value = "eth0")]
    egress_iface: String,

    #[arg(long, default_value = "/etc/shadowpipe/keys.json")]
    keys: PathBuf,

    /// Root-owned, single-link mode-0600 hybrid client authorization database.
    /// Missing, empty, malformed, or unsafe files abort before bind or TUN.
    #[arg(long, default_value = "/etc/shadowpipe/client-allowlist.json")]
    client_allowlist: PathBuf,

    /// Explicit no-TUN lab mode: accept an exact-0600 allowlist owned by the
    /// effective user. Normal daemon/tunnel starts remain root-owned only.
    #[arg(long, conflicts_with = "tunnel")]
    development_user_allowlist: bool,

    /// INSECURE LAB ONLY: permit Raw/H2/TLS/QUIC, whose distinguishable
    /// ShadowPipe bootstrap/challenge is reachable by an active probe even
    /// though the mutual PSK gate withholds ML-KEM and KEM work. Requires the
    /// user-owned no-TUN allowlist mode. Production requires REALITY's outer
    /// cover and genuine-service forward-on-fail behavior.
    #[arg(
        long,
        requires = "development_user_allowlist",
        conflicts_with_all = ["tunnel", "reality"]
    )]
    allow_insecure_lab_carriers: bool,

    /// One-shot: strictly load a non-empty client authorization database and
    /// exit before server keys, bind, cover profiling, or TUN. Production mode
    /// requires effective UID 0 plus a root-owned, single-link mode-0600 file.
    #[arg(
        long,
        conflicts_with_all = [
            "enroll_client",
            "revoke_client",
            "listen",
            "tunnel",
            "nat_hint",
            "gen_keys",
            "gen_reality_key",
            "print_uri",
            "tls",
            "reality",
            "quic"
        ]
    )]
    validate_client_allowlist: bool,

    /// One-shot: add a root-owned mode-0600 secret enrollment artifact to the
    /// allowlist under a serialized nonblocking mutation lease, then exit.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = [
            "revoke_client",
            "listen",
            "tunnel",
            "nat_hint",
            "gen_keys",
            "gen_reality_key",
            "print_uri",
            "tls",
            "reality",
            "quic"
        ]
    )]
    enroll_client: Option<PathBuf>,

    /// One-shot: revoke a 128-bit lowercase-hex client key id, then exit. The
    /// last authorized client cannot be removed.
    #[arg(
        long,
        value_name = "32_LOWER_HEX",
        conflicts_with_all = [
            "enroll_client",
            "listen",
            "tunnel",
            "nat_hint",
            "gen_keys",
            "gen_reality_key",
            "print_uri",
            "tls",
            "reality",
            "quic"
        ]
    )]
    revoke_client: Option<String>,

    /// Create the ML-KEM identity if absent, or load the existing identity;
    /// print its fingerprint and exit. Never performs implicit key rotation.
    #[arg(long)]
    gen_keys: bool,

    /// Terminate a real Chrome-JA4 TLS layer (boring-front) and run shadowpipe
    /// inside it. On the wire the connection looks like HTTPS. Uses an ephemeral
    /// self-signed cert; the client pins the inner ML-KEM server identity instead.
    #[arg(long)]
    tls: bool,

    /// Use the REALITY carrier instead of --tls: terminate a from-scratch
    /// TLS 1.3 + REALITY handshake. Peers presenting an accepted REALITY token
    /// run shadowpipe inside; every other peer is transparently forwarded to the
    /// cover. Token acceptance is not client identity authentication. Mutually
    /// exclusive with --tls.
    #[arg(long, conflicts_with = "tls")]
    reality: bool,

    /// REALITY X25519 static secret file (hex). Loaded on start, or generated if
    /// absent. The public half is what clients pass as --reality-pubkey.
    #[arg(long, default_value = "/etc/shadowpipe/reality.key")]
    reality_key: PathBuf,

    /// Durable authenticated REALITY exact-replay store. Production defaults to
    /// /var/lib/shadowpipe/reality-replay-v1.bin. Explicit user-owned no-TUN
    /// development runs must provide their own private path. The same-host lease
    /// is exclusive; replicas without strongly consistent shared replay state
    /// must use distinct REALITY static keys.
    #[arg(
        long,
        value_name = "PATH",
        requires = "reality",
        conflicts_with_all = [
            "print_uri",
            "gen_keys",
            "gen_reality_key",
            "validate_client_allowlist",
            "enroll_client",
            "revoke_client",
            "nat_hint"
        ]
    )]
    reality_replay_store: Option<PathBuf>,

    /// Create the REALITY X25519 identity if absent, or load the existing one;
    /// print its public key and exit. Never performs implicit key rotation.
    #[arg(long)]
    gen_reality_key: bool,

    /// INSECURE DEVELOPMENT ONLY: inline REALITY short_id tokens for explicit
    /// user-owned no-TUN runs. Production and --print-uri read the root-owned
    /// --reality-short-id-file so tokens never appear in daemon argv.
    #[arg(
        long,
        requires = "development_user_allowlist",
        conflicts_with_all = ["tunnel", "print_uri"]
    )]
    reality_short_id: Vec<String>,

    /// Production REALITY short_id ACL: root-owned, single-link, non-symlink,
    /// exact mode 0600; 1..16 sorted unique lines, each 16 lowercase hex chars.
    #[arg(long, default_value = "/etc/shadowpipe/reality-short-ids")]
    reality_short_id_file: PathBuf,

    /// Cover site `host:port` REALITY forwards non-accepted-token peers to. Use a
    /// real TLS site that plausibly matches the client SNI.
    #[arg(long, default_value = "www.microsoft.com:443")]
    cover: String,

    /// Skip profiling the cover at startup. By default the server connects once to
    /// --cover to measure its cipher + flight size so the accepted-token carrier
    /// mimics it (anti-passive-correlation). Disable for a slow/unreachable cover.
    #[arg(long)]
    no_cover_profile: bool,

    /// Public `host:port` to advertise in the printed connection URI (defaults to
    /// --listen). Set this to the address clients actually dial.
    #[arg(long)]
    advertise: Option<String>,

    /// Explicit secret-output one-shot: strictly read --reality-short-id-file,
    /// load keys, print `reality-uri:` (including its first short_id), and exit.
    /// Does not bind, open TUN, or profile the cover site.
    #[arg(long)]
    print_uri: bool,

    /// Use the QUIC carrier (UDP) instead of --tls/--reality: terminate a QUIC
    /// (TLS 1.3) handshake on a UDP socket bound to --listen and run shadowpipe
    /// inside one bi-stream. The client pins the inner ML-KEM server identity,
    /// not the ephemeral certificate. Runs as its own UDP listener alongside the
    /// TCP socket. Requires a build with `--features quic`.
    #[arg(long, conflicts_with_all = ["tls", "reality"])]
    quic: bool,

    /// Degradation-symmetric pacer on the server's downlink (the heavier
    /// direction): throttle covert send rate to track the path's goodput so it
    /// backs off like an ordinary flow. OFF by default. NOTE: RU on-path effect NOT
    /// validated. ADAPTIVE only for QUIC clients (downlink goodput = cwnd/rtt);
    /// inert on TCP carriers (--tls/--reality), which have no path-feedback signal.
    #[arg(long, default_value = "false")]
    pace: bool,

    /// Hard cap shared by accepted TCP and QUIC connection tasks, including
    /// established sessions. At saturation a new peer is rejected before spawn.
    #[arg(long, default_value_t = 256)]
    max_connections: usize,

    /// Monotonic deadline for TLS/REALITY/carrier/QUIC establishment after
    /// transport admission. For a rejected REALITY token this bounds only
    /// classification, cover connect, ClientHello write and flush; the
    /// established cover splice has a separate sliding idle deadline.
    #[arg(long, default_value_t = 15)]
    outer_handshake_timeout_secs: u64,

    /// Sliding monotonic idle timeout for an established REALITY forward-to-cover
    /// splice. Progress in either direction resets it, so an active asymmetric
    /// HTTP/2 download is not cut off by the outer-handshake absolute deadline.
    #[arg(long, default_value_t = 300)]
    forward_idle_timeout_secs: u64,

    /// Monotonic deadline for the inner post-quantum session handshake.
    #[arg(long, default_value_t = 15)]
    inner_handshake_timeout_secs: u64,

    /// Authenticated receive-idle interval before an encrypted liveness probe.
    #[arg(long, default_value_t = 30)]
    carrier_idle_timeout_secs: u64,

    /// Deadline after a probe for any newly authenticated peer frame.
    #[arg(long, default_value_t = 10)]
    carrier_probe_timeout_secs: u64,

    /// Bound for acquiring/emitting the encrypted liveness or echo write.
    #[arg(long, default_value_t = 5)]
    carrier_write_timeout_secs: u64,
}

#[derive(Clone, Copy, Debug)]
struct RuntimeLimits {
    max_connections: usize,
    outer_handshake: Duration,
    forward_idle: Duration,
    inner_handshake: Duration,
    liveness: CarrierLivenessConfig,
}

fn validate_identity_parent(path: &Path, development_user_owned: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // SAFETY: geteuid takes no arguments and has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        if !development_user_owned {
            anyhow::ensure!(
                effective_uid == 0,
                "production server identity paths require effective UID 0"
            );
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .context("resolve server identity working directory")?
                .join(path)
        };
        let parent = absolute
            .parent()
            .context("server identity path has no parent")?;
        let mut cursor = PathBuf::new();
        for component in parent.components() {
            match component {
                Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                    cursor.push(component.as_os_str());
                }
                Component::CurDir => continue,
                Component::ParentDir => {
                    anyhow::bail!("server identity path may not contain parent traversal")
                }
            }
            let metadata = std::fs::symlink_metadata(&cursor).with_context(|| {
                format!("inspect server identity directory {}", cursor.display())
            })?;
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "server identity directory is not a real directory: {}",
                cursor.display()
            );
            let owner_allowed =
                metadata.uid() == 0 || (development_user_owned && metadata.uid() == effective_uid);
            anyhow::ensure!(
                owner_allowed,
                "server identity directory {} has untrusted owner UID {}",
                cursor.display(),
                metadata.uid()
            );
            let mode = metadata.permissions().mode() & 0o777;
            anyhow::ensure!(
                mode & 0o022 == 0,
                "server identity directory {} is group/world writable ({mode:04o})",
                cursor.display()
            );
        }
    }
    Ok(())
}

fn load_or_create_server_identity(
    path: &Path,
    development_user_owned: bool,
) -> Result<ServerState> {
    validate_identity_parent(path, development_user_owned)?;
    ServerState::load_or_generate(path)
}

fn load_or_create_reality_public(path: &Path, development_user_owned: bool) -> Result<String> {
    let secret = load_or_create_reality_secret(path, development_user_owned)?;
    Ok(shadowpipe_core::reality::static_public_hex(&secret))
}

fn load_or_create_reality_secret(
    path: &Path,
    development_user_owned: bool,
) -> Result<shadowpipe_core::reality::StaticSecret> {
    validate_identity_parent(path, development_user_owned)?;
    shadowpipe_core::reality::load_or_generate_static_secret(path)
}

impl RuntimeLimits {
    const MIN_CONNECTIONS: usize = 1;
    const MAX_CONNECTIONS: usize = 4096;
    const MIN_STAGE_SECONDS: u64 = 1;
    const MAX_STAGE_SECONDS: u64 = 120;
    const MIN_IDLE_SECONDS: u64 = 5;
    const MAX_IDLE_SECONDS: u64 = 15 * 60;

    fn from_args(args: &Args) -> Result<Self> {
        fn bounded_seconds(name: &str, value: u64, min: u64, max: u64) -> Result<Duration> {
            anyhow::ensure!(
                (min..=max).contains(&value),
                "--{name} must be between {min} and {max} seconds"
            );
            Ok(Duration::from_secs(value))
        }

        anyhow::ensure!(
            (Self::MIN_CONNECTIONS..=Self::MAX_CONNECTIONS).contains(&args.max_connections),
            "--max-connections must be between {} and {}",
            Self::MIN_CONNECTIONS,
            Self::MAX_CONNECTIONS
        );
        let outer_handshake = bounded_seconds(
            "outer-handshake-timeout-secs",
            args.outer_handshake_timeout_secs,
            Self::MIN_STAGE_SECONDS,
            Self::MAX_STAGE_SECONDS,
        )?;
        let inner_handshake = bounded_seconds(
            "inner-handshake-timeout-secs",
            args.inner_handshake_timeout_secs,
            Self::MIN_STAGE_SECONDS,
            Self::MAX_STAGE_SECONDS,
        )?;
        let forward_idle = bounded_seconds(
            "forward-idle-timeout-secs",
            args.forward_idle_timeout_secs,
            Self::MIN_IDLE_SECONDS,
            Self::MAX_IDLE_SECONDS,
        )?;
        let idle_timeout = bounded_seconds(
            "carrier-idle-timeout-secs",
            args.carrier_idle_timeout_secs,
            Self::MIN_IDLE_SECONDS,
            Self::MAX_IDLE_SECONDS,
        )?;
        let probe_timeout = bounded_seconds(
            "carrier-probe-timeout-secs",
            args.carrier_probe_timeout_secs,
            Self::MIN_STAGE_SECONDS,
            Self::MAX_STAGE_SECONDS,
        )?;
        let write_timeout = bounded_seconds(
            "carrier-write-timeout-secs",
            args.carrier_write_timeout_secs,
            Self::MIN_STAGE_SECONDS,
            Self::MAX_STAGE_SECONDS,
        )?;
        let liveness = CarrierLivenessConfig::new(idle_timeout, probe_timeout, write_timeout)
            .context("validate authenticated carrier liveness deadlines")?;
        Ok(Self {
            max_connections: args.max_connections,
            outer_handshake,
            forward_idle,
            inner_handshake,
            liveness,
        })
    }
}

fn validate_daemon_carrier_security(args: &Args) -> Result<()> {
    if args.reality {
        anyhow::ensure!(
            !args.allow_insecure_lab_carriers,
            "--allow-insecure-lab-carriers cannot weaken the production REALITY path"
        );
        resolve_reality_replay_store(args)?;
        return Ok(());
    }

    anyhow::ensure!(
        args.allow_insecure_lab_carriers
            && args.development_user_allowlist
            && !args.tunnel,
        "production daemon requires --reality: Raw/H2/TLS/QUIC expose a distinguishable ShadowPipe bootstrap/challenge to active probes (the mutual PSK gate still withholds ML-KEM bytes and KEM work); lab use requires --allow-insecure-lab-carriers with --development-user-allowlist and no --tunnel"
    );
    Ok(())
}

const DEFAULT_REALITY_REPLAY_STORE: &str = "/var/lib/shadowpipe/reality-replay-v1.bin";

fn resolve_reality_replay_store(
    args: &Args,
) -> Result<Option<(PathBuf, shadowpipe_core::reality::ReplayStoreOwner)>> {
    use shadowpipe_core::reality::ReplayStoreOwner;

    if !args.reality || args.print_uri {
        return Ok(None);
    }
    if args.development_user_allowlist {
        let path = args.reality_replay_store.clone().context(
            "development REALITY requires explicit --reality-replay-store; process-local replay state is forbidden",
        )?;
        Ok(Some((path, ReplayStoreOwner::EffectiveUser)))
    } else {
        Ok(Some((
            args.reality_replay_store
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_REALITY_REPLAY_STORE)),
            ReplayStoreOwner::Root,
        )))
    }
}

const MAX_PRODUCTION_REALITY_SHORT_IDS: usize = 16;
const MAX_REALITY_SHORT_ID_FILE_BYTES: u64 = 1024;

fn parse_full_width_reality_short_ids(contents: &str) -> Result<Vec<Vec<u8>>> {
    anyhow::ensure!(
        !contents.contains('\r'),
        "REALITY short_id ACL must use canonical LF separators, not CR/CRLF"
    );
    let lines = contents.lines().collect::<Vec<_>>();
    anyhow::ensure!(
        (1..=MAX_PRODUCTION_REALITY_SHORT_IDS).contains(&lines.len()),
        "REALITY short_id ACL requires 1..={MAX_PRODUCTION_REALITY_SHORT_IDS} entries"
    );

    let mut decoded = Vec::with_capacity(lines.len());
    for encoded in lines {
        anyhow::ensure!(
            encoded.len() == 16
                && encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "REALITY short_id must be exactly 16 lowercase hex characters (8 bytes)"
        );
        let token: [u8; 8] = hex::decode(encoded)
            .map_err(|_| anyhow::anyhow!("invalid REALITY short_id"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid REALITY short_id length"))?;
        decoded.push(token);
    }
    anyhow::ensure!(
        decoded.windows(2).all(|pair| pair[0] < pair[1]),
        "REALITY short_id ACL must be strictly sorted and unique"
    );
    Ok(decoded.into_iter().map(|token| token.to_vec()).collect())
}

fn load_production_reality_short_ids(path: &Path) -> Result<Vec<Vec<u8>>> {
    #[cfg(not(unix))]
    anyhow::bail!("production REALITY short_id files require Unix ownership semantics");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        validate_identity_parent(path, false)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open production REALITY short_id file {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("stat production REALITY short_id file {}", path.display()))?;
        anyhow::ensure!(
            metadata.is_file(),
            "production REALITY short_id path is not a regular file"
        );
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.gid() == 0,
            "production REALITY short_id file must be owned by root:root"
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o777 == 0o600,
            "production REALITY short_id file must have exact mode 0600"
        );
        anyhow::ensure!(
            metadata.nlink() == 1,
            "production REALITY short_id file must have exactly one hard link"
        );
        anyhow::ensure!(
            metadata.len() <= MAX_REALITY_SHORT_ID_FILE_BYTES,
            "production REALITY short_id file exceeds {MAX_REALITY_SHORT_ID_FILE_BYTES} bytes"
        );

        let mut contents = String::with_capacity(metadata.len() as usize);
        file.take(MAX_REALITY_SHORT_ID_FILE_BYTES + 1)
            .read_to_string(&mut contents)
            .with_context(|| format!("read production REALITY short_id file {}", path.display()))?;
        anyhow::ensure!(
            contents.len() as u64 <= MAX_REALITY_SHORT_ID_FILE_BYTES,
            "production REALITY short_id file grew beyond its bound while reading"
        );
        parse_full_width_reality_short_ids(&contents)
            .context("validate production REALITY short_id ACL")
    }
}

/// REALITY's public X25519 key alone is not an admission secret. Production
/// uses a strict root-owned file; only explicit user-owned no-TUN development
/// runs may place tokens in argv. This 64-bit online ACL is carrier admission,
/// not per-device identity authentication.
fn load_reality_short_ids(args: &Args) -> Result<Option<Vec<Vec<u8>>>> {
    if !args.reality {
        return Ok(None);
    }
    if args.development_user_allowlist && !args.print_uri {
        anyhow::ensure!(
            !args.reality_short_id.is_empty(),
            "development REALITY requires at least one inline --reality-short-id"
        );
        let canonical = args.reality_short_id.join("\n");
        return parse_full_width_reality_short_ids(&canonical)
            .context("validate development REALITY short_id ACL")
            .map(Some);
    }
    anyhow::ensure!(
        args.reality_short_id.is_empty(),
        "inline --reality-short-id is restricted to explicit development-user no-TUN mode"
    );
    load_production_reality_short_ids(&args.reality_short_id_file)
        .map(Some)
        .context("load mandatory production REALITY short_id ACL before startup")
}

#[derive(Clone)]
struct ConnectionAdmission {
    permits: Arc<Semaphore>,
}

impl ConnectionAdmission {
    fn new(limit: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit)),
        }
    }

    fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }
}

struct AdmittedConnection {
    runtime: RuntimeLimits,
    permit: OwnedSemaphorePermit,
    observed_camouflage: Option<CamouflageMode>,
}

#[derive(Clone)]
struct TcpCarrierConfig {
    #[cfg(feature = "tls-chrome")]
    tls_acceptor: Option<Arc<shadowpipe_core::tls::TlsAcceptor>>,
    reality: Option<Arc<shadowpipe_core::reality::RealityServerConfig>>,
}

#[derive(Debug)]
struct StageTimeout {
    stage: &'static str,
    limit: Duration,
}

impl std::fmt::Display for StageTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} exceeded monotonic deadline of {:.3} seconds",
            self.stage,
            self.limit.as_secs_f64()
        )
    }
}

impl std::error::Error for StageTimeout {}

async fn bounded_stage<T, E, F>(stage: &'static str, limit: Duration, future: F) -> Result<T>
where
    E: Into<anyhow::Error>,
    F: Future<Output = std::result::Result<T, E>>,
{
    match tokio::time::timeout(limit, future).await {
        Ok(result) => result
            .map_err(Into::into)
            .with_context(|| format!("{stage} failed")),
        Err(_) => Err(StageTimeout { stage, limit }.into()),
    }
}

struct RealityStartup {
    sk: shadowpipe_core::reality::StaticSecret,
    pubhex: String,
    short_ids: Vec<Vec<u8>>,
    uri: shadowpipe_core::reality::RealityUri,
}

fn prepare_reality(
    args: &Args,
    state: &ServerState,
    short_ids: Vec<Vec<u8>>,
) -> Result<RealityStartup> {
    use shadowpipe_core::reality::{static_public_hex, PublicKey, RealityUri};
    let sk = load_or_create_reality_secret(&args.reality_key, args.development_user_allowlist)?;
    let pubhex = static_public_hex(&sk);
    let uri = RealityUri {
        host: args
            .advertise
            .clone()
            .unwrap_or_else(|| args.listen.clone()),
        pubkey: PublicKey::from(&sk).to_bytes(),
        sni: args
            .cover
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| args.cover.clone()),
        short_id: short_ids.first().cloned().unwrap_or_default(),
        server_fp: state.fingerprint(),
    };
    Ok(RealityStartup {
        sk,
        pubhex,
        short_ids,
        uri,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let runtime = RuntimeLimits::from_args(&args).context("validate bounded server runtime")?;
    let admission = ConnectionAdmission::new(runtime.max_connections);

    if args.nat_hint {
        nat_setup_hint(args.tun_addr, &args.egress_iface);
        return Ok(());
    }

    if args.gen_keys {
        let state = load_or_create_server_identity(&args.keys, args.development_user_allowlist)?;
        let fp = hex::encode(state.fingerprint());
        info!(path = %args.keys.display(), fingerprint = %fp, "server identity loaded or created without replacement");
        // printed to stdout so the operator can copy it into the client's --server-fp
        println!("server-fp: {fp}");
        return Ok(());
    }

    if args.gen_reality_key {
        let pubhex =
            load_or_create_reality_public(&args.reality_key, args.development_user_allowlist)?;
        info!(path = %args.reality_key.display(), reality_pubkey = %pubhex, "REALITY identity loaded or created without replacement");
        // printed to stdout so the operator can copy it into the client's --reality-pubkey
        println!("reality-pubkey: {pubhex}");
        return Ok(());
    }

    if args.validate_client_allowlist {
        #[cfg(unix)]
        if !args.development_user_allowlist {
            // SAFETY: geteuid takes no arguments and has no preconditions.
            anyhow::ensure!(
                unsafe { libc::geteuid() } == 0,
                "client allowlist validation failed"
            );
        }
        let authorized_clients = if args.development_user_allowlist {
            AuthorizedClients::load_development_user_owned(&args.client_allowlist)
        } else {
            AuthorizedClients::load_root_owned(&args.client_allowlist)
        }
        .map_err(|_| anyhow::anyhow!("client allowlist validation failed"))?;
        anyhow::ensure!(
            !authorized_clients.is_empty(),
            "client allowlist validation failed"
        );
        info!(
            allowlist = %args.client_allowlist.display(),
            clients = authorized_clients.len(),
            "client allowlist validation passed"
        );
        return Ok(());
    }

    if let Some(enrollment) = args.enroll_client.as_deref() {
        let key_id = if args.development_user_allowlist {
            AuthorizedClients::enroll_development_user_owned(&args.client_allowlist, enrollment)
        } else {
            AuthorizedClients::enroll_root_owned(&args.client_allowlist, enrollment)
        }
        .context("atomically enroll hybrid client credential")?;
        info!(
            allowlist = %args.client_allowlist.display(),
            client_kid = %hex::encode(key_id),
            "client enrollment committed; restart the daemon only after validating the intended overlap"
        );
        return Ok(());
    }

    if let Some(encoded) = args.revoke_client.as_deref() {
        let key_id = parse_client_key_id(encoded).context("parse --revoke-client")?;
        if args.development_user_allowlist {
            AuthorizedClients::revoke_development_user_owned(&args.client_allowlist, key_id)
        } else {
            AuthorizedClients::revoke_root_owned(&args.client_allowlist, key_id)
        }
        .context("atomically revoke hybrid client credential")?;
        info!(
            allowlist = %args.client_allowlist.display(),
            client_kid = %hex::encode(key_id),
            "client revocation committed; restart the daemon to activate it"
        );
        return Ok(());
    }

    #[cfg(not(feature = "tls-chrome"))]
    if args.tls {
        anyhow::bail!(
            "--tls requires a build with `--features tls-chrome` (BoringSSL not compiled in)"
        );
    }
    #[cfg(not(feature = "quic"))]
    if args.quic {
        anyhow::bail!("--quic requires a build with `--features quic` (quinn not compiled in)");
    }

    // The public REALITY key is not sufficient admission control. Load and
    // validate the full-width online-token ACL before --print-uri can
    // load/generate either identity and before normal startup can load an
    // allowlist, profile a cover, bind, or open TUN.
    let reality_short_ids = load_reality_short_ids(&args)?;

    // URI inspection is a non-daemon one-shot: it never binds or opens TUN and
    // contains no client credential material, so it does not require an
    // allowlist. Normal startup below remains strictly gated.
    if args.print_uri {
        if !args.reality {
            anyhow::bail!("--print-uri requires --reality");
        }
        let state = load_or_create_server_identity(&args.keys, args.development_user_allowlist)?;
        let prep = prepare_reality(
            &args,
            &state,
            reality_short_ids
                .clone()
                .expect("--print-uri with --reality has validated short ids"),
        )?;
        println!("reality-pubkey: {}", prep.pubhex);
        println!("reality-uri: {}", prep.uri.to_uri());
        return Ok(());
    }

    // Carrier exposure is a configuration error, not a runtime discovery. This
    // gate precedes allowlist/key loading, identity generation, cover profiling,
    // every listener bind and TUN creation. Only REALITY's token-authenticated
    // forward-on-fail path is a production daemon carrier.
    validate_daemon_carrier_security(&args)?;

    // Mandatory startup gate. This happens before server key generation, bind,
    // cover profiling, or TUN creation; there is no empty-list/open fallback.
    let authorized_clients = Arc::new(if args.development_user_allowlist {
        warn!(
            allowlist = %args.client_allowlist.display(),
            "explicit no-TUN development user-owned client allowlist enabled"
        );
        AuthorizedClients::load_development_user_owned(&args.client_allowlist)
            .context("load explicit development user-owned client allowlist before startup")?
    } else {
        AuthorizedClients::load_root_owned(&args.client_allowlist)
            .context("load mandatory root-owned client allowlist before startup")?
    });
    anyhow::ensure!(
        !authorized_clients.is_empty(),
        "client allowlist may not be empty"
    );

    let state = Arc::new(load_or_create_server_identity(
        &args.keys,
        args.development_user_allowlist,
    )?);
    let fp = hex::encode(state.fingerprint());
    info!(keys = %args.keys.display(), fingerprint = %fp, "server keys loaded");
    println!("server-fp: {fp}");

    // tls-chrome: build the self-signed acceptor once (ephemeral per-process cert)
    // and share it across connections.
    #[cfg(feature = "tls-chrome")]
    let acceptor = if args.tls {
        let acc = Arc::new(shadowpipe_core::tls::self_signed_acceptor()?);
        info!("tls-chrome enabled: wire is real TLS, shadowpipe runs inside");
        Some(acc)
    } else {
        None
    };
    // REALITY: build the accept config once (static key + short_id ACL + cover)
    // and share it. The ML-KEM session still runs INSIDE REALITY, so the keys
    // above are also loaded — REALITY's X25519 auth and the PQ pin compose.
    let reality_cfg = if args.reality {
        use shadowpipe_core::reality::{RealityServerConfig, ReplayCache};
        let prep = prepare_reality(
            &args,
            state.as_ref(),
            reality_short_ids
                .clone()
                .expect("--reality has validated short ids"),
        )?;
        info!(
            reality_pubkey = %prep.pubhex,
            cover = %args.cover,
            short_ids = prep.short_ids.len(),
            "reality enabled: accepted tokens enter the carrier; other peers are forwarded to cover"
        );
        println!("reality-pubkey: {}", prep.pubhex);
        let (replay_store_path, replay_store_owner) = resolve_reality_replay_store(&args)?
            .expect("daemon REALITY validation resolved a durable replay store");
        let replay_cache =
            ReplayCache::open_persistent(&replay_store_path, &prep.sk, replay_store_owner)
                .with_context(|| {
                    format!(
                        "open and exclusively load durable REALITY replay store {} before bind",
                        replay_store_path.display()
                    )
                })?;
        if let Some(reason) = replay_cache.fail_forward_reason() {
            warn!(
                replay_store = %replay_store_path.display(),
                %reason,
                "REALITY replay store is corrupted or incomplete; all carrier tokens will fail forward until operator repair"
            );
        } else {
            info!(
                replay_store = %replay_store_path.display(),
                "durable REALITY replay store loaded and exclusively leased before bind"
            );
        }
        // Profile the cover once at startup (best-effort) so the accepted-token handshake
        // mimics its cipher + flight size; falls back to no-mimicry if unreachable.
        let cover_profile = if args.no_cover_profile {
            None
        } else {
            shadowpipe_core::reality::profile_cover_best_effort(&args.cover).await
        };
        Some(Arc::new(RealityServerConfig {
            static_secret: prep.sk,
            short_ids: prep.short_ids,
            cover: args.cover.clone(),
            max_time_skew_secs: Some(120),
            replay_cache,
            cover_profile,
        }))
    } else {
        None
    };

    // All feature, key, allowlist, and carrier configuration validation is now
    // complete. Only after those fail-closed gates may startup bind or open TUN.
    let listener = TcpListener::bind(&args.listen).await?;
    info!(
        listen = %args.listen,
        tunnel = args.tunnel,
        magic = shadowpipe_core::BUILD_MAGIC,
        "listening"
    );

    let shared_tunnel = if args.tunnel {
        nat_setup_hint(args.tun_addr, &args.egress_iface);
        let tun_cfg = server_tun_config(
            Some(args.tun_name.clone()),
            Some(args.tun_addr),
            Some(args.tun_peer),
            args.mtu,
        );
        let tun = open_async_exclusive_named(&tun_cfg).await?;
        info!(
            tun = %tun_cfg.address,
            peer = %tun_cfg.peer,
            iface = %args.tun_name,
            "tunnel device ready"
        );
        Some(Arc::new(SharedTunnel {
            tun: SharedTun::new(tun),
            slot: TunnelSlot::new(),
        }))
    } else {
        None
    };

    // QUIC carrier (UDP): a separate quinn endpoint listener task, since QUIC
    // can never arrive on the TcpListener above. It mirrors handle_client+serve,
    // sharing the SAME state/args/tunnel slot so QUIC and TCP clients contend
    // for the one TUN through the existing single-owner handoff. The TCP loop
    // below still runs (a --quic-only server simply leaves it idle / plain).
    #[cfg(feature = "quic")]
    if args.quic {
        let quic_addr = shadowpipe_core::quic::resolve_quic_addr(&args.listen)?;
        let quic_listener = shadowpipe_core::quic::QuicListener::bind(quic_addr)?;
        info!(listen = %args.listen, "quic carrier enabled (UDP): wire is QUIC, shadowpipe runs inside");
        let q_state = Arc::clone(&state);
        let q_args = args.clone();
        let q_tunnel = shared_tunnel.clone();
        let q_admission = admission.clone();
        let q_authorized = Arc::clone(&authorized_clients);
        tokio::spawn(async move {
            while let Some(connecting) = quic_listener.accept().await {
                let Some(permit) = q_admission.try_admit() else {
                    warn!(
                        max_connections = q_args.max_connections,
                        "rejecting QUIC peer before spawn: connection admission saturated"
                    );
                    continue;
                };
                let state = Arc::clone(&q_state);
                let args = q_args.clone();
                let shared_tunnel = q_tunnel.clone();
                let authorized_clients = Arc::clone(&q_authorized);
                let connection = AdmittedConnection {
                    runtime,
                    permit,
                    observed_camouflage: Some(CamouflageMode::Raw),
                };
                tokio::spawn(async move {
                    match bounded_stage(
                        "QUIC outer handshake",
                        connection.runtime.outer_handshake,
                        connecting.establish(),
                    )
                    .await
                    {
                        Ok(stream) => {
                            info!("quic client connected");
                            // Capture the live QUIC path-stats handle before the
                            // stream is consumed, so the downlink pacer (if --pace)
                            // gets real cwnd/rtt feedback.
                            let stats: Option<Arc<dyn shadowpipe_core::pacing::PathStatsSource>> =
                                Some(Arc::new(stream.path_stats_handle()));
                            if let Err(err) = serve(
                                stream,
                                state,
                                authorized_clients,
                                args,
                                shared_tunnel,
                                stats,
                                connection,
                            )
                            .await
                            {
                                warn!(%err, "quic client error");
                            }
                        }
                        Err(err) => warn!(%err, "quic handshake failed"),
                    }
                });
            }
            warn!("quic listener closed");
        });
    }
    loop {
        let (stream, addr) = listener.accept().await?;
        let Some(permit) = admission.try_admit() else {
            warn!(
                %addr,
                max_connections = runtime.max_connections,
                "rejecting TCP peer before spawn: connection admission saturated"
            );
            continue;
        };
        let state = Arc::clone(&state);
        let args = args.clone();
        let shared_tunnel = shared_tunnel.clone();
        let authorized_clients = Arc::clone(&authorized_clients);
        let carriers = TcpCarrierConfig {
            #[cfg(feature = "tls-chrome")]
            tls_acceptor: acceptor.clone(),
            reality: reality_cfg.clone(),
        };
        let connection = AdmittedConnection {
            runtime,
            permit,
            observed_camouflage: (args.tls || args.reality).then_some(CamouflageMode::Raw),
        };
        tokio::spawn(async move {
            if let Err(err) = handle_client(
                stream,
                state,
                authorized_clients,
                args,
                shared_tunnel,
                carriers,
                connection,
            )
            .await
            {
                warn!(%addr, %err, "client error");
            }
        });
    }
}

async fn handle_client(
    stream: TcpStream,
    state: Arc<ServerState>,
    authorized_clients: Arc<AuthorizedClients>,
    args: Args,
    shared_tunnel: Option<Arc<SharedTunnel>>,
    carriers: TcpCarrierConfig,
    connection: AdmittedConnection,
) -> Result<()> {
    // REALITY token acceptance or forwarding. An accepted token yields a byte
    // stream for shadowpipe; this is carrier admission, not client identity.
    if let Some(cfg) = carriers.reality {
        match bounded_stage(
            "REALITY classification and cover setup",
            connection.runtime.outer_handshake,
            shadowpipe_core::reality::reality_accept_start(stream, &cfg),
        )
        .await?
        {
            shadowpipe_core::reality::RealityCarrierAccept::TokenAccepted(rs) => {
                info!("reality token accepted; carrier established; awaiting v3 device proof");
                serve(
                    rs,
                    state,
                    authorized_clients,
                    args,
                    shared_tunnel,
                    None,
                    connection,
                )
                .await
            }
            shadowpipe_core::reality::RealityCarrierAccept::Forwarded(forwarded) => {
                let forward_idle = connection.runtime.forward_idle;
                let _permit = connection.permit;
                info!(
                    idle_seconds = forward_idle.as_secs(),
                    "reality token not accepted; cover splice established"
                );
                forwarded
                    .run_with_idle_timeout(forward_idle)
                    .await
                    .context("drive REALITY cover splice under sliding idle deadline")
            }
        }
    } else if args.tls {
        #[cfg(feature = "tls-chrome")]
        {
            // tls-chrome: terminate the real TLS layer first; shadowpipe runs inside it
            // with raw framing (no carrier h2/dns — TLS itself is the camouflage).
            let acceptor = carriers
                .tls_acceptor
                .as_ref()
                .context("TLS mode started without a configured acceptor")?;
            let tls = bounded_stage(
                "TLS outer handshake",
                connection.runtime.outer_handshake,
                shadowpipe_core::tls::accept(acceptor, stream),
            )
            .await?;
            info!("tls-chrome carrier accepted");
            serve(
                tls,
                state,
                authorized_clients,
                args,
                shared_tunnel,
                None,
                connection,
            )
            .await
        }
        #[cfg(not(feature = "tls-chrome"))]
        anyhow::bail!(
            "--tls requires a build with `--features tls-chrome` (BoringSSL not compiled in)"
        );
    } else {
        let carrier = bounded_stage(
            "carrier outer handshake",
            connection.runtime.outer_handshake,
            server_accept(stream),
        )
        .await?;
        let observed_camouflage = carrier.mode();
        info!(wire_mode = ?observed_camouflage, "carrier mode detected");
        let mut connection = connection;
        connection.observed_camouflage = Some(observed_camouflage);
        serve(
            carrier,
            state,
            authorized_clients,
            args,
            shared_tunnel,
            None,
            connection,
        )
        .await
    }
}

async fn serve<S>(
    mut stream: S,
    state: Arc<ServerState>,
    authorized_clients: Arc<AuthorizedClients>,
    args: Args,
    shared_tunnel: Option<Arc<SharedTunnel>>,
    carrier_stats: Option<Arc<dyn shadowpipe_core::pacing::PathStatsSource>>,
    connection: AdmittedConnection,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let AdmittedConnection {
        runtime,
        permit,
        observed_camouflage,
    } = connection;
    let observed_camouflage = observed_camouflage
        .context("outer adapter did not provide an observed inner framing class")?;
    let (session, hello, session_id) = bounded_stage(
        "inner post-quantum session handshake",
        runtime.inner_handshake,
        AuthenticatedSession::server_accept(
            &mut stream,
            &state,
            &authorized_clients,
            observed_camouflage,
        ),
    )
    .await?;
    info!(
        session_id = hex::encode(session_id),
        client_kid = %hex::encode(session.client_key_id()),
        camouflage = ?hello.camouflage,
        padding = ?hello.padding_profile,
        "session established"
    );

    if args.tunnel {
        let shared = shared_tunnel.ok_or_else(|| anyhow::anyhow!("tunnel mode not initialized"))?;
        let mux = MuxConfig {
            stream_count: args.mux_streams,
            max_chunk_size: args.mux_chunk,
        };
        let tun = shared.tun.clone();
        let mtu = args.mtu;
        let pace = args.pace;
        // Even an authenticated newcomer never evicts an active task. A failed,
        // timed-out, or concurrently racing connection cannot displace the
        // current TUN owner.
        let Some(gen) = shared
            .slot
            .install_if_idle(move |gen, slot| {
                tokio::spawn(async move {
                    // Hold global admission for the full established lifetime.
                    let _permit = permit;
                    // Degradation pacer on the downlink (the heavier direction).
                    // Adaptive only when carrier_stats is Some (QUIC cwnd/rtt);
                    // TCP falls back to the app-RTT probe in the core runner.
                    let pacer = std::sync::Arc::new(pacer_from_config(PacerConfig {
                        enabled: pace,
                        ..Default::default()
                    }));
                    if let Err(err) = run_tunnel_guarded_with_liveness(
                        tun,
                        stream,
                        session,
                        mux,
                        mtu,
                        VolumeGuard::disabled(),
                        pacer,
                        carrier_stats,
                        Some(runtime.liveness),
                    )
                    .await
                    {
                        warn!(%err, gen, "tunnel session ended");
                    }
                    slot.clear_if_current(gen).await;
                })
            })
            .await
        else {
            anyhow::bail!("active tunnel retained; authenticated newcomer refused while busy");
        };
        info!(
            mux_streams = args.mux_streams,
            gen, "tunnel session starting"
        );
        return Ok(());
    }

    let _permit = permit;
    run_echo_session(&mut stream, session, runtime.liveness).await?;
    bounded_stage(
        "session shutdown",
        runtime.liveness.write_timeout(),
        stream.shutdown(),
    )
    .await
}

async fn bounded_session_send<S>(
    session: &mut AuthenticatedSession,
    stream: &mut S,
    stream_id: u32,
    flags: FrameFlags,
    payload: &[u8],
    limit: Duration,
) -> Result<u64>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout(limit, session.send(stream, stream_id, flags, payload))
        .await
        .map_err(|_| anyhow::Error::from(DeadCarrier))?
}

/// Echo-mode counterpart of the tunnel runner's authenticated liveness monitor.
/// Only a frame returned by `AuthenticatedSession::recv` (and therefore AEAD-verified)
/// resets the idle state. Carrier bytes alone cannot pin a connection permit.
async fn run_echo_session<S>(
    stream: &mut S,
    mut session: AuthenticatedSession,
    liveness: CarrierLivenessConfig,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut probe_nonce = 0u64;
    loop {
        let frame = match tokio::time::timeout(liveness.idle_timeout(), session.recv(stream)).await
        {
            Ok(result) => result?,
            Err(_) => {
                probe_nonce = probe_nonce.wrapping_add(1);
                let request = build_ping_request(probe_nonce);
                bounded_session_send(
                    &mut session,
                    stream,
                    0,
                    FrameFlags::PING,
                    &request,
                    liveness.write_timeout(),
                )
                .await?;
                tokio::time::timeout(liveness.probe_timeout(), session.recv(stream))
                    .await
                    .map_err(|_| anyhow::Error::from(DeadCarrier))??
            }
        };

        let (stream_id, flags, payload, _wire) = frame;
        if flags.contains(FrameFlags::FIN) {
            info!(stream_id, "client closed");
            return Ok(());
        }
        if flags.contains(FrameFlags::PING) {
            // Echo a tagged request; replies and legacy payloads never recurse.
            if let PingMsg::Request(timestamp) = parse_ping(&payload) {
                let reply = build_ping_reply(timestamp);
                bounded_session_send(
                    &mut session,
                    stream,
                    stream_id,
                    FrameFlags::PING,
                    &reply,
                    liveness.write_timeout(),
                )
                .await?;
            }
            continue;
        }
        bounded_session_send(
            &mut session,
            stream,
            stream_id,
            FrameFlags::DATA,
            &payload,
            liveness.write_timeout(),
        )
        .await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowpipe_core::client_auth::{AuthFailed, ClientCredential};
    use shadowpipe_core::session::ClientConfig;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::DuplexStream;

    async fn secure_session_pair() -> (
        DuplexStream,
        AuthenticatedSession,
        DuplexStream,
        AuthenticatedSession,
    ) {
        let state = ServerState::generate();
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = credential.authorized_clients().unwrap();
        let config = ClientConfig::pinned(state.fingerprint(), credential);
        let (mut client_io, mut server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let (session, _, _) = AuthenticatedSession::server_accept(
                &mut server_io,
                &state,
                &authorized,
                CamouflageMode::Raw,
            )
            .await
            .unwrap();
            (server_io, session)
        });
        let (client_session, _) = AuthenticatedSession::client_connect(&mut client_io, &config)
            .await
            .unwrap();
        let (server_io, server_session) = server.await.unwrap();
        (client_io, client_session, server_io, server_session)
    }

    #[test]
    fn key_generation_management_is_idempotent_and_never_rotates_existing_pins() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // The production validator intentionally rejects every 01777 ancestor,
        // including /tmp and /private/var/tmp. Use one unique create-only child
        // of HOME so this custody test remains valid even when the source tree
        // itself is an independent read-only snapshot under a public temp root.
        let root = PathBuf::from(std::env::var_os("HOME").expect("test requires HOME")).join(
            format!(".shadowpipe-server-key-cli-{}-{nonce}", std::process::id()),
        );
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mlkem_path = root.join("keys.json");
        let reality_path = root.join("reality.key");

        let first_state = load_or_create_server_identity(&mlkem_path, true).unwrap();
        let first_key_file = std::fs::read(&mlkem_path).unwrap();
        let second_state = load_or_create_server_identity(&mlkem_path, true).unwrap();
        assert_eq!(first_state.fingerprint(), second_state.fingerprint());
        assert_eq!(first_key_file, std::fs::read(&mlkem_path).unwrap());

        let first_reality = load_or_create_reality_public(&reality_path, true).unwrap();
        let first_reality_file = std::fs::read(&reality_path).unwrap();
        let second_reality = load_or_create_reality_public(&reality_path, true).unwrap();
        assert_eq!(first_reality, second_reality);
        assert_eq!(first_reality_file, std::fs::read(&reality_path).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
            assert!(load_or_create_server_identity(&mlkem_path, true).is_err());
            assert!(load_or_create_reality_public(&reality_path, true).is_err());
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

            let real_parent = root.join("real-parent");
            let linked_parent = root.join("linked-parent");
            std::fs::create_dir(&real_parent).unwrap();
            std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
            assert!(
                load_or_create_server_identity(&linked_parent.join("keys.json"), true).is_err()
            );
            std::fs::remove_file(linked_parent).unwrap();
        }

        std::fs::remove_dir_all(root).unwrap();
    }

    /// Many clients race for the single TUN. Exactly one is admitted and every
    /// other closure is rejected without spawning or aborting the winner.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_tunnel_admission_leaves_exactly_one_live_task() {
        let slot = TunnelSlot::new();
        let live = Arc::new(AtomicUsize::new(0));

        // Dropped when a task's future is torn down (natural end *or* abort).
        struct LiveGuard(Arc<AtomicUsize>);
        impl Drop for LiveGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let mut installers = Vec::new();
        for _ in 0..64 {
            let slot = Arc::clone(&slot);
            let live = Arc::clone(&live);
            installers.push(tokio::spawn(async move {
                slot.install_if_idle(move |_gen, _slot| {
                    tokio::spawn(async move {
                        live.fetch_add(1, Ordering::SeqCst);
                        let _guard = LiveGuard(live);
                        // Hold the synthetic TUN until test cleanup.
                        std::future::pending::<()>().await;
                    })
                })
                .await
            }));
        }
        let mut admitted = 0;
        for installer in installers {
            admitted += usize::from(installer.await.unwrap().is_some());
        }
        assert_eq!(admitted, 1, "only one racing peer may be admitted");

        // Poll until the lone winner is scheduled (its fetch_add may lag joins).
        let mut settled = 0;
        for _ in 0..200 {
            settled = live.load(Ordering::SeqCst);
            if settled == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(settled, 1, "exactly one tunnel task must own the TUN");
        assert!(
            slot.active.lock().await.is_some(),
            "slot must hold the surviving task"
        );
        slot.active.lock().await.take().unwrap().handle.abort();
    }

    /// A task ending on its own clears the slot — but only if a newer client
    /// hasn't already taken over.
    #[tokio::test]
    async fn clear_if_current_respects_generation() {
        let slot = TunnelSlot::new();
        let g1 = slot
            .install_if_idle(|_gen, _slot| tokio::spawn(async {}))
            .await
            .unwrap();
        assert_eq!(g1, 1);
        // Stale cleanup for a different generation must not evict the current task.
        slot.clear_if_current(g1 + 100).await;
        assert!(
            slot.active.lock().await.is_some(),
            "stale-gen cleanup must not evict the current task"
        );
        // Matching-gen cleanup does clear it.
        slot.clear_if_current(g1).await;
        assert!(
            slot.active.lock().await.is_none(),
            "matching-gen cleanup clears the slot"
        );
    }

    /// Sequential reconnects: each install hands out a strictly increasing
    /// generation and leaves exactly one task registered.
    #[tokio::test]
    async fn sequential_installs_increment_generation() {
        let slot = TunnelSlot::new();
        let mut last = 0;
        for expected in 1..=5 {
            let gen = slot
                .install_if_idle(|_gen, _slot| tokio::spawn(async {}))
                .await
                .unwrap();
            assert_eq!(gen, expected);
            assert!(gen > last);
            last = gen;
            assert_eq!(
                slot.active.lock().await.as_ref().map(|a| a.gen),
                Some(gen),
                "slot tracks the latest generation"
            );
            slot.clear_if_current(gen).await;
        }
    }

    #[tokio::test]
    async fn busy_slot_rejects_newcomer_without_displacing_active_task() {
        let slot = TunnelSlot::new();
        let first = slot
            .install_if_idle(|_gen, _slot| {
                tokio::spawn(async { std::future::pending::<()>().await })
            })
            .await
            .unwrap();
        let second_spawned = Arc::new(AtomicUsize::new(0));
        let marker = Arc::clone(&second_spawned);
        let second = slot
            .install_if_idle(move |_gen, _slot| {
                marker.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async {})
            })
            .await;

        assert!(second.is_none());
        assert_eq!(second_spawned.load(Ordering::SeqCst), 0);
        let mut active = slot.active.lock().await;
        assert_eq!(active.as_ref().map(|entry| entry.gen), Some(first));
        assert!(!active.as_ref().unwrap().handle.is_finished());
        active.take().unwrap().handle.abort();
    }

    #[tokio::test]
    async fn invalid_device_proof_cannot_reach_tunnel_slot() {
        let slot = TunnelSlot::new();
        let server_slot = Arc::clone(&slot);
        let state = ServerState::generate();
        let enrolled = ClientCredential::generate().unwrap();
        let authorized = enrolled.authorized_clients().unwrap();
        let stranger = Arc::new(ClientCredential::generate().unwrap());
        let config = ClientConfig::pinned(state.fingerprint(), stranger);
        let (mut client_io, mut server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            if AuthenticatedSession::server_accept(
                &mut server_io,
                &state,
                &authorized,
                CamouflageMode::Raw,
            )
            .await
            .is_ok()
            {
                server_slot
                    .install_if_idle(|_, _| tokio::spawn(async {}))
                    .await;
            }
        });

        assert!(
            AuthenticatedSession::client_connect(&mut client_io, &config)
                .await
                .is_err()
        );
        drop(client_io);
        server.await.unwrap();
        assert_eq!(slot.generation.load(Ordering::SeqCst), 0);
        assert!(slot.active.lock().await.is_none());
    }

    #[tokio::test]
    async fn outer_framing_class_mismatch_is_rejected_before_application_io() {
        let state = Arc::new(ServerState::generate());
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = Arc::new(credential.authorized_clients().unwrap());
        let config = ClientConfig {
            server_fingerprint: state.fingerprint(),
            camouflage: CamouflageMode::H2Chunk,
            padding_profile: shadowpipe_core::proto::PaddingProfile::Balanced,
            client_credential: credential,
        };
        let args = Args::try_parse_from(["shadowpipe-server"]).unwrap();
        let runtime = RuntimeLimits::from_args(&args).unwrap();
        let admission = ConnectionAdmission::new(1);
        let connection = AdmittedConnection {
            runtime,
            permit: admission.try_admit().unwrap(),
            // Simulate a carrier translator/stripper: the authenticated hello
            // claims H2, while the server actually observed raw bytes.
            observed_camouflage: Some(CamouflageMode::Raw),
        };
        let (mut client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(serve(
            server_io, state, authorized, args, None, None, connection,
        ));

        let client_error = match AuthenticatedSession::client_connect(&mut client_io, &config).await
        {
            Ok(_) => panic!("mismatched outer framing class constructed a typed client session"),
            Err(error) => error,
        };
        drop(client_io);
        let error = server.await.unwrap().unwrap_err();
        assert!(
            error.downcast_ref::<AuthFailed>().is_some(),
            "unexpected rejection: {error:#}"
        );
        assert!(
            client_error.downcast_ref::<AuthFailed>().is_some(),
            "client did not observe pre-application rejection: {client_error:#}"
        );
    }

    #[tokio::test]
    async fn panicked_owner_is_reaped_without_manual_replacement() {
        let slot = TunnelSlot::new();
        let first = slot
            .install_if_idle(|_gen, _slot| tokio::spawn(async { panic!("synthetic panic") }))
            .await
            .unwrap();
        assert_eq!(first, 1);
        for _ in 0..100 {
            if slot
                .active
                .lock()
                .await
                .as_ref()
                .is_some_and(|entry| entry.handle.is_finished())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let second = slot
            .install_if_idle(|_gen, _slot| {
                tokio::spawn(async { std::future::pending::<()>().await })
            })
            .await
            .expect("confirmed-finished owner must be reaped");
        assert_eq!(second, 2);
        slot.active.lock().await.take().unwrap().handle.abort();
    }

    #[test]
    fn connection_admission_rejects_saturation_before_spawn() {
        let admission = ConnectionAdmission::new(1);
        let permit = admission.try_admit().expect("first peer admitted");
        assert!(admission.try_admit().is_none(), "second peer is rejected");
        drop(permit);
        assert!(admission.try_admit().is_some(), "permit is RAII-released");
    }

    #[test]
    fn runtime_limit_defaults_and_invalid_bounds_fail_closed() {
        let args = Args::try_parse_from(["shadowpipe-server"]).unwrap();
        let limits = RuntimeLimits::from_args(&args).unwrap();
        assert_eq!(limits.max_connections, 256);
        assert_eq!(limits.outer_handshake, Duration::from_secs(15));
        assert_eq!(limits.forward_idle, Duration::from_secs(300));
        assert_eq!(limits.inner_handshake, Duration::from_secs(15));
        assert_eq!(limits.liveness.idle_timeout(), Duration::from_secs(30));
        assert_eq!(limits.liveness.probe_timeout(), Duration::from_secs(10));
        assert_eq!(limits.liveness.write_timeout(), Duration::from_secs(5));

        for argv in [
            vec!["shadowpipe-server", "--max-connections", "0"],
            vec!["shadowpipe-server", "--max-connections", "4097"],
            vec!["shadowpipe-server", "--outer-handshake-timeout-secs", "121"],
            vec!["shadowpipe-server", "--forward-idle-timeout-secs", "4"],
            vec!["shadowpipe-server", "--forward-idle-timeout-secs", "901"],
            vec!["shadowpipe-server", "--carrier-idle-timeout-secs", "4"],
            vec![
                "shadowpipe-server",
                "--carrier-probe-timeout-secs",
                "5",
                "--carrier-write-timeout-secs",
                "6",
            ],
        ] {
            let args = Args::try_parse_from(argv).unwrap();
            assert!(RuntimeLimits::from_args(&args).is_err());
        }
    }

    #[test]
    fn client_allowlist_management_is_exclusive_and_development_mode_is_no_tun() {
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--enroll-client",
            "enrollment.json",
            "--client-allowlist",
            "allowlist.json",
        ])
        .is_ok());
        for conflicting in [
            ["--gen-keys", ""],
            ["--gen-reality-key", ""],
            ["--nat-hint", ""],
            ["--print-uri", ""],
            ["--listen", "127.0.0.1:48000"],
        ] {
            let mut argv = vec!["shadowpipe-server", "--enroll-client", "enrollment.json"];
            argv.push(conflicting[0]);
            if !conflicting[1].is_empty() {
                argv.push(conflicting[1]);
            }
            assert!(Args::try_parse_from(argv).is_err());
        }
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--development-user-allowlist",
            "--tunnel",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--validate-client-allowlist",
            "--client-allowlist",
            "allowlist.json",
        ])
        .is_ok());
        for conflicting in [
            ["--enroll-client", "enrollment.json"],
            ["--revoke-client", "00"],
            ["--tunnel", ""],
            ["--nat-hint", ""],
            ["--listen", "127.0.0.1:48000"],
        ] {
            let mut argv = vec!["shadowpipe-server", "--validate-client-allowlist"];
            argv.push(conflicting[0]);
            if !conflicting[1].is_empty() {
                argv.push(conflicting[1]);
            }
            assert!(Args::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn daemon_rejects_raw_and_h2_before_key_load_or_bind_without_lab_gate() {
        let default_raw_h2 = Args::try_parse_from(["shadowpipe-server"]).unwrap();
        let error = validate_daemon_carrier_security(&default_raw_h2).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("production daemon requires --reality"),
            "unexpected error: {error:#}"
        );

        assert!(
            Args::try_parse_from(["shadowpipe-server", "--allow-insecure-lab-carriers",]).is_err()
        );
        let explicit_lab = Args::try_parse_from([
            "shadowpipe-server",
            "--development-user-allowlist",
            "--allow-insecure-lab-carriers",
        ])
        .unwrap();
        validate_daemon_carrier_security(&explicit_lab).unwrap();

        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--development-user-allowlist",
            "--allow-insecure-lab-carriers",
            "--tunnel",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--development-user-allowlist",
            "--allow-insecure-lab-carriers",
            "--reality",
        ])
        .is_err());

        let production = Args::try_parse_from(["shadowpipe-server", "--reality"]).unwrap();
        validate_daemon_carrier_security(&production).unwrap();
    }

    #[test]
    fn reality_daemon_resolves_only_explicit_or_root_durable_replay_state() {
        use shadowpipe_core::reality::ReplayStoreOwner;

        let production = Args::try_parse_from(["shadowpipe-server", "--reality"]).unwrap();
        assert_eq!(
            resolve_reality_replay_store(&production).unwrap(),
            Some((
                PathBuf::from(DEFAULT_REALITY_REPLAY_STORE),
                ReplayStoreOwner::Root
            ))
        );

        let overridden = Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--reality-replay-store",
            "/var/lib/shadowpipe/other-replay.bin",
        ])
        .unwrap();
        assert_eq!(
            resolve_reality_replay_store(&overridden).unwrap(),
            Some((
                PathBuf::from("/var/lib/shadowpipe/other-replay.bin"),
                ReplayStoreOwner::Root
            ))
        );

        let development_without_store = Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--development-user-allowlist",
        ])
        .unwrap();
        let error = validate_daemon_carrier_security(&development_without_store).unwrap_err();
        assert!(
            error.to_string().contains("--reality-replay-store"),
            "unexpected error: {error:#}"
        );

        let development = Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--development-user-allowlist",
            "--reality-replay-store",
            "./private-replay.bin",
        ])
        .unwrap();
        assert_eq!(
            resolve_reality_replay_store(&development).unwrap(),
            Some((
                PathBuf::from("./private-replay.bin"),
                ReplayStoreOwner::EffectiveUser
            ))
        );

        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--reality-replay-store",
            "./replay.bin",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--print-uri",
            "--reality-replay-store",
            "./replay.bin",
        ])
        .is_err());
    }

    #[test]
    fn reality_short_id_acl_is_full_width_sorted_unique_and_bounded() {
        let valid =
            parse_full_width_reality_short_ids("0011223344556677\n8899aabbccddeeff\n").unwrap();
        assert_eq!(valid.len(), 2);
        assert_eq!(valid[0], hex::decode("0011223344556677").unwrap());

        for invalid in [
            "",
            "ab\n",
            "001122334455667G\n",
            "0011223344556677 \n",
            "0011223344556677\r\n",
            "8899aabbccddeeff\n0011223344556677\n",
            "0011223344556677\n0011223344556677\n",
        ] {
            assert!(
                parse_full_width_reality_short_ids(invalid).is_err(),
                "non-canonical ACL was accepted: {invalid:?}"
            );
        }
        let overfull = (0..=MAX_PRODUCTION_REALITY_SHORT_IDS)
            .map(|index| format!("{index:016x}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_full_width_reality_short_ids(&overfull).is_err());
    }

    #[test]
    fn inline_reality_short_ids_are_development_no_tun_only() {
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--reality-short-id",
            "0011223344556677",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--development-user-allowlist",
            "--reality-short-id",
            "0011223344556677",
            "--tunnel",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--development-user-allowlist",
            "--reality-short-id",
            "0011223344556677",
            "--print-uri",
        ])
        .is_err());

        let lab = Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--development-user-allowlist",
            "--reality-short-id",
            "0011223344556677",
            "--reality-short-id",
            "8899aabbccddeeff",
        ])
        .unwrap();
        assert_eq!(load_reality_short_ids(&lab).unwrap().unwrap().len(), 2);

        let malformed_lab = Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--development-user-allowlist",
            "--reality-short-id",
            "ab",
        ])
        .unwrap();
        assert!(load_reality_short_ids(&malformed_lab).is_err());
    }

    #[test]
    fn print_uri_requires_the_production_short_id_file_before_key_loading() {
        let args = Args::try_parse_from([
            "shadowpipe-server",
            "--reality",
            "--print-uri",
            "--reality-short-id-file",
            "/definitely/missing/shadowpipe-reality-short-ids",
        ])
        .unwrap();
        let error = load_reality_short_ids(&args).unwrap_err();
        assert!(
            format!("{error:#}").contains("REALITY short_id"),
            "unexpected failure: {error:#}"
        );
    }

    #[cfg(feature = "tls-chrome")]
    #[test]
    fn tls_is_active_probe_reachable_and_therefore_lab_gated() {
        let ungated = Args::try_parse_from(["shadowpipe-server", "--tls"]).unwrap();
        assert!(validate_daemon_carrier_security(&ungated).is_err());
        let gated = Args::try_parse_from([
            "shadowpipe-server",
            "--tls",
            "--development-user-allowlist",
            "--allow-insecure-lab-carriers",
        ])
        .unwrap();
        validate_daemon_carrier_security(&gated).unwrap();
    }

    #[cfg(feature = "quic")]
    #[test]
    fn quic_is_active_probe_reachable_and_therefore_lab_gated() {
        let ungated = Args::try_parse_from(["shadowpipe-server", "--quic"]).unwrap();
        assert!(validate_daemon_carrier_security(&ungated).is_err());
        let gated = Args::try_parse_from([
            "shadowpipe-server",
            "--quic",
            "--development-user-allowlist",
            "--allow-insecure-lab-carriers",
        ])
        .unwrap();
        validate_daemon_carrier_security(&gated).unwrap();
    }

    #[tokio::test]
    async fn silent_inner_handshake_hits_monotonic_deadline() {
        let state = ServerState::generate();
        let credential = ClientCredential::generate().unwrap();
        let authorized = credential.authorized_clients().unwrap();
        // Tiny capacity blocks the server's first ML-KEM public-key write while
        // the silent peer deliberately neither reads nor writes.
        let (mut server_io, _silent_peer) = tokio::io::duplex(64);
        let result = bounded_stage(
            "test inner handshake",
            Duration::from_millis(20),
            AuthenticatedSession::server_accept(
                &mut server_io,
                &state,
                &authorized,
                CamouflageMode::Raw,
            ),
        )
        .await;
        let Err(error) = result else {
            panic!("silent handshake unexpectedly completed");
        };
        assert!(error.downcast_ref::<StageTimeout>().is_some());
    }

    #[tokio::test]
    async fn silent_established_echo_session_expires_after_authenticated_probe() {
        let (_client_io, _client_session, mut server_io, server_session) =
            secure_session_pair().await;
        let liveness = CarrierLivenessConfig::new(
            Duration::from_millis(20),
            Duration::from_millis(20),
            Duration::from_millis(10),
        )
        .unwrap();
        let error = tokio::time::timeout(
            Duration::from_millis(200),
            run_echo_session(&mut server_io, server_session, liveness),
        )
        .await
        .expect("server liveness must be bounded")
        .unwrap_err();
        assert!(error.downcast_ref::<DeadCarrier>().is_some());
    }

    #[tokio::test]
    async fn authenticated_ping_reply_keeps_established_echo_session_live() {
        let (mut client_io, mut client_session, mut server_io, server_session) =
            secure_session_pair().await;
        let liveness = CarrierLivenessConfig::new(
            Duration::from_millis(30),
            Duration::from_millis(30),
            Duration::from_millis(10),
        )
        .unwrap();
        let server = tokio::spawn(async move {
            run_echo_session(&mut server_io, server_session, liveness).await
        });

        let (stream_id, flags, payload, _) = tokio::time::timeout(
            Duration::from_millis(150),
            client_session.recv(&mut client_io),
        )
        .await
        .expect("server must send an encrypted idle probe")
        .unwrap();
        let PingMsg::Request(timestamp) = parse_ping(&payload) else {
            panic!("expected authenticated PING request");
        };
        assert!(flags.contains(FrameFlags::PING));
        client_session
            .send(
                &mut client_io,
                stream_id,
                FrameFlags::PING,
                &build_ping_reply(timestamp),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(
            !server.is_finished(),
            "authenticated reply must reset established-session liveness"
        );
        server.abort();
        let _ = server.await;
    }
}
