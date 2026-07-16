use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rand::RngCore;
use shadowpipe_core::carrier::client_connect;
use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::endpoint::{
    CandidateKey, CarrierProtocol as LiveCarrierProtocol, CarrierTuple, DialCandidate,
    EndpointLease, LogicalEndpointId, ObservationResult, PreparedLeaseRelease, PreparedObservation,
    PreparedRetirement, ResolutionObservation,
};
use shadowpipe_core::endpoint_dns::{resolve_a, EndpointDnsConfig};
use shadowpipe_core::endpoint_policy::{VerifiedEndpointPolicy, VerifiedRealityDialTarget};
use shadowpipe_core::endpoint_runtime::{
    AppliedHostTransaction, EndpointHostAdapter, EndpointTransitionExecutor, OwnedMutation,
};
use shadowpipe_core::host_recovery::{
    recover_host_state, PreparedDnsGroup, PreparedHostRecoveryAdapter, PreparedLinuxRouteGroup,
    PreparedResourceGroup, PreparedTunGroup, RecoveryRunOutcome,
};
use shadowpipe_core::host_state::{
    classify_owner, observe_owner, AddressFamily, BootEvidence, DurableHostJournal,
    DurableJournalError, FirewallBackend, FirewallChainToken, FirewallEndpointResource,
    FirewallResource, HostStateError, HostStateJournalV2, HostStateLease, JournalPhase,
    JournalStore, LeaseError, LeaseEvidence, NamespaceEvidence, OperationState, OwnedResource,
    OwnerDisposition, OwnerEvidence, OwnerIdentity, RouteResource, SessionId, TunResource,
};
use shadowpipe_core::lockdown::{LockdownBarrier, LockdownControlFlow};
use shadowpipe_core::measurement::{
    CloseOutcome, DialOutcome, Direction, EventKind, EvidenceAssessment, EvidenceOutcome,
    EvidenceScope, ExecutionEnvironment, MeasurementRecorder, NodeRole, PathState, PublicId,
    RunMetadata, SoftwareVersion, StallState, TransportKind,
};
use shadowpipe_core::netguard::{
    AllowedEndpoint, DnsGuard, EndpointProtocol, KillSwitch, KillSwitchIdentity,
    KillSwitchInstallToken, KillSwitchPrepareError, PreparedKillSwitchRecovery,
};
use shadowpipe_core::platform::Ipv6Mode;
use shadowpipe_core::policy_state::{PolicyExpiryCheckpoint, PolicyStateStore};
use shadowpipe_core::profile::{profile_from_env, TunnelProfile};
use shadowpipe_core::proto::{CamouflageMode, FrameFlags, PaddingProfile};
use shadowpipe_core::reality::RealityUri;
use shadowpipe_core::routes::{
    current_linux_network_namespace_identity, LinuxOwnedRouteSpec, LinuxRouteOwner,
    LinuxRoutePrepareError, LinuxUnderlayPath, RouteGuard,
};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerPins};
use shadowpipe_core::signed_policy::{Kid, TrustedRoot, VerifiedRealityPlan, MAX_BUNDLE_BYTES};
use shadowpipe_core::split::{
    LeakGuardConfig, MacSplitDnsGuard, SplitDnsConfig, SplitLeakGuard, SplitTunnel,
};
use shadowpipe_core::tun_dev::{iface_name, open_async_client, SharedTun};
use shadowpipe_core::tun_state::{capture_tun_resource, inspect_tun, mark_tun_owned};
use shadowpipe_core::tunnel::{
    client_tun_config, pacer_from_config, run_tunnel_guarded_with_liveness,
    volume_guard_from_config, CarrierLivenessConfig, RotateConnection,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use shadowpipe_core::dns_exchange::{
    preflight_dns_exchange, ActiveDnsExchange, DnsExchangePreflight, PreparedDnsExchange,
};
use shadowpipe_core::dns_exchange::{DnsExchangeFailure, DnsExchangeFailureKind};
#[cfg(target_os = "linux")]
use shadowpipe_core::netguard::resolv_conf;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MeasurementScopeArg {
    Loopback,
    VirtualMachine,
    ControlledNetwork,
    PublicInternet,
    TargetNetwork,
}

impl From<MeasurementScopeArg> for EvidenceScope {
    fn from(value: MeasurementScopeArg) -> Self {
        match value {
            MeasurementScopeArg::Loopback => Self::Loopback,
            MeasurementScopeArg::VirtualMachine => Self::VirtualMachine,
            MeasurementScopeArg::ControlledNetwork => Self::ControlledNetwork,
            MeasurementScopeArg::PublicInternet => Self::PublicInternet,
            MeasurementScopeArg::TargetNetwork => Self::TargetNetwork,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MeasurementEnvironmentArg {
    BareMetal,
    VirtualMachine,
    Container,
    ContinuousIntegration,
}

impl From<MeasurementEnvironmentArg> for ExecutionEnvironment {
    fn from(value: MeasurementEnvironmentArg) -> Self {
        match value {
            MeasurementEnvironmentArg::BareMetal => Self::BareMetal,
            MeasurementEnvironmentArg::VirtualMachine => Self::VirtualMachine,
            MeasurementEnvironmentArg::Container => Self::Container,
            MeasurementEnvironmentArg::ContinuousIntegration => Self::ContinuousIntegration,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum Ipv6ModeArg {
    Block,
    OuterOnly,
    Tunnel,
}

impl Ipv6ModeArg {
    const fn as_cli_value(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::OuterOnly => "outer-only",
            Self::Tunnel => "tunnel",
        }
    }
}

impl From<Ipv6ModeArg> for Ipv6Mode {
    fn from(value: Ipv6ModeArg) -> Self {
        match value {
            Ipv6ModeArg::Block => Self::Block,
            Ipv6ModeArg::OuterOnly => Self::OuterOnly,
            Ipv6ModeArg::Tunnel => Self::Tunnel,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "shadowpipe-client",
    about = "shadowpipe / ZATMENIE B-plane client"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:47843")]
    server: String,

    #[arg(long)]
    tunnel: bool,

    /// Wire camouflage: raw | h2. DNS chunking is not implemented.
    #[arg(long, default_value = "h2")]
    camouflage: String,

    /// Auto-add split-default routes (0.0.0.0/1 + 128.0.0.0/1) — needs root.
    #[arg(long)]
    auto_route: bool,

    /// Explicit IPv6 policy. Only fail-closed blocking is implemented today;
    /// outer transport and inner IPv6 tunneling remain unavailable.
    #[arg(long, value_enum, default_value = "block")]
    ipv6_mode: Ipv6ModeArg,

    #[arg(long)]
    tun_name: Option<String>,

    #[arg(long, default_value = "10.8.0.2")]
    tun_addr: Ipv4Addr,

    #[arg(long, default_value = "10.8.0.1")]
    tun_peer: Ipv4Addr,

    #[arg(long, default_value = "1280")]
    mtu: u16,

    /// Monotonic deadline for one pre-authorized TCP/QUIC carrier dial.
    #[arg(long, default_value_t = 10)]
    connect_timeout_secs: u64,

    /// Monotonic deadline for REALITY/TLS/carrier bootstrap after transport
    /// connection. This does not include the inner authenticated handshake.
    #[arg(long, default_value_t = 15)]
    outer_handshake_timeout_secs: u64,

    /// Monotonic deadline for the inner pinned post-quantum session handshake.
    #[arg(long, default_value_t = 15)]
    inner_handshake_timeout_secs: u64,

    /// Authenticated receive-idle interval before sending an encrypted probe.
    #[arg(long, default_value_t = 30)]
    carrier_idle_timeout_secs: u64,

    /// Deadline after an encrypted probe for a newly authenticated peer frame.
    #[arg(long, default_value_t = 10)]
    carrier_probe_timeout_secs: u64,

    /// Bound for acquiring the carrier writer and emitting a liveness probe.
    #[arg(long, default_value_t = 5)]
    carrier_write_timeout_secs: u64,

    #[arg(long, default_value = "24")]
    mux_streams: u32,

    #[arg(long, default_value = "1024")]
    mux_chunk: usize,

    /// Per-TCP byte budget before a guard rotation (only used if the guard is
    /// enabled via --rotate-conn). The default is a legacy experimental value,
    /// not an inferred censor threshold.
    #[arg(long, default_value = "8192")]
    guard_bytes: u64,

    /// Rotate the TCP/TLS connection (new 5-tuple) every `guard_bytes` to test
    /// a per-flow volume-budget hypothesis. OFF by default: the event it targets
    /// did NOT reproduce on RU→NL Chrome-TLS (planeb 328MB raw + live netns
    /// 20MB×2 single-connection, zero stalls), and each rotation rebuilds the
    /// entire TLS+PQ session, crushing throughput ~1000x (≈3.8 MB/s → 3 KB/s).
    /// Enable only if you actually observe per-flow stalls on your path.
    #[arg(long, default_value = "false")]
    rotate_conn: bool,

    /// Force the volume guard off (redundant now that it is off by default;
    /// kept so an explicit "no guard" stays valid alongside --rotate-conn).
    #[arg(long)]
    no_guard: bool,

    /// Degradation-symmetric pacer: throttle the covert send rate to track the
    /// path's own goodput, so a tunnel under loss/RTT growth backs off like an
    /// ordinary flow to the same dest instead of hammering a degrading path
    /// as an experimental degradation-response heuristic. This does not prove
    /// cover-traffic equivalence. OFF by default. NOTE: real RU on-path effect
    /// is NOT validated — loopback-correct shaper only. Adaptive on --quic
    /// (goodput = cwnd/rtt) AND on TCP carriers
    /// (--tls/--reality), where an app-RTT PING probe (round-trip + peer
    /// delivered-rate + reply-stall) supplies a gate-independent signal.
    #[arg(long, default_value = "false")]
    pace: bool,

    /// Use SHADOWPIPE_PROFILE_SEED env for POLYMORPH-lite mux/guard params.
    #[arg(long, default_value = "true")]
    profile_seed: bool,

    #[arg(long)]
    message: Option<String>,

    /// Loadtest probe (no TUN): connect via the carrier, run the PQ handshake, then
    /// pump this many MB of DATA frames through the echo server and report
    /// round-trip throughput + whether/where the stream stalls. A stall is only
    /// an observation, never automatic censor attribution. Prefer an isolated VM
    /// or a pre-existing test route; this command does not edit routes, DNS, or
    /// sing-box. 0 = off (normal echo mode).
    #[arg(long, default_value = "0")]
    loadtest: u64,

    /// Write one bounded, closed-schema raw v1 trace for --loadtest to a new file.
    /// This is observational only: it never opens a TUN or changes routes/DNS.
    /// Exact timings and byte counts remain correlation-sensitive. The file is
    /// crash-safely published with no overwrite. Its connection lifecycle is
    /// terminal, while its epistemic outcome is "pending" until offline
    /// assessment. One bounded dial observation covers DNS/outer transport
    /// establishment and the inner authenticated session.
    /// Requires explicit scope, environment, experiment ID and artifact ID,
    /// caps the workload at 1024 MiB, and requires a server fingerprint outside
    /// loopback/VM scope.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "tunnel",
        requires_all = [
            "measurement_scope",
            "measurement_environment",
            "experiment_id",
            "artifact_id"
        ]
    )]
    measurement_json: Option<PathBuf>,

    /// Epistemic scope of the requested loadtest trace; never inferred from an IP.
    #[arg(long, value_enum, requires = "measurement_json")]
    measurement_scope: Option<MeasurementScopeArg>,

    /// Execution environment of the requested loadtest trace.
    #[arg(long, value_enum, requires = "measurement_json")]
    measurement_environment: Option<MeasurementEnvironmentArg>,

    /// Opaque 128-bit experiment cohort ID as 32 lowercase hex digits.
    /// Generate randomly or with a keyed domain-separated pseudonym; never use
    /// endpoint, credential, key, or configuration bytes.
    #[arg(long, value_name = "32_LOWER_HEX", requires = "measurement_json")]
    experiment_id: Option<String>,

    /// Opaque 128-bit ID of the exact tested artifact as 32 lowercase hex
    /// digits. All traces compared by replay must declare the same artifact ID.
    #[arg(long, value_name = "32_LOWER_HEX", requires = "measurement_json")]
    artifact_id: Option<String>,

    /// Required pin of the server's ML-KEM key fingerprint (64-hex SHA-256).
    /// Missing or malformed pins fail before any socket or TUN is opened. Get it
    /// from an independently authenticated server log or key manifest.
    #[arg(long)]
    server_fp: Option<String>,

    /// Root-owned, single-link mode-0600 Ed25519 + 256-bit PSK device
    /// credential. Mandatory for every network session; never accepted through
    /// argv, environment, endpoint URI, or logs.
    #[arg(long, default_value = "/etc/shadowpipe/client-credential.json")]
    client_credential: PathBuf,

    /// Explicit no-TUN research mode: accept an exact-0600 credential owned by
    /// the effective user. Production daemon/tunnel starts never use this path.
    #[arg(long, conflicts_with = "tunnel")]
    development_user_credential: bool,

    /// One-shot: create a new private credential without replacement and exit.
    /// Requires --write-client-enrollment; no endpoint is parsed or contacted.
    #[arg(long, requires = "write_client_enrollment")]
    generate_client_credential: bool,

    /// One-shot create-only mode-0600 secret enrollment artifact. With
    /// --generate-client-credential it exports the newly created credential;
    /// alone it safely re-exports an existing credential after a partial
    /// provisioning failure. It never includes the Ed25519 private seed.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = [
            "tunnel",
            "server",
            "camouflage",
            "auto_route",
            "tun_name",
            "tun_addr",
            "tun_peer",
            "mtu",
            "message",
            "loadtest",
            "measurement_json",
            "server_fp",
            "policy_bundle",
            "release_lockdown",
            "restore_lockdown",
            "tls",
            "sni",
            "reality",
            "reality_pubkey",
            "reality_short_id",
            "uri",
            "uri_file",
            "quic",
            "kill_switch",
            "dns",
            "split",
            "split_dns_guard"
        ]
    )]
    write_client_enrollment: Option<PathBuf>,

    /// Root+online-signed canonical CBOR endpoint policy. Production policy
    /// mode is deliberately narrow: full-tunnel REALITY/TCP with exact signed
    /// IPv4 tuples and bounded ML-KEM pin overlap. It never falls back to the
    /// unsigned/manual endpoint flags when verification fails.
    #[arg(long, value_name = "PATH")]
    policy_bundle: Option<PathBuf>,

    /// Offline Ed25519 root key identifier (16 bytes / 32 hex characters).
    #[arg(long, value_name = "32_HEX", requires = "policy_bundle")]
    policy_root_kid: Option<String>,

    /// Offline Ed25519 root public key (32 bytes / 64 hex characters).
    #[arg(long, value_name = "64_HEX", requires = "policy_bundle")]
    policy_root_key: Option<String>,

    /// Durable anti-rollback floor. Defaults below --host-state-dir.
    #[arg(long, value_name = "PATH", requires = "policy_bundle")]
    policy_state: Option<PathBuf>,

    /// Explicitly create the first durable policy anchor. Omit on every normal
    /// start/update; a missing anchor then fails closed instead of resetting
    /// anti-rollback history.
    #[arg(long, requires = "policy_bundle")]
    policy_enroll: bool,

    /// Root-owned 0700 directory for the single-client lease, crash journal,
    /// and default signed-policy floor.
    #[arg(long, default_value = "/var/lib/shadowpipe")]
    host_state_dir: PathBuf,

    /// Explicit one-shot direct-network restoration. Acquires the host lease,
    /// arms/adopts the durable restart barrier, recovers any ordinary stale
    /// main journal, proves it is gone, then removes the barrier. Normal
    /// SIGINT/SIGTERM intentionally never performs this release.
    #[arg(
        long,
        conflicts_with_all = [
            "tunnel",
            "restore_lockdown",
            "auto_route",
            "split",
            "kill_switch",
            "dns",
            "policy_bundle",
            "measurement_json",
            "loadtest",
            "reality",
            "tls",
            "quic",
            "uri",
            "uri_file",
            "message",
            "server_fp"
        ]
    )]
    release_lockdown: bool,

    /// Early-boot fail-closed restore. Under the singleton lease, re-arm an
    /// existing lockdown WAL (or create one when any main WAL entry may exist),
    /// prove the exact native-nft table Active, and exit without main recovery,
    /// DNS, resolver, socket, TUN, or route activity.
    #[arg(
        long,
        conflicts_with_all = [
            "tunnel",
            "release_lockdown",
            "auto_route",
            "split",
            "kill_switch",
            "dns",
            "policy_bundle",
            "measurement_json",
            "loadtest",
            "reality",
            "tls",
            "quic",
            "uri",
            "uri_file",
            "message",
            "server_fp"
        ]
    )]
    restore_lockdown: bool,

    /// Wrap the transport in a real Chrome-JA4 TLS layer (boring-front). On the
    /// wire it looks like HTTPS; shadowpipe runs inside with raw framing, so
    /// --camouflage is ignored. The server must run with --tls too.
    #[arg(long)]
    tls: bool,

    /// SNI for the TLS ClientHello when --tls is set. Prefer a plausible domain
    /// that resolves to this server (with a real cert) to avoid an SNI/IP tell.
    #[arg(long, default_value = "example.com")]
    sni: String,

    /// Use the REALITY carrier (from-scratch TLS 1.3 + REALITY) instead of
    /// --tls/--camouflage: the wire is a genuine TLS 1.3 handshake to --sni, and
    /// the server transparently forwards any unauthenticated peer to a cover
    /// site. Requires --reality-pubkey. Mutually exclusive with --tls.
    #[arg(long, conflicts_with = "tls")]
    reality: bool,

    /// Server's REALITY X25519 static PUBLIC key (64 hex), from the server's
    /// `--gen-reality-key`. Required with --reality.
    #[arg(long)]
    reality_pubkey: Option<String>,

    /// REALITY short_id (≤16 hex chars / 8 bytes) presented to the server's ACL.
    /// Manual client starts require exactly 16 lowercase hex characters.
    #[arg(long, default_value = "")]
    reality_short_id: String,

    /// One-paste REALITY connection URI(s): `shadowpipe://<pubkey>@host:port?sni=..&sid=..&fp=..`.
    /// Repeatable, or one comma/space/newline-separated list — the tunnel rotates
    /// through the pool on connect/handshake failure (anti-IP-block; CDN is dead in
    /// RU). Implies --reality and fills the connection params from each endpoint.
    /// This diagnostic form exposes the URI's 64-bit carrier selector in the
    /// process argv. Production/tunnel starts should use --uri-file instead.
    #[arg(
        long,
        conflicts_with_all = [
            "uri_file",
            "policy_bundle",
            "tls",
            "quic",
            "reality",
            "server",
            "reality_pubkey",
            "reality_short_id",
            "sni",
            "server_fp"
        ]
    )]
    uri: Vec<String>,

    /// Private file containing one or more REALITY connection URIs. The file
    /// is opened no-follow/nonblocking, bounded to 64 KiB, and must be a
    /// single-link regular file with exact mode 0600. Production and tunnel
    /// starts additionally require effective UID 0 and root:root ownership;
    /// explicit --development-user-credential no-TUN mode permits the exact
    /// effective UID:GID. Contents are parsed before credential, host, DNS or
    /// network state and are never logged.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = [
            "uri",
            "policy_bundle",
            "tls",
            "quic",
            "reality",
            "server",
            "reality_pubkey",
            "reality_short_id",
            "sni",
            "server_fp"
        ]
    )]
    uri_file: Option<PathBuf>,

    /// Use the QUIC carrier (UDP) instead of --tls/--reality/--camouflage: the PQ
    /// session + tunnel ride inside one QUIC bi-stream. The QUIC TLS cert is not
    /// trusted (auth is the inner --server-fp pin); SNI reuses --sni. Single
    /// endpoint (--server), like --tls. Requires a build with `--features quic`.
    /// Hysteria2-class: UDP often traverses TCP-tuned DPI better (premise unvalidated).
    #[arg(long, conflicts_with_all = ["tls", "reality", "uri", "uri_file"])]
    quic: bool,

    /// Fail-closed kill-switch: while the tunnel is up, drop all egress except the
    /// tunnel, loopback, and the server IP (Linux/iptables; needs --auto-route +
    /// root). Prevents leaks if the tunnel drops. NOTE: effect not yet host-validated.
    #[arg(long)]
    kill_switch: bool,

    /// Pin the system DNS resolver to this IP while the tunnel is up so queries
    /// ride the tunnel; restores /etc/resolv.conf on exit (Linux-only, needs
    /// --auto-route).
    #[arg(long)]
    dns: Option<Ipv4Addr>,

    /// Split tunnel: only proxy-list domains/IPs via NL; rest = direct residential.
    /// Uses runetfreedom geosite.dat/geoip.dat (no sing-box). Mutually exclusive
    /// with --auto-route. Point system DNS to --split-dns (default 127.0.0.1:1053).
    #[arg(long, conflicts_with = "auto_route")]
    split: bool,

    /// Directory with geosite.dat + geoip.dat (from scripts/macos/update-rules.sh).
    #[arg(long, default_value = "")]
    split_rules_dir: String,

    /// Proxy tag list (geosite:… / geoip:… lines); default: repo proxy-rules.list.
    #[arg(long, default_value = "")]
    split_rules_list: String,

    /// Split DNS listen address (system resolver should point here).
    #[arg(long, default_value = "127.0.0.1:1053")]
    split_dns: String,

    /// Upstream resolver for proxy-list domains (foreign DNS).
    #[arg(long, default_value = "8.8.8.8:53")]
    split_dns_upstream: String,

    /// Upstream for direct/RU domains (sing-box split DNS `local` server).
    #[arg(long, default_value = "77.88.8.8:53")]
    split_dns_direct_upstream: String,

    /// Direct-bypass rule list (checked before proxy-rules); default: direct-rules.list.
    #[arg(long, default_value = "")]
    split_direct_rules_list: String,

    /// Pin macOS system DNS to --split-dns via networksetup (restore on exit).
    #[arg(long)]
    split_dns_guard: bool,

    /// networksetup service name (default: auto-detect from default route).
    #[arg(long, default_value = "")]
    split_dns_service: String,

    /// Pre-resolve domains from this list at split start (install /32 routes early).
    #[arg(long, default_value = "")]
    split_preload_list: String,

    /// Hard DNS leak guard: hijack :53, block DoT/DoH (pf/iptables). Default on for --split.
    #[arg(long, default_value_t = true)]
    split_leak_guard: bool,
}

#[derive(Debug)]
struct MeasurementOutput {
    path: PathBuf,
    scope: EvidenceScope,
    environment: ExecutionEnvironment,
    transport: TransportKind,
    experiment_id: PublicId,
    artifact_id: PublicId,
}

fn measurement_transport(args: &Args, camouflage: CamouflageMode) -> TransportKind {
    if args.quic {
        TransportKind::Quic
    } else if args.reality {
        TransportKind::Reality
    } else if args.tls {
        TransportKind::TlsChrome
    } else if camouflage == CamouflageMode::H2Chunk {
        TransportKind::Http2
    } else {
        TransportKind::Tcp
    }
}

/// Validate the opt-in recorder configuration before any socket is opened.
fn measurement_output(
    args: &Args,
    camouflage: CamouflageMode,
) -> Result<Option<MeasurementOutput>> {
    let Some(path) = &args.measurement_json else {
        if args.measurement_scope.is_some()
            || args.measurement_environment.is_some()
            || args.experiment_id.is_some()
            || args.artifact_id.is_some()
        {
            anyhow::bail!("measurement metadata flags require --measurement-json");
        }
        return Ok(None);
    };
    if args.tunnel {
        anyhow::bail!("--measurement-json is no-TUN only and conflicts with --tunnel");
    }
    if args.loadtest == 0 {
        anyhow::bail!("--measurement-json requires --loadtest greater than zero");
    }
    if args.loadtest > LOADTEST_MEASUREMENT_MAX_MIB {
        anyhow::bail!("--measurement-json caps --loadtest at {LOADTEST_MEASUREMENT_MAX_MIB} MiB");
    }
    #[cfg(not(feature = "quic"))]
    if args.quic {
        anyhow::bail!("--quic measurement requires a build with `--features quic`");
    }
    #[cfg(not(feature = "tls-chrome"))]
    if args.tls {
        anyhow::bail!("--tls measurement requires a build with `--features tls-chrome`");
    }
    if args.reality {
        // Syntax/configuration faults are preflight errors, not network
        // observations. Validate them before reserving output or opening TCP.
        reality_server_pub(args).context("preflight --reality-pubkey")?;
        parse_short_id(&args.reality_short_id).context("preflight --reality-short-id")?;
    }
    let scope: EvidenceScope = args
        .measurement_scope
        .ok_or_else(|| anyhow::anyhow!("--measurement-json requires --measurement-scope"))?
        .into();
    let environment = args
        .measurement_environment
        .ok_or_else(|| anyhow::anyhow!("--measurement-json requires --measurement-environment"))?;
    let experiment_id = PublicId::from_hex(
        args.experiment_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--measurement-json requires --experiment-id"))?,
    )
    .context("parse --experiment-id")?;
    let artifact_id = PublicId::from_hex(
        args.artifact_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--measurement-json requires --artifact-id"))?,
    )
    .context("parse --artifact-id")?;
    if matches!(
        scope,
        EvidenceScope::ControlledNetwork
            | EvidenceScope::PublicInternet
            | EvidenceScope::TargetNetwork
    ) && args.server_fp.is_none()
    {
        anyhow::bail!(
            "non-lab --measurement-scope requires an authenticated --server-fp (or URI fp)"
        );
    }

    Ok(Some(MeasurementOutput {
        path: path.clone(),
        scope,
        environment: environment.into(),
        transport: measurement_transport(args, camouflage),
        experiment_id,
        artifact_id,
    }))
}

fn parse_server_fp(s: &Option<String>) -> Result<[u8; 32]> {
    let h = s.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "missing required --server-fp: refusing an unauthenticated server before network I/O"
        )
    })?;
    let bytes = hex::decode(h.trim()).context("decode --server-fp hex")?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "--server-fp must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })
}

fn parse_fixed_hex<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value.trim()).with_context(|| format!("decode {label} hex"))?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "{label} must be {N} bytes ({} hex chars), got {} bytes",
            N * 2,
            bytes.len()
        )
    })
}

fn read_policy_bundle(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)
        .with_context(|| format!("open signed policy bundle {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat signed policy bundle {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "signed policy bundle is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_BUNDLE_BYTES as u64,
        "signed policy bundle is {} bytes; maximum is {}",
        metadata.len(),
        MAX_BUNDLE_BYTES
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read signed policy bundle {}", path.display()))?;
    anyhow::ensure!(!bytes.is_empty(), "signed policy bundle is empty");
    anyhow::ensure!(
        bytes.len() <= MAX_BUNDLE_BYTES,
        "signed policy bundle grew beyond the {} byte bound while reading",
        MAX_BUNDLE_BYTES
    );
    Ok(bytes)
}

#[cfg(unix)]
const MAX_URI_FILE_BYTES: u64 = 64 * 1024;

#[cfg(unix)]
fn validate_private_uri_parent(path: &Path, development_user_credential: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for private REALITY URI file")?
            .join(path)
    };
    let parent = absolute.parent().ok_or_else(|| {
        anyhow::anyhow!("private REALITY URI file has no parent: {}", path.display())
    })?;
    // SAFETY: geteuid takes no arguments and has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(_) => {
                cursor.push(component.as_os_str());
                continue;
            }
            Component::RootDir => cursor.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => anyhow::bail!(
                "private REALITY URI path may not contain parent traversal: {}",
                path.display()
            ),
            Component::Normal(part) => cursor.push(part),
        }
        let metadata = std::fs::symlink_metadata(&cursor).with_context(|| {
            format!("inspect private REALITY URI directory {}", cursor.display())
        })?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink() && metadata.is_dir(),
            "private REALITY URI directory component is not a real directory: {}",
            cursor.display()
        );
        let owner_allowed = if development_user_credential {
            metadata.uid() == 0 || metadata.uid() == effective_uid
        } else {
            metadata.uid() == 0
        };
        anyhow::ensure!(
            owner_allowed,
            "private REALITY URI directory {} has untrusted UID {}",
            cursor.display(),
            metadata.uid()
        );
        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode & 0o022 == 0,
            "private REALITY URI directory {} is group/world writable ({:04o})",
            cursor.display(),
            mode
        );
    }
    Ok(())
}

/// Read a URI pool through an already-open descriptor so a final-component
/// symlink, FIFO, device, hard link, permissive file, or ownership mismatch is
/// rejected before credential loading or any host/network operation. URI
/// contents are deliberately absent from every error and log message.
#[cfg(unix)]
fn read_private_uri_file(
    path: &Path,
    development_user_credential: bool,
    tunnel: bool,
) -> Result<String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    // SAFETY: geteuid/getegid take no arguments and have no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    let (expected_uid, expected_gid, ownership_label) = if development_user_credential {
        anyhow::ensure!(
            !tunnel,
            "--development-user-credential URI files are restricted to explicit no-TUN mode"
        );
        (effective_uid, effective_gid, "effective user")
    } else {
        anyhow::ensure!(
            effective_uid == 0,
            "production/tunnel --uri-file requires effective UID 0"
        );
        (0, 0, "root:root")
    };

    validate_private_uri_parent(path, development_user_credential)?;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open private REALITY URI file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat private REALITY URI file {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "private REALITY URI path is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.uid() == expected_uid && metadata.gid() == expected_gid,
        "private REALITY URI file {} must have exact {ownership_label} UID:GID ownership",
        path.display()
    );
    anyhow::ensure!(
        metadata.permissions().mode() & 0o7777 == 0o600,
        "private REALITY URI file {} must have exact mode 0600",
        path.display()
    );
    anyhow::ensure!(
        metadata.nlink() == 1,
        "private REALITY URI file {} must have exactly one hard link",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_URI_FILE_BYTES,
        "private REALITY URI file {} exceeds the {} byte bound",
        path.display(),
        MAX_URI_FILE_BYTES
    );

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_URI_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read private REALITY URI file {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_URI_FILE_BYTES,
        "private REALITY URI file {} grew beyond the {} byte bound while reading",
        path.display(),
        MAX_URI_FILE_BYTES
    );
    anyhow::ensure!(
        !bytes.is_empty(),
        "private REALITY URI file {} is empty",
        path.display()
    );
    String::from_utf8(bytes)
        .with_context(|| format!("private REALITY URI file {} is not UTF-8", path.display()))
}

#[cfg(not(unix))]
fn read_private_uri_file(
    _path: &Path,
    _development_user_credential: bool,
    _tunnel: bool,
) -> Result<String> {
    anyhow::bail!("--uri-file requires Unix no-follow, ownership, mode, and hard-link semantics")
}

/// Consume `--uri-file` into the same in-memory pool used by `--uri`. This is
/// called exactly once and validates the complete pool before credential state.
fn load_uri_file_source(args: &mut Args) -> Result<()> {
    let Some(path) = args.uri_file.take() else {
        return Ok(());
    };
    anyhow::ensure!(
        args.uri.is_empty(),
        "--uri and --uri-file are mutually exclusive"
    );
    let contents = read_private_uri_file(&path, args.development_user_credential, args.tunnel)?;
    let pool = parse_client_uri_list(&contents)
        .with_context(|| format!("parse private REALITY URI file {}", path.display()))?;
    anyhow::ensure!(
        !pool.is_empty(),
        "private REALITY URI file {} contains no endpoints",
        path.display()
    );
    args.uri.push(contents);
    Ok(())
}

fn ensure_host_state_directory(path: &Path) -> Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("chmod host-state directory {}", path.display()))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("create host-state directory {}", path.display()))
        }
    }
    Ok(())
}

fn requires_host_state_coordination(args: &Args) -> bool {
    requires_host_state_coordination_for_platform(args, cfg!(target_os = "linux"))
}

fn requires_host_state_coordination_for_platform(args: &Args, linux: bool) -> bool {
    // The durable privileged host-state vocabulary is currently Linux-only;
    // macOS/Windows TUN modes cannot have created one of these journals and
    // must not be forced to create root-owned /var/lib state merely to check.
    linux && (args.tunnel || args.release_lockdown || args.restore_lockdown)
}

/// The presence check is deliberately conservative and does not parse the
/// journal. Any directory entry -- or inability to prove absence -- requires
/// the independent lockdown before startup recovery is allowed to inspect or
/// remove the old main kill switch.
fn main_host_journal_may_exist(args: &Args) -> bool {
    let path = args.host_state_dir.join("host-state-v2.json");
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Ok(_) | Err(_) => true,
    }
}

fn acquire_host_state_lease(args: &Args) -> Result<Option<HostStateLease>> {
    // Every TUN mode must serialize with crash recovery, even when this
    // invocation will not create new full-tunnel host resources. Otherwise a
    // split/manual-route client could open a fresh TUN while a stale
    // full-tunnel journal still authorizes route/firewall/DNS convergence.
    if !requires_host_state_coordination(args) {
        return Ok(None);
    }
    ensure_host_state_directory(&args.host_state_dir)?;
    let path = args.host_state_dir.join("host.lock");
    match HostStateLease::try_acquire(&path) {
        Ok(lease) => Ok(Some(lease)),
        Err(LeaseError::Busy { .. }) => {
            eprintln!(
                "shadowpipe: another full-tunnel client owns {}; exiting with EX_TEMPFAIL (75)",
                path.display()
            );
            std::process::exit(75);
        }
        Err(error) => Err(anyhow::Error::new(error)).context("acquire exclusive host-state lease"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupRecoveryBoot {
    Same,
    Different,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupRecoveryRefusal {
    ActiveOwner,
    AmbiguousOwner,
    JournalConflict,
    InconsistentOwnerEvidence,
}

/// Pure startup gate. In particular, a same-boot owner is recoverable only
/// when both of its journaled namespaces still identify this calling thread.
/// Namespace inode numbers are intentionally ignored after a reboot.
fn decide_startup_recovery(
    evidence: OwnerEvidence,
    phase: JournalPhase,
) -> std::result::Result<StartupRecoveryBoot, StartupRecoveryRefusal> {
    if phase == JournalPhase::Conflict {
        return Err(StartupRecoveryRefusal::JournalConflict);
    }
    match classify_owner(evidence) {
        OwnerDisposition::Active => Err(StartupRecoveryRefusal::ActiveOwner),
        OwnerDisposition::Ambiguous => Err(StartupRecoveryRefusal::AmbiguousOwner),
        OwnerDisposition::Stale => match (evidence.boot, evidence.namespaces) {
            (BootEvidence::Same, NamespaceEvidence::Same) => Ok(StartupRecoveryBoot::Same),
            (BootEvidence::Different, NamespaceEvidence::NotApplicableAfterReboot) => {
                Ok(StartupRecoveryBoot::Different)
            }
            _ => Err(StartupRecoveryRefusal::InconsistentOwnerEvidence),
        },
    }
}

#[derive(Clone, Debug)]
struct ReconstructedRecoveryIdentity {
    tun: Option<TunResource>,
    kill_switch: Option<KillSwitchIdentity>,
}

fn merge_reconstructed<T>(slot: &mut Option<T>, candidate: T, label: &str) -> Result<()>
where
    T: Clone + Eq + std::fmt::Debug,
{
    if let Some(previous) = slot {
        anyhow::ensure!(
            previous == &candidate,
            "journal history contains contradictory {label}: {previous:?} vs {candidate:?}"
        );
    } else {
        *slot = Some(candidate);
    }
    Ok(())
}

/// Reconstruct only from immutable journal history. No PID-derived name,
/// runtime backend detection, current interface enumeration, or policy input
/// is allowed to participate in recovery authorization.
fn reconstruct_recovery_identity(
    journal: &HostStateJournalV2,
) -> Result<ReconstructedRecoveryIdentity> {
    let mut tun = None;
    let mut backend: Option<FirewallBackend> = None;
    let mut ipv4_token: Option<FirewallChainToken> = None;
    let mut ipv6_token: Option<FirewallChainToken> = None;
    let mut saw_firewall_history = false;

    for operation in &journal.operations {
        match &operation.resource {
            OwnedResource::Tun(resource) => {
                merge_reconstructed(&mut tun, resource.clone(), "TUN identity")?;
            }
            OwnedResource::Firewall(resource) => {
                saw_firewall_history = true;
                merge_reconstructed(&mut backend, resource.backend, "firewall backend")?;
                match resource.family {
                    AddressFamily::Ipv4 => merge_reconstructed(
                        &mut ipv4_token,
                        resource.chain_token,
                        "IPv4 firewall chain token",
                    )?,
                    AddressFamily::Ipv6 => merge_reconstructed(
                        &mut ipv6_token,
                        resource.chain_token,
                        "IPv6 firewall chain token",
                    )?,
                }
            }
            OwnedResource::FirewallEndpoint(resource) => {
                saw_firewall_history = true;
                merge_reconstructed(&mut backend, resource.backend, "firewall backend")?;
                match resource.family {
                    AddressFamily::Ipv4 => merge_reconstructed(
                        &mut ipv4_token,
                        resource.chain_token,
                        "IPv4 firewall chain token",
                    )?,
                    AddressFamily::Ipv6 => merge_reconstructed(
                        &mut ipv6_token,
                        resource.chain_token,
                        "IPv6 firewall chain token",
                    )?,
                }
            }
            OwnedResource::Route(_) | OwnedResource::Dns(_) => {}
        }
    }

    let kill_switch = if saw_firewall_history {
        let backend = backend.context("firewall history has no backend")?;
        let ipv4_token = ipv4_token.context("firewall history has no IPv4 chain token")?;
        let ipv6_token = ipv6_token.context("firewall history has no IPv6 chain token")?;
        Some(
            KillSwitchIdentity::from_parts(
                journal.owner.session_id,
                ipv4_token,
                ipv6_token,
                backend,
            )
            .context("reconstruct kill-switch identity from journal history")?,
        )
    } else {
        None
    };

    Ok(ReconstructedRecoveryIdentity { tun, kill_switch })
}

#[derive(Debug)]
enum StartupRecoveryPrepareError {
    Conflict(anyhow::Error),
    Operational(anyhow::Error),
}

impl StartupRecoveryPrepareError {
    fn conflict(error: impl Into<anyhow::Error>) -> Self {
        Self::Conflict(error.into())
    }

    fn operational(error: impl Into<anyhow::Error>) -> Self {
        Self::Operational(error.into())
    }
}

fn route_prepare_error(error: LinuxRoutePrepareError) -> StartupRecoveryPrepareError {
    match error {
        LinuxRoutePrepareError::Conflict { detail } => {
            StartupRecoveryPrepareError::conflict(anyhow::anyhow!(detail))
        }
        LinuxRoutePrepareError::Operational { detail } => {
            StartupRecoveryPrepareError::operational(anyhow::anyhow!(detail))
        }
    }
}

fn firewall_prepare_error(error: KillSwitchPrepareError) -> StartupRecoveryPrepareError {
    match error {
        KillSwitchPrepareError::Conflict { detail } => {
            StartupRecoveryPrepareError::conflict(anyhow::anyhow!(detail))
        }
        KillSwitchPrepareError::Operational { detail } => {
            StartupRecoveryPrepareError::operational(anyhow::anyhow!(detail))
        }
    }
}

fn dns_prepare_error(error: anyhow::Error) -> StartupRecoveryPrepareError {
    if error
        .downcast_ref::<DnsExchangeFailure>()
        .is_some_and(|failure| failure.kind() == DnsExchangeFailureKind::Conflict)
    {
        StartupRecoveryPrepareError::conflict(error)
    } else {
        StartupRecoveryPrepareError::operational(error)
    }
}

fn prepare_startup_recovery_adapter(
    journal: &HostStateJournalV2,
    boot: StartupRecoveryBoot,
) -> std::result::Result<PreparedHostRecoveryAdapter, StartupRecoveryPrepareError> {
    let same_boot = boot == StartupRecoveryBoot::Same;
    let reconstructed =
        reconstruct_recovery_identity(journal).map_err(StartupRecoveryPrepareError::conflict)?;
    let session = journal.owner.session_id;
    let mut routes = Vec::<RouteResource>::new();
    let mut dns = Vec::new();
    let mut tun = Vec::new();
    let mut firewall = Vec::<FirewallResource>::new();
    let mut firewall_endpoints = Vec::<FirewallEndpointResource>::new();
    for operation in journal
        .operations
        .iter()
        .filter(|operation| operation.state != OperationState::Removed)
    {
        match &operation.resource {
            OwnedResource::Route(resource) => routes.push(resource.clone()),
            OwnedResource::Dns(resource) => dns.push(resource.clone()),
            OwnedResource::Tun(resource) => tun.push(resource.clone()),
            OwnedResource::Firewall(resource) => firewall.push(resource.clone()),
            OwnedResource::FirewallEndpoint(resource) => firewall_endpoints.push(resource.clone()),
        }
    }

    let mut groups: Vec<Box<dyn PreparedResourceGroup>> = Vec::new();
    if !routes.is_empty() {
        let expected_namespace = if same_boot {
            journal
                .owner
                .network_namespace
                .context("same-boot route recovery lacks journaled network namespace")
                .map_err(StartupRecoveryPrepareError::conflict)?
        } else {
            current_linux_network_namespace_identity()
                .context("capture current namespace for different-boot route inspection")
                .map_err(StartupRecoveryPrepareError::operational)?
        };
        groups.push(Box::new(
            PreparedLinuxRouteGroup::prepare(session, expected_namespace, &routes, same_boot)
                .map_err(route_prepare_error)?,
        ));
    }
    if let Some(resource) = tun.first() {
        if tun.len() != 1 {
            return Err(StartupRecoveryPrepareError::conflict(anyhow::anyhow!(
                "journal has multiple live TUN records"
            )));
        }
        groups.push(Box::new(
            PreparedTunGroup::prepare(resource.clone(), session, same_boot)
                .map_err(StartupRecoveryPrepareError::operational)?,
        ));
    }
    for resource in dns {
        groups.push(Box::new(
            PreparedDnsGroup::prepare(Path::new("/etc/resolv.conf"), session, resource)
                .map_err(dns_prepare_error)?,
        ));
    }
    if !firewall.is_empty() || !firewall_endpoints.is_empty() {
        let identity = reconstructed
            .kill_switch
            .context("live firewall resources lack a complete journal-derived kill-switch identity")
            .map_err(StartupRecoveryPrepareError::conflict)?;
        let tun_iface = reconstructed
            .tun
            .as_ref()
            .map(|resource| resource.interface.name.as_str())
            .context("live firewall resources lack a journaled TUN interface")
            .map_err(StartupRecoveryPrepareError::conflict)?;
        groups.push(Box::new(
            PreparedKillSwitchRecovery::prepare_for_boot(
                tun_iface,
                identity,
                &firewall,
                &firewall_endpoints,
                same_boot,
            )
            .map_err(firewall_prepare_error)?,
        ));
    }

    PreparedHostRecoveryAdapter::new(journal, groups).map_err(StartupRecoveryPrepareError::conflict)
}

fn load_optional_host_journal(args: &Args) -> Result<Option<DurableHostJournal>> {
    let store = JournalStore::new(args.host_state_dir.join("host-state-v2.json"));
    match DurableHostJournal::load(store) {
        Ok(journal) => Ok(Some(journal)),
        Err(DurableJournalError::Store(HostStateError::Io { source, .. }))
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(DurableJournalError::Store(HostStateError::Missing(_))) => Ok(None),
        Err(error) => Err(anyhow::Error::new(error)).context("load durable host-state journal"),
    }
}

fn recover_startup_host_state(args: &Args, lease: Option<&HostStateLease>) -> Result<()> {
    if !requires_host_state_coordination(args) {
        return Ok(());
    }
    anyhow::ensure!(
        lease.is_some(),
        "startup recovery requires the host-state lease"
    );
    let Some(mut durable) = load_optional_host_journal(args)? else {
        return Ok(());
    };
    let evidence = observe_owner(&durable.journal().owner, LeaseEvidence::Available);
    let boot = decide_startup_recovery(evidence, durable.journal().phase).map_err(|refusal| {
        anyhow::anyhow!(
            "startup host recovery refused fail-closed: {refusal:?}; owner evidence: {evidence:?}"
        )
    })?;
    let snapshot = durable.journal().clone();
    let mut adapter = match prepare_startup_recovery_adapter(&snapshot, boot) {
        Ok(adapter) => adapter,
        Err(StartupRecoveryPrepareError::Conflict(error)) => {
            durable
                .mark_conflict()
                .context("durably mark startup recovery preflight conflict")?;
            return Err(error).context(
                "startup recovery preflight found conflicting ownership; host was not mutated",
            );
        }
        Err(StartupRecoveryPrepareError::Operational(error)) => {
            return Err(error).context(
                "startup recovery preflight failed operationally; journal remains retryable",
            )
        }
    };
    match recover_host_state(&mut durable, OwnerDisposition::Stale, &mut adapter)
        .context("execute all-resource startup host recovery")?
    {
        RecoveryRunOutcome::Recovered { removed_records } => {
            info!(removed_records, "stale host state recovered before startup");
            Ok(())
        }
        outcome => anyhow::bail!(
            "startup host recovery did not reach mandatory Recovered outcome: {outcome:?}"
        ),
    }
}

#[cfg(target_os = "linux")]
type RuntimeDnsPreflight = DnsExchangePreflight;

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
struct RuntimeDnsPreflight;

struct NewHostStateSession {
    journal: DurableHostJournal,
    kill_switch_install: KillSwitchInstallToken,
    dns_preflight: RuntimeDnsPreflight,
}

impl NewHostStateSession {
    /// Remove the empty Preparing WAL when startup stops before the first host
    /// mutation. This is valid only before a TUN resource has been appended;
    /// any non-empty journal must remain for ordinary recovery.
    fn abort_before_first_mutation(mut self) -> Result<()> {
        anyhow::ensure!(
            self.journal.journal().operations.is_empty(),
            "cannot discard a host-state WAL after a resource intent exists"
        );
        self.journal
            .begin_cleaning()
            .context("mark empty pre-mutation host-state WAL Cleaning")?;
        self.journal
            .remove_completed()
            .context("remove empty pre-mutation host-state WAL")
    }
}

struct NewHostStateRuntime {
    journal: DurableHostJournal,
    tun: TunResource,
    kill_switch_install: KillSwitchInstallToken,
    dns_preflight: RuntimeDnsPreflight,
}

/// New Linux host-state WALs are recoverable only when every attribution
/// field needed by both same-boot and different-boot recovery was captured.
/// Optional fields remain part of the on-disk schema so old/foreign-platform
/// journals fail closed at read time, but a privileged Linux writer must never
/// publish an ambiguity that it created itself.
fn require_complete_linux_owner_evidence(owner: &OwnerIdentity) -> Result<()> {
    let mut missing = Vec::new();
    if owner.boot_id.is_none() {
        missing.push("boot_id");
    }
    if owner.pid_start_ticks.is_none() {
        missing.push("pid_start_ticks");
    }
    if owner.network_namespace.is_none() {
        missing.push("network_namespace");
    }
    if owner.mount_namespace.is_none() {
        missing.push("mount_namespace");
    }
    anyhow::ensure!(
        missing.is_empty(),
        "refusing to create an unrecoverable Linux host-state WAL; missing owner evidence: {}",
        missing.join(", ")
    );
    Ok(())
}

fn prepare_new_host_state_session(args: &Args) -> Result<NewHostStateSession> {
    let kill_switch_install = KillSwitchInstallToken::prepare_runtime()
        .context("capture journal-bound kill-switch identity and table lifecycle")?;
    let owner = OwnerIdentity::capture_with_session(kill_switch_install.identity().session_id())
        .context("capture host-state owner identity")?;
    require_complete_linux_owner_evidence(&owner)
        .context("validate complete owner evidence before durable WAL creation")?;
    let store = JournalStore::new(args.host_state_dir.join("host-state-v2.json"));
    let journal = DurableHostJournal::create(store, owner)
        .context("create empty host-state WAL before privileged host mutation")?;

    #[cfg(target_os = "linux")]
    let dns_preflight = preflight_dns_exchange(
        Path::new("/etc/resolv.conf"),
        kill_switch_install.identity().session_id(),
    )
    .map_err(anyhow::Error::new)
    .context("preflight resolver topology and exchange capabilities before TUN")?;
    #[cfg(not(target_os = "linux"))]
    let dns_preflight = RuntimeDnsPreflight;

    Ok(NewHostStateSession {
        journal,
        kill_switch_install,
        dns_preflight,
    })
}

fn attach_new_tun_to_host_state(
    session: NewHostStateSession,
    iface: &str,
) -> Result<NewHostStateRuntime> {
    let NewHostStateSession {
        mut journal,
        kill_switch_install,
        dns_preflight,
    } = session;
    let tun = capture_tun_resource(iface).context("capture new TUN identity")?;
    let operation = journal
        .begin_add(OwnedResource::Tun(tun.clone()))
        .context("WAL planned TUN ownership marker")?;
    mark_tun_owned(&tun, kill_switch_install.identity().session_id())
        .context("mark exact TUN with journal owner alias")?;
    journal
        .acknowledge_add(operation)
        .context("acknowledge journal-owned TUN")?;
    journal
        .publish_active()
        .context("publish journal-owned TUN checkpoint")?;

    Ok(NewHostStateRuntime {
        journal,
        tun,
        kill_switch_install,
        dns_preflight,
    })
}

fn wal_kill_switch_install(
    journal: &mut DurableHostJournal,
    install: &KillSwitchInstallToken,
    endpoints: &[AllowedEndpoint],
) -> Result<Vec<u32>> {
    let identity = install.identity();
    let mut resources = install
        .journal_resources()
        .into_iter()
        .map(OwnedResource::Firewall)
        .collect::<Vec<_>>();
    let mut unique = endpoints.to_vec();
    unique.sort_unstable();
    unique.dedup();
    resources.extend(unique.into_iter().map(|endpoint| {
        OwnedResource::FirewallEndpoint(identity.endpoint_journal_resource(endpoint))
    }));
    journal
        .begin_add_batch(resources)
        .context("WAL complete kill-switch identity before firewall mutation")
}

#[derive(Clone, Debug)]
struct AcceptedSignedPolicy {
    plan: VerifiedRealityPlan,
    expires_at: i64,
    monotonic_deadline: Instant,
    expiry_checkpoint: PolicyExpiryCheckpoint,
    policy_store: PolicyStateStore,
    policy_root: TrustedRoot,
}

fn unix_time_seconds() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs()
        .try_into()
        .context("system clock does not fit signed-policy timestamp")
}

fn signed_policy_deadline(expires_at: i64, now: i64, monotonic_now: Instant) -> Result<Instant> {
    let remaining: u64 = expires_at
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .context("signed endpoint policy is already expired")?
        .try_into()
        .context("signed endpoint policy lifetime does not fit Duration")?;
    monotonic_now
        .checked_add(Duration::from_secs(remaining))
        .context("signed endpoint policy deadline overflows Instant")
}

async fn wait_signed_policy_expiry(policy: &AcceptedSignedPolicy) {
    const WALL_CLOCK_RECHECK: Duration = Duration::from_secs(30);
    loop {
        if unix_time_seconds().map_or(true, |now| now >= policy.expires_at) {
            return;
        }
        let recheck = Instant::now()
            .checked_add(WALL_CLOCK_RECHECK)
            .unwrap_or(policy.monotonic_deadline);
        let wake = recheck.min(policy.monotonic_deadline);
        tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
        if Instant::now() >= policy.monotonic_deadline {
            return;
        }
    }
}

fn signed_policy_expired(policy: &AcceptedSignedPolicy) -> bool {
    Instant::now() >= policy.monotonic_deadline
        || unix_time_seconds().map_or(true, |now| now >= policy.expires_at)
}

fn accept_signed_policy(args: &Args) -> Result<Option<AcceptedSignedPolicy>> {
    let Some(bundle_path) = args.policy_bundle.as_deref() else {
        return Ok(None);
    };
    let root_kid = args
        .policy_root_kid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--policy-bundle requires --policy-root-kid"))?;
    let root_key = args
        .policy_root_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--policy-bundle requires --policy-root-key"))?;
    let root = TrustedRoot {
        kid: Kid::new(parse_fixed_hex("--policy-root-kid", root_kid)?),
        ed25519_public_key: parse_fixed_hex("--policy-root-key", root_key)?,
    };
    let bytes = read_policy_bundle(bundle_path)?;
    let state_path = args
        .policy_state
        .clone()
        .unwrap_or_else(|| args.host_state_dir.join("policy-state-v1.bin"));
    let now = unix_time_seconds()?;
    let store = PolicyStateStore::new(&state_path);
    let transition = if args.policy_enroll {
        store.enroll(&root, &bytes, now)
    } else {
        store.update(&root, &bytes, now)
    }
    .with_context(|| format!("accept signed policy {}", bundle_path.display()))?;
    let state = transition.into_state();
    info!(
        policy_epoch = state.plan().policy_epoch(),
        policy_sequence = state.plan().sequence(),
        endpoints = state.plan().endpoints().len(),
        expires_at = state.plan().expires_at(),
        state = %state_path.display(),
        "signed endpoint policy durably accepted"
    );
    let expiry_checkpoint = PolicyExpiryCheckpoint::from_state(&state);
    let plan = state.into_plan();
    let expires_at = plan.expires_at();
    let monotonic_deadline = signed_policy_deadline(expires_at, now, Instant::now())?;
    Ok(Some(AcceptedSignedPolicy {
        plan,
        expires_at,
        monotonic_deadline,
        expiry_checkpoint,
        policy_store: store,
        policy_root: root,
    }))
}

/// Reject configurations that look protected but would silently run without
/// the requested routing/leak controls. This is called before trace
/// reservation, DNS, sockets, TUN creation, or host mutation.
fn validate_policy_authority(args: &Args) -> Result<()> {
    if args.policy_bundle.is_some() {
        if !args.tunnel || !args.auto_route {
            anyhow::bail!("--policy-bundle requires fail-closed --tunnel --auto-route");
        }
        if args.tls || args.quic || args.reality || !args.uri.is_empty() || args.uri_file.is_some()
        {
            anyhow::bail!(
                "--policy-bundle is an exclusive REALITY/TCP authority; do not mix --tls/--quic/--reality/--uri/--uri-file"
            );
        }
        if args.server_fp.is_some()
            || args.reality_pubkey.is_some()
            || !args.reality_short_id.is_empty()
        {
            anyhow::bail!(
                "--policy-bundle forbids unsigned manual pin/REALITY key flags (no fallback)"
            );
        }
        if args.policy_root_kid.is_none() || args.policy_root_key.is_none() {
            anyhow::bail!("--policy-bundle requires --policy-root-kid and --policy-root-key");
        }
    } else if args.policy_root_kid.is_some()
        || args.policy_root_key.is_some()
        || args.policy_state.is_some()
        || args.policy_enroll
    {
        anyhow::bail!("policy root/state flags require --policy-bundle");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct RuntimeDeadlines {
    connect: Duration,
    outer_handshake: Duration,
    inner_handshake: Duration,
    liveness: CarrierLivenessConfig,
}

impl RuntimeDeadlines {
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

        let connect = bounded_seconds(
            "connect-timeout-secs",
            args.connect_timeout_secs,
            Self::MIN_STAGE_SECONDS,
            Self::MAX_STAGE_SECONDS,
        )?;
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
            connect,
            outer_handshake,
            inner_handshake,
            liveness,
        })
    }
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

fn validate_release_lockdown_mode(args: &Args) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        anyhow::ensure!(
            !args.auto_route
                && !args.split
                && !args.kill_switch
                && args.dns.is_none()
                && args.policy_bundle.is_none()
                && args.measurement_json.is_none()
                && args.loadtest == 0
                && !args.reality
                && !args.tls
                && !args.quic
                && args.uri.is_empty()
                && args.uri_file.is_none()
                && args.message.is_none()
                && args.server_fp.is_none(),
            "--release-lockdown is a standalone host-state operation"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("--release-lockdown is implemented only on Linux")
    }
}

fn validate_restore_lockdown_mode(args: &Args) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        anyhow::ensure!(
            !args.auto_route
                && !args.split
                && !args.kill_switch
                && args.dns.is_none()
                && args.policy_bundle.is_none()
                && args.measurement_json.is_none()
                && args.loadtest == 0
                && !args.reality
                && !args.tls
                && !args.quic
                && args.uri.is_empty()
                && args.uri_file.is_none()
                && args.message.is_none()
                && args.server_fp.is_none(),
            "--restore-lockdown is a standalone early-boot host-state operation"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("--restore-lockdown is implemented only on Linux")
    }
}

fn validate_runtime_safety(args: &Args) -> Result<()> {
    validate_ipv6_mode(args)?;
    if args.release_lockdown {
        return validate_release_lockdown_mode(args);
    }
    if args.restore_lockdown {
        return validate_restore_lockdown_mode(args);
    }
    // This validation runs before credential loading, the singleton host-state
    // lease, recovery, policy-state mutation, resolution, sockets, or TUNs.
    // A binary that cannot implement the requested carrier must therefore fail
    // without touching either the host or credential state.
    #[cfg(not(feature = "quic"))]
    if args.quic {
        anyhow::bail!("--quic requires a build with `--features quic` (quinn not compiled in)");
    }
    #[cfg(not(feature = "tls-chrome"))]
    if args.tls {
        anyhow::bail!(
            "--tls requires a build with `--features tls-chrome` (BoringSSL not compiled in)"
        );
    }
    validate_policy_authority(args)?;
    if args.policy_bundle.is_none() {
        parse_server_fp(&args.server_fp)
            .context("validate mandatory manual server identity before runtime state")?;
        if args.reality {
            reality_server_pub(args)
                .context("validate manual REALITY public key before runtime state")?;
            parse_short_id(&args.reality_short_id)
                .context("validate manual REALITY short_id before runtime state")?;
        }
    }
    RuntimeDeadlines::from_args(args).context("validate bounded runtime deadlines")?;
    if (args.auto_route || args.split) && !args.tunnel {
        anyhow::bail!("--auto-route/--split require --tunnel");
    }
    if (args.kill_switch || args.dns.is_some()) && !args.auto_route {
        anyhow::bail!("--kill-switch/--dns require --tunnel --auto-route");
    }
    if args.split_dns_guard && !args.split {
        anyhow::bail!("--split-dns-guard requires --tunnel --split");
    }
    if args.auto_route {
        if !args.kill_switch {
            anyhow::bail!("--auto-route requires --kill-switch (no fail-open full tunnel)");
        }
        if args.dns.is_none() {
            anyhow::bail!("--auto-route requires --dns <TUN_RESOLVER> (no DNS leak window)");
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("fail-closed --auto-route is currently Linux-only; use an isolated Linux VM");
    }
    Ok(())
}

fn validate_ipv6_mode(args: &Args) -> Result<()> {
    let requested = Ipv6Mode::from(args.ipv6_mode);
    anyhow::ensure!(
        requested == Ipv6Mode::Block,
        "--ipv6-mode {} is not implemented; only --ipv6-mode block has a proven fail-closed client backend",
        args.ipv6_mode.as_cli_value()
    );
    Ok(())
}

fn parse_camouflage(s: &str) -> Result<CamouflageMode> {
    match s.to_lowercase().as_str() {
        "raw" => Ok(CamouflageMode::Raw),
        "h2" | "h2-chunk" | "h2chunk" => Ok(CamouflageMode::H2Chunk),
        "dns" | "dns-chunk" => anyhow::bail!(
            "DNS camouflage is not implemented; refusing to authenticate a raw carrier as DNS"
        ),
        other => Err(anyhow::anyhow!("unknown camouflage {other}")),
    }
}

/// Strict client-side URI parser. Server-side research helpers retain a more
/// permissive parser, but every manual client endpoint must carry one full-width
/// canonical 64-bit selector so no empty/short selector silently reaches the
/// production carrier ACL.
fn parse_client_uri_list(input: &str) -> Result<Vec<RealityUri>> {
    let mut pool = Vec::new();
    for token in input.split(|character: char| character == ',' || character.is_whitespace()) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let query = token
            .split_once('?')
            .map(|(_, query)| query)
            .ok_or_else(|| anyhow::anyhow!("manual REALITY URI requires a query string"))?;
        let mut short_id = None;
        let mut fingerprint = None;
        let mut sni = None;
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("malformed manual REALITY URI query"))?;
            match key {
                "sid" => anyhow::ensure!(
                    short_id.replace(value).is_none(),
                    "manual REALITY URI must contain exactly one sid"
                ),
                "fp" => anyhow::ensure!(
                    fingerprint.replace(value).is_none(),
                    "manual REALITY URI must contain exactly one fp"
                ),
                "sni" => anyhow::ensure!(
                    sni.replace(value).is_none(),
                    "manual REALITY URI must contain exactly one sni"
                ),
                _ => anyhow::bail!("manual REALITY URI contains an unknown query key"),
            }
        }
        let short_id = short_id
            .ok_or_else(|| anyhow::anyhow!("manual REALITY URI requires sid=<16-lower-hex>"))?;
        anyhow::ensure!(
            short_id.len() == 16
                && short_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "manual REALITY URI sid must be exactly 16 lowercase hex characters (8 bytes)"
        );
        anyhow::ensure!(
            fingerprint.is_some_and(|value| !value.is_empty()),
            "manual REALITY URI requires fp=<64-hex ML-KEM server fingerprint>"
        );
        anyhow::ensure!(
            sni.is_some_and(|value| !value.is_empty()),
            "manual REALITY URI requires one non-empty sni"
        );
        let uri = RealityUri::parse(token)
            .map_err(|_| anyhow::anyhow!("manual REALITY URI is malformed"))?;
        anyhow::ensure!(
            shadowpipe_core::reality::reality_public_key_is_contributory(&uri.pubkey),
            "manual REALITY URI contains a non-contributory low-order X25519 public key"
        );
        anyhow::ensure!(
            uri.short_id.len() == 8,
            "manual REALITY URI sid must decode to exactly 8 bytes"
        );
        pool.push(uri);
    }
    Ok(pool)
}

/// If a manual URI source is set, fill the equivalent REALITY flags from the FIRST endpoint
/// (so the one-shot echo path works); the tunnel path builds the full rotation
/// pool separately via [`reality_pool`]. The URI is authoritative — it sets
/// --reality and the server/pubkey/short_id/sni/fp.
fn apply_uri(args: &mut Args) -> Result<()> {
    let mut pool = Vec::new();
    for entry in &args.uri {
        pool.extend(parse_client_uri_list(entry).context("parse manual URI source")?);
    }
    anyhow::ensure!(
        args.uri.is_empty() || !pool.is_empty(),
        "manual URI source contains no endpoints"
    );
    let Some(u) = pool.into_iter().next() else {
        return Ok(());
    };
    args.reality = true;
    args.server = u.host;
    args.reality_pubkey = Some(hex::encode(u.pubkey));
    args.reality_short_id = hex::encode(&u.short_id);
    args.sni = u.sni;
    args.server_fp = Some(hex::encode(u.server_fp));
    Ok(())
}

/// The server's REALITY X25519 static public key from --reality-pubkey (required
/// with --reality).
fn reality_server_pub(args: &Args) -> Result<[u8; 32]> {
    let hex = args.reality_pubkey.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "--reality requires --reality-pubkey (the server's X25519 static public key)"
        )
    })?;
    let public_key = shadowpipe_core::reality::parse_x25519_32(hex)?;
    anyhow::ensure!(
        shadowpipe_core::reality::reality_public_key_is_contributory(&public_key),
        "--reality-pubkey is a non-contributory low-order X25519 point"
    );
    Ok(public_key)
}

/// Parse the full-width canonical REALITY carrier selector required by every
/// manual client path.
fn parse_short_id(s: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        s.len() == 16
            && s.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "--reality-short-id must be exactly 16 lowercase hex characters (8 bytes)"
    );
    let b = hex::decode(s).context("decode --reality-short-id hex")?;
    anyhow::ensure!(b.len() == 8, "--reality-short-id must decode to 8 bytes");
    Ok(b)
}

/// Build the REALITY endpoint pool the tunnel rotates through: the `--uri` list
/// (each entry may itself be comma/space/newline-separated), or — when --reality
/// is set via flags — a single endpoint synthesized from the flags. Empty for the
/// --tls / plain-carrier paths (which don't rotate). Fails early (before the retry
/// loop) on a bad pubkey/short_id/fp.
fn reality_pool(args: &Args) -> Result<Vec<RealityUri>> {
    let mut pool = Vec::new();
    for entry in &args.uri {
        pool.extend(parse_client_uri_list(entry)?);
    }
    if !pool.is_empty() {
        return Ok(pool);
    }
    if args.reality {
        pool.push(RealityUri {
            host: args.server.clone(),
            pubkey: reality_server_pub(args)?,
            sni: args.sni.clone(),
            short_id: parse_short_id(&args.reality_short_id)?,
            server_fp: parse_server_fp(&args.server_fp)?,
        });
    }
    Ok(pool)
}

fn parse_literal_ipv4_socket(value: &str) -> Result<SocketAddrV4> {
    value.parse::<SocketAddrV4>().with_context(|| {
        format!(
            "restart-lockdown bootstrap requires a numeric IPv4 socket (A.B.C.D:PORT), got {value:?}"
        )
    })
}

/// With an adopted barrier, the legacy/manual compatibility path may not call
/// the direct resolver. Signed production plans already carry literal IPv4
/// sockets; manual mode must do the same or fail before TUN/host mutation.
fn require_literal_manual_restart_endpoints(args: &Args) -> Result<()> {
    let pool = reality_pool(args)?;
    if pool.is_empty() {
        parse_literal_ipv4_socket(&args.server)?;
    } else {
        for endpoint in pool {
            parse_literal_ipv4_socket(&endpoint.host)?;
        }
    }
    Ok(())
}

fn resolve_tunnel_endpoints(
    server: &str,
    restart_lockdown_active: bool,
) -> Result<Vec<SocketAddrV4>> {
    if restart_lockdown_active {
        return Ok(vec![parse_literal_ipv4_socket(server)?]);
    }
    resolve_server_endpoints(server)
}

/// Pick the next endpoint index after a session ends. Sticky-until-fail: only a
/// transient failure (Backoff) advances to the next endpoint and wraps; a
/// volume-guard rotation or a clean stop stays put. No-op for a single endpoint.
fn rotate_endpoint(idx: usize, len: usize, action: ReconnectAction) -> usize {
    if len <= 1 {
        return idx;
    }
    match action {
        ReconnectAction::Backoff | ReconnectAction::RemoteClose => (idx + 1) % len,
        _ => idx,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let mut args = Args::parse();
    // Keep this policy check ahead of credential provisioning as well as every
    // network/runtime path. Unsupported IPv6 modes must be inert CLI requests.
    validate_ipv6_mode(&args)?;
    if args.generate_client_credential || args.write_client_enrollment.is_some() {
        #[cfg(not(unix))]
        anyhow::ensure!(
            args.development_user_credential,
            "credential provisioning on non-Unix platforms requires --development-user-credential and is no-TUN only"
        );
        let enrollment_path = args
            .write_client_enrollment
            .as_deref()
            .context("--generate-client-credential requires --write-client-enrollment")?;
        let credential = if args.generate_client_credential {
            ClientCredential::create(&args.client_credential)
                .context("create non-overwriting private client credential")?
        } else {
            ClientCredential::load(&args.client_credential)
                .context("load existing private client credential for secret re-export")?
        };
        credential
            .write_enrollment(enrollment_path)
            .context("create non-overwriting secret client enrollment artifact")?;
        info!(
            client_kid = %hex::encode(credential.key_id()),
            generated = args.generate_client_credential,
            "secret client enrollment artifact created"
        );
        return Ok(());
    }
    // Parse a private URI file before credential reads, singleton leases,
    // recovery, policy-state mutation, DNS, sockets, TUNs, or routes.
    load_uri_file_source(&mut args)?;
    apply_uri(&mut args)?;
    let camouflage = parse_camouflage(&args.camouflage)?;
    validate_runtime_safety(&args)?;
    let client_credential = if args.release_lockdown || args.restore_lockdown {
        None
    } else {
        let credential = if args.development_user_credential {
            ClientCredential::load(&args.client_credential)
                .context("load explicit development user-owned client credential")?
        } else {
            ClientCredential::load_root_owned(&args.client_credential)
                .context("load mandatory root-owned client credential before startup")?
        };
        Some(Arc::new(credential))
    };
    // The global lease gates both journals. If either restart-barrier state or
    // any possible main-journal directory entry exists, the independent native
    // nft barrier is Active before old host recovery can remove a base hook.
    // No socket, resolver query, TUN, route, DNS, or signed-state mutation is
    // reachable before this ordering boundary.
    let host_state_lease = acquire_host_state_lease(&args)?;
    let lockdown_control = if cfg!(target_os = "linux") && !args.restore_lockdown {
        ssh_lockdown_control_flow()?
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let mut restart_lockdown: Option<LockdownBarrier> = {
        let stale_main_journal = main_host_journal_may_exist(&args);
        if args.release_lockdown {
            Some(
                LockdownBarrier::engage_required(&args.host_state_dir, lockdown_control)
                    .context("arm/adopt lockdown before explicit host cleanup")?,
            )
        } else if requires_host_state_coordination(&args) {
            LockdownBarrier::engage_for_startup(
                &args.host_state_dir,
                lockdown_control,
                stale_main_journal,
            )
            .context("arm/adopt restart lockdown before main-journal recovery")?
        } else {
            None
        }
    };
    #[cfg(not(target_os = "linux"))]
    let mut restart_lockdown: Option<LockdownBarrier> = None;
    if args.restore_lockdown {
        if let Some(barrier) = restart_lockdown.as_mut() {
            barrier
                .verify_active()
                .context("prove early-boot lockdown kernel/WAL state Active")?;
            info!("early-boot durable lockdown restored and strictly verified Active");
        } else {
            info!("early-boot lockdown restore found no barrier or main WAL; no-op");
        }
        return Ok(());
    }
    recover_startup_host_state(&args, host_state_lease.as_ref())?;
    if args.release_lockdown {
        anyhow::ensure!(
            !main_host_journal_may_exist(&args) && load_optional_host_journal(&args)?.is_none(),
            "refusing explicit lockdown release while the main host WAL may still exist"
        );
        let mut barrier = restart_lockdown
            .take()
            .context("explicit lockdown release has no armed barrier")?;
        barrier
            .release_after_explicit_host_cleanup()
            .context("explicitly restore direct networking after complete host cleanup")?;
        info!("durable restart lockdown explicitly released; direct networking restored");
        return Ok(());
    }
    let client_credential =
        client_credential.context("network session startup has no loaded client credential")?;
    if restart_lockdown.is_some() {
        anyhow::ensure!(
            args.tunnel && args.auto_route,
            "an adopted restart lockdown requires a full --tunnel --auto-route replacement; use --release-lockdown for intentional direct networking"
        );
    }
    let signed_policy = accept_signed_policy(&args)?;
    if restart_lockdown.is_some() && signed_policy.is_none() {
        require_literal_manual_restart_endpoints(&args)?;
    }
    let server_fp = if let Some(policy) = &signed_policy {
        *policy
            .plan
            .endpoints()
            .first()
            .and_then(|endpoint| endpoint.server_pins().as_slice().first())
            .ok_or_else(|| anyhow::anyhow!("verified signed policy has no server pin"))?
    } else {
        // Manual compatibility path remains authenticated, but is explicitly
        // distinct from signed production policy and never used as fallback.
        parse_server_fp(&args.server_fp)?
    };
    let measurement = measurement_output(&args, camouflage)?
        .map(LoadtestMeasurement::reserve)
        .transpose()?;

    // Measurement owns one pre-socket reservation and one recorder spanning
    // the complete outer+inner establishment. Keep it on a separate no-TUN
    // path so ordinary echo and tunnel behavior remain unchanged.
    if let Some(measurement) = measurement {
        return run_measured_loadtest(
            &args,
            camouflage,
            server_fp,
            Arc::clone(&client_credential),
            measurement,
        )
        .await;
    }

    let mut profile = if args.profile_seed {
        profile_from_env()
    } else {
        TunnelProfile::default()
    };
    profile.mux.stream_count = args.mux_streams;
    profile.mux.max_chunk_size = args.mux_chunk;
    profile.volume_guard.threshold = args.guard_bytes;
    profile.volume_guard.enabled = args.rotate_conn && !args.no_guard;
    profile.pacer.enabled = args.pace;

    if args.tunnel {
        run_tunnel_mode(
            &args,
            camouflage,
            profile,
            ClientAuthContext {
                server_fingerprint: server_fp,
                credential: Arc::clone(&client_credential),
            },
            signed_policy.as_ref(),
            &mut restart_lockdown,
            lockdown_control,
        )
        .await?;
        return Ok(());
    }

    let deadlines = RuntimeDeadlines::from_args(&args)
        .expect("runtime deadlines were validated before network startup");

    if args.quic {
        // QUIC is UDP — no TCP dial. The PQ session rides inside one bi-stream.
        #[cfg(feature = "quic")]
        {
            let stream = bounded_stage(
                "QUIC connect and outer handshake",
                deadlines.connect.saturating_add(deadlines.outer_handshake),
                async {
                    let addr = shadowpipe_core::quic::resolve_quic_addr(&args.server)?;
                    shadowpipe_core::quic::quic_connect(addr, &args.sni).await
                },
            )
            .await?;
            info!(server = %args.server, sni = %args.sni, "connected (quic)");
            let config = ClientConfig {
                camouflage: CamouflageMode::Raw,
                padding_profile: PaddingProfile::Balanced,
                server_fingerprint: server_fp,
                client_credential: Arc::clone(&client_credential),
            };
            return run_session(stream, &config, &args).await;
        }
        #[cfg(not(feature = "quic"))]
        anyhow::bail!("--quic requires a build with `--features quic` (quinn not compiled in)");
    }
    let tcp = bounded_stage(
        "TCP connect",
        deadlines.connect,
        TcpStream::connect(&args.server),
    )
    .await?;
    if args.reality {
        let server_pub = reality_server_pub(&args)?;
        let short_id = parse_short_id(&args.reality_short_id)?;
        info!(server = %args.server, sni = %args.sni, "connected (reality)");
        let stream = bounded_stage(
            "REALITY outer handshake",
            deadlines.outer_handshake,
            shadowpipe_core::reality::reality_connect(tcp, &server_pub, &short_id, &args.sni),
        )
        .await?;
        let config = ClientConfig {
            camouflage: CamouflageMode::Raw,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: server_fp,
            client_credential: Arc::clone(&client_credential),
        };
        run_session(stream, &config, &args).await
    } else if args.tls {
        #[cfg(feature = "tls-chrome")]
        {
            info!(server = %args.server, sni = %args.sni, "connected (tls-chrome)");
            let stream = bounded_stage(
                "TLS outer handshake",
                deadlines.outer_handshake,
                shadowpipe_core::tls::chrome_connect(tcp, &args.sni),
            )
            .await?;
            let config = ClientConfig {
                camouflage: CamouflageMode::Raw,
                padding_profile: PaddingProfile::Balanced,
                server_fingerprint: server_fp,
                client_credential: Arc::clone(&client_credential),
            };
            run_session(stream, &config, &args).await
        }
        #[cfg(not(feature = "tls-chrome"))]
        anyhow::bail!(
            "--tls requires a build with `--features tls-chrome` (BoringSSL not compiled in)"
        );
    } else {
        info!(server = %args.server, ?camouflage, "connected");
        let stream = bounded_stage(
            "carrier bootstrap",
            deadlines.outer_handshake,
            client_connect(tcp, camouflage),
        )
        .await?;
        let config = ClientConfig {
            camouflage,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: server_fp,
            client_credential,
        };
        run_session(stream, &config, &args).await
    }
}

#[derive(Clone, Copy, Debug)]
enum EstablishmentStage {
    OuterCarrier,
    InnerAuthentication,
}

/// Establish the selected outer carrier and inner AuthenticatedSession under one
/// monotonic deadline, then continue into the bounded loadtest. Every observed
/// establishment failure owns and publishes the same terminal Pending trace.
async fn run_measured_loadtest(
    args: &Args,
    camouflage: CamouflageMode,
    server_fp: [u8; 32],
    client_credential: Arc<ClientCredential>,
    measurement: LoadtestMeasurement,
) -> Result<()> {
    if args.quic {
        #[cfg(feature = "quic")]
        {
            let config = ClientConfig {
                camouflage: CamouflageMode::Raw,
                padding_profile: PaddingProfile::Balanced,
                server_fingerprint: server_fp,
                client_credential: Arc::clone(&client_credential),
            };
            return establish_and_run_measured(
                async {
                    let addr = tokio::net::lookup_host(&args.server)
                        .await
                        .context("resolve measured QUIC endpoint")?
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("measured QUIC endpoint resolved empty"))?;
                    shadowpipe_core::quic::quic_connect(addr, &args.sni).await
                },
                &config,
                args.loadtest,
                measurement,
                LOADTEST_MEASUREMENT_DIAL_TIMEOUT,
            )
            .await;
        }
        #[cfg(not(feature = "quic"))]
        unreachable!("measurement preflight rejects QUIC when the feature is absent");
    }

    if args.reality {
        let server_pub = reality_server_pub(args)?;
        let short_id = parse_short_id(&args.reality_short_id)?;
        let config = ClientConfig {
            camouflage: CamouflageMode::Raw,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: server_fp,
            client_credential: Arc::clone(&client_credential),
        };
        return establish_and_run_measured(
            async {
                let tcp = TcpStream::connect(&args.server).await?;
                shadowpipe_core::reality::reality_connect(tcp, &server_pub, &short_id, &args.sni)
                    .await
            },
            &config,
            args.loadtest,
            measurement,
            LOADTEST_MEASUREMENT_DIAL_TIMEOUT,
        )
        .await;
    }

    if args.tls {
        #[cfg(feature = "tls-chrome")]
        {
            let config = ClientConfig {
                camouflage: CamouflageMode::Raw,
                padding_profile: PaddingProfile::Balanced,
                server_fingerprint: server_fp,
                client_credential: Arc::clone(&client_credential),
            };
            return establish_and_run_measured(
                async {
                    let tcp = TcpStream::connect(&args.server).await?;
                    shadowpipe_core::tls::chrome_connect(tcp, &args.sni).await
                },
                &config,
                args.loadtest,
                measurement,
                LOADTEST_MEASUREMENT_DIAL_TIMEOUT,
            )
            .await;
        }
        #[cfg(not(feature = "tls-chrome"))]
        unreachable!("measurement preflight rejects TLS when the feature is absent");
    }

    let config = ClientConfig {
        camouflage,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: server_fp,
        client_credential,
    };
    establish_and_run_measured(
        async {
            let tcp = TcpStream::connect(&args.server).await?;
            client_connect(tcp, camouflage).await
        },
        &config,
        args.loadtest,
        measurement,
        LOADTEST_MEASUREMENT_DIAL_TIMEOUT,
    )
    .await
}

async fn establish_and_run_measured<S, F>(
    connect_outer: F,
    config: &ClientConfig,
    mb: u64,
    mut measurement: LoadtestMeasurement,
    dial_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = Result<S>>,
{
    let dial_start = Instant::now();
    let established = tokio::time::timeout(dial_timeout, async {
        let mut stream = connect_outer
            .await
            .map_err(|error| (EstablishmentStage::OuterCarrier, error))?;
        let (session, session_id) = AuthenticatedSession::client_connect(&mut stream, config)
            .await
            .map_err(|error| (EstablishmentStage::InnerAuthentication, error))?;
        Ok::<_, (EstablishmentStage, anyhow::Error)>((stream, session, session_id))
    })
    .await;
    let dial_duration = dial_start.elapsed();

    match established {
        Ok(Ok((stream, session, session_id))) => {
            measurement.record_dial(dial_duration, DialOutcome::Connected)?;
            measurement.record_selected_path()?;
            run_loadtest_established(
                stream,
                session,
                session_id,
                mb,
                Some(measurement),
                dial_duration,
            )
            .await
        }
        Ok(Err((stage, error))) => {
            let (dial_outcome, close_outcome) = establishment_failure_outcomes(stage, &error);
            let trace_result = finish_failed_establishment(
                measurement,
                dial_duration,
                dial_outcome,
                close_outcome,
            );
            return_establishment_error(error, trace_result)
        }
        Err(_) => {
            let error = anyhow::anyhow!(
                "measured outer carrier plus authenticated-session establishment exceeded {} seconds",
                dial_timeout.as_secs_f64()
            );
            let trace_result = finish_failed_establishment(
                measurement,
                dial_duration,
                DialOutcome::TimedOut,
                CloseOutcome::TimedOut,
            );
            return_establishment_error(error, trace_result)
        }
    }
}

fn finish_failed_establishment(
    mut measurement: LoadtestMeasurement,
    duration: Duration,
    dial_outcome: DialOutcome,
    close_outcome: CloseOutcome,
) -> Result<()> {
    measurement.record_dial(duration, dial_outcome)?;
    measurement.finish(
        LoadtestProgress::default().snapshot()?,
        duration,
        close_outcome,
    )
}

fn return_establishment_error(error: anyhow::Error, trace_result: Result<()>) -> Result<()> {
    match trace_result {
        Ok(()) => Err(error),
        Err(trace_error) => Err(error).with_context(|| {
            format!("failed to publish terminal measurement trace: {trace_error:#}")
        }),
    }
}

fn establishment_failure_outcomes(
    stage: EstablishmentStage,
    error: &anyhow::Error,
) -> (DialOutcome, CloseOutcome) {
    if matches!(stage, EstablishmentStage::InnerAuthentication)
        && error.to_string().contains("server key pin mismatch")
    {
        return (
            DialOutcome::AuthenticationRejected,
            CloseOutcome::AuthenticationError,
        );
    }
    if matches!(stage, EstablishmentStage::InnerAuthentication) {
        return (DialOutcome::ProtocolError, CloseOutcome::ProtocolError);
    }

    let Some(io_error) = error.downcast_ref::<std::io::Error>() else {
        return (DialOutcome::ProtocolError, CloseOutcome::ProtocolError);
    };
    match io_error.kind() {
        std::io::ErrorKind::ConnectionRefused => {
            (DialOutcome::Refused, CloseOutcome::TransportError)
        }
        std::io::ErrorKind::TimedOut => (DialOutcome::TimedOut, CloseOutcome::TimedOut),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::NotFound => {
            (DialOutcome::Unreachable, CloseOutcome::TransportError)
        }
        _ => (DialOutcome::Unreachable, CloseOutcome::TransportError),
    }
}

/// Authenticate an already-established outer carrier under the same bounded
/// inner-handshake deadline used by tunnel mode, then dispatch only the
/// established typed session to loadtest or echo/stdin. Interactive lifetime is
/// intentionally unbounded; unauthenticated establishment is not.
async fn run_session<S>(mut stream: S, config: &ClientConfig, args: &Args) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadlines = RuntimeDeadlines::from_args(args)
        .expect("runtime deadlines were validated before network startup");
    let handshake_start = Instant::now();
    let (session, session_id) = bounded_stage(
        "inner authenticated handshake",
        deadlines.inner_handshake,
        AuthenticatedSession::client_connect(&mut stream, config),
    )
    .await?;
    let handshake_duration = handshake_start.elapsed();
    if args.loadtest > 0 {
        run_loadtest_established(
            stream,
            session,
            session_id,
            args.loadtest,
            None,
            handshake_duration,
        )
        .await
    } else {
        run_echo_established(stream, session, session_id, args.message.clone()).await
    }
}

/// First downlink-progress log fires at 64 KB so an early candidate stall is
/// visible before the first MB tick. It does not encode a censor threshold.
const LOADTEST_CHUNK: usize = 16 * 1024;
/// No echo for this long mid-transfer is recorded as a candidate stall. It may
/// also be congestion, backpressure, or peer failure and is not attribution by
/// itself.
const LOADTEST_STALL: Duration = Duration::from_secs(8);
/// Dial + path + TX + RX + optional stall + close, with two spare slots.
const LOADTEST_MEASUREMENT_MAX_EVENTS: usize = 8;
/// Bound an opt-in observation's byte/time budget independently of output size.
const LOADTEST_MEASUREMENT_MAX_MIB: u64 = 1024;
/// Bound DNS, outer carrier establishment, and inner AuthenticatedSession auth as one
/// observation. Transfer has its own workload-dependent bound below.
const LOADTEST_MEASUREMENT_DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// A bounded number of random create-new attempts avoids an unbounded preflight
/// loop if the output directory is hostile or the RNG is catastrophically bad.
const MEASUREMENT_TEMP_CREATE_ATTEMPTS: usize = 16;

#[derive(Debug, Default)]
struct LoadtestProgress {
    transmitted_payload_bytes: AtomicU64,
    transmitted_session_wire_bytes: AtomicU64,
    received_payload_bytes: AtomicU64,
    received_session_wire_bytes: AtomicU64,
    overflowed: AtomicBool,
    stall_detected: AtomicBool,
}

#[derive(Clone, Copy, Debug)]
struct LoadtestProgressSnapshot {
    transmitted_payload_bytes: u64,
    transmitted_session_wire_bytes: u64,
    received_payload_bytes: u64,
    received_session_wire_bytes: u64,
    stall_detected: bool,
}

impl LoadtestProgress {
    fn add_pair(&self, payload: &AtomicU64, wire: &AtomicU64, p: u64, w: u64) -> Result<()> {
        if w < p {
            self.overflowed.store(true, Ordering::Relaxed);
            anyhow::bail!("secure-session wire accounting fell below payload accounting");
        }
        let payload_ok = payload
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(p)
            })
            .is_ok();
        let wire_ok = wire
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(w)
            })
            .is_ok();
        if !payload_ok || !wire_ok {
            self.overflowed.store(true, Ordering::Relaxed);
            anyhow::bail!("loadtest measurement byte counter overflowed");
        }
        Ok(())
    }

    fn add_transmit(&self, payload: u64, session_wire: u64) -> Result<()> {
        self.add_pair(
            &self.transmitted_payload_bytes,
            &self.transmitted_session_wire_bytes,
            payload,
            session_wire,
        )
    }

    fn add_receive(&self, payload: u64, session_wire: u64) -> Result<()> {
        self.add_pair(
            &self.received_payload_bytes,
            &self.received_session_wire_bytes,
            payload,
            session_wire,
        )
    }

    fn snapshot(&self) -> Result<LoadtestProgressSnapshot> {
        if self.overflowed.load(Ordering::Relaxed) {
            anyhow::bail!("loadtest measurement counters are incomplete after overflow");
        }
        Ok(LoadtestProgressSnapshot {
            transmitted_payload_bytes: self.transmitted_payload_bytes.load(Ordering::Relaxed),
            transmitted_session_wire_bytes: self
                .transmitted_session_wire_bytes
                .load(Ordering::Relaxed),
            received_payload_bytes: self.received_payload_bytes.load(Ordering::Relaxed),
            received_session_wire_bytes: self.received_session_wire_bytes.load(Ordering::Relaxed),
            stall_detected: self.stall_detected.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug)]
struct LoadtestMeasurement {
    reservation: MeasurementReservation,
    transport: TransportKind,
    recorder: MeasurementRecorder,
}

impl LoadtestMeasurement {
    /// Reserve and preflight the output before any DNS lookup or socket dial.
    fn reserve(output: MeasurementOutput) -> Result<Self> {
        let reservation = MeasurementReservation::reserve(output.path)?;
        let metadata = RunMetadata {
            run_id: random_public_id(),
            experiment_id: Some(output.experiment_id),
            artifact_id: Some(output.artifact_id),
            started_unix_ms: unix_time_ms()?,
            software_version: SoftwareVersion {
                major: env!("CARGO_PKG_VERSION_MAJOR").parse()?,
                minor: env!("CARGO_PKG_VERSION_MINOR").parse()?,
                patch: env!("CARGO_PKG_VERSION_PATCH").parse()?,
            },
            role: NodeRole::Client,
            environment: output.environment,
        };
        let evidence = EvidenceAssessment {
            scope: output.scope,
            // The trace is an observation, not an automatic causal verdict.
            // Offline analysis must explicitly promote/refute the claim.
            outcome: EvidenceOutcome::Pending,
        };
        let recorder =
            MeasurementRecorder::new(metadata, evidence, LOADTEST_MEASUREMENT_MAX_EVENTS)
                .context("initialize bounded loadtest measurement recorder")?;
        Ok(Self {
            reservation,
            transport: output.transport,
            recorder,
        })
    }

    fn record_dial(&mut self, duration: Duration, outcome: DialOutcome) -> Result<()> {
        // The single dial observation intentionally spans DNS, the outer
        // carrier handshake, and inner AuthenticatedSession authentication. The
        // closed schema records only a run-local endpoint reference.
        self.recorder
            .push(EventKind::Dial {
                endpoint_ref: 0,
                transport: self.transport,
                attempt: 1,
                duration_us: duration_us(duration)?,
                outcome,
            })
            .context("record loadtest dial")
    }

    fn record_selected_path(&mut self) -> Result<()> {
        self.recorder
            .push(EventKind::Path {
                path_ref: 0,
                endpoint_ref: 0,
                state: PathState::Selected,
                metrics: None,
            })
            .context("record selected loadtest path")
    }

    fn finish(
        mut self,
        progress: LoadtestProgressSnapshot,
        transfer_duration: Duration,
        close_outcome: CloseOutcome,
    ) -> Result<()> {
        // `wire_bytes` is the exact encoded AuthenticatedSession frame count returned
        // by send/recv. It intentionally excludes outer TLS/H2/QUIC/IP overhead;
        // this path never opens packet capture or changes socket topology.
        let interval_us = duration_us(transfer_duration)?.max(1);
        if progress.transmitted_payload_bytes != 0 || progress.transmitted_session_wire_bytes != 0 {
            self.recorder
                .push(EventKind::Transfer {
                    path_ref: 0,
                    direction: Direction::Transmit,
                    payload_bytes: progress.transmitted_payload_bytes,
                    wire_bytes: progress.transmitted_session_wire_bytes,
                    interval_us,
                })
                .context("record loadtest transmit aggregate")?;
        }
        if progress.received_payload_bytes != 0 || progress.received_session_wire_bytes != 0 {
            self.recorder
                .push(EventKind::Transfer {
                    path_ref: 0,
                    direction: Direction::Receive,
                    payload_bytes: progress.received_payload_bytes,
                    wire_bytes: progress.received_session_wire_bytes,
                    interval_us,
                })
                .context("record loadtest receive aggregate")?;
        }
        if progress.stall_detected {
            let threshold_us = duration_us(LOADTEST_STALL)?;
            self.recorder
                .push(EventKind::Stall {
                    path_ref: 0,
                    direction: Direction::Receive,
                    state: StallState::Detected,
                    gap_us: threshold_us,
                    threshold_us,
                    progress_bytes: progress.received_payload_bytes,
                })
                .context("record loadtest stall")?;
        }
        self.recorder
            .push(EventKind::Close {
                outcome: close_outcome,
                transmitted_payload_bytes: progress.transmitted_payload_bytes,
                received_payload_bytes: progress.received_payload_bytes,
            })
            .context("record terminal loadtest event")?;

        let run = self
            .recorder
            .finish()
            .context("finalize loadtest measurement")?;
        let output_path = self.reservation.final_path().to_path_buf();
        self.reservation.publish(&run)?;
        info!(path = %output_path.display(), "loadtest measurement trace written");
        Ok(())
    }
}

/// Same-directory private temporary file created before measurement traffic.
///
/// Publication is a hard-link operation: unlike `rename`, it fails atomically
/// if the final path appeared after preflight, so a completed trace can never
/// clobber another run. The source file is fully synced before linking and the
/// directory is synced after link/unlink on Unix. A crash can leave an orphaned
/// hidden temp, but never a partial final JSON file.
#[derive(Debug)]
struct MeasurementReservation {
    final_path: PathBuf,
    temp_path: PathBuf,
    file: Option<File>,
}

impl MeasurementReservation {
    fn reserve(final_path: PathBuf) -> Result<Self> {
        let parent = normalized_parent(&final_path);
        let parent_metadata = std::fs::metadata(parent)
            .with_context(|| format!("inspect measurement directory {}", parent.display()))?;
        if !parent_metadata.is_dir() {
            anyhow::bail!(
                "measurement output parent is not a directory: {}",
                parent.display()
            );
        }
        match std::fs::symlink_metadata(&final_path) {
            Ok(_) => anyhow::bail!(
                "measurement output already exists; refusing to overwrite {}",
                final_path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("preflight measurement output {}", final_path.display())
                })
            }
        }

        let file_name = final_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("measurement output must name a file"))?;
        for _ in 0..MEASUREMENT_TEMP_CREATE_ATTEMPTS {
            let temp_name = format!(
                ".{}.shadowpipe-{}.tmp",
                file_name.to_string_lossy(),
                random_public_id()
            );
            let temp_path = parent.join(temp_name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&temp_path) {
                Ok(file) => {
                    // Exercise the exact atomic publication primitive now,
                    // before any socket. This rejects filesystems/directories
                    // that cannot hard-link or durably sync instead of finding
                    // out only after the network observation has completed.
                    let probe_path =
                        parent.join(format!(".shadowpipe-link-probe-{}", random_public_id()));
                    let preflight = (|| -> Result<()> {
                        std::fs::hard_link(&temp_path, &probe_path).with_context(|| {
                            format!(
                                "preflight atomic measurement publication in {}",
                                parent.display()
                            )
                        })?;
                        std::fs::remove_file(&probe_path).with_context(|| {
                            format!(
                                "remove measurement publication probe {}",
                                probe_path.display()
                            )
                        })?;
                        sync_parent_directory(&temp_path)
                    })();
                    if let Err(error) = preflight {
                        drop(file);
                        let _ = std::fs::remove_file(&probe_path);
                        let _ = std::fs::remove_file(&temp_path);
                        return Err(error);
                    }
                    return Ok(Self {
                        final_path,
                        temp_path,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("reserve measurement temp in {}", parent.display())
                    })
                }
            }
        }
        anyhow::bail!(
            "could not reserve a unique measurement temp after {MEASUREMENT_TEMP_CREATE_ATTEMPTS} attempts"
        )
    }

    fn final_path(&self) -> &Path {
        &self.final_path
    }

    fn publish(mut self, run: &shadowpipe_core::measurement::MeasurementRun) -> Result<()> {
        let mut encoded = serde_json::to_vec_pretty(run).context("serialize measurement trace")?;
        encoded.push(b'\n');

        let mut file = self
            .file
            .take()
            .context("measurement reservation lost its temporary file")?;
        file.write_all(&encoded)
            .with_context(|| format!("write measurement temp {}", self.temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync measurement temp {}", self.temp_path.display()))?;
        drop(file);

        std::fs::hard_link(&self.temp_path, &self.final_path).with_context(|| {
            format!(
                "atomically publish measurement {} without overwrite",
                self.final_path.display()
            )
        })?;
        sync_parent_directory(&self.final_path)?;
        std::fs::remove_file(&self.temp_path).with_context(|| {
            format!(
                "remove published measurement temp {}",
                self.temp_path.display()
            )
        })?;
        sync_parent_directory(&self.final_path)?;
        Ok(())
    }
}

impl Drop for MeasurementReservation {
    fn drop(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

fn normalized_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = normalized_parent(path);
    File::open(parent)
        .with_context(|| format!("open measurement directory {} for fsync", parent.display()))?
        .sync_all()
        .with_context(|| format!("fsync measurement directory {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    // Rust's portable std API cannot open a directory for fsync on Windows.
    // The data file itself is still sync_all'd and hard-link publication remains
    // no-clobber; callers needing power-loss directory durability must run on a
    // platform where directory fsync is available.
    Ok(())
}

fn random_public_id() -> PublicId {
    loop {
        let mut bytes = [0_u8; PublicId::BYTE_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(id) = PublicId::from_bytes(bytes) {
            return id;
        }
    }
}

fn unix_time_ms() -> Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("Unix time milliseconds exceed u64")
}

fn duration_us(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_micros()).context("measurement duration exceeds u64 microseconds")
}

/// Pump `mb` MiB through an authenticated AuthenticatedSession while concurrently
/// draining echoes. The optional recorder already covers the complete outer +
/// inner establishment; this function adds transfer/stall/terminal events.
async fn run_loadtest_established<S>(
    stream: S,
    session: AuthenticatedSession,
    session_id: [u8; 8],
    mb: u64,
    measurement: Option<LoadtestMeasurement>,
    dial_duration: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake_ms = dial_duration.as_millis();
    info!(
        session_id = hex::encode(session_id),
        handshake_ms, mb, "handshake ok — starting loadtest"
    );

    let total: u64 = mb.max(1).saturating_mul(1024 * 1024);
    let (mut tx, mut rx) = session.split();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let xfer_start = Instant::now();
    // Keep the existing loadtest's hot path unchanged unless instrumentation
    // was explicitly requested. The optional branch is the only per-frame cost
    // when recording is disabled.
    let progress = measurement
        .as_ref()
        .map(|_| Arc::new(LoadtestProgress::default()));

    // Uplink: pump `total` bytes as DATA frames as fast as the carrier accepts
    // them. Under a silent stall the socket's send buffer can fill and block on
    // backpressure — the overall timeout below bounds the observation.
    let sender_progress = progress.as_ref().map(Arc::clone);
    let sender = async move {
        let payload = vec![0xABu8; LOADTEST_CHUNK];
        let mut sent = 0u64;
        while sent < total {
            let n = ((total - sent) as usize).min(LOADTEST_CHUNK);
            let wire = tx.send(&mut wr, 0, FrameFlags::DATA, &payload[..n]).await?;
            if let Some(progress) = &sender_progress {
                progress.add_transmit(n as u64, wire)?;
            }
            sent += n as u64;
        }
        tx.send(&mut wr, 0, FrameFlags::FIN, b"done").await?;
        Ok::<u64, anyhow::Error>(sent)
    };

    // Downlink: drain echoes, log progress (first tick at 64 KB to expose an
    // early stall), and treat an 8 s gap as a candidate stall.
    let receiver_progress = progress.as_ref().map(Arc::clone);
    let receiver = async move {
        let mut got = 0u64;
        let mut next_log = 64 * 1024u64;
        loop {
            match tokio::time::timeout(LOADTEST_STALL, rx.recv(&mut rd)).await {
                Ok(Ok((_, flags, payload, wire))) => {
                    if flags.contains(FrameFlags::FIN) {
                        break;
                    }
                    if let Some(progress) = &receiver_progress {
                        progress.add_receive(payload.len() as u64, wire)?;
                    }
                    got = got.saturating_add(payload.len() as u64);
                    if got >= next_log {
                        info!(echoed_kb = got / 1024, "loadtest: downlink progress");
                        next_log = got + 1024 * 1024;
                    }
                    if got >= total {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    if let Some(progress) = &receiver_progress {
                        progress.stall_detected.store(true, Ordering::Relaxed);
                    }
                    warn!(
                        echoed_kb = got / 1024,
                        "loadtest STALL: no echo for >8s (candidate event; attribution pending)"
                    );
                    return Ok::<(u64, bool), anyhow::Error>((got, true));
                }
            }
        }
        Ok((got, false))
    };

    let overall = Duration::from_secs(mb.max(1).saturating_mul(2).max(60));
    let joined = tokio::time::timeout(overall, async { tokio::join!(sender, receiver) }).await;
    let transfer_duration = xfer_start.elapsed();
    let elapsed = transfer_duration.as_secs_f64();
    let snapshot = progress
        .as_ref()
        .map(|progress| progress.snapshot())
        .transpose()?;

    let (close_outcome, deferred_error) = match joined {
        Ok((send_res, recv_res)) => {
            let (sent, send_error) = match send_res {
                Ok(sent) => (sent, None),
                Err(error) => {
                    warn!(%error, "loadtest sender failed");
                    (
                        snapshot
                            .map(|progress| progress.transmitted_payload_bytes)
                            .unwrap_or(0),
                        Some(error),
                    )
                }
            };
            match recv_res {
                Ok((got, stalled)) => {
                    let mbps = (got as f64 / 1_048_576.0) / elapsed.max(1e-3);
                    if stalled {
                        warn!(
                            handshake_ms,
                            sent_kb = sent / 1024,
                            echoed_kb = got / 1024,
                            elapsed_s = format!("{elapsed:.1}"),
                            "LOADTEST: STALLED — echoed {} KB before receive progress stopped",
                            got / 1024
                        );
                        (CloseOutcome::TimedOut, send_error)
                    } else if send_error.is_some() {
                        warn!(
                            handshake_ms,
                            sent_kb = sent / 1024,
                            echoed_kb = got / 1024,
                            "LOADTEST: INCOMPLETE — sender failed"
                        );
                        (CloseOutcome::TransportError, send_error)
                    } else if sent < total || got < total {
                        warn!(
                            handshake_ms,
                            sent_kb = sent / 1024,
                            echoed_kb = got / 1024,
                            expected_kb = total / 1024,
                            "LOADTEST: INCOMPLETE — peer closed before the representative workload"
                        );
                        (CloseOutcome::PeerClosed, None)
                    } else {
                        info!(
                            handshake_ms,
                            sent_kb = sent / 1024,
                            echoed_kb = got / 1024,
                            throughput_mbps = format!("{mbps:.2}"),
                            elapsed_s = format!("{elapsed:.1}"),
                            "LOADTEST: OK — {} MB round-tripped clean",
                            got / (1024 * 1024)
                        );
                        (CloseOutcome::Clean, None)
                    }
                }
                Err(error) => (CloseOutcome::TransportError, Some(error)),
            }
        }
        Err(_) => {
            warn!(
                elapsed_s = format!("{elapsed:.1}"),
                "LOADTEST: overall timeout — connection hung (cause not attributed)"
            );
            (CloseOutcome::TimedOut, None)
        }
    };

    if let Some(trace) = measurement {
        trace.finish(
            snapshot.expect("measurement sink has progress counters"),
            transfer_duration,
            close_outcome,
        )?;
    }
    if let Some(error) = deferred_error {
        return Err(error);
    }
    Ok(())
}

/// Echo / interactive-stdin client over an already authenticated transport
/// (plain carrier or TLS SslStream — generic so both share one body).
async fn run_echo_established<S>(
    mut stream: S,
    mut session: AuthenticatedSession,
    session_id: [u8; 8],
    message: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    info!(session_id = hex::encode(session_id), "handshake ok");

    if let Some(message) = message {
        session
            .send(&mut stream, 0, FrameFlags::DATA, message.as_bytes())
            .await?;
        let (_, flags, reply, _) = session.recv(&mut stream).await?;
        println!("echo: {} ({:?})", String::from_utf8_lossy(&reply), flags);
        session
            .send(&mut stream, 0, FrameFlags::FIN, b"bye")
            .await?;
        stream.shutdown().await?;
        return Ok(());
    }

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    info!("type a line to echo, Ctrl-D to quit");
    while let Some(line) = lines.next_line().await? {
        session
            .send(&mut stream, 0, FrameFlags::DATA, line.as_bytes())
            .await?;
        let (_, flags, reply, _) = session.recv(&mut stream).await?;
        println!("{} ({:?})", String::from_utf8_lossy(&reply), flags);
    }

    session
        .send(&mut stream, 0, FrameFlags::FIN, b"bye")
        .await?;
    stream.shutdown().await?;
    Ok(())
}

/// Quick reconnect after a volume-guard rotation (a new 5-tuple, not a failure).
const ROTATE_DELAY: Duration = Duration::from_millis(50);
/// A session that lasted at least this long counts as "healthy": its drop
/// reconnects fast instead of climbing the backoff curve.
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// Signal listeners are installed before opening a TUN or mutating host state.
/// A normal service stop can therefore cancel the active carrier future and
/// return through `run_tunnel_mode`, letting every route/firewall/DNS guard run
/// its deterministic teardown instead of relying on process-exit semantics.
#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn install() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("install SIGINT handler")?,
            terminate: signal(SignalKind::terminate()).context("install SIGTERM handler")?,
        })
    }

    async fn recv(&mut self) -> Result<&'static str> {
        tokio::select! {
            value = self.interrupt.recv() => {
                value.ok_or_else(|| anyhow::anyhow!("SIGINT stream closed"))?;
                Ok("SIGINT")
            }
            value = self.terminate.recv() => {
                value.ok_or_else(|| anyhow::anyhow!("SIGTERM stream closed"))?;
                Ok("SIGTERM")
            }
        }
    }
}

/// Owns the full-tunnel host guards from the instant the firewall is armed and
/// overrides Rust's ordinary
/// reverse-local-binding destruction order. Teardown must keep the firewall
/// closed while removing split-default and endpoint-bypass routes and restoring
/// DNS, then release the kill-switch last. Partial setup errors use the same
/// order because each successful mutation is moved here immediately.
struct JournaledRouteGuard {
    guard: RouteGuard,
    resource: OwnedResource,
}

struct FullTunnelGuards {
    routes: Option<Vec<JournaledRouteGuard>>,
    bypass_routes: Option<BTreeMap<Ipv4Addr, JournaledRouteGuard>>,
    underlay_paths: BTreeMap<Ipv4Addr, LinuxUnderlayPath>,
    ssh_bypass: Option<JournaledRouteGuard>,
    legacy_dns: Option<DnsGuard>,
    #[cfg(target_os = "linux")]
    dns_exchange: Option<ActiveDnsExchange>,
    tun_resource: Option<TunResource>,
    tun_remove_operation: Option<u32>,
    kill_switch: Option<KillSwitch>,
    journal: DurableHostJournal,
    session_id: SessionId,
    route_owner: LinuxRouteOwner,
    host_state_ambiguous: bool,
    shutdown_complete: bool,
}

impl FullTunnelGuards {
    fn armed(
        kill_switch: KillSwitch,
        underlay_paths: BTreeMap<Ipv4Addr, LinuxUnderlayPath>,
        journal: DurableHostJournal,
        tun_resource: TunResource,
        firewall_operations: &[u32],
    ) -> Result<Self> {
        let session_id = journal.journal().owner.session_id;
        anyhow::ensure!(
            kill_switch.identity().session_id() == session_id,
            "kill-switch and host journal session identities differ"
        );
        let mut guards = Self {
            routes: None,
            bypass_routes: Some(BTreeMap::new()),
            underlay_paths,
            ssh_bypass: None,
            legacy_dns: None,
            #[cfg(target_os = "linux")]
            dns_exchange: None,
            tun_resource: Some(tun_resource),
            tun_remove_operation: None,
            kill_switch: Some(kill_switch),
            journal,
            session_id,
            route_owner: LinuxRouteOwner::for_session(session_id),
            host_state_ambiguous: true,
            shutdown_complete: false,
        };
        for operation in firewall_operations {
            guards
                .journal
                .acknowledge_add(*operation)
                .context("acknowledge installed kill-switch resource")?;
        }
        guards
            .journal
            .publish_active()
            .context("publish installed kill-switch checkpoint")?;
        guards.host_state_ambiguous = false;
        Ok(guards)
    }

    fn set_ssh_bypass(&mut self, route: JournaledRouteGuard) {
        debug_assert!(self.ssh_bypass.is_none());
        self.ssh_bypass = Some(route);
    }

    fn insert_bypass(&mut self, ip: Ipv4Addr, route: JournaledRouteGuard) -> Result<()> {
        let routes = self
            .bypass_routes
            .as_mut()
            .expect("bypass route owner exists until teardown");
        anyhow::ensure!(
            !routes.contains_key(&ip),
            "duplicate owned bypass route for {ip}"
        );
        routes.insert(ip, route);
        Ok(())
    }

    fn set_routes(&mut self, routes: Vec<JournaledRouteGuard>) {
        debug_assert!(self.routes.is_none());
        self.routes = Some(routes);
    }

    fn journaled_add_route(&mut self, spec: &LinuxOwnedRouteSpec) -> Result<JournaledRouteGuard> {
        let route_resource = spec
            .journal_resource()
            .context("capture exact Linux route journal resource")?;
        let resource = OwnedResource::Route(route_resource.clone());
        let operation = self
            .journal
            .begin_add(resource.clone())
            .context("WAL planned owned route before add")?;
        self.host_state_ambiguous = true;
        let guard = RouteGuard::install_linux_owned_journaled(spec, &route_resource)
            .context("install exact WAL-bound owned route")?;
        self.journal
            .acknowledge_add(operation)
            .context("acknowledge exact owned route add")?;
        self.journal
            .publish_active()
            .context("publish exact owned route checkpoint")?;
        self.host_state_ambiguous = false;
        Ok(JournaledRouteGuard { guard, resource })
    }

    #[cfg(target_os = "linux")]
    fn apply_dns_exchange(
        &mut self,
        preflight: RuntimeDnsPreflight,
        servers: &[Ipv4Addr],
    ) -> Result<()> {
        anyhow::ensure!(
            self.dns_exchange.is_none(),
            "DNS exchange is already active"
        );
        let contents = resolv_conf(servers);
        let prepared = PreparedDnsExchange::stage_preflighted(preflight, contents.as_bytes())
            .map_err(anyhow::Error::new)
            .context("stage preflighted crash-recoverable resolver object")?;
        let resource = OwnedResource::Dns(prepared.resource().clone());
        let operation = self
            .journal
            .begin_add(resource)
            .context("WAL planned DNS exchange before link or rename")?;
        self.host_state_ambiguous = true;
        let linked = prepared
            .link_after_journal()
            .context("link journaled resolver stage")?;
        let active = linked
            .activate_after_journal()
            .context("atomically activate journaled resolver exchange")?;
        self.journal
            .acknowledge_add(operation)
            .context("acknowledge active resolver exchange")?;
        self.journal
            .publish_active()
            .context("publish active resolver checkpoint")?;
        self.dns_exchange = Some(active);
        self.host_state_ambiguous = false;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn apply_dns_exchange(
        &mut self,
        _preflight: RuntimeDnsPreflight,
        _servers: &[Ipv4Addr],
    ) -> Result<()> {
        anyhow::bail!("crash-recoverable resolver exchange is Linux-only")
    }

    /// The only normal-start authorization edge for deleting the independent
    /// restart barrier. Re-read the anchored main WAL and require the complete
    /// full-tunnel object graph to be durably Active before invoking the typed
    /// replacement release API.
    #[cfg(target_os = "linux")]
    fn release_restart_lockdown_after_verified_activation(
        &self,
        barrier: &mut LockdownBarrier,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.shutdown_complete && !self.host_state_ambiguous,
            "full-tunnel activation is incomplete or ambiguous"
        );
        anyhow::ensure!(
            self.kill_switch.is_some(),
            "replacement kill-switch is absent"
        );
        anyhow::ensure!(self.tun_resource.is_some(), "replacement TUN is absent");
        anyhow::ensure!(
            self.tun_remove_operation.is_none(),
            "replacement TUN already has removal intent"
        );
        anyhow::ensure!(
            self.routes.as_ref().is_some_and(|routes| routes.len() == 2),
            "replacement split-default route pair is incomplete"
        );
        anyhow::ensure!(
            self.bypass_routes
                .as_ref()
                .is_some_and(|routes| !routes.is_empty()),
            "replacement carrier bypass routes are incomplete"
        );
        anyhow::ensure!(
            self.dns_exchange.is_some(),
            "replacement DNS exchange is absent"
        );

        let memory = self.journal.journal();
        anyhow::ensure!(
            memory.phase == JournalPhase::Active,
            "replacement main WAL is not Active"
        );
        anyhow::ensure!(
            !memory.operations.is_empty()
                && memory
                    .operations
                    .iter()
                    .all(|operation| operation.state == OperationState::Applied),
            "replacement main WAL contains a non-Applied operation"
        );
        for (label, present) in [
            (
                "TUN",
                memory
                    .operations
                    .iter()
                    .any(|operation| matches!(&operation.resource, OwnedResource::Tun(_))),
            ),
            (
                "route",
                memory
                    .operations
                    .iter()
                    .any(|operation| matches!(&operation.resource, OwnedResource::Route(_))),
            ),
            (
                "DNS",
                memory
                    .operations
                    .iter()
                    .any(|operation| matches!(&operation.resource, OwnedResource::Dns(_))),
            ),
            (
                "firewall",
                memory
                    .operations
                    .iter()
                    .any(|operation| matches!(&operation.resource, OwnedResource::Firewall(_))),
            ),
            (
                "firewall endpoint",
                memory.operations.iter().any(|operation| {
                    matches!(&operation.resource, OwnedResource::FirewallEndpoint(_))
                }),
            ),
        ] {
            anyhow::ensure!(
                present,
                "replacement main WAL lacks an Applied {label} resource"
            );
        }
        let disk = self
            .journal
            .store()
            .load()
            .context("re-read durable replacement main WAL before barrier release")?;
        anyhow::ensure!(
            &disk == memory,
            "replacement main WAL differs between memory and anchored disk"
        );
        barrier
            .release_after_full_tunnel_active()
            .context("release restart barrier after strict durable Active proof")
    }

    #[cfg(not(target_os = "linux"))]
    fn release_restart_lockdown_after_verified_activation(
        &self,
        barrier: &mut LockdownBarrier,
    ) -> Result<()> {
        let _ = (self, barrier);
        anyhow::bail!("restart-lockdown handoff is Linux-only")
    }

    /// Remove every resource ranked ahead of the TUN, then durably record the
    /// TUN removal intent. The actual interface lifetime is owned by
    /// `SharedTun`; this method deliberately never deletes an interface by
    /// name while its exact file descriptor may still be live.
    fn prepare_tun_close(&mut self) -> Result<()> {
        if self.shutdown_complete {
            return Ok(());
        }
        anyhow::ensure!(
            !self.host_state_ambiguous,
            "host WAL has an ambiguous Preparing transition; recovery must inspect it before firewall release"
        );

        if let Some(routes) = self.routes.as_mut() {
            for route in routes.iter_mut() {
                journaled_route_remove(&mut self.journal, &mut self.host_state_ambiguous, route)
                    .context("remove split-default route before releasing firewall")?;
            }
            drop(self.routes.take());
        }

        // Restore the original resolver while the endpoint bypasses and the
        // fail-closed firewall still exist. This matches durable recovery rank.
        #[cfg(target_os = "linux")]
        if let Some(dns) = self.dns_exchange.as_mut() {
            let resource = OwnedResource::Dns(dns.resource().clone());
            let operation = self
                .journal
                .begin_remove(&resource)
                .context("WAL DNS exchange removal intent")?;
            self.host_state_ambiguous = true;
            dns.restore_after_journal()
                .context("restore exact resolver exchange")?;
            self.journal
                .acknowledge_remove(operation)
                .context("acknowledge resolver restoration")?;
            self.journal
                .publish_active()
                .context("publish restored resolver checkpoint")?;
            self.host_state_ambiguous = false;
            drop(self.dns_exchange.take());
        }

        if let Some(dns) = self.legacy_dns.as_mut() {
            dns.try_restore()
                .context("restore legacy DNS before releasing firewall")?;
            drop(self.legacy_dns.take());
        }

        if let Some(routes) = self.bypass_routes.as_mut() {
            let mut failures = Vec::new();
            for (ip, route) in routes.iter_mut() {
                if let Err(error) =
                    journaled_route_remove(&mut self.journal, &mut self.host_state_ambiguous, route)
                {
                    failures.push(format!("{ip}: {error:#}"));
                }
            }
            if !failures.is_empty() {
                anyhow::bail!(
                    "remove endpoint bypass routes before releasing firewall: {}",
                    failures.join("; ")
                );
            }
            drop(self.bypass_routes.take());
        }

        if let Some(ssh) = self.ssh_bypass.as_mut() {
            journaled_route_remove(&mut self.journal, &mut self.host_state_ambiguous, ssh)
                .context("remove SSH control bypass before releasing firewall")?;
            drop(self.ssh_bypass.take());
        }

        if let Some(tun) = self.tun_resource.as_ref() {
            anyhow::ensure!(
                self.tun_remove_operation.is_none(),
                "TUN close was already prepared but not yet verified"
            );
            let resource = OwnedResource::Tun(tun.clone());
            let operation = self
                .journal
                .begin_remove(&resource)
                .context("WAL TUN removal intent")?;
            self.host_state_ambiguous = true;
            self.tun_remove_operation = Some(operation);
        }
        Ok(())
    }

    /// Continue teardown only after the caller has dropped the last
    /// `SharedTun` owner. A still-present exact TUN is treated as evidence of a
    /// leaked descriptor; a changed name/index/alias is a conflict. In either
    /// case the firewall is retained and the journal remains recoverable.
    fn finish_after_tun_close(&mut self) -> Result<()> {
        if self.shutdown_complete {
            return Ok(());
        }
        let tun = self
            .tun_resource
            .as_ref()
            .context("TUN close verification has no journaled TUN resource")?;
        let operation = self
            .tun_remove_operation
            .context("TUN close verification was not durably prepared")?;
        match inspect_tun(tun, self.session_id).context("inspect TUN after descriptor close")? {
            shadowpipe_core::host_state::ResourceObservationKind::Absent => {}
            shadowpipe_core::host_state::ResourceObservationKind::ExactOwnedPresent => {
                anyhow::bail!(
                    "journaled TUN remains present after descriptor close; another SharedTun clone is still live"
                )
            }
            shadowpipe_core::host_state::ResourceObservationKind::Conflict => {
                self.journal
                    .mark_conflict()
                    .context("durably mark post-close TUN identity conflict")?;
                anyhow::bail!("TUN identity changed while closing; refusing firewall release")
            }
        }
        self.journal
            .acknowledge_remove(operation)
            .context("acknowledge descriptor-driven TUN removal")?;
        self.journal
            .publish_active()
            .context("publish removed TUN checkpoint")?;
        self.host_state_ambiguous = false;
        self.tun_remove_operation = None;
        drop(self.tun_resource.take());

        anyhow::ensure!(
            self.routes.is_none()
                && self.bypass_routes.is_none()
                && self.ssh_bypass.is_none()
                && self.legacy_dns.is_none()
                && {
                    #[cfg(target_os = "linux")]
                    {
                        self.dns_exchange.is_none()
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        true
                    }
                },
            "resource ranked ahead of the TUN survived close preparation"
        );

        if let Some(kill_switch) = self.kill_switch.as_mut() {
            let mut resources: Vec<OwnedResource> = kill_switch
                .journal_endpoint_resources()
                .into_iter()
                .map(OwnedResource::FirewallEndpoint)
                .collect();
            resources.extend(
                kill_switch
                    .journal_resources()
                    .into_iter()
                    .map(OwnedResource::Firewall),
            );
            let mut operations = Vec::with_capacity(resources.len());
            for resource in &resources {
                operations.push(
                    self.journal
                        .begin_remove(resource)
                        .context("WAL kill-switch removal intent")?,
                );
            }
            self.host_state_ambiguous = true;
            kill_switch
                .shutdown()
                .context("remove exact owned kill-switch state")?;
            for operation in operations {
                self.journal
                    .acknowledge_remove(operation)
                    .context("acknowledge removed kill-switch resource")?;
            }
            self.journal
                .publish_active()
                .context("publish removed kill-switch checkpoint")?;
            self.host_state_ambiguous = false;
            drop(self.kill_switch.take());
        }

        self.journal
            .begin_cleaning()
            .context("publish final host-state Cleaning checkpoint")?;
        self.journal
            .remove_completed_file()
            .context("remove fully cleaned host-state journal")?;
        self.shutdown_complete = true;
        Ok(())
    }

    fn close_after_sessions(&mut self, tun: SharedTun) -> Result<()> {
        self.prepare_tun_close()?;
        // The non-persistent Linux TUN is destroyed by closing its exact owned
        // descriptor, eliminating the name-reuse race of `ip link delete dev`.
        drop(tun);
        self.finish_after_tun_close()
    }

    /// A failed prerequisite must leave the firewall in the kernel. Forgetting
    /// this userspace guard is intentional: the exact random chain names and
    /// owner comments remain inspectable, while the journal-aware production
    /// path records the same identity before engagement.
    fn preserve_firewall(&mut self) {
        if let Some(kill_switch) = self.kill_switch.take() {
            std::mem::forget(kill_switch);
        }
    }

    /// Persist an operator-visible fail-closed terminal state. `Conflict` is
    /// intentionally used as the existing non-auto-recoverable journal phase:
    /// the next process must refuse startup recovery instead of removing the
    /// firewall before a replacement signed authority is accepted.
    fn seal_fail_closed(&mut self, reason: &'static str) -> Result<()> {
        anyhow::ensure!(
            !self.shutdown_complete,
            "cannot seal host state after completed shutdown"
        );
        // Preserve the kernel firewall even if the durable phase write fails.
        self.preserve_firewall();
        self.journal
            .mark_conflict()
            .with_context(|| format!("seal fail-closed host journal after {reason}"))?;
        warn!(reason, "host firewall and journal sealed fail-closed");
        Ok(())
    }
}

fn journaled_route_remove(
    journal: &mut DurableHostJournal,
    ambiguous: &mut bool,
    route: &mut JournaledRouteGuard,
) -> Result<()> {
    let operation = journal
        .begin_remove(&route.resource)
        .context("WAL owned route removal intent")?;
    *ambiguous = true;
    route
        .guard
        .try_remove()
        .context("remove exact owned route")?;
    journal
        .acknowledge_remove(operation)
        .context("acknowledge exact owned route removal")?;
    journal
        .publish_active()
        .context("publish removed owned route checkpoint")?;
    *ambiguous = false;
    Ok(())
}

fn allowed_endpoint(tuple: CarrierTuple) -> AllowedEndpoint {
    AllowedEndpoint {
        address: tuple.address,
        protocol: match tuple.protocol {
            LiveCarrierProtocol::Tcp => EndpointProtocol::Tcp,
            LiveCarrierProtocol::Udp => EndpointProtocol::Udp,
        },
    }
}

impl EndpointHostAdapter for FullTunnelGuards {
    type Error = anyhow::Error;

    fn firewall_allow(&mut self, tuple: CarrierTuple) -> Result<OwnedMutation> {
        let endpoint = allowed_endpoint(tuple);
        let identity = self
            .kill_switch
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("kill-switch is not active"))?
            .identity();
        if !self
            .kill_switch
            .as_ref()
            .expect("checked active kill-switch")
            .can_allow_endpoint(endpoint)
            .context("preflight dynamic firewall endpoint before WAL")?
        {
            return Ok(OwnedMutation::AlreadyExact);
        }
        let resource =
            OwnedResource::FirewallEndpoint(identity.endpoint_journal_resource(endpoint));
        let operation = self
            .journal
            .begin_add(resource)
            .context("WAL dynamic firewall allow before mutation")?;
        self.host_state_ambiguous = true;
        anyhow::ensure!(
            self.kill_switch
                .as_mut()
                .expect("checked active kill-switch")
                .allow_endpoint(endpoint)?,
            "dynamic firewall endpoint became exact without this transaction"
        );
        self.journal
            .acknowledge_add(operation)
            .context("acknowledge dynamic firewall allow")?;
        self.journal
            .publish_active()
            .context("publish dynamic firewall allow checkpoint")?;
        self.host_state_ambiguous = false;
        Ok(OwnedMutation::Changed)
    }

    fn firewall_deny(&mut self, tuple: CarrierTuple) -> Result<OwnedMutation> {
        let endpoint = allowed_endpoint(tuple);
        let identity = self
            .kill_switch
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("kill-switch is not active"))?
            .identity();
        if !self
            .kill_switch
            .as_ref()
            .expect("checked active kill-switch")
            .allows_endpoint(endpoint)
        {
            return Ok(OwnedMutation::AlreadyExact);
        }
        let resource =
            OwnedResource::FirewallEndpoint(identity.endpoint_journal_resource(endpoint));
        let operation = self
            .journal
            .begin_remove(&resource)
            .context("WAL dynamic firewall deny before mutation")?;
        self.host_state_ambiguous = true;
        anyhow::ensure!(
            self.kill_switch
                .as_mut()
                .expect("checked active kill-switch")
                .deny_endpoint(endpoint)?,
            "dynamic firewall endpoint disappeared outside this transaction"
        );
        self.journal
            .acknowledge_remove(operation)
            .context("acknowledge dynamic firewall deny")?;
        self.journal
            .publish_active()
            .context("publish dynamic firewall deny checkpoint")?;
        self.host_state_ambiguous = false;
        Ok(OwnedMutation::Changed)
    }

    fn route_add_bypass(&mut self, ip: Ipv4Addr) -> Result<OwnedMutation> {
        let routes = self
            .bypass_routes
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bypass-route owner is unavailable"))?;
        if routes.contains_key(&ip) {
            return Ok(OwnedMutation::AlreadyExact);
        }
        let underlay = self
            .underlay_paths
            .get(&ip)
            .ok_or_else(|| anyhow::anyhow!("no pre-TUN underlay path authorized for {ip}"))?;
        let spec = underlay
            .owned_bypass_spec(ip, self.route_owner)
            .with_context(|| format!("derive exact dynamic bypass for {ip}"))?;
        let route = self
            .journaled_add_route(&spec)
            .with_context(|| format!("install journaled dynamic bypass for {ip}"))?;
        self.insert_bypass(ip, route)?;
        Ok(OwnedMutation::Changed)
    }

    fn route_remove_bypass(&mut self, ip: Ipv4Addr) -> Result<OwnedMutation> {
        let routes = self
            .bypass_routes
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("bypass-route owner is unavailable"))?;
        let Some(route) = routes.get_mut(&ip) else {
            return Ok(OwnedMutation::AlreadyExact);
        };
        journaled_route_remove(&mut self.journal, &mut self.host_state_ambiguous, route)
            .with_context(|| format!("remove exact dynamic bypass for {ip}"))?;
        drop(routes.remove(&ip));
        Ok(OwnedMutation::Changed)
    }
}

fn transaction_error(context: &str, error: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{context}: {error}")
}

fn rollback_after_model_failure(
    guards: &mut FullTunnelGuards,
    applied: AppliedHostTransaction,
    context: &str,
    model_error: anyhow::Error,
) -> anyhow::Error {
    match EndpointTransitionExecutor::rollback_applied(guards, applied) {
        Ok(()) => model_error.context(format!(
            "{context}; exact host prefix rolled back after model commit failure"
        )),
        Err(rollback_error) => anyhow::anyhow!(
            "{context}: {model_error:#}; exact host rollback also failed: {rollback_error}"
        ),
    }
}

enum ObservationCommit {
    Committed(ObservationResult),
    PolicyExpired,
}

fn commit_observation_transaction(
    policy: &mut VerifiedEndpointPolicy,
    guards: &mut FullTunnelGuards,
    prepared: PreparedObservation,
    accepted: &AcceptedSignedPolicy,
) -> Result<ObservationCommit> {
    let applied = match EndpointTransitionExecutor::stage_observation(guards, prepared.plan()) {
        Ok(applied) => applied,
        Err(error) => {
            let abort_error = policy.coordinator().abort_observation(prepared).err();
            return Err(match abort_error {
                Some(abort_error) => anyhow::anyhow!(
                    "stage endpoint observation host prefix failed: {error}; model abort also failed: {abort_error:#}"
                ),
                None => transaction_error("stage endpoint observation host prefix", error),
            });
        }
    };
    // Host commands are synchronous so cancellation cannot split a command
    // from its WAL acknowledgement. Re-evaluate both clocks after the complete
    // host prefix and immediately before publishing the model snapshot. An
    // authority deadline crossed while blocked in the kernel therefore rolls
    // the exact prefix back and can never publish a newly authorized address.
    if signed_policy_expired(accepted) {
        let abort = policy
            .coordinator()
            .abort_observation(prepared)
            .context("abort prepared observation after authority expiry");
        let rollback = EndpointTransitionExecutor::rollback_applied(guards, applied)
            .map_err(|error| anyhow::anyhow!("rollback expired observation host prefix: {error}"));
        return match (abort, rollback) {
            (Ok(()), Ok(())) => Ok(ObservationCommit::PolicyExpired),
            (abort, rollback) => Err(anyhow::anyhow!(
                "signed policy expired during host transaction; model abort: {}; host rollback: {}",
                abort
                    .err()
                    .map_or_else(|| "ok".to_string(), |error| format!("{error:#}")),
                rollback
                    .err()
                    .map_or_else(|| "ok".to_string(), |error| format!("{error:#}")),
            )),
        };
    }
    match policy.coordinator_mut().commit_observation(prepared) {
        Ok(result) => Ok(ObservationCommit::Committed(result)),
        Err(error) => Err(rollback_after_model_failure(
            guards,
            applied,
            "commit prepared endpoint observation",
            error,
        )),
    }
}

enum AuthorityRehydrationCommit {
    Committed { revived_candidates: usize },
    PolicyExpired,
}

/// Restore the complete signed address authority without consulting an
/// underlay resolver. The coordinator can only derive candidates from its
/// private `VerifiedIpv4Authority`; the host prefix remains
/// firewall-allow -> route-add -> snapshot publish and is compensated exactly
/// if authority expires or model publication fails.
fn commit_authority_rehydration_transaction(
    policy: &mut VerifiedEndpointPolicy,
    guards: &mut FullTunnelGuards,
    accepted: &AcceptedSignedPolicy,
) -> Result<AuthorityRehydrationCommit> {
    let prepared = policy
        .coordinator()
        .prepare_authority_rehydration()
        .context("prepare complete signed-authority rehydration")?;
    let revived_candidates = prepared.revived_candidates().len();
    let applied = match EndpointTransitionExecutor::stage_authority_rehydration(
        guards,
        prepared.plan(),
    ) {
        Ok(applied) => applied,
        Err(error) => {
            let abort_error = policy
                .coordinator()
                .abort_authority_rehydration(prepared)
                .err();
            return Err(match abort_error {
                Some(abort_error) => anyhow::anyhow!(
                    "stage signed-authority rehydration failed: {error}; model abort also failed: {abort_error:#}"
                ),
                None => transaction_error("stage signed-authority rehydration", error),
            });
        }
    };
    if signed_policy_expired(accepted) {
        let abort = policy
            .coordinator()
            .abort_authority_rehydration(prepared)
            .context("abort authority rehydration after signed policy expiry");
        let rollback = EndpointTransitionExecutor::rollback_applied(guards, applied)
            .map_err(|error| anyhow::anyhow!("rollback expired authority rehydration: {error}"));
        return match (abort, rollback) {
            (Ok(()), Ok(())) => Ok(AuthorityRehydrationCommit::PolicyExpired),
            (abort, rollback) => Err(anyhow::anyhow!(
                "signed policy expired during authority rehydration; model abort: {}; host rollback: {}",
                abort
                    .err()
                    .map_or_else(|| "ok".to_string(), |error| format!("{error:#}")),
                rollback
                    .err()
                    .map_or_else(|| "ok".to_string(), |error| format!("{error:#}")),
            )),
        };
    }
    match policy
        .coordinator_mut()
        .commit_authority_rehydration(prepared)
    {
        Ok(result) => {
            anyhow::ensure!(
                result.revived_candidates().len() == revived_candidates,
                "committed authority rehydration changed its prepared candidate count"
            );
            Ok(AuthorityRehydrationCommit::Committed { revived_candidates })
        }
        Err(error) => Err(rollback_after_model_failure(
            guards,
            applied,
            "commit complete signed-authority rehydration",
            error,
        )),
    }
}

fn commit_retirement_transaction(
    policy: &mut VerifiedEndpointPolicy,
    guards: &mut FullTunnelGuards,
    prepared: PreparedRetirement,
) -> Result<()> {
    let applied = match EndpointTransitionExecutor::execute_retirement(guards, prepared.plan()) {
        Ok(applied) => applied,
        Err(error) => {
            let abort_error = policy.coordinator().abort_retirement(prepared).err();
            return Err(match abort_error {
                Some(abort_error) => anyhow::anyhow!(
                    "execute endpoint retirement failed: {error}; model abort also failed: {abort_error:#}"
                ),
                None => transaction_error("execute endpoint retirement", error),
            });
        }
    };
    match policy.coordinator_mut().commit_retirement(prepared) {
        Ok(_) => Ok(()),
        Err(error) => Err(rollback_after_model_failure(
            guards,
            applied,
            "commit endpoint retirement",
            error,
        )),
    }
}

fn cleanup_retired_endpoints(
    policy: &mut VerifiedEndpointPolicy,
    guards: &mut FullTunnelGuards,
) -> Result<()> {
    while let Some(prepared) = policy.coordinator().prepare_retirement()? {
        commit_retirement_transaction(policy, guards, prepared)?;
    }
    Ok(())
}

fn commit_release_transaction(
    policy: &mut VerifiedEndpointPolicy,
    guards: &mut FullTunnelGuards,
    prepared: PreparedLeaseRelease,
) -> Result<()> {
    let applied = match EndpointTransitionExecutor::execute_release(guards, prepared.plan()) {
        Ok(applied) => applied,
        Err(error) => {
            let abort_error = policy.coordinator().abort_release(prepared).err();
            return Err(match abort_error {
                Some(abort_error) => anyhow::anyhow!(
                    "execute endpoint lease release failed: {error}; model abort also failed: {abort_error:#}"
                ),
                None => transaction_error("execute endpoint lease release", error),
            });
        }
    };
    match policy.coordinator_mut().commit_release(prepared) {
        Ok(_) => Ok(()),
        Err(error) => Err(rollback_after_model_failure(
            guards,
            applied,
            "commit endpoint lease release",
            error,
        )),
    }
}

fn release_endpoint_lease(
    policy: &mut VerifiedEndpointPolicy,
    guards: &mut FullTunnelGuards,
    lease: EndpointLease,
) -> Result<()> {
    let prepared = policy.coordinator().prepare_release(lease)?;
    commit_release_transaction(policy, guards, prepared)
}

fn monotonic_millis(origin: Instant) -> u64 {
    origin.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn next_endpoint_refresh(
    policy: &VerifiedEndpointPolicy,
    now_ms: u64,
) -> Result<(LogicalEndpointId, String, Duration)> {
    let mut earliest: Option<(LogicalEndpointId, String, u64)> = None;
    for (logical, hostname) in policy.scheduler_endpoints() {
        let due = policy.coordinator().next_refresh_at_ms(*logical)?;
        if earliest
            .as_ref()
            .is_none_or(|(_, _, earliest_due)| due < *earliest_due)
        {
            earliest = Some((*logical, hostname.clone(), due));
        }
    }
    let (logical, hostname, due) = earliest.context("signed endpoint scheduler is empty")?;
    Ok((
        logical,
        hostname,
        Duration::from_millis(due.saturating_sub(now_ms)),
    ))
}

async fn resolve_endpoint_observation(
    policy: &mut VerifiedEndpointPolicy,
    resolver: SocketAddr,
    dns_config: &EndpointDnsConfig,
    logical: LogicalEndpointId,
    hostname: &str,
    origin: Instant,
) -> Result<PreparedObservation> {
    let stamp = policy.coordinator_mut().begin_query(logical)?;
    let observation = match resolve_a(resolver, hostname, dns_config).await {
        Ok(answer) => ResolutionObservation::from(answer),
        Err(error) => {
            warn!(%error, %hostname, "signed endpoint DNS refresh failed; retaining last-known-good authority subset");
            ResolutionObservation::TransientFailure
        }
    };
    let now_ms = monotonic_millis(origin);
    let entropy = rand::thread_rng().next_u64();
    policy
        .coordinator()
        .prepare_observation(stamp, observation, now_ms, entropy)
        .context("prepare transactional signed endpoint observation")
}

fn select_signed_candidate(
    policy: &VerifiedEndpointPolicy,
    preferred: Option<CandidateKey>,
) -> Result<DialCandidate> {
    let snapshot = policy.coordinator().snapshot();
    let selected = preferred
        .and_then(|key| {
            snapshot
                .candidates
                .iter()
                .find(|candidate| candidate.key == key)
        })
        .or_else(|| snapshot.candidates.first())
        .context("verified signed endpoint snapshot is empty")?;
    Ok(selected.clone())
}

fn next_signed_candidate_preference(
    policy: &VerifiedEndpointPolicy,
    current: CandidateKey,
    action: ReconnectAction,
) -> Option<CandidateKey> {
    let snapshot = policy.coordinator().snapshot();
    let candidates = &snapshot.candidates;
    let current_index = candidates
        .iter()
        .position(|candidate| candidate.key == current);
    match (action, current_index) {
        (ReconnectAction::Backoff | ReconnectAction::RemoteClose, Some(index))
            if candidates.len() > 1 =>
        {
            Some(candidates[(index + 1) % candidates.len()].key)
        }
        (_, Some(index)) => Some(candidates[index].key),
        (_, None) => candidates.first().map(|candidate| candidate.key),
    }
}

#[derive(Debug)]
struct SignedFailureEpoch {
    snapshot_generation: u64,
    attempted_candidates: BTreeSet<CandidateKey>,
    rehydrated: bool,
}

impl SignedFailureEpoch {
    fn new(snapshot_generation: u64) -> Self {
        Self {
            snapshot_generation,
            attempted_candidates: BTreeSet::new(),
            rehydrated: false,
        }
    }

    fn synchronize(&mut self, generation: u64) {
        if self.snapshot_generation != generation {
            self.snapshot_generation = generation;
            self.attempted_candidates.clear();
            self.rehydrated = false;
        }
    }

    /// Record one short-session carrier failure. Returns true exactly once
    /// after every candidate in the current DNS-selected snapshot has failed.
    fn record_failure(
        &mut self,
        generation: u64,
        candidates: &[DialCandidate],
        key: CandidateKey,
    ) -> bool {
        self.synchronize(generation);
        let current: BTreeSet<_> = candidates.iter().map(|candidate| candidate.key).collect();
        if current.contains(&key) {
            self.attempted_candidates.insert(key);
        }
        !current.is_empty()
            && !self.rehydrated
            && current
                .iter()
                .all(|candidate| self.attempted_candidates.contains(candidate))
    }

    fn note_rehydrated(
        &mut self,
        generation: u64,
        candidates: &[DialCandidate],
        failed_key: CandidateKey,
    ) {
        let current: BTreeSet<_> = candidates.iter().map(|candidate| candidate.key).collect();
        self.snapshot_generation = generation;
        self.attempted_candidates
            .retain(|candidate| current.contains(candidate));
        if current.contains(&failed_key) {
            self.attempted_candidates.insert(failed_key);
        }
        self.rehydrated = true;
    }

    fn reset(&mut self, generation: u64) {
        self.snapshot_generation = generation;
        self.attempted_candidates.clear();
        self.rehydrated = false;
    }
}

enum SignedSessionEnd {
    Session(Result<()>),
    Shutdown(Result<&'static str>),
    PolicyExpired,
}

enum SignedSessionEvent {
    Session(Result<()>),
    Refresh(Result<PreparedObservation>),
    Shutdown(Result<&'static str>),
    PolicyExpired,
}

enum SignedBackoffEvent {
    Complete,
    Shutdown(Result<&'static str>),
    PolicyExpired,
}

enum SignedBackoffEnd {
    Complete,
    Shutdown(&'static str),
    PolicyExpired,
}

async fn wait_signed_backoff(
    accepted: &AcceptedSignedPolicy,
    shutdown: &mut ShutdownSignals,
    delay: Duration,
) -> Result<SignedBackoffEnd> {
    let deadline = Instant::now()
        .checked_add(delay)
        .context("signed reconnect backoff deadline overflow")?;
    if signed_policy_expired(accepted) {
        return Ok(SignedBackoffEnd::PolicyExpired);
    }
    // The pinned system resolver is reachable only through the TUN. During a
    // carrier outage, querying it here would deadlock bootstrap and could never
    // expand signed authority anyway. Reconnect backoff is therefore pure
    // waiting; the failure epoch restores candidates locally from the signed
    // manifest, and tunneled DNS resumes immediately after a carrier succeeds.
    let remaining = deadline.saturating_duration_since(Instant::now());
    let event = tokio::select! {
        biased;
        _ = wait_signed_policy_expiry(accepted) => SignedBackoffEvent::PolicyExpired,
        signal = shutdown.recv() => SignedBackoffEvent::Shutdown(signal),
        _ = tokio::time::sleep(remaining) => SignedBackoffEvent::Complete,
    };
    match event {
        SignedBackoffEvent::Complete => Ok(SignedBackoffEnd::Complete),
        SignedBackoffEvent::Shutdown(signal) => Ok(SignedBackoffEnd::Shutdown(signal?)),
        SignedBackoffEvent::PolicyExpired => Ok(SignedBackoffEnd::PolicyExpired),
    }
}

async fn run_signed_endpoint_loop(
    args: &Args,
    carrier: SignedCarrierContext<'_>,
    policy: &mut VerifiedEndpointPolicy,
    guards: &mut FullTunnelGuards,
    accepted: &AcceptedSignedPolicy,
    shutdown: &mut ShutdownSignals,
) -> Result<TunnelTerminalOutcome> {
    let SignedCarrierContext {
        profile,
        tun,
        client_credential,
    } = carrier;
    let resolver = SocketAddr::V4(SocketAddrV4::new(
        args.dns
            .context("signed endpoint runtime requires the pinned tunnel DNS resolver")?,
        53,
    ));
    let dns_config = EndpointDnsConfig::default();
    let origin = Instant::now();
    let backoff = Backoff::new(250, 30_000);
    let mut rotation = 0u32;
    let mut fail_streak = 0u32;
    let mut preferred = None;
    let mut failure_epoch = SignedFailureEpoch::new(policy.coordinator().snapshot().generation);
    let mut jitter_state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0x1234_5678_9ABC_DEF0)
        ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);

    loop {
        if signed_policy_expired(accepted) {
            warn!("signed endpoint policy expired before the next carrier dial");
            return Ok(TunnelTerminalOutcome::PolicyExpired);
        }
        let candidate = select_signed_candidate(policy, preferred)?;
        let target = policy
            .auth_registry()
            .lookup(&candidate)
            .context("authorize signed endpoint candidate before lease acquisition")?;
        let endpoint = RuntimeRealityEndpoint::from_verified_target(&target);
        let address = target.address();
        let lease = policy
            .coordinator_mut()
            .acquire(candidate.key)
            .context("acquire signed endpoint lease before carrier dial")?;
        let session_start = Instant::now();

        let end = {
            let session =
                run_reality_session(args, &endpoint, address, profile, tun, client_credential);
            tokio::pin!(session);
            loop {
                let (logical, hostname, refresh_delay) =
                    next_endpoint_refresh(policy, monotonic_millis(origin))?;
                let event = {
                    let refresh = async {
                        tokio::time::sleep(refresh_delay).await;
                        resolve_endpoint_observation(
                            policy,
                            resolver,
                            &dns_config,
                            logical,
                            &hostname,
                            origin,
                        )
                        .await
                    };
                    tokio::pin!(refresh);
                    tokio::select! {
                        biased;
                        _ = wait_signed_policy_expiry(accepted) => SignedSessionEvent::PolicyExpired,
                        signal = shutdown.recv() => SignedSessionEvent::Shutdown(signal),
                        result = &mut session => SignedSessionEvent::Session(result),
                        result = &mut refresh => SignedSessionEvent::Refresh(result),
                    }
                };
                match event {
                    SignedSessionEvent::Session(result) => {
                        break SignedSessionEnd::Session(result);
                    }
                    SignedSessionEvent::Refresh(result) => {
                        let prepared =
                            result.context("resolve signed endpoint during active carrier")?;
                        if signed_policy_expired(accepted) {
                            policy
                                .coordinator()
                                .abort_observation(prepared)
                                .context("abort active DNS observation after policy expiry")?;
                            break SignedSessionEnd::PolicyExpired;
                        }
                        let observation = match commit_observation_transaction(
                            policy, guards, prepared, accepted,
                        )? {
                            ObservationCommit::Committed(observation) => observation,
                            ObservationCommit::PolicyExpired => {
                                break SignedSessionEnd::PolicyExpired
                            }
                        };
                        let generation = policy.coordinator().snapshot().generation;
                        info!(
                            ?observation.disposition,
                            generation,
                            %hostname,
                            "committed transactional signed endpoint DNS refresh"
                        );
                        cleanup_retired_endpoints(policy, guards)?;
                    }
                    SignedSessionEvent::Shutdown(signal) => {
                        break SignedSessionEnd::Shutdown(signal);
                    }
                    SignedSessionEvent::PolicyExpired => {
                        break SignedSessionEnd::PolicyExpired;
                    }
                }
            }
        };

        // The session future (and therefore its carrier socket) is dropped at
        // the block boundary above.  Only now may a final lease release deny
        // and remove a DNS-depublished tuple.
        release_endpoint_lease(policy, guards, lease)
            .context("release signed endpoint lease after carrier socket drop")?;
        cleanup_retired_endpoints(policy, guards)?;

        let result = match end {
            SignedSessionEnd::Session(result) => result,
            SignedSessionEnd::Shutdown(signal) => {
                let signal = signal?;
                info!(
                    signal,
                    "shutdown requested; restoring signed tunnel host state"
                );
                return Ok(TunnelTerminalOutcome::LocalShutdown(signal));
            }
            SignedSessionEnd::PolicyExpired => {
                warn!(
                    "signed endpoint policy expired; carrier dropped before revoking host authority"
                );
                return Ok(TunnelTerminalOutcome::PolicyExpired);
            }
        };

        let action = classify_run_result(&result);
        let delay = match action {
            ReconnectAction::Rotate => {
                rotation = rotation.saturating_add(1);
                fail_streak = next_fail_streak(ReconnectAction::Rotate, true, fail_streak);
                failure_epoch.reset(policy.coordinator().snapshot().generation);
                preferred = next_signed_candidate_preference(policy, candidate.key, action);
                info!(rotation, "reconnecting signed carrier after volume guard");
                ROTATE_DELAY
            }
            ReconnectAction::Backoff | ReconnectAction::RemoteClose => {
                rotation = rotation.saturating_add(1);
                let session_ok = session_start.elapsed() >= STABLE_AFTER;
                fail_streak = next_fail_streak(action, session_ok, fail_streak);
                if session_ok {
                    failure_epoch.reset(policy.coordinator().snapshot().generation);
                }

                let snapshot = policy.coordinator().snapshot();
                let should_rehydrate = failure_epoch.record_failure(
                    snapshot.generation,
                    &snapshot.candidates,
                    candidate.key,
                );
                drop(snapshot);
                if should_rehydrate {
                    match commit_authority_rehydration_transaction(policy, guards, accepted)? {
                        AuthorityRehydrationCommit::Committed { revived_candidates } => {
                            let snapshot = policy.coordinator().snapshot();
                            failure_epoch.note_rehydrated(
                                snapshot.generation,
                                &snapshot.candidates,
                                candidate.key,
                            );
                            info!(
                                revived_candidates,
                                generation = snapshot.generation,
                                "exhausted DNS-selected carrier subset; transactionally restored complete signed authority"
                            );
                        }
                        AuthorityRehydrationCommit::PolicyExpired => {
                            warn!("signed endpoint policy expired during authority rehydration");
                            return Ok(TunnelTerminalOutcome::PolicyExpired);
                        }
                    }
                }
                preferred = next_signed_candidate_preference(policy, candidate.key, action);
                if preferred != Some(candidate.key) {
                    if let Some(next) = preferred {
                        info!(?next, "rotating to next live signed endpoint candidate");
                    }
                }
                let delay = backoff.delay_jittered(fail_streak, splitmix64(&mut jitter_state));
                match &result {
                    Ok(()) => warn!(
                        fail_streak,
                        rotation,
                        session_ok,
                        ?delay,
                        "authenticated remote FIN; reconnecting without restoring host state"
                    ),
                    Err(error) => warn!(
                        %error,
                        fail_streak,
                        rotation,
                        session_ok,
                        ?delay,
                        "signed carrier ended; reconnecting without underlay DNS during backoff"
                    ),
                }
                delay
            }
        };

        match wait_signed_backoff(accepted, shutdown, delay).await? {
            SignedBackoffEnd::Complete => {}
            SignedBackoffEnd::Shutdown(signal) => {
                info!(signal, "shutdown requested during signed reconnect backoff");
                return Ok(TunnelTerminalOutcome::LocalShutdown(signal));
            }
            SignedBackoffEnd::PolicyExpired => {
                warn!("signed endpoint policy expired during reconnect backoff");
                return Ok(TunnelTerminalOutcome::PolicyExpired);
            }
        }
    }
}

#[cfg(test)]
fn drop_full_tunnel_guards<R, B, S, D, K>(
    routes: &mut Option<R>,
    bypass_routes: &mut Option<B>,
    ssh_bypass: &mut Option<S>,
    dns: &mut Option<D>,
    kill_switch: &mut Option<K>,
) {
    drop(routes.take());
    drop(bypass_routes.take());
    drop(ssh_bypass.take());
    drop(dns.take());
    drop(kill_switch.take());
}

impl Drop for FullTunnelGuards {
    fn drop(&mut self) {
        if self.shutdown_complete {
            return;
        }
        // An unwind, remote stop, task cancellation, or process-level runtime
        // error is not authority to restore direct networking. Only the
        // explicit local-signal path calls `close_after_sessions`. Every other
        // drop seals the existing kernel state and makes startup recovery refuse
        // until an operator resolves the terminal condition.
        self.preserve_firewall();
        match self.journal.mark_conflict() {
            Ok(()) => tracing::warn!(
                "full-tunnel guard dropped without local shutdown; firewall and Conflict journal deliberately retained fail-closed"
            ),
            Err(error) => tracing::error!(
                %error,
                "full-tunnel journal sealing failed; firewall still deliberately retained fail-closed"
            ),
        }
    }
}

fn arm_restart_lockdown_for_teardown(
    args: &Args,
    control_flow: Option<LockdownControlFlow>,
    barrier: &mut Option<LockdownBarrier>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if let Some(existing) = barrier.as_mut() {
            existing
                .arm_for_teardown()
                .context("adopt/re-arm restart lockdown before main teardown")?;
        } else {
            *barrier = Some(
                LockdownBarrier::engage_required(&args.host_state_dir, control_flow)
                    .context("WAL and arm restart lockdown before main teardown")?,
            );
        }
        anyhow::ensure!(
            barrier.as_ref().is_some_and(LockdownBarrier::is_active),
            "restart lockdown is not Active before main teardown"
        );
        info!("durable restart lockdown active before main host-state teardown");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (args, control_flow, barrier);
        anyhow::bail!("restart-lockdown teardown handoff is Linux-only")
    }
}

#[cfg(not(unix))]
struct ShutdownSignals;

#[cfg(not(unix))]
impl ShutdownSignals {
    fn install() -> Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) -> Result<&'static str> {
        tokio::signal::ctrl_c()
            .await
            .context("wait for Ctrl-C shutdown")?;
        Ok("Ctrl-C")
    }
}

/// Reconnect backoff for tunnel mode: exponential (`base * 2^(streak-1)`) capped
/// at `max_ms`, saturating so an extreme streak can never overflow or panic.
#[derive(Clone, Copy)]
struct Backoff {
    base_ms: u64,
    max_ms: u64,
}

impl Backoff {
    const fn new(base_ms: u64, max_ms: u64) -> Self {
        Self { base_ms, max_ms }
    }

    /// Delay before the `streak`-th consecutive retry (streak counts from 1).
    fn delay(&self, streak: u32) -> Duration {
        if streak == 0 {
            return Duration::from_millis(0);
        }
        let shift = (streak - 1).min(32);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let ms = self.base_ms.saturating_mul(factor).min(self.max_ms);
        Duration::from_millis(ms)
    }

    /// `delay`, scaled by a jitter factor in [0.8, 1.2) derived from `r` (a random
    /// u64), so independent clients (and successive retries) don't reconnect in
    /// lockstep — avoids a thundering herd and lockstep with a periodic censor.
    /// Pure in `r` so it stays unit-testable.
    fn delay_jittered(&self, streak: u32, r: u64) -> Duration {
        let base = self.delay(streak).as_millis() as f64;
        let frac = (r >> 11) as f64 / (1u64 << 53) as f64; // [0, 1)
        Duration::from_millis((base * (0.8 + 0.4 * frac)) as u64)
    }
}

/// One SplitMix64 step — a tiny, dependency-free PRNG for reconnect jitter.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// What the reconnect loop should do after a tunnel session ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconnectAction {
    /// Authenticated peer FIN. This is remote input, never authorization to
    /// restore fail-closed host state.
    RemoteClose,
    /// Volume guard fired (data flowed) — reconnect immediately on a new 5-tuple.
    Rotate,
    /// Transient error — reconnect after backoff.
    Backoff,
}

fn classify_run_result(res: &Result<()>) -> ReconnectAction {
    match res {
        Ok(()) => ReconnectAction::RemoteClose,
        Err(e) if e.downcast_ref::<RotateConnection>().is_some() => ReconnectAction::Rotate,
        Err(_) => ReconnectAction::Backoff,
    }
}

/// Next `fail_streak` after a session ends. The streak only climbs while we have
/// no evidence the tunnel works; any progress (a guard rotation, or a session
/// that stayed up past `STABLE_AFTER`) collapses it so we reconnect promptly.
fn next_fail_streak(action: ReconnectAction, session_ok: bool, current: u32) -> u32 {
    match action {
        ReconnectAction::RemoteClose if session_ok => 1,
        ReconnectAction::RemoteClose => current.saturating_add(1),
        ReconnectAction::Rotate => 0,
        ReconnectAction::Backoff if session_ok => 1,
        ReconnectAction::Backoff => current.saturating_add(1),
    }
}

/// Only `LocalShutdown` authorizes deterministic host-state restoration.
/// Every other terminal cause is remote, time-derived, or fatal and must leave
/// the durable firewall journal sealed fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelTerminalOutcome {
    LocalShutdown(&'static str),
    PolicyExpired,
}

impl TunnelTerminalOutcome {
    const fn authorizes_host_restore(self) -> bool {
        matches!(self, Self::LocalShutdown(_))
    }
}

fn split_rules_dir(args: &Args) -> std::path::PathBuf {
    if !args.split_rules_dir.is_empty() {
        return args.split_rules_dir.clone().into();
    }
    std::env::var("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".config/shadowpipe-macos"))
        .unwrap_or_else(|_| ".config/shadowpipe-macos".into())
}

fn split_direct_rules_list(args: &Args) -> Option<std::path::PathBuf> {
    if !args.split_direct_rules_list.is_empty() {
        return Some(args.split_direct_rules_list.clone().into());
    }
    Some(std::path::PathBuf::from("scripts/macos/direct-rules.list"))
}

fn split_preload_list(args: &Args) -> Option<std::path::PathBuf> {
    if !args.split_preload_list.is_empty() {
        return Some(args.split_preload_list.clone().into());
    }
    Some(std::path::PathBuf::from("scripts/macos/proxy-preload.list"))
}

fn split_rules_list(args: &Args) -> std::path::PathBuf {
    if !args.split_rules_list.is_empty() {
        return args.split_rules_list.clone().into();
    }
    // Relative to cwd when run from repo; override with --split-rules-list.
    std::path::PathBuf::from("scripts/macos/proxy-rules.list")
}

#[cfg(target_os = "macos")]
fn install_server_bypass_macos(ip: Ipv4Addr) -> Result<RouteGuard> {
    use std::process::Command;
    let ip_s = ip.to_string();
    let gw = Command::new("route")
        .args(["-n", "get", &ip_s])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.trim().strip_prefix("gateway: ").map(str::to_string))
        });
    let Some(gw) = gw else {
        anyhow::bail!("could not determine the pre-tunnel gateway for server bypass");
    };
    RouteGuard::install_server_bypass(&ip_s, &gw, "")
}

#[cfg(not(target_os = "macos"))]
fn install_server_bypass_macos(ip: Ipv4Addr) -> Result<RouteGuard> {
    RouteGuard::install_server_bypass_linux(ip)
}

#[derive(Clone, Debug)]
struct RuntimeRealityEndpoint {
    uri: RealityUri,
    server_pins: ServerPins,
}

struct ClientAuthContext {
    server_fingerprint: [u8; 32],
    credential: Arc<ClientCredential>,
}

struct SignedCarrierContext<'a> {
    profile: &'a TunnelProfile,
    tun: &'a SharedTun,
    client_credential: &'a Arc<ClientCredential>,
}

impl RuntimeRealityEndpoint {
    fn from_verified_target(target: &VerifiedRealityDialTarget) -> Self {
        let server_pins = *target.server_pins();
        let primary_pin = *server_pins
            .as_slice()
            .first()
            .expect("verified target pin set is non-empty");
        Self {
            uri: RealityUri {
                host: target.address().to_string(),
                pubkey: *target.reality_x25519_public_key(),
                sni: target.sni().to_string(),
                short_id: target.reality_short_id().to_vec(),
                server_fp: primary_pin,
            },
            server_pins,
        }
    }
}

fn signed_reality_pool(policy: &VerifiedEndpointPolicy) -> Result<Vec<RuntimeRealityEndpoint>> {
    let snapshot = policy.coordinator().snapshot();
    snapshot
        .candidates
        .iter()
        .map(|candidate| {
            policy
                .auth_registry()
                .lookup(candidate)
                .map(|target| RuntimeRealityEndpoint::from_verified_target(&target))
        })
        .collect()
}

async fn run_tunnel_mode(
    args: &Args,
    camouflage: CamouflageMode,
    profile: TunnelProfile,
    client_auth: ClientAuthContext,
    signed_policy: Option<&AcceptedSignedPolicy>,
    restart_lockdown: &mut Option<LockdownBarrier>,
    lockdown_control: Option<LockdownControlFlow>,
) -> Result<()> {
    let ClientAuthContext {
        server_fingerprint: server_fp,
        credential: client_credential,
    } = client_auth;
    let restart_lockdown_active = restart_lockdown.is_some();
    // Parse the whole endpoint pool before creating TUN or mutating routes. A
    // missing `fp` in any URI is therefore a pure configuration failure.
    let mut live_endpoint_policy = if let Some(policy) = signed_policy {
        if Instant::now() >= policy.monotonic_deadline
            || unix_time_seconds().map_or(true, |now| now >= policy.expires_at)
        {
            anyhow::bail!("signed endpoint policy expired before TUN setup");
        }
        Some(
            VerifiedEndpointPolicy::from_verified_plan(&policy.plan, 0)
                .context("derive live endpoint authority from verified signed policy")?,
        )
    } else {
        None
    };
    let configured_pool: Vec<RuntimeRealityEndpoint> = if let Some(policy) = &live_endpoint_policy {
        signed_reality_pool(policy)?
    } else {
        reality_pool(args)?
            .into_iter()
            .map(|uri| RuntimeRealityEndpoint {
                server_pins: ServerPins::single(uri.server_fp),
                uri,
            })
            .collect()
    };
    let carrier_protocol = if args.quic {
        EndpointProtocol::Udp
    } else {
        EndpointProtocol::Tcp
    };
    let (pool, carrier_endpoints): (Vec<RuntimeRealityEndpoint>, Vec<AllowedEndpoint>) =
        if live_endpoint_policy.is_some() {
            let endpoints = configured_pool
                .iter()
                .map(|endpoint| AllowedEndpoint {
                    address: endpoint.uri.host.parse().expect("signed socket address"),
                    protocol: EndpointProtocol::Tcp,
                })
                .collect();
            (configured_pool, endpoints)
        } else if !configured_pool.is_empty() {
            let mut expanded_pool = Vec::new();
            let mut endpoints = Vec::new();
            for endpoint in configured_pool {
                let addresses =
                    resolve_tunnel_endpoints(&endpoint.uri.host, restart_lockdown_active)
                        .with_context(|| {
                            format!("resolve REALITY endpoint {}", endpoint.uri.host)
                        })?;
                for address in addresses {
                    expanded_pool.push(endpoint.clone());
                    endpoints.push(AllowedEndpoint {
                        address,
                        protocol: EndpointProtocol::Tcp,
                    });
                }
            }
            (expanded_pool, endpoints)
        } else {
            let endpoints = resolve_tunnel_endpoints(&args.server, restart_lockdown_active)
                .context("resolve tunnel server")?
                .into_iter()
                .map(|address| AllowedEndpoint {
                    address,
                    protocol: carrier_protocol,
                })
                .collect();
            (Vec::new(), endpoints)
        };
    if carrier_endpoints.is_empty() {
        anyhow::bail!("tunnel has no authenticated, resolvable IPv4 server endpoint");
    }
    if args.auto_route {
        LockdownBarrier::preflight_native_nft(&args.host_state_dir).context(
            "preflight the future durable teardown barrier before first full-tunnel mutation",
        )?;
    }
    let mut shutdown = ShutdownSignals::install()
        .context("install shutdown handlers before TUN/route/firewall/DNS mutation")?;
    let mut server_ips: Vec<Ipv4Addr> = carrier_endpoints
        .iter()
        .map(|endpoint| *endpoint.address.ip())
        .collect();
    server_ips.sort_unstable();
    server_ips.dedup();
    let ssh_endpoint = lockdown_control.map(|flow| AllowedEndpoint {
        address: SocketAddrV4::new(flow.destination_ipv4, flow.destination_port),
        protocol: EndpointProtocol::Tcp,
    });
    // Capture every carrier's physical next hop before opening the TUN or
    // installing either split-default. Live DNS rotation may later re-enable a
    // signed address, and must reuse this snapshot instead of recursively
    // resolving a route through the tunnel it is trying to carry.
    let underlay_paths: BTreeMap<Ipv4Addr, LinuxUnderlayPath> = if args.auto_route {
        let mut underlay_ips = server_ips.clone();
        if let Some(ssh) = ssh_endpoint {
            underlay_ips.push(*ssh.address.ip());
        }
        underlay_ips.sort_unstable();
        underlay_ips.dedup();
        underlay_ips
            .iter()
            .copied()
            .map(|ip| {
                LinuxUnderlayPath::capture(ip)
                    .with_context(|| format!("capture pre-TUN underlay path for {ip}"))
                    .map(|path| (ip, path))
            })
            .collect::<Result<_>>()?
    } else {
        BTreeMap::new()
    };
    // Keep the exact pre-resolved tuples both for the firewall and for every
    // subsequent dial. Re-resolving a hostname inside TcpStream/QUIC could pick
    // a different A record than the one allowed by the kill-switch and routed
    // around the TUN.
    let mut allowed_endpoints = Vec::with_capacity(carrier_endpoints.len() + 1);
    for endpoint in &carrier_endpoints {
        if !allowed_endpoints.contains(endpoint) {
            allowed_endpoints.push(*endpoint);
        }
    }
    if let Some(ssh) = ssh_endpoint {
        allowed_endpoints.push(ssh);
    }
    // Session/firewall identity and the anchored resolver capability token are
    // established before opening the TUN. The token stays live until DNS is
    // staged, so no post-TUN capability/topology discovery is required.
    let mut new_host_session = if args.auto_route {
        Some(prepare_new_host_state_session(args)?)
    } else {
        None
    };
    let mut bypass_routes = Vec::<RouteGuard>::new();
    let tun_cfg = client_tun_config(
        args.tun_name.clone(),
        Some(args.tun_addr),
        Some(args.tun_peer),
        args.mtu,
    );
    let tun_open = tokio::select! {
        signal = shutdown.recv() => {
            let signal = signal?;
            info!(signal, "shutdown requested before TUN creation completed");
            if let Some(session) = new_host_session.take() {
                session
                    .abort_before_first_mutation()
                    .context("discard empty host-state WAL after pre-TUN shutdown")?;
            }
            return Ok(());
        }
        result = open_async_client(&tun_cfg) => result,
    };
    let dev = match tun_open {
        Ok(device) => device,
        Err(error) => {
            if let Some(session) = new_host_session.take() {
                session
                    .abort_before_first_mutation()
                    .context("discard empty host-state WAL after TUN open failure")?;
            }
            return Err(error);
        }
    };
    let iface = iface_name(&dev)?;
    let tun = SharedTun::new(dev);
    info!(%iface, tun = %tun_cfg.address, peer = %tun_cfg.peer, "tun up");
    let mut new_host_runtime = if let Some(session) = new_host_session.take() {
        Some(attach_new_tun_to_host_state(session, &iface)?)
    } else {
        None
    };

    if carrier_endpoints.len() > 1 {
        info!(
            endpoints = carrier_endpoints.len(),
            reality = !pool.is_empty(),
            "resolved carrier endpoint pool (rotates on failure)"
        );
    }

    // Route + leak guards are held for the whole process lifetime (Drop restores
    // them on exit). The kill-switch and DNS pin only make sense with full-tunnel
    // routes, so they live inside the --auto-route arm.
    // FullTunnelGuards owns the explicit routes -> DNS -> kill-switch teardown
    // order. Ordinary destructured local bindings would drop in reverse order.
    let (mut full_tunnel_guards, _split_tunnel, _split_dns_guard, _split_leak_guard) = if args.split
    {
        debug_assert!(!args.kill_switch && args.dns.is_none());
        for ip in &server_ips {
            bypass_routes.push(
                install_server_bypass_macos(*ip)
                    .with_context(|| format!("install split server bypass for {ip}"))?,
            );
            info!(server_ip = %ip, "server bypass route installed");
        }
        #[cfg(target_os = "macos")]
        {
            bypass_routes.push(
                RouteGuard::install_peer(&iface, &args.tun_peer.to_string())
                    .context("install TUN peer route")?,
            );
            info!(peer = %args.tun_peer, %iface, "tun peer route installed");
        }
        let rules_dir = split_rules_dir(args);
        let rules_list = split_rules_list(args);
        let dns_addr: std::net::SocketAddr = args.split_dns.parse().context("parse --split-dns")?;
        let upstream: std::net::SocketAddr = args
            .split_dns_upstream
            .parse()
            .context("parse --split-dns-upstream")?;
        let direct_upstream: std::net::SocketAddr = args
            .split_dns_direct_upstream
            .parse()
            .context("parse --split-dns-direct-upstream")?;
        let dns_cfg = SplitDnsConfig {
            bind: dns_addr,
            direct_upstream,
            proxy_upstream: upstream,
            reject_aaaa_for_proxy: true,
        };
        let split_tunnel = tokio::select! {
            signal = shutdown.recv() => {
                let signal = signal?;
                info!(signal, "shutdown requested during split-tunnel setup; restoring routes");
                return Ok(());
            }
            result = SplitTunnel::start(
                &iface,
                rules_dir,
                rules_list,
                split_direct_rules_list(args),
                dns_cfg.clone(),
                split_preload_list(args),
            ) => result?,
        };
        info!(
            dns = %dns_addr,
            direct_upstream = %direct_upstream,
            proxy_upstream = %upstream,
            direct_tags = split_tunnel.policy.loaded_direct_tags().len(),
            proxy_tags = split_tunnel.policy.loaded_proxy_tags().len(),
            "split tunnel active (sing-box-style policy + dual DNS)"
        );
        // Explicit type: on non-macOS targets both arms yield `None`, so the
        // element type can't be inferred (the `Some(guard)` arm is macOS-only).
        let split_dns_guard: Option<MacSplitDnsGuard> = if args.split_dns_guard {
            #[cfg(target_os = "macos")]
            {
                let resolver_ip = dns_addr.ip().to_string();
                let service = if args.split_dns_service.is_empty() {
                    MacSplitDnsGuard::detect_service()
                        .context("detect network service for split DNS")?
                } else {
                    args.split_dns_service.clone()
                };
                let guard = MacSplitDnsGuard::apply(&service, &resolver_ip)
                    .context("apply split DNS guard")?;
                info!(service, resolver = %resolver_ip, "system DNS pinned for split mode");
                Some(guard)
            }
            #[cfg(not(target_os = "macos"))]
            {
                anyhow::bail!("--split-dns-guard is currently implemented only on macOS")
            }
        } else {
            info!("set system DNS to {dns_addr} (or pass --split-dns-guard on macOS)");
            None
        };
        let split_leak_guard = if args.split_leak_guard {
            let guard = SplitLeakGuard::engage(&LeakGuardConfig::from_split_dns(&dns_cfg))
                .context("engage split DNS leak guard")?;
            info!("split DNS leak guard engaged (hijack :53, block DoT/DoH)");
            Some(guard)
        } else {
            warn!("--split-leak-guard off — DoH/DoT and direct :53 queries may leak");
            None
        };
        (None, Some(split_tunnel), split_dns_guard, split_leak_guard)
    } else if args.auto_route {
        // Engage the fail-closed kill-switch FIRST, before any routing change, so
        // there's no window where traffic egresses in cleartext on the physical
        // NIC between the default route flipping to the TUN and the switch arming.
        // Server IPs are already resolved above (no DNS chicken-and-egg). The
        // switch allows every pool endpoint IP (so the carrier can still
        // (re)connect/rotate), the exact SSH control tuple (when present), the
        // TUN iface and loopback; the rest is dropped. There is deliberately no
        // broad ESTABLISHED allowance. The bypass routes below are routing-table
        // only and compose with those exact firewall tuples.
        debug_assert!(args.kill_switch && args.dns.is_some());
        let mut runtime = new_host_runtime
            .take()
            .context("full-tunnel host-state runtime was not prepared")?;
        let dns_preflight = runtime.dns_preflight;
        let firewall_operations = wal_kill_switch_install(
            &mut runtime.journal,
            &runtime.kill_switch_install,
            &allowed_endpoints,
        )?;
        let killswitch =
            KillSwitch::engage_preflighted(&iface, &allowed_endpoints, runtime.kill_switch_install)
                .context("engage mandatory journal-bound kill-switch")?;
        // Move the firewall into the aggregate owner before the next fallible
        // operation. Every later `?` therefore tears down with the firewall
        // last, including failures during route or DNS setup.
        let mut guards = FullTunnelGuards::armed(
            killswitch,
            underlay_paths,
            runtime.journal,
            runtime.tun,
            &firewall_operations,
        )?;
        info!(
            endpoints = server_ips.len(),
            validation_scope = "synthetic-linux-ipv4",
            "kill-switch engaged (fail-closed)"
        );
        if let Some(ssh) = ssh_endpoint {
            let ssh_ip = *ssh.address.ip();
            if !server_ips.contains(&ssh_ip) {
                let path = guards
                    .underlay_paths
                    .get(&ssh_ip)
                    .context("pre-TUN SSH underlay path is missing")?;
                let spec = path
                    .owned_ssh_bypass_spec(ssh_ip, guards.route_owner)
                    .context("derive exact SSH bypass route")?;
                let route = guards
                    .journaled_add_route(&spec)
                    .context("install journaled SSH bypass route")?;
                guards.set_ssh_bypass(route);
            }
        }
        for ip in &server_ips {
            anyhow::ensure!(
                guards.route_add_bypass(*ip)? == OwnedMutation::Changed,
                "initial server bypass unexpectedly already existed for {ip}"
            );
            info!(server_ip = %ip, "server bypass route installed");
        }
        let mut routes = Vec::with_capacity(2);
        for destination in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(128, 0, 0, 0)] {
            let spec =
                LinuxOwnedRouteSpec::split_default(destination, iface.clone(), guards.route_owner)
                    .context("derive owned split-default route")?;
            routes.push(
                guards
                    .journaled_add_route(&spec)
                    .context("install journaled split-default route")?,
            );
        }
        guards.set_routes(routes);
        info!(%iface, "split routes installed");
        // DNS pinning so name resolution rides the tunnel instead of leaking.
        let d = args.dns.expect("validated --auto-route DNS requirement");
        guards
            .apply_dns_exchange(dns_preflight, &[d])
            .context("pin system DNS through crash-recoverable exchange")?;
        info!(dns = %d, "system DNS pinned through the tunnel");
        (Some(guards), None, None, None)
    } else {
        debug_assert!(!args.kill_switch && args.dns.is_none());
        info!("hint: --auto_route or: sudo route add -net 0.0.0.0/1 -interface {iface}");
        (None, None, None, None)
    };

    if let Some(mut barrier) = restart_lockdown.take() {
        let guards = full_tunnel_guards
            .as_ref()
            .context("restart lockdown cannot hand off without full-tunnel guards")?;
        guards
            .release_restart_lockdown_after_verified_activation(&mut barrier)
            .context("handoff restart lockdown to complete replacement kill-switch")?;
        debug_assert!(!barrier.is_active());
        info!("restart lockdown released after durable replacement Active proof");
    }

    info!(
        mux_streams = profile.mux.stream_count,
        mux_chunk = profile.mux.max_chunk_size,
        guard_bytes = profile.volume_guard.threshold,
        guard_enabled = profile.volume_guard.enabled,
        ?camouflage,
        "zatmenie tunnel profile"
    );

    #[cfg(not(feature = "tls-chrome"))]
    if args.tls {
        anyhow::bail!(
            "--tls requires a build with `--features tls-chrome` (BoringSSL not compiled in)"
        );
    }

    // Signed policy has a separate lease-aware dial loop. It refreshes DNS only
    // through an active carrier; after a failed pass it restores the complete
    // signed address authority locally, so reconnect never deadlocks on the
    // TUN-pinned resolver or opens a direct DNS leak. Every new address still
    // requires host prefix -> model commit before entering a dial snapshot.
    // Keeping this branch separate prevents the legacy static pool from
    // accidentally bypassing the verified registry.
    if let Some(policy) = live_endpoint_policy.as_mut() {
        let accepted = signed_policy.context("live signed policy lost its accepted artifact")?;
        let guards = full_tunnel_guards
            .as_mut()
            .context("signed endpoint runtime requires fail-closed full-tunnel host guards")?;
        let terminal = match run_signed_endpoint_loop(
            args,
            SignedCarrierContext {
                profile: &profile,
                tun: &tun,
                client_credential: &client_credential,
            },
            policy,
            guards,
            accepted,
            &mut shutdown,
        )
        .await
        {
            Ok(terminal) => terminal,
            Err(error) => {
                // An expiry discovered inside a host/model transaction can be
                // accompanied by a rollback error and therefore surface as a
                // fatal runtime error instead of the clean PolicyExpired enum.
                // Retire the exact policy first in that case too.
                let checkpoint = signed_policy_expired(accepted).then(|| {
                    accepted
                        .policy_store
                        .checkpoint_expired(&accepted.policy_root, &accepted.expiry_checkpoint)
                });
                let sealed = guards.seal_fail_closed("fatal signed runtime error");
                drop(tun);
                return match (checkpoint, sealed) {
                    (None, Ok(())) => Err(error)
                        .context("signed runtime failed; host state remains durably fail-closed"),
                    (Some(Ok(())), Ok(())) => Err(error).context(
                        "signed runtime failed after policy expiry; expiry is durably tombstoned and host state remains fail-closed",
                    ),
                    (Some(Err(checkpoint_error)), Ok(())) => Err(error).with_context(|| {
                        format!(
                            "signed runtime failed and expiry checkpoint failed: {checkpoint_error:#}; host state remains durably fail-closed"
                        )
                    }),
                    (None, Err(seal_error)) => Err(error).with_context(|| {
                        format!("signed runtime failed and journal sealing failed: {seal_error:#}")
                    }),
                    (Some(Ok(())), Err(seal_error)) => Err(error).with_context(|| {
                        format!(
                            "signed runtime failed after durably tombstoned policy expiry and journal sealing failed: {seal_error:#}"
                        )
                    }),
                    (Some(Err(checkpoint_error)), Err(seal_error)) => {
                        Err(error).with_context(|| {
                            format!(
                                "signed runtime, expiry checkpoint, and journal sealing failed: checkpoint={checkpoint_error:#}; seal={seal_error:#}"
                            )
                        })
                    }
                };
            }
        };
        if let TunnelTerminalOutcome::LocalShutdown(signal) = terminal {
            debug_assert!(terminal.authorizes_host_restore());
            info!(
                signal,
                "local shutdown requested; installing durable restart lockdown before signed host teardown"
            );
            arm_restart_lockdown_for_teardown(args, lockdown_control, restart_lockdown)?;
            guards
                .close_after_sessions(tun)
                .context("close signed TUN and restore host state in fail-closed order")?;
            return Ok(());
        }

        let reason = match terminal {
            TunnelTerminalOutcome::PolicyExpired => "signed policy expiry",
            TunnelTerminalOutcome::LocalShutdown(_) => unreachable!("handled above"),
        };
        // Persist the exact accepted hash before sealing the host journal. This
        // prevents an orderly monotonic expiry followed by wall-clock rollback
        // and restart from resurrecting the same signed bundle. The store
        // rechecks the current anchor under its policy lock, so a delayed
        // runtime cannot tombstone a successor accepted by another process.
        let checkpoint = accepted
            .policy_store
            .checkpoint_expired(&accepted.policy_root, &accepted.expiry_checkpoint);
        let sealed = guards.seal_fail_closed(reason);
        drop(tun);
        return match (checkpoint, sealed) {
            (Ok(()), Ok(())) => Err(anyhow::anyhow!(
                "signed tunnel stopped after {reason}; expiry is durably tombstoned and host state remains fail-closed"
            )),
            (Err(checkpoint_error), Ok(())) => Err(checkpoint_error).context(
                "signed-policy expiry checkpoint failed; host state remains durably fail-closed",
            ),
            (Ok(()), Err(seal_error)) => Err(seal_error).context(
                "signed-policy expiry is durably tombstoned but host journal sealing failed",
            ),
            (Err(checkpoint_error), Err(seal_error)) => Err(checkpoint_error).with_context(|| {
                format!(
                    "signed-policy expiry checkpoint and host journal sealing both failed: {seal_error:#}"
                )
            }),
        };
    }

    // A tunnel client is a daemon: it rides out transient *and* sustained
    // outages (server restart, TSPU blocking, network flap) with bounded
    // exponential backoff and never gives up — exiting would drop the user's
    // connectivity exactly when the network is most hostile. `fail_streak`
    // drives the backoff and only climbs while the tunnel has no evidence of
    // working; a guard rotation or a long-lived session collapses it. (review M3)
    let backoff = Backoff::new(250, 30_000);
    let mut rotation = 0u32;
    let mut fail_streak = 0u32;
    let mut endpoint_idx = 0usize;
    // Per-process jitter seed (de-syncs reconnects across clients and restarts).
    let mut jitter_state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678_9ABC_DEF0)
        ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let terminal;
    loop {
        // One whole connection attempt (connect -> handshake -> forward) lives in
        // a session helper; connect/handshake failures surface as Err -> Backoff,
        // a guard rotation as Err(RotateConnection) -> Rotate, clean close as Ok.
        let session_start = Instant::now();
        let res = tokio::select! {
            signal = shutdown.recv() => {
                let signal = match signal {
                    Ok(signal) => signal,
                    Err(error) => {
                        if let Some(guards) = full_tunnel_guards.as_mut() {
                            guards.seal_fail_closed("fatal shutdown-signal error")?;
                        }
                        drop(tun);
                        return Err(error).context(
                            "shutdown signal listener failed; host state remains fail-closed",
                        );
                    }
                };
                info!(signal, "shutdown requested; restoring routes, DNS and firewall");
                terminal = TunnelTerminalOutcome::LocalShutdown(signal);
                break;
            }
            result = async {
                if !pool.is_empty() {
                    run_reality_session(
                        args,
                        &pool[endpoint_idx],
                        carrier_endpoints[endpoint_idx].address,
                        &profile,
                        &tun,
                        &client_credential,
                    ).await
                } else if args.quic {
                    run_quic_session(
                        args,
                        carrier_endpoints[endpoint_idx].address,
                        &args.sni,
                        &profile,
                        &tun,
                        server_fp,
                        &client_credential,
                    ).await
                } else if args.tls {
                    #[cfg(feature = "tls-chrome")]
                    {
                        run_tls_session(
                            args,
                            carrier_endpoints[endpoint_idx].address,
                            &args.sni,
                            &profile,
                            &tun,
                            server_fp,
                            &client_credential,
                        ).await
                    }
                    #[cfg(not(feature = "tls-chrome"))]
                    unreachable!("--tls rejected before retry loop")
                } else {
                    run_carrier_session(
                        args,
                        carrier_endpoints[endpoint_idx].address,
                        camouflage,
                        &profile,
                        &tun,
                        server_fp,
                        &client_credential,
                    ).await
                }
            } => result,
        };

        let action = classify_run_result(&res);
        // Rotate to the next pool endpoint on a transient failure (sticky otherwise).
        let prev = endpoint_idx;
        endpoint_idx = rotate_endpoint(endpoint_idx, carrier_endpoints.len(), action);
        if endpoint_idx != prev {
            info!(
                endpoint = %carrier_endpoints[endpoint_idx].address,
                "rotating to next pre-authorized endpoint"
            );
        }

        let delay = match action {
            ReconnectAction::Rotate => {
                rotation += 1;
                fail_streak = next_fail_streak(ReconnectAction::Rotate, true, fail_streak);
                info!(rotation, "reconnecting after volume guard");
                ROTATE_DELAY
            }
            ReconnectAction::Backoff | ReconnectAction::RemoteClose => {
                rotation += 1;
                let session_ok = session_start.elapsed() >= STABLE_AFTER;
                fail_streak = next_fail_streak(action, session_ok, fail_streak);
                let delay = backoff.delay_jittered(fail_streak, splitmix64(&mut jitter_state));
                match &res {
                    Ok(()) => warn!(
                        fail_streak,
                        rotation,
                        session_ok,
                        ?delay,
                        "authenticated remote FIN; reconnecting without restoring host state"
                    ),
                    Err(error) => warn!(
                        %error,
                        fail_streak,
                        rotation,
                        session_ok,
                        ?delay,
                        "session ended, reconnecting"
                    ),
                }
                delay
            }
        };
        tokio::select! {
            signal = shutdown.recv() => {
                let signal = match signal {
                    Ok(signal) => signal,
                    Err(error) => {
                        if let Some(guards) = full_tunnel_guards.as_mut() {
                            guards.seal_fail_closed("fatal shutdown-signal error")?;
                        }
                        drop(tun);
                        return Err(error).context(
                            "shutdown signal listener failed during backoff; host state remains fail-closed",
                        );
                    }
                };
                info!(signal, "shutdown requested during reconnect backoff; restoring guards");
                terminal = TunnelTerminalOutcome::LocalShutdown(signal);
                break;
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
    if let Some(guards) = full_tunnel_guards.as_mut() {
        match terminal {
            TunnelTerminalOutcome::LocalShutdown(signal) => {
                debug_assert!(terminal.authorizes_host_restore());
                info!(
                    signal,
                    "local shutdown requested; installing durable restart lockdown before host teardown"
                );
                arm_restart_lockdown_for_teardown(args, lockdown_control, restart_lockdown)?;
                guards
                    .close_after_sessions(tun)
                    .context("close TUN and restore full-tunnel host state in fail-closed order")?;
            }
            TunnelTerminalOutcome::PolicyExpired => {
                unreachable!("unsigned/manual tunnel loop has no policy expiry")
            }
        }
    } else {
        drop(tun);
    }
    Ok(())
}

/// Plain-carrier tunnel session: connect -> bootstrap -> PQ handshake -> forward.
/// Returns run_tunnel_guarded's result; any setup failure carries stage context
/// and surfaces as Err (the caller treats it as Backoff).
async fn run_carrier_session(
    args: &Args,
    server_addr: SocketAddrV4,
    camouflage: CamouflageMode,
    profile: &TunnelProfile,
    tun: &SharedTun,
    server_fp: [u8; 32],
    client_credential: &Arc<ClientCredential>,
) -> Result<()> {
    let deadlines = RuntimeDeadlines::from_args(args).expect("runtime deadlines validated");
    let tcp = bounded_stage(
        "TCP connect",
        deadlines.connect,
        TcpStream::connect(server_addr),
    )
    .await?;
    info!(server = %args.server, endpoint = %server_addr, "tcp connected");
    let mut stream = bounded_stage(
        "outer carrier bootstrap",
        deadlines.outer_handshake,
        client_connect(tcp, camouflage),
    )
    .await?;
    let config = ClientConfig {
        camouflage,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: server_fp,
        client_credential: Arc::clone(client_credential),
    };
    let (session, session_id) = bounded_stage(
        "inner post-quantum authentication",
        deadlines.inner_handshake,
        AuthenticatedSession::client_connect(&mut stream, &config),
    )
    .await?;
    info!(session_id = hex::encode(session_id), "handshake ok");
    let guard = volume_guard_from_config(profile.volume_guard);
    let pacer = Arc::new(pacer_from_config(profile.pacer));
    run_tunnel_guarded_with_liveness(
        tun.clone(),
        stream,
        session,
        profile.mux.clone(),
        args.mtu,
        guard,
        pacer,
        None,
        Some(deadlines.liveness),
    )
    .await
}

/// Same, but the transport is a real Chrome-JA4 TLS layer (boring-front); the
/// shadowpipe protocol runs inside it with raw framing.
#[cfg(feature = "tls-chrome")]
async fn run_tls_session(
    args: &Args,
    server_addr: SocketAddrV4,
    sni: &str,
    profile: &TunnelProfile,
    tun: &SharedTun,
    server_fp: [u8; 32],
    client_credential: &Arc<ClientCredential>,
) -> Result<()> {
    let deadlines = RuntimeDeadlines::from_args(args).expect("runtime deadlines validated");
    let tcp = bounded_stage(
        "TCP connect",
        deadlines.connect,
        TcpStream::connect(server_addr),
    )
    .await?;
    info!(server = %args.server, endpoint = %server_addr, %sni, "tcp connected (tls-chrome)");
    let mut tls = bounded_stage(
        "outer TLS handshake",
        deadlines.outer_handshake,
        shadowpipe_core::tls::chrome_connect(tcp, sni),
    )
    .await?;
    let config = ClientConfig {
        camouflage: CamouflageMode::Raw,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: server_fp,
        client_credential: Arc::clone(client_credential),
    };
    let (session, session_id) = bounded_stage(
        "inner post-quantum authentication",
        deadlines.inner_handshake,
        AuthenticatedSession::client_connect(&mut tls, &config),
    )
    .await?;
    info!(
        session_id = hex::encode(session_id),
        "handshake ok (tls-chrome)"
    );
    let guard = volume_guard_from_config(profile.volume_guard);
    let pacer = Arc::new(pacer_from_config(profile.pacer));
    run_tunnel_guarded_with_liveness(
        tun.clone(),
        tls,
        session,
        profile.mux.clone(),
        args.mtu,
        guard,
        pacer,
        None,
        Some(deadlines.liveness),
    )
    .await
}

/// Same as the carrier/TLS sessions, but the transport is the REALITY carrier:
/// a genuine TLS 1.3 handshake to --sni that authenticates to the server's X25519
/// static key. The shadowpipe PQ session + tunnel run inside it (raw framing —
/// the TLS itself is the camouflage), exactly as under --tls.
async fn run_reality_session(
    args: &Args,
    endpoint: &RuntimeRealityEndpoint,
    server_addr: SocketAddrV4,
    profile: &TunnelProfile,
    tun: &SharedTun,
    client_credential: &Arc<ClientCredential>,
) -> Result<()> {
    let uri = &endpoint.uri;
    let deadlines = RuntimeDeadlines::from_args(args).expect("runtime deadlines validated");
    let tcp = bounded_stage(
        "TCP connect",
        deadlines.connect,
        TcpStream::connect(server_addr),
    )
    .await?;
    info!(server = %uri.host, endpoint = %server_addr, sni = %uri.sni, "tcp connected (reality)");
    let mut stream = bounded_stage(
        "outer REALITY handshake",
        deadlines.outer_handshake,
        shadowpipe_core::reality::reality_connect(tcp, &uri.pubkey, &uri.short_id, &uri.sni),
    )
    .await?;
    let config = ClientConfig {
        camouflage: CamouflageMode::Raw,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: uri.server_fp,
        client_credential: Arc::clone(client_credential),
    };
    let (session, session_id) = bounded_stage(
        "inner pinned post-quantum authentication",
        deadlines.inner_handshake,
        AuthenticatedSession::client_connect_pins(&mut stream, &config, &endpoint.server_pins),
    )
    .await?;
    info!(
        session_id = hex::encode(session_id),
        "handshake ok (reality)"
    );
    let guard = volume_guard_from_config(profile.volume_guard);
    let pacer = Arc::new(pacer_from_config(profile.pacer));
    run_tunnel_guarded_with_liveness(
        tun.clone(),
        stream,
        session,
        profile.mux.clone(),
        args.mtu,
        guard,
        pacer,
        None,
        Some(deadlines.liveness),
    )
    .await
}

/// Same as the TLS session, but the transport is the QUIC carrier (UDP): the PQ
/// session + tunnel ride inside one QUIC bidirectional stream. Single-endpoint
/// like --tls (no REALITY pool); the daemon reconnect loop rebuilds the QUIC
/// connection on failure. The QUIC TLS cert is untrusted — auth is the inner
/// ML-KEM --server-fp pin, exactly as under --tls.
#[cfg(feature = "quic")]
async fn run_quic_session(
    args: &Args,
    server_addr: SocketAddrV4,
    sni: &str,
    profile: &TunnelProfile,
    tun: &SharedTun,
    server_fp: [u8; 32],
    client_credential: &Arc<ClientCredential>,
) -> Result<()> {
    info!(server = %args.server, endpoint = %server_addr, %sni, "quic connecting");
    let deadlines = RuntimeDeadlines::from_args(args).expect("runtime deadlines validated");
    let mut stream = bounded_stage(
        "QUIC connect and outer handshake",
        deadlines.connect.saturating_add(deadlines.outer_handshake),
        shadowpipe_core::quic::quic_connect(server_addr.into(), sni),
    )
    .await?;
    let config = ClientConfig {
        camouflage: CamouflageMode::Raw,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: server_fp,
        client_credential: Arc::clone(client_credential),
    };
    let (session, session_id) = bounded_stage(
        "inner post-quantum authentication",
        deadlines.inner_handshake,
        AuthenticatedSession::client_connect(&mut stream, &config),
    )
    .await?;
    info!(session_id = hex::encode(session_id), "handshake ok (quic)");
    let guard = volume_guard_from_config(profile.volume_guard);
    let pacer = Arc::new(pacer_from_config(profile.pacer));
    // Capture the live QUIC path-stats handle BEFORE the stream is moved into
    // run_tunnel_guarded (and consumed by tokio::io::split). quinn::Connection is
    // Clone, so the handle stays valid for the whole session.
    let stats: Arc<dyn shadowpipe_core::pacing::PathStatsSource> =
        Arc::new(stream.path_stats_handle());
    run_tunnel_guarded_with_liveness(
        tun.clone(),
        stream,
        session,
        profile.mux.clone(),
        args.mtu,
        guard,
        pacer,
        Some(stats),
        Some(deadlines.liveness),
    )
    .await
}

/// Stub when built without the `quic` feature: the dispatch still compiles, but
/// `--quic` fails fast with a clear message instead of silently doing nothing.
#[cfg(not(feature = "quic"))]
async fn run_quic_session(
    _args: &Args,
    _server_addr: SocketAddrV4,
    _sni: &str,
    _profile: &TunnelProfile,
    _tun: &SharedTun,
    _server_fp: [u8; 32],
    _client_credential: &Arc<ClientCredential>,
) -> Result<()> {
    anyhow::bail!("--quic requires a build with `--features quic` (quinn not compiled in)")
}

fn resolve_server_endpoints(server: &str) -> anyhow::Result<Vec<SocketAddrV4>> {
    let addresses = server
        .to_socket_addrs()
        .with_context(|| format!("resolve server {server}"))?;
    let mut ipv4 = Vec::new();
    for address in addresses {
        if let SocketAddr::V4(address) = address {
            if !ipv4.contains(&address) {
                ipv4.push(address);
            }
        }
    }
    anyhow::ensure!(
        !ipv4.is_empty(),
        "no IPv4 addresses for {server}; IPv6 carrier support is not implemented"
    );
    Ok(ipv4)
}

/// Preserve an already-established remote SSH control connection without the
/// broad ESTABLISHED allowance that would let arbitrary pre-VPN sockets leak.
fn ssh_lockdown_control_flow() -> Result<Option<LockdownControlFlow>> {
    let connection = match std::env::var("SSH_CONNECTION") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    let fields: Vec<&str> = connection.split_whitespace().collect();
    if fields.len() != 4 {
        anyhow::bail!("invalid SSH_CONNECTION: expected four fields");
    }
    let client_ip: Ipv4Addr = fields[0]
        .parse()
        .with_context(|| format!("SSH client address is not IPv4: {}", fields[0]))?;
    let client_port: u16 = fields[1]
        .parse()
        .with_context(|| format!("invalid SSH client port: {}", fields[1]))?;
    let server_ip: Ipv4Addr = fields[2]
        .parse()
        .with_context(|| format!("SSH server address is not IPv4: {}", fields[2]))?;
    let server_port: u16 = fields[3]
        .parse()
        .with_context(|| format!("invalid SSH server port: {}", fields[3]))?;
    Ok(Some(LockdownControlFlow::new(
        server_ip,
        server_port,
        client_ip,
        client_port,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowpipe_core::client_auth::AuthorizedClients;
    use shadowpipe_core::endpoint::AuthConfigRef;
    use shadowpipe_core::host_state::{
        BootId, InterfaceIdentity, NamespaceIdentity, OperationRecord, ProcessEvidence,
    };
    use shadowpipe_core::measurement::MeasurementRun;
    use shadowpipe_core::session::ServerState;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::ReadBuf;

    fn test_client_auth() -> (Arc<ClientCredential>, AuthorizedClients) {
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = credential.authorized_clients().unwrap();
        (credential, authorized)
    }

    fn recovery_test_owner() -> OwnerIdentity {
        OwnerIdentity {
            session_id: SessionId::from_bytes([0x31; 16]),
            boot_id: None,
            uid: 0,
            pid: 7,
            pid_start_ticks: None,
            network_namespace: None,
            mount_namespace: None,
        }
    }

    fn recovery_test_journal(
        resources: Vec<(OperationState, OwnedResource)>,
    ) -> HostStateJournalV2 {
        let operations = resources
            .into_iter()
            .enumerate()
            .map(|(index, (state, resource))| OperationRecord {
                id: u32::try_from(index + 1).unwrap(),
                state,
                resource,
            })
            .collect();
        HostStateJournalV2::new(recovery_test_owner(), operations).unwrap()
    }

    fn recovery_test_tun(name: &str, ifindex: u32) -> TunResource {
        TunResource {
            interface: InterfaceIdentity {
                name: name.to_string(),
                ifindex,
            },
        }
    }

    fn recovery_test_identity(backend: FirewallBackend, ipv4: u8, ipv6: u8) -> KillSwitchIdentity {
        KillSwitchIdentity::from_parts(
            recovery_test_owner().session_id,
            FirewallChainToken::from_bytes([ipv4; 10]),
            FirewallChainToken::from_bytes([ipv6; 10]),
            backend,
        )
        .unwrap()
    }

    #[test]
    fn recovery_identity_uses_removed_history_for_firewall_and_tun() {
        let identity = recovery_test_identity(FirewallBackend::IptablesNft, 0x41, 0x42);
        let journal = recovery_test_journal(vec![
            (
                OperationState::Removed,
                OwnedResource::Tun(recovery_test_tun("sp0", 17)),
            ),
            (
                OperationState::Removed,
                OwnedResource::Firewall(identity.ipv4_journal_resource()),
            ),
            (
                OperationState::Applied,
                OwnedResource::Firewall(identity.ipv6_journal_resource()),
            ),
        ]);

        let reconstructed = reconstruct_recovery_identity(&journal).unwrap();
        assert_eq!(reconstructed.tun.unwrap().interface.name, "sp0");
        assert_eq!(reconstructed.kill_switch, Some(identity));
    }

    #[test]
    fn recovery_identity_rejects_backend_change_hidden_in_removed_history() {
        let old = recovery_test_identity(FirewallBackend::IptablesNft, 0x51, 0x52);
        let current = recovery_test_identity(FirewallBackend::IptablesLegacy, 0x61, 0x62);
        let journal = recovery_test_journal(vec![
            (
                OperationState::Removed,
                OwnedResource::Firewall(old.ipv4_journal_resource()),
            ),
            (
                OperationState::Applied,
                OwnedResource::Firewall(current.ipv4_journal_resource()),
            ),
            (
                OperationState::Applied,
                OwnedResource::Firewall(current.ipv6_journal_resource()),
            ),
        ]);

        let error = reconstruct_recovery_identity(&journal).unwrap_err();
        assert!(error.to_string().contains("contradictory firewall backend"));
    }

    #[test]
    fn recovery_identity_rejects_chain_change_hidden_in_removed_history() {
        let old = recovery_test_identity(FirewallBackend::IptablesNft, 0x63, 0x64);
        let current = recovery_test_identity(FirewallBackend::IptablesNft, 0x65, 0x66);
        let journal = recovery_test_journal(vec![
            (
                OperationState::Removed,
                OwnedResource::Firewall(old.ipv4_journal_resource()),
            ),
            (
                OperationState::Applied,
                OwnedResource::Firewall(current.ipv4_journal_resource()),
            ),
            (
                OperationState::Applied,
                OwnedResource::Firewall(current.ipv6_journal_resource()),
            ),
        ]);

        let error = reconstruct_recovery_identity(&journal).unwrap_err();
        assert!(error
            .to_string()
            .contains("contradictory IPv4 firewall chain token"));
    }

    #[test]
    fn recovery_identity_rejects_incomplete_firewall_vocabulary() {
        let identity = recovery_test_identity(FirewallBackend::IptablesNft, 0x71, 0x72);
        let journal = recovery_test_journal(vec![(
            OperationState::Applied,
            OwnedResource::Firewall(identity.ipv4_journal_resource()),
        )]);

        let error = reconstruct_recovery_identity(&journal).unwrap_err();
        assert!(error.to_string().contains("no IPv6 chain token"));
    }

    #[test]
    fn recovery_identity_rejects_reused_tun_name_or_ifindex_history() {
        let journal = recovery_test_journal(vec![
            (
                OperationState::Removed,
                OwnedResource::Tun(recovery_test_tun("sp0", 17)),
            ),
            (
                OperationState::Applied,
                OwnedResource::Tun(recovery_test_tun("sp0", 18)),
            ),
        ]);

        let error = reconstruct_recovery_identity(&journal).unwrap_err();
        assert!(error.to_string().contains("contradictory TUN identity"));
    }

    #[test]
    fn startup_recovery_gate_is_fail_closed_and_boot_explicit() {
        let same_boot_stale = OwnerEvidence {
            lease: LeaseEvidence::Available,
            boot: BootEvidence::Same,
            process: ProcessEvidence::Missing,
            namespaces: NamespaceEvidence::Same,
        };
        assert_eq!(
            decide_startup_recovery(same_boot_stale, JournalPhase::Active),
            Ok(StartupRecoveryBoot::Same)
        );

        let different_boot_stale = OwnerEvidence {
            lease: LeaseEvidence::Available,
            boot: BootEvidence::Different,
            process: ProcessEvidence::Unknown,
            namespaces: NamespaceEvidence::NotApplicableAfterReboot,
        };
        assert_eq!(
            decide_startup_recovery(different_boot_stale, JournalPhase::Cleaning),
            Ok(StartupRecoveryBoot::Different)
        );
        assert_eq!(
            decide_startup_recovery(different_boot_stale, JournalPhase::Conflict),
            Err(StartupRecoveryRefusal::JournalConflict)
        );

        let active = OwnerEvidence {
            lease: LeaseEvidence::Held,
            ..same_boot_stale
        };
        assert_eq!(
            decide_startup_recovery(active, JournalPhase::Active),
            Err(StartupRecoveryRefusal::ActiveOwner)
        );

        let unknown_boot = OwnerEvidence {
            lease: LeaseEvidence::Available,
            boot: BootEvidence::Unknown,
            process: ProcessEvidence::Missing,
            namespaces: NamespaceEvidence::Unknown,
        };
        assert_eq!(
            decide_startup_recovery(unknown_boot, JournalPhase::Active),
            Err(StartupRecoveryRefusal::AmbiguousOwner)
        );
    }

    #[test]
    fn every_tun_mode_requires_host_state_coordination() {
        let ordinary = Args::try_parse_from(["shadowpipe-client"]).unwrap();
        let manual_tun = Args::try_parse_from(["shadowpipe-client", "--tunnel"]).unwrap();
        let split_tun = Args::try_parse_from(["shadowpipe-client", "--tunnel", "--split"]).unwrap();
        let release = Args::try_parse_from(["shadowpipe-client", "--release-lockdown"]).unwrap();
        let restore = Args::try_parse_from(["shadowpipe-client", "--restore-lockdown"]).unwrap();

        assert!(!requires_host_state_coordination_for_platform(
            &ordinary, true
        ));
        assert!(requires_host_state_coordination_for_platform(
            &manual_tun,
            true
        ));
        assert!(requires_host_state_coordination_for_platform(
            &split_tun, true
        ));
        assert!(requires_host_state_coordination_for_platform(
            &release, true
        ));
        assert!(requires_host_state_coordination_for_platform(
            &restore, true
        ));
        assert!(!requires_host_state_coordination_for_platform(
            &manual_tun,
            false
        ));
    }

    #[test]
    fn early_boot_restore_is_standalone_and_manual_restart_requires_literal_ipv4() {
        assert!(
            Args::try_parse_from(["shadowpipe-client", "--restore-lockdown", "--tunnel"]).is_err()
        );
        assert!(Args::try_parse_from([
            "shadowpipe-client",
            "--restore-lockdown",
            "--release-lockdown"
        ])
        .is_err());

        let numeric =
            Args::try_parse_from(["shadowpipe-client", "--server", "192.0.2.9:443"]).unwrap();
        require_literal_manual_restart_endpoints(&numeric).unwrap();
        let hostname =
            Args::try_parse_from(["shadowpipe-client", "--server", "vpn.example:443"]).unwrap();
        assert!(require_literal_manual_restart_endpoints(&hostname).is_err());
    }

    #[test]
    fn any_main_wal_directory_entry_triggers_restart_protection() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "shadowpipe-main-wal-presence-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
        std::fs::create_dir_all(&root).unwrap();
        let args = Args::try_parse_from([
            "shadowpipe-client",
            "--host-state-dir",
            root.to_str().unwrap(),
        ])
        .unwrap();
        assert!(!main_host_journal_may_exist(&args));
        std::fs::create_dir(root.join("host-state-v2.json")).unwrap();
        assert!(main_host_journal_may_exist(&args));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn new_linux_wal_requires_complete_recovery_evidence() {
        let incomplete = recovery_test_owner();
        let error = require_complete_linux_owner_evidence(&incomplete).unwrap_err();
        let detail = error.to_string();
        for field in [
            "boot_id",
            "pid_start_ticks",
            "network_namespace",
            "mount_namespace",
        ] {
            assert!(
                detail.contains(field),
                "missing field name {field}: {detail}"
            );
        }

        let complete = OwnerIdentity {
            boot_id: Some(BootId::from_bytes([0x41; 16])),
            pid_start_ticks: Some(99),
            network_namespace: Some(NamespaceIdentity {
                device: 1,
                inode: 2,
            }),
            mount_namespace: Some(NamespaceIdentity {
                device: 1,
                inode: 3,
            }),
            ..incomplete
        };
        require_complete_linux_owner_evidence(&complete).unwrap();
    }

    #[test]
    fn firewall_prepare_classification_preserves_conflict_vs_operational() {
        assert!(matches!(
            firewall_prepare_error(KillSwitchPrepareError::Conflict {
                detail: "foreign rule".to_string(),
            }),
            StartupRecoveryPrepareError::Conflict(_)
        ));
        assert!(matches!(
            firewall_prepare_error(KillSwitchPrepareError::Operational {
                detail: "inspection unavailable".to_string(),
            }),
            StartupRecoveryPrepareError::Operational(_)
        ));

        let dns_conflict = anyhow::Error::new(DnsExchangeFailure::Conflict {
            operation: "pure-test",
            detail: "target identity changed".to_string(),
        })
        .context("prepared DNS group context");
        assert!(matches!(
            dns_prepare_error(dns_conflict),
            StartupRecoveryPrepareError::Conflict(_)
        ));
        let dns_operational = anyhow::Error::new(DnsExchangeFailure::Operational {
            operation: "pure-test",
            detail: "read unavailable".to_string(),
        })
        .context("prepared DNS group context");
        assert!(matches!(
            dns_prepare_error(dns_operational),
            StartupRecoveryPrepareError::Operational(_)
        ));
    }

    struct FailWrites<S> {
        inner: S,
        fail: Arc<AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for FailWrites<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for FailWrites<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.fail.load(Ordering::Relaxed) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic writer failure",
                )));
            }
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let b = Backoff::new(250, 30_000);
        assert_eq!(b.delay(0), Duration::from_millis(0));
        assert_eq!(b.delay(1), Duration::from_millis(250));
        assert_eq!(b.delay(2), Duration::from_millis(500));
        assert_eq!(b.delay(3), Duration::from_millis(1_000));
        assert_eq!(b.delay(4), Duration::from_millis(2_000));
        assert_eq!(b.delay(7), Duration::from_millis(16_000));
        // 250 * 2^7 = 32_000 -> capped to 30_000, and stays there.
        assert_eq!(b.delay(8), Duration::from_millis(30_000));
        assert_eq!(b.delay(50), Duration::from_millis(30_000));
        // No overflow / panic at an absurd streak.
        assert_eq!(b.delay(u32::MAX), Duration::from_millis(30_000));
    }

    #[test]
    fn jittered_delay_stays_within_band_and_varies() {
        let b = Backoff::new(250, 30_000);
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        let base = b.delay(4).as_millis() as u64; // 2_000 ms
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let d = b.delay_jittered(4, splitmix64(&mut state)).as_millis() as u64;
            // Always within [0.8, 1.2) of the base, never zero for a non-zero base.
            assert!(
                d >= (base * 8 / 10) && d < (base * 12 / 10),
                "jittered delay {d}ms out of band for base {base}ms"
            );
            seen.insert(d);
        }
        // The jitter actually moves (not a constant) across many draws.
        assert!(
            seen.len() > 10,
            "jitter barely varied: {} distinct",
            seen.len()
        );
        // Streak 0 stays immediate even with jitter (0 * anything == 0).
        assert_eq!(
            b.delay_jittered(0, splitmix64(&mut state)),
            Duration::from_millis(0)
        );
    }

    #[test]
    fn full_tunnel_guards_drop_routes_bypasses_dns_then_kill_switch() {
        use std::cell::RefCell;
        use std::rc::Rc;

        struct Marker(&'static str, Rc<RefCell<Vec<&'static str>>>);
        impl Drop for Marker {
            fn drop(&mut self) {
                self.1.borrow_mut().push(self.0);
            }
        }

        let order = Rc::new(RefCell::new(Vec::new()));
        let mut routes = Some(Marker("routes", Rc::clone(&order)));
        let mut bypass_routes = Some(Marker("bypass-routes", Rc::clone(&order)));
        let mut ssh_bypass = Some(Marker("ssh-bypass", Rc::clone(&order)));
        let mut dns = Some(Marker("dns", Rc::clone(&order)));
        let mut kill_switch = Some(Marker("kill-switch", Rc::clone(&order)));
        drop_full_tunnel_guards(
            &mut routes,
            &mut bypass_routes,
            &mut ssh_bypass,
            &mut dns,
            &mut kill_switch,
        );

        assert_eq!(
            &*order.borrow(),
            &[
                "routes",
                "bypass-routes",
                "ssh-bypass",
                "dns",
                "kill-switch"
            ]
        );
    }

    #[test]
    fn classify_maps_clean_rotate_and_error() {
        let ok: Result<()> = Ok(());
        assert_eq!(classify_run_result(&ok), ReconnectAction::RemoteClose);

        let rotate: Result<()> = Err(RotateConnection.into());
        assert_eq!(classify_run_result(&rotate), ReconnectAction::Rotate);

        let boom: Result<()> = Err(anyhow::anyhow!("decrypt frame: aead error"));
        assert_eq!(classify_run_result(&boom), ReconnectAction::Backoff);
    }

    #[test]
    fn only_explicit_local_shutdown_authorizes_host_restore() {
        assert!(TunnelTerminalOutcome::LocalShutdown("SIGTERM").authorizes_host_restore());
        assert!(!TunnelTerminalOutcome::PolicyExpired.authorizes_host_restore());
    }

    #[tokio::test]
    async fn bounded_stage_timeout_is_typed_and_maps_to_backoff() {
        let result: Result<()> = bounded_stage(
            "synthetic blackhole",
            Duration::from_millis(20),
            std::future::pending::<Result<()>>(),
        )
        .await;
        let error = result.unwrap_err();
        assert!(error.downcast_ref::<StageTimeout>().is_some());
        assert_eq!(classify_run_result(&Err(error)), ReconnectAction::Backoff);
    }

    #[tokio::test]
    async fn ordinary_echo_path_bounds_a_blackholed_inner_handshake() {
        let args = Args::try_parse_from([
            "shadowpipe-client",
            "--inner-handshake-timeout-secs",
            "1",
            "--message",
            "deadline-probe",
        ])
        .unwrap();
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let config = ClientConfig {
            camouflage: CamouflageMode::Raw,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: [0x91; 32],
            client_credential: credential,
        };
        let (client_io, _blackholed_peer) = tokio::io::duplex(4096);

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_session(client_io, &config, &args),
        )
        .await
        .expect("ordinary echo path exceeded its inner-handshake bound")
        .unwrap_err();
        let stage = result
            .downcast_ref::<StageTimeout>()
            .expect("blackholed ordinary path did not return a typed stage timeout");
        assert_eq!(stage.stage, "inner authenticated handshake");
        assert_eq!(stage.limit, Duration::from_secs(1));
    }

    #[test]
    fn fail_streak_resets_on_progress_and_climbs_on_flap() {
        use ReconnectAction::*;
        // A rotation means 8 KB actually flowed -> fresh start.
        assert_eq!(next_fail_streak(Rotate, true, 5), 0);
        // A long-lived session that finally dropped -> reconnect fast.
        assert_eq!(next_fail_streak(Backoff, true, 5), 1);
        assert_eq!(next_fail_streak(RemoteClose, true, 5), 1);
        // A connection that keeps flapping -> climb the curve (no storm).
        assert_eq!(next_fail_streak(Backoff, false, 5), 6);
        assert_eq!(next_fail_streak(RemoteClose, false, 5), 6);
        assert_eq!(next_fail_streak(Backoff, false, 0), 1);
        // No overflow at the ceiling.
        assert_eq!(next_fail_streak(Backoff, false, u32::MAX), u32::MAX);
    }

    fn failure_candidate(logical: u64, octet: u8) -> DialCandidate {
        let ip = Ipv4Addr::new(203, 0, 113, octet);
        DialCandidate {
            key: CandidateKey {
                logical: LogicalEndpointId(logical),
                ip,
            },
            address: SocketAddrV4::new(ip, 443),
            protocol: LiveCarrierProtocol::Tcp,
            auth: AuthConfigRef(logical as u32),
            authority_generation: 9,
        }
    }

    #[test]
    fn failure_epoch_rehydrates_once_after_one_complete_snapshot_pass() {
        let a = failure_candidate(1, 10);
        let b = failure_candidate(1, 11);
        let c = failure_candidate(1, 12);
        let mut epoch = SignedFailureEpoch::new(7);

        assert!(!epoch.record_failure(7, &[a.clone(), b.clone()], a.key));
        assert!(!epoch.record_failure(7, &[a.clone(), b.clone()], a.key));
        assert!(epoch.record_failure(7, &[a.clone(), b.clone()], b.key));

        epoch.note_rehydrated(8, &[a.clone(), b.clone(), c.clone()], b.key);
        assert!(!epoch.record_failure(8, &[a.clone(), b.clone(), c.clone()], c.key));
        assert!(!epoch.record_failure(8, &[a.clone(), b.clone(), c.clone()], a.key));

        epoch.reset(8);
        assert!(!epoch.record_failure(8, &[a.clone(), b.clone(), c.clone()], a.key));
        assert!(!epoch.record_failure(8, &[a.clone(), b.clone(), c.clone()], b.key));
        assert!(epoch.record_failure(8, &[a, b, c.clone()], c.key));
    }

    #[test]
    fn rotate_endpoint_is_sticky_until_failure() {
        use ReconnectAction::*;
        // Single (or empty) pool never moves.
        assert_eq!(rotate_endpoint(0, 1, Backoff), 0);
        assert_eq!(rotate_endpoint(0, 0, Backoff), 0);
        // Multi-endpoint: only a transient failure advances, and it wraps around.
        assert_eq!(rotate_endpoint(0, 3, Backoff), 1);
        assert_eq!(rotate_endpoint(2, 3, Backoff), 0);
        // A volume-guard rotation stays sticky; remote FIN is remote input and
        // rotates/backoffs exactly like a transport failure.
        assert_eq!(rotate_endpoint(1, 3, Rotate), 1);
        assert_eq!(rotate_endpoint(1, 3, RemoteClose), 2);
    }

    #[test]
    fn signed_policy_deadline_uses_a_monotonic_lifetime() {
        let base = Instant::now();
        let deadline = signed_policy_deadline(1_005, 1_000, base).unwrap();
        assert_eq!(deadline.duration_since(base), Duration::from_secs(5));
    }

    #[test]
    fn signed_policy_deadline_rejects_expired_or_zero_lifetime() {
        let base = Instant::now();
        assert!(signed_policy_deadline(1_000, 1_000, base).is_err());
        assert!(signed_policy_deadline(999, 1_000, base).is_err());
    }

    #[test]
    fn parse_server_fp_roundtrip_and_rejects_bad_input() {
        assert!(parse_server_fp(&None).is_err());
        let fp = "be8fdb5fc5b51a5ca0180d1b7281d5ce3be3f104884603c6e7e4d621ecc133da";
        let parsed = parse_server_fp(&Some(fp.to_string())).unwrap();
        assert_eq!(hex::encode(parsed), fp);
        // wrong length and non-hex are rejected, not silently accepted.
        assert!(parse_server_fp(&Some("dead".to_string())).is_err());
        assert!(parse_server_fp(&Some("zz".repeat(32))).is_err());
    }

    fn valid_manual_reality_uri() -> String {
        format!(
            "shadowpipe://{}@127.0.0.1:443?sni=cover.test&sid=0123456789abcdef&fp={}",
            "11".repeat(32),
            "22".repeat(32)
        )
    }

    #[test]
    fn manual_reality_selectors_are_full_width_lowercase_only() {
        assert_eq!(
            parse_short_id("0123456789abcdef").unwrap(),
            hex::decode("0123456789abcdef").unwrap()
        );
        for invalid in [
            "",
            "00",
            "0123456789abcde",
            "0123456789abcdef00",
            "0123456789abcdeF",
            "0123456789abcdeg",
            " 0123456789abcdef",
            "0123456789abcdef ",
        ] {
            assert!(parse_short_id(invalid).is_err(), "accepted {invalid:?}");
        }

        let valid = valid_manual_reality_uri();
        assert_eq!(parse_client_uri_list(&valid).unwrap().len(), 1);
        for invalid in [
            valid.replace("sid=0123456789abcdef", "sid="),
            valid.replace("sid=0123456789abcdef", "sid=01"),
            valid.replace("sid=0123456789abcdef", "sid=0123456789abcdeF"),
            valid.replace("&sid=0123456789abcdef", ""),
            format!("{valid}&sid=0123456789abcdef"),
            format!("{valid}&sni=second.test"),
            format!("{valid}&unknown=value"),
        ] {
            assert!(
                parse_client_uri_list(&invalid).is_err(),
                "accepted malformed manual URI"
            );
        }
        let low_order = valid.replacen(&"11".repeat(32), &"00".repeat(32), 1);
        assert!(parse_client_uri_list(&low_order).is_err());

        let direct_low_order =
            Args::try_parse_from(["shadowpipe-client", "--reality-pubkey", &"00".repeat(32)])
                .unwrap();
        assert!(reality_server_pub(&direct_low_order)
            .unwrap_err()
            .to_string()
            .contains("non-contributory"));
    }

    #[test]
    fn uri_sources_and_manual_authorities_are_strictly_exclusive() {
        let uri = valid_manual_reality_uri();
        for argv in [
            vec![
                "shadowpipe-client",
                "--uri",
                uri.as_str(),
                "--uri-file",
                "endpoint.uri",
            ],
            vec![
                "shadowpipe-client",
                "--uri-file",
                "endpoint.uri",
                "--server-fp",
                "22",
            ],
            vec![
                "shadowpipe-client",
                "--uri-file",
                "endpoint.uri",
                "--reality-short-id",
                "0123456789abcdef",
            ],
            vec![
                "shadowpipe-client",
                "--uri-file",
                "endpoint.uri",
                "--policy-bundle",
                "policy.cbor",
            ],
        ] {
            assert!(Args::try_parse_from(argv).is_err());
        }
    }

    #[cfg(unix)]
    struct UriFileTestDir(PathBuf);

    #[cfg(unix)]
    impl UriFileTestDir {
        fn create() -> Self {
            use std::os::unix::fs::PermissionsExt;
            // The production loader deliberately rejects every writable/symlink
            // ancestor. Test source trees are often copied below `/var/tmp` on
            // Linux ARM64, so current_dir would make a valid fixture fail on the
            // world-writable staging ancestor before reaching the case under
            // test. HOME is the same trusted user-owned root used by the
            // development credential path; the unique child remains 0700.
            let base = PathBuf::from(std::env::var_os("HOME").expect("HOME for URI-file test"));
            let path = base.join(format!(
                "shadowpipe-uri-file-test-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn private_file(&self, name: &str, contents: &[u8]) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let path = self.0.join(name);
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }

    #[cfg(unix)]
    impl Drop for UriFileTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn uri_file_loader_rejects_links_modes_special_files_and_bounds() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = UriFileTestDir::create();
        let valid = format!("{}\n", valid_manual_reality_uri());
        let good = root.private_file("good.uri", valid.as_bytes());
        assert_eq!(read_private_uri_file(&good, true, false).unwrap(), valid);

        let symlink_path = root.0.join("symlink.uri");
        symlink(&good, &symlink_path).unwrap();
        assert!(read_private_uri_file(&symlink_path, true, false).is_err());

        let real_parent = root.0.join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent_file = real_parent.join("endpoint.uri");
        std::fs::write(&parent_file, valid.as_bytes()).unwrap();
        std::fs::set_permissions(&parent_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let linked_parent = root.0.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(
            read_private_uri_file(&linked_parent.join("endpoint.uri"), true, false)
                .unwrap_err()
                .to_string()
                .contains("not a real directory")
        );

        let writable_parent = root.0.join("writable-parent");
        std::fs::create_dir(&writable_parent).unwrap();
        std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let writable_file = writable_parent.join("endpoint.uri");
        std::fs::write(&writable_file, valid.as_bytes()).unwrap();
        std::fs::set_permissions(&writable_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private_uri_file(&writable_file, true, false)
            .unwrap_err()
            .to_string()
            .contains("group/world writable"));

        let hardlink_path = root.0.join("hardlink.uri");
        std::fs::hard_link(&good, &hardlink_path).unwrap();
        assert!(read_private_uri_file(&good, true, false)
            .unwrap_err()
            .to_string()
            .contains("exactly one hard link"));
        std::fs::remove_file(hardlink_path).unwrap();

        let permissive = root.private_file("permissive.uri", valid.as_bytes());
        std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_private_uri_file(&permissive, true, false)
            .unwrap_err()
            .to_string()
            .contains("exact mode 0600"));

        let oversized = root.private_file(
            "oversized.uri",
            &vec![b'x'; (MAX_URI_FILE_BYTES + 1) as usize],
        );
        assert!(read_private_uri_file(&oversized, true, false)
            .unwrap_err()
            .to_string()
            .contains("byte bound"));

        let empty = root.private_file("empty.uri", b"");
        assert!(read_private_uri_file(&empty, true, false)
            .unwrap_err()
            .to_string()
            .contains("is empty"));

        let fifo = root.0.join("fifo.uri");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_c is NUL-terminated and points to a valid pathname.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(read_private_uri_file(&fifo, true, false)
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn uri_file_loader_enforces_owner_and_parses_before_credential_state() {
        use std::os::unix::ffi::OsStrExt;

        let root = UriFileTestDir::create();
        let malformed = root.private_file("malformed.uri", b"not-a-shadowpipe-uri\n");
        let mut args = Args::try_parse_from([
            "shadowpipe-client",
            "--development-user-credential",
            "--uri-file",
            malformed.to_str().unwrap(),
        ])
        .unwrap();
        let error = load_uri_file_source(&mut args).unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("parse private REALITY URI file"));
        assert!(!detail.contains("not-a-shadowpipe-uri"));
        assert!(args.uri.is_empty());

        // A production URI source is never silently downgraded to user-owned
        // semantics. Non-root tests must fail before open; root tests exercise
        // an explicit foreign-owner mismatch instead.
        // SAFETY: geteuid takes no arguments and has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            let error = read_private_uri_file(&malformed, false, false)
                .unwrap_err()
                .to_string();
            assert!(error.contains("effective UID 0"));
        } else {
            let foreign = root.private_file("foreign.uri", valid_manual_reality_uri().as_bytes());
            let foreign_c = std::ffi::CString::new(foreign.as_os_str().as_bytes()).unwrap();
            // SAFETY: foreign_c is a valid NUL-terminated pathname; this branch
            // runs only as root and the test-owned file is removed on drop.
            assert_eq!(unsafe { libc::chown(foreign_c.as_ptr(), 1, 1) }, 0);
            let error = read_private_uri_file(&foreign, false, false)
                .unwrap_err()
                .to_string();
            assert!(error.contains("root:root"));
        }
    }

    #[test]
    fn signed_policy_mode_is_exclusive_and_requires_explicit_enrollment() {
        let root_kid = "10".repeat(16);
        let root_key = "20".repeat(32);
        let policy = Args::try_parse_from([
            "shadowpipe-client",
            "--tunnel",
            "--auto-route",
            "--kill-switch",
            "--dns",
            "10.8.0.1",
            "--policy-bundle",
            "policy.cbor",
            "--policy-root-kid",
            &root_kid,
            "--policy-root-key",
            &root_key,
        ])
        .unwrap();
        validate_policy_authority(&policy).unwrap();

        let mixed = Args::try_parse_from([
            "shadowpipe-client",
            "--tunnel",
            "--auto-route",
            "--kill-switch",
            "--dns",
            "10.8.0.1",
            "--policy-bundle",
            "policy.cbor",
            "--policy-root-kid",
            &root_kid,
            "--policy-root-key",
            &root_key,
            "--server-fp",
            &"30".repeat(32),
        ])
        .unwrap();
        assert!(validate_policy_authority(&mixed)
            .unwrap_err()
            .to_string()
            .contains("no fallback"));

        assert!(Args::try_parse_from(["shadowpipe-client", "--policy-enroll"]).is_err());
        assert_eq!(parse_fixed_hex::<16>("kid", &root_kid).unwrap(), [0x10; 16]);
        assert!(parse_fixed_hex::<16>("kid", "dead").is_err());
    }

    #[test]
    fn runtime_safety_rejects_fail_open_tunnel_combinations() {
        let fp = "11".repeat(32);
        let plain =
            Args::try_parse_from(["shadowpipe-client", "--server-fp", &fp, "--message", "ok"])
                .unwrap();
        validate_runtime_safety(&plain).unwrap();

        let missing_guard = Args::try_parse_from([
            "shadowpipe-client",
            "--server-fp",
            &fp,
            "--tunnel",
            "--auto-route",
        ])
        .unwrap();
        assert!(validate_runtime_safety(&missing_guard).is_err());

        let missing_dns = Args::try_parse_from([
            "shadowpipe-client",
            "--server-fp",
            &fp,
            "--tunnel",
            "--auto-route",
            "--kill-switch",
        ])
        .unwrap();
        assert!(validate_runtime_safety(&missing_dns).is_err());

        let misplaced_guard =
            Args::try_parse_from(["shadowpipe-client", "--server-fp", &fp, "--kill-switch"])
                .unwrap();
        assert!(validate_runtime_safety(&misplaced_guard).is_err());

        let split_without_tun =
            Args::try_parse_from(["shadowpipe-client", "--server-fp", &fp, "--split"]).unwrap();
        assert!(validate_runtime_safety(&split_without_tun).is_err());
    }

    #[test]
    fn runtime_safety_defaults_to_explicit_fail_closed_ipv6_blocking() {
        let fp = "11".repeat(32);
        let default =
            Args::try_parse_from(["shadowpipe-client", "--server-fp", &fp, "--message", "ok"])
                .unwrap();
        assert_eq!(default.ipv6_mode, Ipv6ModeArg::Block);
        assert_eq!(Ipv6Mode::from(default.ipv6_mode), Ipv6Mode::Block);
        validate_runtime_safety(&default).unwrap();

        let explicit = Args::try_parse_from([
            "shadowpipe-client",
            "--server-fp",
            &fp,
            "--message",
            "ok",
            "--ipv6-mode",
            "block",
        ])
        .unwrap();
        assert_eq!(explicit.ipv6_mode, Ipv6ModeArg::Block);
        validate_runtime_safety(&explicit).unwrap();

        #[cfg(target_os = "linux")]
        {
            let full_tunnel = Args::try_parse_from([
                "shadowpipe-client",
                "--server-fp",
                &fp,
                "--tunnel",
                "--auto-route",
                "--kill-switch",
                "--dns",
                "10.8.0.1",
                "--ipv6-mode",
                "block",
            ])
            .unwrap();
            validate_runtime_safety(&full_tunnel).unwrap();
        }
    }

    #[test]
    fn runtime_safety_rejects_unimplemented_ipv6_modes_before_other_preflight() {
        for mode in ["outer-only", "tunnel"] {
            let args = Args::try_parse_from([
                "shadowpipe-client",
                "--server-fp",
                "malformed",
                "--kill-switch",
                "--ipv6-mode",
                mode,
            ])
            .unwrap();
            let error = validate_runtime_safety(&args).unwrap_err().to_string();
            assert!(
                error.contains(&format!("--ipv6-mode {mode} is not implemented")),
                "unexpected error for {mode}: {error}"
            );
        }
    }

    #[test]
    fn unavailable_carriers_fail_preflight_before_runtime_state() {
        #[cfg(any(not(feature = "quic"), not(feature = "tls-chrome")))]
        let fp = "11".repeat(32);
        #[cfg(not(feature = "quic"))]
        {
            let args =
                Args::try_parse_from(["shadowpipe-client", "--server-fp", &fp, "--quic"]).unwrap();
            let error = validate_runtime_safety(&args).unwrap_err().to_string();
            assert!(error.contains("--features quic"));
        }
        #[cfg(not(feature = "tls-chrome"))]
        {
            let args =
                Args::try_parse_from(["shadowpipe-client", "--server-fp", &fp, "--tls"]).unwrap();
            let error = validate_runtime_safety(&args).unwrap_err().to_string();
            assert!(error.contains("--features tls-chrome"));
        }
        let dns_error = parse_camouflage("dns").unwrap_err().to_string();
        assert!(dns_error.contains("not implemented"));
    }

    #[test]
    fn credential_provisioning_is_exclusive_with_network_and_host_modes() {
        assert!(Args::try_parse_from([
            "shadowpipe-client",
            "--generate-client-credential",
            "--write-client-enrollment",
            "enrollment.json",
            "--client-credential",
            "credential.json",
        ])
        .is_ok());
        assert!(Args::try_parse_from([
            "shadowpipe-client",
            "--write-client-enrollment",
            "enrollment.json",
            "--client-credential",
            "credential.json",
        ])
        .is_ok());

        for forbidden in [
            ["--tunnel", ""],
            ["--server", "198.51.100.7:443"],
            ["--uri", "shadowpipe://invalid"],
            ["--release-lockdown", ""],
        ] {
            let mut argv = vec![
                "shadowpipe-client",
                "--write-client-enrollment",
                "enrollment.json",
            ];
            argv.push(forbidden[0]);
            if !forbidden[1].is_empty() {
                argv.push(forbidden[1]);
            }
            assert!(Args::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn runtime_deadline_cli_rejects_zero_unbounded_and_incoherent_values() {
        let fp = "11".repeat(32);
        for flags in [
            vec!["--connect-timeout-secs", "0"],
            vec!["--outer-handshake-timeout-secs", "121"],
            vec!["--carrier-idle-timeout-secs", "901"],
            vec![
                "--carrier-probe-timeout-secs",
                "5",
                "--carrier-write-timeout-secs",
                "6",
            ],
        ] {
            let mut argv = vec!["shadowpipe-client", "--server-fp", fp.as_str()];
            argv.extend(flags);
            let args = Args::try_parse_from(argv).unwrap();
            assert!(RuntimeDeadlines::from_args(&args).is_err());
            assert!(validate_runtime_safety(&args).is_err());
        }
    }

    #[test]
    fn measurement_flags_are_opt_in_no_tun_and_validate_before_connect() {
        const EXPERIMENT_ID: &str = "11111111111111111111111111111111";
        const ARTIFACT_ID: &str = "22222222222222222222222222222222";
        let args = Args::try_parse_from([
            "shadowpipe-client",
            "--loadtest",
            "1",
            "--measurement-json",
            "trace.json",
            "--measurement-scope",
            "loopback",
            "--measurement-environment",
            "continuous-integration",
            "--experiment-id",
            EXPERIMENT_ID,
            "--artifact-id",
            ARTIFACT_ID,
        ])
        .unwrap();
        let output = measurement_output(&args, CamouflageMode::H2Chunk)
            .unwrap()
            .unwrap();
        assert_eq!(output.path, PathBuf::from("trace.json"));
        assert_eq!(output.scope, EvidenceScope::Loopback);
        assert_eq!(
            output.environment,
            ExecutionEnvironment::ContinuousIntegration
        );
        assert_eq!(output.transport, TransportKind::Http2);
        assert_eq!(output.experiment_id.to_string(), EXPERIMENT_ID);
        assert_eq!(output.artifact_id.to_string(), ARTIFACT_ID);

        let zero_load = Args::try_parse_from([
            "shadowpipe-client",
            "--measurement-json",
            "trace.json",
            "--measurement-scope",
            "loopback",
            "--measurement-environment",
            "continuous-integration",
            "--experiment-id",
            EXPERIMENT_ID,
            "--artifact-id",
            ARTIFACT_ID,
        ])
        .unwrap();
        assert!(measurement_output(&zero_load, CamouflageMode::Raw).is_err());

        let oversized = Args::try_parse_from([
            "shadowpipe-client",
            "--loadtest",
            "1025",
            "--measurement-json",
            "trace.json",
            "--measurement-scope",
            "virtual-machine",
            "--measurement-environment",
            "virtual-machine",
            "--experiment-id",
            EXPERIMENT_ID,
            "--artifact-id",
            ARTIFACT_ID,
        ])
        .unwrap();
        assert!(measurement_output(&oversized, CamouflageMode::Raw).is_err());

        let unpinned_field = Args::try_parse_from([
            "shadowpipe-client",
            "--loadtest",
            "1",
            "--measurement-json",
            "trace.json",
            "--measurement-scope",
            "target-network",
            "--measurement-environment",
            "bare-metal",
            "--experiment-id",
            EXPERIMENT_ID,
            "--artifact-id",
            ARTIFACT_ID,
        ])
        .unwrap();
        assert!(measurement_output(&unpinned_field, CamouflageMode::Raw).is_err());

        let mut pinned_field = unpinned_field;
        pinned_field.server_fp = Some("11".repeat(32));
        assert!(measurement_output(&pinned_field, CamouflageMode::Raw).is_ok());

        assert!(Args::try_parse_from([
            "shadowpipe-client",
            "--tunnel",
            "--loadtest",
            "1",
            "--measurement-json",
            "trace.json",
            "--measurement-scope",
            "loopback",
            "--measurement-environment",
            "continuous-integration",
            "--experiment-id",
            EXPERIMENT_ID,
            "--artifact-id",
            ARTIFACT_ID,
        ])
        .is_err());

        assert!(Args::try_parse_from([
            "shadowpipe-client",
            "--loadtest",
            "1",
            "--measurement-json",
            "trace.json",
            "--measurement-scope",
            "loopback",
            "--measurement-environment",
            "continuous-integration",
        ])
        .is_err());
    }

    fn test_measurement_output(path: PathBuf) -> MeasurementOutput {
        MeasurementOutput {
            path,
            scope: EvidenceScope::Loopback,
            environment: ExecutionEnvironment::ContinuousIntegration,
            transport: TransportKind::Tcp,
            experiment_id: PublicId::from_bytes([0x11; PublicId::BYTE_LEN]).unwrap(),
            artifact_id: PublicId::from_bytes([0x22; PublicId::BYTE_LEN]).unwrap(),
        }
    }

    fn unique_measurement_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "shadowpipe-{label}-{}-{}.json",
            std::process::id(),
            random_public_id()
        ))
    }

    fn read_valid_trace(path: &Path) -> MeasurementRun {
        let encoded = std::fs::read(path).expect("read published measurement");
        let run: MeasurementRun = serde_json::from_slice(&encoded).expect("decode measurement");
        run.validate().expect("measurement validates");
        assert_eq!(run.evidence.outcome, EvidenceOutcome::Pending);
        assert!(matches!(
            run.events.last().map(|event| &event.event),
            Some(EventKind::Close { .. })
        ));
        run
    }

    #[tokio::test]
    async fn measured_loadtest_spans_auth_and_writes_bounded_trace() {
        let (client_io, mut server_io) = tokio::io::duplex(128 * 1024);
        let state = Arc::new(ServerState::generate());
        let server_fingerprint = state.fingerprint();
        let (credential, authorized) = test_client_auth();
        let server = tokio::spawn(async move {
            let (mut session, _, _) = AuthenticatedSession::server_accept(
                &mut server_io,
                &state,
                &authorized,
                CamouflageMode::Raw,
            )
            .await
            .unwrap();
            loop {
                let (stream_id, flags, payload, _) = session.recv(&mut server_io).await.unwrap();
                if flags.contains(FrameFlags::FIN) {
                    break;
                }
                session
                    .send(&mut server_io, stream_id, FrameFlags::DATA, &payload)
                    .await
                    .unwrap();
            }
        });

        let output_path = unique_measurement_path("loadtest");
        let measurement =
            LoadtestMeasurement::reserve(test_measurement_output(output_path.clone())).unwrap();
        let reserved_temp = measurement.reservation.temp_path.clone();
        assert!(
            !output_path.exists(),
            "preflight must not expose partial JSON"
        );
        assert!(reserved_temp.exists(), "pre-socket temp must be reserved");
        let config = ClientConfig::pinned(server_fingerprint, credential);

        establish_and_run_measured(
            async { Ok(client_io) },
            &config,
            1,
            measurement,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert!(!reserved_temp.exists(), "published temp must be unlinked");

        let encoded = tokio::fs::read(&output_path).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&output_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(
            encoded.len() < 16 * 1024,
            "trace must remain structurally bounded"
        );
        let run = read_valid_trace(&output_path);
        assert!(run.events.len() <= LOADTEST_MEASUREMENT_MAX_EVENTS);
        assert_eq!(run.evidence.scope, EvidenceScope::Loopback);
        assert_eq!(run.evidence.outcome, EvidenceOutcome::Pending);
        assert_eq!(
            run.metadata.environment,
            ExecutionEnvironment::ContinuousIntegration
        );
        assert_eq!(
            run.metadata.experiment_id,
            Some(PublicId::from_bytes([0x11; PublicId::BYTE_LEN]).unwrap())
        );
        assert_eq!(
            run.metadata.artifact_id,
            Some(PublicId::from_bytes([0x22; PublicId::BYTE_LEN]).unwrap())
        );
        assert!(matches!(
            run.events.first().map(|event| &event.event),
            Some(EventKind::Dial {
                outcome: DialOutcome::Connected,
                ..
            })
        ));
        assert!(run.events.iter().any(|event| matches!(
            event.event,
            EventKind::Close {
                outcome: CloseOutcome::Clean,
                transmitted_payload_bytes: 1_048_576,
                received_payload_bytes: 1_048_576,
            }
        )));

        let json = String::from_utf8(encoded).unwrap();
        for forbidden in ["127.0.0.1", "localhost", "server_fp", "session_id"] {
            assert!(!json.contains(forbidden));
        }
        assert!(MeasurementReservation::reserve(output_path.clone()).is_err());
        tokio::fs::remove_file(output_path).await.unwrap();
    }

    #[tokio::test]
    async fn sender_failure_is_published_then_returned() {
        let (client_io, mut server_io) = tokio::io::duplex(128 * 1024);
        let state = Arc::new(ServerState::generate());
        let server_fingerprint = state.fingerprint();
        let (credential, authorized) = test_client_auth();
        let server = tokio::spawn(async move {
            let (mut session, _, _) = AuthenticatedSession::server_accept(
                &mut server_io,
                &state,
                &authorized,
                CamouflageMode::Raw,
            )
            .await
            .unwrap();
            session
                .send(&mut server_io, 0, FrameFlags::FIN, b"synthetic close")
                .await
                .unwrap();
        });

        let fail = Arc::new(AtomicBool::new(false));
        let mut client_io = FailWrites {
            inner: client_io,
            fail: Arc::clone(&fail),
        };
        let config = ClientConfig::pinned(server_fingerprint, credential);
        let (session, session_id) = AuthenticatedSession::client_connect(&mut client_io, &config)
            .await
            .unwrap();
        server.await.unwrap();
        fail.store(true, Ordering::Relaxed);

        let output_path = unique_measurement_path("sender-failure");
        let mut measurement =
            LoadtestMeasurement::reserve(test_measurement_output(output_path.clone())).unwrap();
        measurement
            .record_dial(Duration::from_millis(1), DialOutcome::Connected)
            .unwrap();
        measurement.record_selected_path().unwrap();

        let result = run_loadtest_established(
            client_io,
            session,
            session_id,
            1,
            Some(measurement),
            Duration::from_millis(1),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("synthetic writer failure"),
            "the real sender error must survive trace publication"
        );

        let run = read_valid_trace(&output_path);
        assert!(matches!(
            run.events.last().map(|event| &event.event),
            Some(EventKind::Close {
                outcome: CloseOutcome::TransportError,
                transmitted_payload_bytes: 0,
                received_payload_bytes: 0,
            })
        ));
        std::fs::remove_file(output_path).unwrap();
    }

    #[tokio::test]
    async fn outer_failure_publishes_terminal_pending_trace() {
        let output_path = unique_measurement_path("outer-failure");
        let measurement =
            LoadtestMeasurement::reserve(test_measurement_output(output_path.clone())).unwrap();
        let (credential, _) = test_client_auth();
        let config = ClientConfig::pinned([0x11; 32], credential);
        let result = establish_and_run_measured(
            async {
                Err::<tokio::io::DuplexStream, _>(
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "synthetic refusal")
                        .into(),
                )
            },
            &config,
            1,
            measurement,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());

        let run = read_valid_trace(&output_path);
        assert!(matches!(
            run.events.first().map(|event| &event.event),
            Some(EventKind::Dial {
                outcome: DialOutcome::Refused,
                ..
            })
        ));
        assert!(matches!(
            run.events.last().map(|event| &event.event),
            Some(EventKind::Close {
                outcome: CloseOutcome::TransportError,
                transmitted_payload_bytes: 0,
                received_payload_bytes: 0,
            })
        ));
        std::fs::remove_file(output_path).unwrap();
    }

    #[tokio::test]
    async fn inner_auth_failure_publishes_terminal_pending_trace() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        drop(server_io);
        let output_path = unique_measurement_path("inner-failure");
        let measurement =
            LoadtestMeasurement::reserve(test_measurement_output(output_path.clone())).unwrap();
        let result = establish_and_run_measured(
            async { Ok(client_io) },
            &ClientConfig::pinned([0x11; 32], test_client_auth().0),
            1,
            measurement,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());

        let run = read_valid_trace(&output_path);
        assert!(matches!(
            run.events.first().map(|event| &event.event),
            Some(EventKind::Dial {
                outcome: DialOutcome::ProtocolError,
                ..
            })
        ));
        assert!(matches!(
            run.events.last().map(|event| &event.event),
            Some(EventKind::Close {
                outcome: CloseOutcome::ProtocolError,
                ..
            })
        ));
        std::fs::remove_file(output_path).unwrap();
    }

    #[tokio::test]
    async fn pin_mismatch_is_classified_as_authentication_failure() {
        let (client_io, mut server_io) = tokio::io::duplex(128 * 1024);
        let (credential, authorized) = test_client_auth();
        let server = tokio::spawn(async move {
            let state = ServerState::generate();
            AuthenticatedSession::server_accept(
                &mut server_io,
                &state,
                &authorized,
                CamouflageMode::Raw,
            )
            .await
        });
        let output_path = unique_measurement_path("pin-mismatch");
        let measurement =
            LoadtestMeasurement::reserve(test_measurement_output(output_path.clone())).unwrap();
        let config = ClientConfig {
            server_fingerprint: [0xA5; 32],
            camouflage: CamouflageMode::Raw,
            padding_profile: PaddingProfile::Balanced,
            client_credential: credential,
        };

        let result = establish_and_run_measured(
            async { Ok(client_io) },
            &config,
            1,
            measurement,
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_err());
        let _ = server.await;

        let run = read_valid_trace(&output_path);
        assert!(matches!(
            run.events.first().map(|event| &event.event),
            Some(EventKind::Dial {
                outcome: DialOutcome::AuthenticationRejected,
                ..
            })
        ));
        assert!(matches!(
            run.events.last().map(|event| &event.event),
            Some(EventKind::Close {
                outcome: CloseOutcome::AuthenticationError,
                transmitted_payload_bytes: 0,
                received_payload_bytes: 0,
            })
        ));
        std::fs::remove_file(output_path).unwrap();
    }

    #[tokio::test]
    async fn establishment_timeout_publishes_terminal_pending_trace() {
        let output_path = unique_measurement_path("dial-timeout");
        let measurement =
            LoadtestMeasurement::reserve(test_measurement_output(output_path.clone())).unwrap();
        let result = establish_and_run_measured(
            std::future::pending::<Result<tokio::io::DuplexStream>>(),
            &ClientConfig::pinned([0x11; 32], test_client_auth().0),
            1,
            measurement,
            Duration::from_millis(10),
        )
        .await;
        assert!(result.is_err());

        let run = read_valid_trace(&output_path);
        assert!(matches!(
            run.events.first().map(|event| &event.event),
            Some(EventKind::Dial {
                outcome: DialOutcome::TimedOut,
                ..
            })
        ));
        assert!(matches!(
            run.events.last().map(|event| &event.event),
            Some(EventKind::Close {
                outcome: CloseOutcome::TimedOut,
                ..
            })
        ));
        std::fs::remove_file(output_path).unwrap();
    }

    #[test]
    fn publication_is_atomic_no_clobber_and_cleans_reserved_temp() {
        let output_path = unique_measurement_path("no-clobber");
        let measurement =
            LoadtestMeasurement::reserve(test_measurement_output(output_path.clone())).unwrap();
        let temp_path = measurement.reservation.temp_path.clone();
        assert_eq!(
            normalized_parent(&temp_path),
            normalized_parent(&output_path)
        );
        std::fs::write(&output_path, b"competitor\n").unwrap();

        let result = finish_failed_establishment(
            measurement,
            Duration::from_millis(1),
            DialOutcome::Refused,
            CloseOutcome::TransportError,
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&output_path).unwrap(), b"competitor\n");
        assert!(
            !temp_path.exists(),
            "failed publication temp must be cleaned"
        );
        std::fs::remove_file(output_path).unwrap();
    }
}
