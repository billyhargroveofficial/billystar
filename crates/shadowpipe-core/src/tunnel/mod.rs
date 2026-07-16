use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{watch, Mutex};
use tracing::{debug, info, warn};

use crate::mux::{encode_packet, MuxConfig, Reassembler};
use crate::pacing::{
    build_ping_reply, build_ping_request, parse_ping, DegradationPacer, PacerConfig,
    PathStatsSource, PingMsg, TcpAppRttProbe,
};
use crate::packet::fix_ipv4_checksum;
use crate::proto::FrameFlags;
use crate::session::AuthenticatedSession;
use crate::tun_dev::{TunConfig, TunnelIo};
use crate::volume_guard::{RotateSignal, VolumeGuard, VolumeGuardConfig};

/// Tunnel ended because the volume guard requires a fresh TCP 5-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotateConnection;

impl std::fmt::Display for RotateConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "volume guard: TCP connection rotation required")
    }
}

impl std::error::Error for RotateConnection {}

/// An established, authenticated carrier stopped producing authenticated
/// frames after an encrypted PING probe. The client maps this typed condition
/// to endpoint rotation/backoff; it is never a clean daemon shutdown signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadCarrier;

impl std::fmt::Display for DeadCarrier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "authenticated carrier liveness deadline expired")
    }
}

impl std::error::Error for DeadCarrier {}

/// Bounded authenticated dead-peer detection for an established tunnel.
/// Activity is recorded only after `AuthenticatedSession::recv` authenticates a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierLivenessConfig {
    idle_timeout: Duration,
    probe_timeout: Duration,
    write_timeout: Duration,
}

impl CarrierLivenessConfig {
    const MIN_TIMEOUT: Duration = Duration::from_millis(10);
    const MAX_TIMEOUT: Duration = Duration::from_secs(15 * 60);

    pub fn new(
        idle_timeout: Duration,
        probe_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self> {
        for (name, value) in [
            ("idle timeout", idle_timeout),
            ("probe timeout", probe_timeout),
            ("write timeout", write_timeout),
        ] {
            anyhow::ensure!(
                (Self::MIN_TIMEOUT..=Self::MAX_TIMEOUT).contains(&value),
                "carrier {name} must be between {:?} and {:?}",
                Self::MIN_TIMEOUT,
                Self::MAX_TIMEOUT
            );
        }
        anyhow::ensure!(
            write_timeout <= probe_timeout,
            "carrier write timeout must not exceed probe timeout"
        );
        Ok(Self {
            idle_timeout,
            probe_timeout,
            write_timeout,
        })
    }

    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }

    pub const fn probe_timeout(self) -> Duration {
        self.probe_timeout
    }

    pub const fn write_timeout(self) -> Duration {
        self.write_timeout
    }
}

fn jittered_idle_delay(maximum: Duration, random: u64) -> Duration {
    let fraction = (random >> 11) as f64 / (1u64 << 53) as f64;
    // Probe no later than the operator's configured maximum while avoiding a
    // fixed cadence that itself becomes a trivial timing feature.
    maximum.mul_f64(0.80 + 0.20 * fraction)
}

pub async fn run_tunnel<S>(
    tun: impl Into<TunnelIo>,
    stream: S,
    session: AuthenticatedSession,
    mux: MuxConfig,
    mtu: u16,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_tunnel_guarded(
        tun,
        stream,
        session,
        mux,
        mtu,
        VolumeGuard::disabled(),
        Arc::new(DegradationPacer::disabled()),
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_guarded<S>(
    tun: impl Into<TunnelIo>,
    stream: S,
    session: AuthenticatedSession,
    mux: MuxConfig,
    mtu: u16,
    guard: VolumeGuard,
    pacer: Arc<DegradationPacer>,
    carrier_stats: Option<Arc<dyn PathStatsSource>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_tunnel_guarded_with_liveness(
        tun,
        stream,
        session,
        mux,
        mtu,
        guard,
        pacer,
        carrier_stats,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_guarded_with_liveness<S>(
    tun: impl Into<TunnelIo>,
    stream: S,
    session: AuthenticatedSession,
    mux: MuxConfig,
    mtu: u16,
    guard: VolumeGuard,
    pacer: Arc<DegradationPacer>,
    carrier_stats: Option<Arc<dyn PathStatsSource>>,
    liveness: Option<CarrierLivenessConfig>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tun: TunnelIo = tun.into();
    let (session_tx, session_rx) = session.split();
    let session_tx = Arc::new(Mutex::new(session_tx));
    let session_rx = Arc::new(Mutex::new(session_rx));
    let guard = Arc::new(guard);
    // The pacer's goodput signal is QUIC `cwnd/rtt`. A QUIC carrier passes
    // `Some(carrier_stats)`; a TCP carrier passes `None`, so when `--pace` is set on
    // TCP we build an app-RTT probe (PING/reply RTT + peer delivered-rate + stall)
    // as the gate-independent signal instead of going inert. The typed handle is
    // also threaded into the downlink/originator tasks below.
    let (carrier_stats, tcp_probe): (
        Option<Arc<dyn PathStatsSource>>,
        Option<Arc<TcpAppRttProbe>>,
    ) = if pacer.is_enabled() && carrier_stats.is_none() {
        let cfg = pacer.config();
        let probe = Arc::new(TcpAppRttProbe::new(cfg.reference_rate_bps, cfg.ewma_alpha));
        info!("--pace on a TCP carrier: driving the pacer from the app-RTT PING probe");
        (Some(probe.clone() as Arc<dyn PathStatsSource>), Some(probe))
    } else {
        (carrier_stats, None)
    };
    let packet_id = Arc::new(AtomicU32::new(0));
    let (mut tcp_read, tcp_write) = tokio::io::split(stream);
    let tcp_write = Arc::new(Mutex::new(tcp_write));
    let (authenticated_rx_tx, authenticated_rx_rx) = watch::channel(Instant::now());

    let tun_to_tcp = {
        let tun = tun.clone();
        let session_tx = Arc::clone(&session_tx);
        let packet_id = Arc::clone(&packet_id);
        let mux = mux.clone();
        let tcp_write = Arc::clone(&tcp_write);
        let guard = Arc::clone(&guard);
        let pacer = Arc::clone(&pacer);
        async move {
            let mut buf = vec![0u8; mtu as usize + 128];
            loop {
                let n = tun.read_packet(&mut buf).await?;
                if n == 0 {
                    continue;
                }
                let id = packet_id.fetch_add(1, Ordering::Relaxed);
                let frames = encode_packet(&buf[..n], id, &mux)?;
                debug!(n, frames = frames.len(), "tun -> tcp");
                // Degradation-symmetric gate: throttle the covert send rate to the
                // path's own goodput. Gate on the estimated WIRE size (≈ payload +
                // ~160 B/frame for mux header + AEAD tag + avg padding) so it shares
                // the unit `on_sent(wire)` feeds back. Done BEFORE the session lock,
                // so a paced sleep never stalls the downlink's PING reply. No-op when
                // the pacer is disabled.
                let wire_est: usize = frames.iter().map(|(_, p)| p.len() + 160).sum();
                pacer.gate(wire_est).await;
                let mut sess = session_tx.lock().await;
                for (stream_id, payload) in frames {
                    let wire = sess
                        .send(
                            &mut *tcp_write.lock().await,
                            stream_id,
                            FrameFlags::DATA,
                            &payload,
                        )
                        .await?;
                    guard
                        .record_sent(wire)
                        .map_err(|RotateSignal| RotateConnection)?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };

    let tcp_to_tun = {
        let tun = tun.clone();
        let session_rx = Arc::clone(&session_rx);
        let session_tx = Arc::clone(&session_tx);
        let tcp_write = Arc::clone(&tcp_write);
        let guard = Arc::clone(&guard);
        let tcp_probe = tcp_probe.clone();
        let authenticated_rx_tx = authenticated_rx_tx.clone();
        async move {
            let mut reasm = Reassembler::new();
            loop {
                let (stream_id, flags, payload, wire) = {
                    let mut sess = session_rx.lock().await;
                    sess.recv(&mut tcp_read).await?
                };
                // `AuthenticatedSession::recv` returns only after AEAD verification;
                // unauthenticated carrier bytes can never refresh liveness.
                authenticated_rx_tx.send_replace(Instant::now());
                guard
                    .record_recv(wire)
                    .map_err(|RotateSignal| RotateConnection)?;

                if flags.contains(FrameFlags::FIN) {
                    break;
                }
                if flags.contains(FrameFlags::PING) {
                    match parse_ping(&payload) {
                        // Our echoed timestamp came back: an RTT sample. Never re-reply.
                        PingMsg::Reply(ts) => {
                            if let Some(p) = &tcp_probe {
                                p.on_reply(ts);
                            }
                        }
                        // A peer asks us to echo: reply with the same timestamp.
                        PingMsg::Request(ts) => {
                            let reply = build_ping_reply(ts);
                            let mut sess = session_tx.lock().await;
                            let sent = sess
                                .send(
                                    &mut *tcp_write.lock().await,
                                    stream_id,
                                    FrameFlags::PING,
                                    &reply,
                                )
                                .await?;
                            guard
                                .record_sent(sent)
                                .map_err(|RotateSignal| RotateConnection)?;
                        }
                        // Legacy `b"pong"` / old peer: no sample, no re-reply (a reply
                        // here would loop with an old binary's unconditional echo).
                        PingMsg::Legacy => {}
                    }
                    continue;
                }

                // Gate-independent delivered-rate signal for the TCP app-RTT pacer.
                if let Some(p) = &tcp_probe {
                    p.on_peer_data(wire);
                }

                if let Some(mut packet) = reasm.feed(&payload)? {
                    fix_ipv4_checksum(&mut packet);
                    debug!(len = packet.len(), "tcp -> tun");
                    tun.write_packet(&packet).await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
    };

    // Path-stats sampler: drives the pacer's control loop. Pends forever when the
    // pacer is disabled (so `select!` ignores it); reads carrier stats and updates
    // pacer atomics only — never touches the session/write locks, so it cannot
    // deadlock the send path. Torn down with the other futures when one exits.
    let sampler = {
        let pacer = Arc::clone(&pacer);
        let carrier_stats = carrier_stats.clone();
        async move {
            if !pacer.is_enabled() {
                std::future::pending::<()>().await;
            }
            // Sleep-per-iteration (re-reading sample_interval each tick) rather than
            // a fixed interval(), so the period can adapt as the path is learned.
            let mut floored = 0u32;
            let mut warned = false;
            loop {
                tokio::time::sleep(pacer.sample_interval()).await;
                // A path-stats source is present whenever the pacer is enabled:
                // QUIC `cwnd/rtt`, or the TCP app-RTT probe built above. When the
                // pacer is disabled this loop already pended out before here.
                if let Some(s) = &carrier_stats {
                    pacer.observe_path(s.sample());
                }
                debug!(
                    rate_bps = pacer.current_rate_bps() as u64,
                    goodput_bps = pacer.current_goodput_bps() as u64,
                    "pacer tick"
                );
                // Surface a collapse once: a long pin to the floor means the path
                // goodput cratered (or, on a TCP carrier, there is no capacity signal).
                if pacer.is_at_floor() {
                    floored += 1;
                    if floored >= 50 && !warned {
                        warn!("pacer pinned to min-rate floor (~50 ticks): path goodput collapsed or no capacity signal on this carrier");
                        warned = true;
                    }
                } else {
                    floored = 0;
                    warned = false;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };

    // PING originator: only active on a TCP carrier with `--pace` (when a probe was
    // built). Sends a timestamped PING on a jittered cadence so the probe can clock
    // RTT and detect reply-stall; pends forever otherwise. Not paced — keepalive
    // must flow even while the data path is throttled, so a freeze is detectable.
    let ping_origin = {
        let tcp_probe = tcp_probe.clone();
        let session_tx = Arc::clone(&session_tx);
        let tcp_write = Arc::clone(&tcp_write);
        let guard = Arc::clone(&guard);
        async move {
            let Some(probe) = tcp_probe else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            loop {
                tokio::time::sleep(probe.ping_interval()).await;
                let payload = probe.next_ping();
                let sent = {
                    let mut sess = session_tx.lock().await;
                    sess.send(&mut *tcp_write.lock().await, 0, FrameFlags::PING, &payload)
                        .await?
                };
                guard
                    .record_sent(sent)
                    .map_err(|RotateSignal| RotateConnection)?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };

    // Authenticated dead-peer detection is independent of traffic pacing. It
    // starts only after an idle interval, sends one encrypted PING under a
    // bounded write/lock deadline, and then requires any newly authenticated
    // frame before the response deadline. A blackholed socket therefore cannot
    // pin endpoint rotation forever, even if another task is stuck holding the
    // write lock.
    let liveness_monitor = {
        let session_tx = Arc::clone(&session_tx);
        let tcp_write = Arc::clone(&tcp_write);
        let guard = Arc::clone(&guard);
        let mut authenticated_rx_rx = authenticated_rx_rx;
        async move {
            let Some(config) = liveness else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            let mut probe_nonce = 0u64;
            let mut jitter_state = rand::random::<u64>();
            loop {
                let last_authenticated_rx = *authenticated_rx_rx.borrow_and_update();
                jitter_state = jitter_state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let idle_delay = jittered_idle_delay(config.idle_timeout(), jitter_state);
                let idle_deadline = last_authenticated_rx
                    .checked_add(idle_delay)
                    .ok_or_else(|| anyhow::anyhow!("carrier idle deadline overflow"))?;
                let idle_sleep =
                    tokio::time::sleep_until(tokio::time::Instant::from_std(idle_deadline));
                tokio::pin!(idle_sleep);
                tokio::select! {
                    biased;
                    changed = authenticated_rx_rx.changed() => {
                        changed.map_err(|_| anyhow::anyhow!("authenticated receive activity stream closed"))?;
                        continue;
                    }
                    _ = &mut idle_sleep => {}
                }

                let probe_started = Instant::now();
                probe_nonce = probe_nonce.wrapping_add(1);
                let payload = build_ping_request(probe_nonce);
                let sent = tokio::time::timeout(config.write_timeout(), async {
                    let mut session = session_tx.lock().await;
                    session
                        .send(&mut *tcp_write.lock().await, 0, FrameFlags::PING, &payload)
                        .await
                })
                .await
                .map_err(|_| DeadCarrier)??;
                guard
                    .record_sent(sent)
                    .map_err(|RotateSignal| RotateConnection)?;

                let probe_deadline = Instant::now()
                    .checked_add(config.probe_timeout())
                    .ok_or_else(|| anyhow::anyhow!("carrier probe deadline overflow"))?;
                loop {
                    if *authenticated_rx_rx.borrow_and_update() > probe_started {
                        break;
                    }
                    let probe_sleep =
                        tokio::time::sleep_until(tokio::time::Instant::from_std(probe_deadline));
                    tokio::pin!(probe_sleep);
                    tokio::select! {
                        biased;
                        changed = authenticated_rx_rx.changed() => {
                            changed.map_err(|_| anyhow::anyhow!("authenticated receive activity stream closed"))?;
                        }
                        _ = &mut probe_sleep => return Err(DeadCarrier.into()),
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };

    tokio::select! {
        res = sampler => res,
        res = ping_origin => res,
        res = liveness_monitor => {
            if let Err(ref error) = res {
                if error.downcast_ref::<DeadCarrier>().is_some() {
                    warn!("authenticated carrier became unresponsive; rotating endpoint");
                } else {
                    warn!(%error, "carrier liveness monitor exit");
                }
            }
            res
        },
        res = tun_to_tcp => {
            if let Err(ref e) = res {
                if e.downcast_ref::<RotateConnection>().is_some() {
                    info!(sent = guard.sent(), recv = guard.recv(), "volume guard: rotate (uplink)");
                } else {
                    warn!(%e, "tun_to_tcp exit");
                }
            }
            res
        },
        res = tcp_to_tun => {
            if let Err(ref e) = res {
                if e.downcast_ref::<RotateConnection>().is_some() {
                    info!(sent = guard.sent(), recv = guard.recv(), "volume guard: rotate (downlink)");
                } else {
                    warn!(%e, "tcp_to_tun exit");
                }
            }
            res
        },
    }
}

pub fn client_tun_config(
    name: Option<String>,
    address: Option<Ipv4Addr>,
    peer: Option<Ipv4Addr>,
    mtu: u16,
) -> TunConfig {
    let mut cfg = TunConfig {
        name,
        mtu,
        ..TunConfig::default()
    };
    if let Some(addr) = address {
        cfg.address = addr;
    }
    if let Some(peer) = peer {
        cfg.peer = peer;
    }
    cfg
}

pub fn server_tun_config(
    name: Option<String>,
    address: Option<Ipv4Addr>,
    peer: Option<Ipv4Addr>,
    mtu: u16,
) -> TunConfig {
    let mut cfg = TunConfig::server_default();
    cfg.name = name.or_else(|| Some("shadowpipe0".to_string()));
    if let Some(addr) = address {
        cfg.address = addr;
    }
    if let Some(peer) = peer {
        cfg.peer = peer;
    }
    cfg.mtu = mtu;
    cfg
}

pub fn volume_guard_from_config(cfg: VolumeGuardConfig) -> VolumeGuard {
    VolumeGuard::new(cfg)
}

pub fn pacer_from_config(cfg: PacerConfig) -> DegradationPacer {
    DegradationPacer::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::{
        jittered_idle_delay, run_tunnel_guarded, run_tunnel_guarded_with_liveness,
        CarrierLivenessConfig, DeadCarrier, DegradationPacer, RotateConnection,
    };
    use crate::carrier::{client_connect, server_accept};
    use crate::client_auth::{AuthorizedClients, ClientCredential};
    use crate::mux::MuxConfig;
    use crate::proto::{CamouflageMode, PaddingProfile};
    use crate::session::{AuthenticatedSession, ClientConfig, ServerState};
    use crate::tun_dev::{MemTun, TunnelIo};
    use crate::volume_guard::{VolumeGuard, VolumeGuardConfig};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn auth_fixture(
        state: &ServerState,
        camouflage: CamouflageMode,
    ) -> (Arc<ClientCredential>, Arc<AuthorizedClients>, ClientConfig) {
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = Arc::new(credential.authorized_clients().unwrap());
        let config = ClientConfig {
            camouflage,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: state.fingerprint(),
            client_credential: Arc::clone(&credential),
        };
        (credential, authorized, config)
    }

    /// End-to-end anti-freeze path (review H2): a sustained download through
    /// `run_tunnel_guarded` with a strict client-side volume guard trips
    /// `RotateConnection` repeatedly; a test-side reconnect loop (mirroring
    /// `client/main.rs`) re-handshakes and resumes on the SAME MemTun. Before
    /// this, `run_tunnel*` had ZERO test call-sites and the rotate→reconnect→
    /// resume cycle was entirely unexercised. It also covers this session's
    /// fixes together: the server accepts each reconnect (H1), the client loops
    /// instead of dying (M3), and every reconnect re-runs the transcript-bound
    /// handshake (M1). The client counts bytes *received*, so `got` accumulates
    /// ~`GUARD` per connection regardless of server-side rotation loss (M4).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn download_resumes_across_volume_guard_rotations() {
        const TOTAL: usize = 1024 * 1024;
        const CHUNK: usize = 1200;
        const GUARD: u64 = 64 * 1024;
        const TARGET_ROTATIONS: u32 = 4;

        let state = Arc::new(ServerState::generate());
        let (credential, authorized, _) = auth_fixture(&state, CamouflageMode::H2Chunk);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mux = MuxConfig {
            stream_count: 24,
            max_chunk_size: 1024,
        };
        let mtu = 1280u16;

        // Persistent server TUN, fed a fixed payload; one run_tunnel per accepted
        // connection (server guard disabled — the client drives rotation).
        let server_tun = MemTun::new();
        let feed = server_tun.clone();
        tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < TOTAL {
                let n = CHUNK.min(TOTAL - sent);
                feed.inject_packet(vec![0xABu8; n]).await;
                sent += n;
            }
        });
        let server_state = Arc::clone(&state);
        let server_authorized = Arc::clone(&authorized);
        let server_mux = mux.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let mut stream = match server_accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let Ok((session, _, _)) = AuthenticatedSession::server_accept(
                    &mut stream,
                    &server_state,
                    &server_authorized,
                    CamouflageMode::H2Chunk,
                )
                .await
                else {
                    continue;
                };
                let _ = run_tunnel_guarded(
                    TunnelIo::Mem(server_tun.clone()),
                    stream,
                    session,
                    server_mux.clone(),
                    mtu,
                    VolumeGuard::disabled(),
                    Arc::new(DegradationPacer::disabled()),
                    None,
                )
                .await;
            }
        });

        // Client reconnect loop: same MemTun across rotations so received bytes
        // accumulate, proving the download resumes after each rotation.
        let client_tun = MemTun::new();
        let mut rotations = 0u32;
        for _ in 0..40 {
            if rotations >= TARGET_ROTATIONS {
                break;
            }
            let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
                continue;
            };
            let mut stream = match client_connect(tcp, CamouflageMode::H2Chunk).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let config = ClientConfig {
                camouflage: CamouflageMode::H2Chunk,
                padding_profile: PaddingProfile::Balanced,
                server_fingerprint: state.fingerprint(),
                client_credential: Arc::clone(&credential),
            };
            let (session, _) =
                match AuthenticatedSession::client_connect(&mut stream, &config).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
            let guard = VolumeGuard::new(VolumeGuardConfig {
                threshold: GUARD,
                enabled: true,
            });
            let res = run_tunnel_guarded(
                TunnelIo::Mem(client_tun.clone()),
                stream,
                session,
                mux.clone(),
                mtu,
                guard,
                Arc::new(DegradationPacer::disabled()),
                None,
            )
            .await;
            if res
                .as_ref()
                .err()
                .and_then(|e| e.downcast_ref::<RotateConnection>())
                .is_some()
            {
                rotations += 1;
            }
        }
        server.abort();

        let got = client_tun.total_written_bytes().await;
        assert!(
            rotations >= 3,
            "volume guard should have rotated the connection >=3 times, got {rotations}"
        );
        // Resumed across rotations: more than a couple connections' budget was
        // delivered (loose bound — rotation drops in-flight frames by design).
        assert!(
            got as u64 > 2 * GUARD,
            "download did not resume across rotations: {got} bytes received"
        );
        // No corruption: every delivered byte is the known pattern.
        for pkt in client_tun.drain_written().await {
            assert!(
                pkt.iter().all(|&b| b == 0xAB),
                "corrupted byte in a delivered packet"
            );
        }
    }

    /// The TCP-carrier pacer is no longer inert: with `--pace` on a plain TCP
    /// (H2Chunk) carrier and `carrier_stats=None`, `run_tunnel_guarded` builds the
    /// app-RTT probe, which clocks the heavy downlink + PING replies and lifts the
    /// pacer's goodput above the reference rate. Before this, the pacer was rebound
    /// to disabled on any TCP carrier and this signal did not exist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pacer_is_live_on_tcp_carrier_via_app_rtt_probe() {
        const TOTAL: usize = 8 * 1024 * 1024;
        const CHUNK: usize = 1200;

        let state = Arc::new(ServerState::generate());
        let (credential, authorized, _) = auth_fixture(&state, CamouflageMode::H2Chunk);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mux = MuxConfig {
            stream_count: 24,
            max_chunk_size: 1024,
        };
        let mtu = 1280u16;

        // Server: stream a big payload into its TUN; pacer OFF — it only needs to be
        // a valid PING responder so the client's probe gets RTT replies.
        let server_tun = MemTun::new();
        let feed = server_tun.clone();
        tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < TOTAL {
                let n = CHUNK.min(TOTAL - sent);
                feed.inject_packet(vec![0xCDu8; n]).await;
                sent += n;
            }
        });
        let server_state = Arc::clone(&state);
        let server_authorized = Arc::clone(&authorized);
        let server_mux = mux.clone();
        let server = tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                if let Ok(mut stream) = server_accept(tcp).await {
                    if let Ok((session, _, _)) = AuthenticatedSession::server_accept(
                        &mut stream,
                        &server_state,
                        &server_authorized,
                        CamouflageMode::H2Chunk,
                    )
                    .await
                    {
                        let _ = run_tunnel_guarded(
                            TunnelIo::Mem(server_tun.clone()),
                            stream,
                            session,
                            server_mux,
                            mtu,
                            VolumeGuard::disabled(),
                            Arc::new(DegradationPacer::disabled()),
                            None,
                        )
                        .await;
                    }
                }
            }
        });

        // Client: `--pace` on a TCP carrier ⇒ run_tunnel_guarded builds the app-RTT
        // probe instead of going inert. Hold the pacer Arc to inspect it live.
        let client_tun = MemTun::new();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = client_connect(tcp, CamouflageMode::H2Chunk).await.unwrap();
        let config = ClientConfig {
            camouflage: CamouflageMode::H2Chunk,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: state.fingerprint(),
            client_credential: credential,
        };
        let (session, _) = AuthenticatedSession::client_connect(&mut stream, &config)
            .await
            .unwrap();
        let pacer = Arc::new(DegradationPacer::new(crate::pacing::PacerConfig {
            enabled: true,
            jitter: false,
            ..Default::default()
        }));
        let pacer_probe = Arc::clone(&pacer);
        let client = tokio::spawn(async move {
            let _ = run_tunnel_guarded(
                TunnelIo::Mem(client_tun.clone()),
                stream,
                session,
                mux,
                mtu,
                VolumeGuard::disabled(),
                pacer,
                None,
            )
            .await;
        });

        // Let the download run so the probe converges above the reference rate.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let enabled = pacer_probe.is_enabled();
        let goodput = pacer_probe.current_goodput_bps();
        client.abort();
        server.abort();

        assert!(
            enabled,
            "pacer must stay ENABLED on a TCP carrier (no longer inert)"
        );
        assert!(
            goodput > crate::pacing::REFERENCE_RATE_BPS,
            "app-RTT probe should have measured the heavy downlink: goodput={goodput} B/s"
        );
    }

    #[test]
    fn liveness_deadlines_and_idle_jitter_are_bounded() {
        assert!(CarrierLivenessConfig::new(
            Duration::from_millis(9),
            Duration::from_millis(20),
            Duration::from_millis(10),
        )
        .is_err());
        assert!(CarrierLivenessConfig::new(
            Duration::from_secs(1),
            Duration::from_millis(20),
            Duration::from_millis(30),
        )
        .is_err());
        let maximum = Duration::from_secs(10);
        for random in [0, 1, u64::MAX / 2, u64::MAX] {
            let delay = jittered_idle_delay(maximum, random);
            assert!(delay >= Duration::from_secs(8));
            assert!(delay <= maximum);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_blackhole_trips_typed_dead_carrier_deadline() {
        let state = Arc::new(ServerState::generate());
        let (credential, authorized, _) = auth_fixture(&state, CamouflageMode::H2Chunk);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        let server_authorized = Arc::clone(&authorized);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = server_accept(tcp).await.unwrap();
            let (session, _, _) = AuthenticatedSession::server_accept(
                &mut stream,
                &server_state,
                &server_authorized,
                CamouflageMode::H2Chunk,
            )
            .await
            .unwrap();
            // Keep the authenticated carrier open while deliberately neither
            // reading nor replying: a true half-open application blackhole.
            let _held = (stream, session);
            std::future::pending::<()>().await;
        });

        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = client_connect(tcp, CamouflageMode::H2Chunk).await.unwrap();
        let config = ClientConfig {
            camouflage: CamouflageMode::H2Chunk,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: state.fingerprint(),
            client_credential: credential,
        };
        let (session, _) = AuthenticatedSession::client_connect(&mut stream, &config)
            .await
            .unwrap();
        let liveness = CarrierLivenessConfig::new(
            Duration::from_millis(30),
            Duration::from_millis(60),
            Duration::from_millis(20),
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_tunnel_guarded_with_liveness(
                TunnelIo::Mem(MemTun::new()),
                stream,
                session,
                MuxConfig::default(),
                1280,
                VolumeGuard::disabled(),
                Arc::new(DegradationPacer::disabled()),
                None,
                Some(liveness),
            ),
        )
        .await
        .expect("blackholed carrier must terminate within the hard test bound")
        .expect_err("blackholed carrier unexpectedly remained healthy");
        server.abort();
        assert!(
            result.downcast_ref::<DeadCarrier>().is_some(),
            "expected typed DeadCarrier, got {result:#}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_ping_replies_keep_idle_carrier_alive() {
        let state = Arc::new(ServerState::generate());
        let (credential, authorized, _) = auth_fixture(&state, CamouflageMode::H2Chunk);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        let server_authorized = Arc::clone(&authorized);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = server_accept(tcp).await.unwrap();
            let (session, _, _) = AuthenticatedSession::server_accept(
                &mut stream,
                &server_state,
                &server_authorized,
                CamouflageMode::H2Chunk,
            )
            .await
            .unwrap();
            let _ = run_tunnel_guarded(
                TunnelIo::Mem(MemTun::new()),
                stream,
                session,
                MuxConfig::default(),
                1280,
                VolumeGuard::disabled(),
                Arc::new(DegradationPacer::disabled()),
                None,
            )
            .await;
        });

        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = client_connect(tcp, CamouflageMode::H2Chunk).await.unwrap();
        let config = ClientConfig {
            camouflage: CamouflageMode::H2Chunk,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: state.fingerprint(),
            client_credential: credential,
        };
        let (session, _) = AuthenticatedSession::client_connect(&mut stream, &config)
            .await
            .unwrap();
        let liveness = CarrierLivenessConfig::new(
            Duration::from_millis(30),
            Duration::from_millis(80),
            Duration::from_millis(20),
        )
        .unwrap();
        let stayed_live = tokio::time::timeout(
            Duration::from_millis(300),
            run_tunnel_guarded_with_liveness(
                TunnelIo::Mem(MemTun::new()),
                stream,
                session,
                MuxConfig::default(),
                1280,
                VolumeGuard::disabled(),
                Arc::new(DegradationPacer::disabled()),
                None,
                Some(liveness),
            ),
        )
        .await;
        server.abort();
        assert!(
            stayed_live.is_err(),
            "responsive authenticated peer was declared dead or closed early: {stayed_live:?}"
        );
    }
}
