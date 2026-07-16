//! Sustained download through `run_tunnel` (review H2 / planeb-02).
#![cfg(feature = "test-util")]

use shadowpipe_core::cam::h2;
use shadowpipe_core::carrier::{client_connect, server_accept, CarrierStream, PrefixedStream};
use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::mux::MuxConfig;
use shadowpipe_core::proto::{CamouflageMode, PaddingProfile};
use shadowpipe_core::reality::{
    generate_static_secret, reality_accept, reality_connect, PublicKey, RealityServerConfig,
    ReplayCache,
};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use shadowpipe_core::tun_dev::{MemTun, TunnelIo};
use shadowpipe_core::tunnel::run_tunnel;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Acceptance target from planeb-02 / review H2: matched pair must carry sustained
/// traffic well past the old ~1–2.5 MB crash window.
const PAYLOAD_TOTAL: usize = 16 * 1024 * 1024;
const PACKET_CHUNK: usize = 1200;
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_download_over_raw_tunnel() {
    run_sustained_download_tcp(CamouflageMode::Raw).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_download_over_h2_tunnel() {
    run_sustained_download_tcp(CamouflageMode::H2Chunk).await;
}

/// REALITY outer carrier + inner PQ session — same stack as `--uri` / `--reality`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_download_over_reality_tunnel() {
    run_sustained_download_reality().await;
}

/// Loopback TCP buffers swallow writes; a tiny duplex buffer forces partial h2
/// frame writes — the planeb-02 carrier desync failure mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_download_h2_under_write_backpressure() {
    run_sustained_download_h2_duplex(64).await;
}

/// Mirrors the client daemon reconnect loop (review M3): aborting a mid-stream
/// session and opening a fresh one must deliver a fresh post-reconnect packet
/// feed into the same client TUN. Packets already read into a doomed carrier are
/// not retransmitted by an IP tunnel, so this test intentionally does not claim
/// preservation of the first session's in-flight packets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_download_resumes_after_connection_drop() {
    const FIRST_TOTAL: usize = 512 * 1024;
    const SECOND_TOTAL: usize = 2 * 1024 * 1024;

    let state = Arc::new(ServerState::generate());
    let server_fingerprint = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = Arc::new(credential.authorized_clients().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mux = mux_cfg();
    let mtu = 1280u16;

    let server_state = Arc::clone(&state);
    let server_mux = mux.clone();
    let server_authorized = Arc::clone(&authorized);
    let server = tokio::spawn(async move {
        let mut accepted_sessions = 0usize;
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let Ok(mut stream) = server_accept(tcp).await else {
                continue;
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
            accepted_sessions += 1;
            let session_tun = MemTun::new();
            let feed_bytes = if accepted_sessions == 1 {
                FIRST_TOTAL
            } else {
                SECOND_TOTAL
            };
            spawn_downlink_feed_to(session_tun.clone(), feed_bytes);
            let _ = run_tunnel(
                TunnelIo::Mem(session_tun),
                stream,
                session,
                server_mux.clone(),
                mtu,
            )
            .await;
        }
    });

    let client_tun = MemTun::new();
    let watch = client_tun.clone();

    // Session 1: run briefly, then hard-abort (simulates carrier death).
    {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = client_connect(tcp, CamouflageMode::H2Chunk).await.unwrap();
        let (session, _) = client_connect_session(
            &mut stream,
            CamouflageMode::H2Chunk,
            server_fingerprint,
            Arc::clone(&credential),
        )
        .await;
        let tun_io = TunnelIo::Mem(client_tun.clone());
        let mux1 = mux.clone();
        let client =
            tokio::spawn(async move { run_tunnel(tun_io, stream, session, mux1, mtu).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        let mid = watch.total_written_bytes().await;
        assert!(
            mid > 0,
            "first session should deliver some bytes before drop"
        );
        client.abort();
        let _ = client.await;
    }

    // Session 2: fresh handshake and fresh server packet source, but the same
    // client MemTun. Require a post-handshake delta rather than treating packets
    // consumed by session 1 as reconnect-replayable application bytes.
    {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = client_connect(tcp, CamouflageMode::H2Chunk).await.unwrap();
        let (session, _) = client_connect_session(
            &mut stream,
            CamouflageMode::H2Chunk,
            server_fingerprint,
            Arc::clone(&credential),
        )
        .await;
        let tun_io = TunnelIo::Mem(client_tun.clone());
        let mux2 = mux.clone();
        let client =
            tokio::spawn(async move { run_tunnel(tun_io, stream, session, mux2, mtu).await });
        let baseline = watch.total_written_bytes().await;
        let min_ok = baseline.saturating_add(SECOND_TOTAL.saturating_sub(PACKET_CHUNK * 16));
        let ok = wait_for_bytes(&watch, min_ok, Duration::from_secs(60)).await;
        client.abort();
        let _ = client.await;
        assert!(ok, "reconnect should deliver the fresh second-session feed");
    }

    server.abort();
    let _ = server.await;
}

async fn wait_for_bytes(watch: &MemTun, min_ok: usize, timeout: Duration) -> bool {
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return watch.total_written_bytes().await >= min_ok,
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                if watch.total_written_bytes().await >= min_ok {
                    return true;
                }
            }
        }
    }
}

async fn run_sustained_download_tcp(camouflage: CamouflageMode) {
    let state = Arc::new(ServerState::generate());
    let server_fingerprint = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = Arc::new(credential.authorized_clients().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mux = mux_cfg();
    let mtu = 1280u16;

    let server_state = Arc::clone(&state);
    let server_mux = mux.clone();
    let server_authorized = Arc::clone(&authorized);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = server_accept(tcp).await.unwrap();
        let (session, _, _) = AuthenticatedSession::server_accept(
            &mut stream,
            &server_state,
            &server_authorized,
            camouflage,
        )
        .await
        .unwrap();
        let tun = MemTun::new();
        spawn_downlink_feed(tun.clone());
        run_tunnel(TunnelIo::Mem(tun), stream, session, server_mux, mtu).await
    });

    tokio::task::yield_now().await;

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stream = client_connect(tcp, camouflage).await.unwrap();
    let (session, _) =
        client_connect_session(&mut stream, camouflage, server_fingerprint, credential).await;
    let client_tun = MemTun::new();
    let watch = client_tun.clone();
    let client = tokio::spawn(async move {
        run_tunnel(TunnelIo::Mem(client_tun), stream, session, mux, mtu).await
    });

    assert_sustained_receive(&format!("{camouflage:?}"), watch, client, server).await;
}

async fn run_sustained_download_reality() {
    let sk = generate_static_secret();
    let server_pub = PublicKey::from(&sk).to_bytes();
    let short_id = vec![0xab, 0xcd];

    let reality_cfg = Arc::new(RealityServerConfig {
        static_secret: sk,
        short_ids: vec![short_id.clone()],
        cover: "127.0.0.1:1".into(),
        max_time_skew_secs: Some(120),
        replay_cache: ReplayCache::in_memory_for_tests(),
        cover_profile: None,
    });
    let state = Arc::new(ServerState::generate());
    let server_fp = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = Arc::new(credential.authorized_clients().unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mux = mux_cfg();
    let mtu = 1280u16;

    let srv_cfg = reality_cfg.clone();
    let server_state = Arc::clone(&state);
    let server_mux = mux.clone();
    let server_authorized = Arc::clone(&authorized);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = reality_accept(tcp, &srv_cfg)
            .await
            .unwrap()
            .expect("reality client should authenticate");
        let (session, _, _) = AuthenticatedSession::server_accept(
            &mut stream,
            &server_state,
            &server_authorized,
            CamouflageMode::Raw,
        )
        .await
        .unwrap();
        let tun = MemTun::new();
        spawn_downlink_feed(tun.clone());
        run_tunnel(TunnelIo::Mem(tun), stream, session, server_mux, mtu).await
    });

    tokio::task::yield_now().await;

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stream = reality_connect(tcp, &server_pub, &short_id, "www.example.com")
        .await
        .unwrap();
    let config = ClientConfig {
        camouflage: CamouflageMode::Raw,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: server_fp,
        client_credential: credential,
    };
    let (session, _) = AuthenticatedSession::client_connect(&mut stream, &config)
        .await
        .unwrap();
    let client_tun = MemTun::new();
    let watch = client_tun.clone();
    let client = tokio::spawn(async move {
        run_tunnel(TunnelIo::Mem(client_tun), stream, session, mux, mtu).await
    });

    assert_sustained_receive("Reality", watch, client, server).await;
}

async fn run_sustained_download_h2_duplex(buf_size: usize) {
    let state = Arc::new(ServerState::generate());
    let server_fingerprint = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = Arc::new(credential.authorized_clients().unwrap());
    let mux = mux_cfg();
    let mtu = 1280u16;

    let (client_io, server_io) = h2_duplex_pair(buf_size).await;

    let server_state = Arc::clone(&state);
    let server_mux = mux.clone();
    let server_authorized = Arc::clone(&authorized);
    let server = tokio::spawn(async move {
        let mut stream = server_io;
        let (session, _, _) = AuthenticatedSession::server_accept(
            &mut stream,
            &server_state,
            &server_authorized,
            CamouflageMode::H2Chunk,
        )
        .await
        .unwrap();
        let tun = MemTun::new();
        spawn_downlink_feed(tun.clone());
        run_tunnel(TunnelIo::Mem(tun), stream, session, server_mux, mtu).await
    });

    tokio::task::yield_now().await;

    let mut stream = client_io;
    let (session, _) = client_connect_session(
        &mut stream,
        CamouflageMode::H2Chunk,
        server_fingerprint,
        credential,
    )
    .await;
    let client_tun = MemTun::new();
    let watch = client_tun.clone();
    let client = tokio::spawn(async move {
        run_tunnel(TunnelIo::Mem(client_tun), stream, session, mux, mtu).await
    });

    assert_sustained_receive("H2Chunk", watch, client, server).await;
}

fn mux_cfg() -> MuxConfig {
    MuxConfig {
        stream_count: 24,
        max_chunk_size: 1024,
    }
}

fn spawn_downlink_feed(tun: MemTun) {
    spawn_downlink_feed_to(tun, PAYLOAD_TOTAL);
}

fn spawn_downlink_feed_to(tun: MemTun, total: usize) {
    tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < total {
            let n = PACKET_CHUNK.min(total - sent);
            tun.inject_packet(vec![0xABu8; n]).await;
            sent += n;
        }
    });
}

async fn client_connect_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    camouflage: CamouflageMode,
    server_fingerprint: [u8; 32],
    client_credential: Arc<ClientCredential>,
) -> (AuthenticatedSession, [u8; 8]) {
    let config = ClientConfig {
        camouflage,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint,
        client_credential,
    };
    AuthenticatedSession::client_connect(stream, &config)
        .await
        .unwrap()
}

/// Connected h2 carrier pair over a tiny duplex buffer (guaranteed partial writes).
async fn h2_duplex_pair(
    buf_size: usize,
) -> (
    CarrierStream<tokio::io::DuplexStream>,
    CarrierStream<PrefixedStream<tokio::io::DuplexStream>>,
) {
    let (client_half, server_half) = tokio::io::duplex(buf_size);

    let mut server_io = server_half;
    let server_task = tokio::spawn(async move {
        CarrierStream::server_bootstrap(&mut server_io)
            .await
            .unwrap();
        CarrierStream::new(
            PrefixedStream::new(server_io, Vec::new()),
            CamouflageMode::H2Chunk,
        )
    });

    let mut client_raw = client_half;
    client_raw.write_all(&h2::client_bootstrap()).await.unwrap();
    client_raw.flush().await.unwrap();
    let client = CarrierStream::new(client_raw, CamouflageMode::H2Chunk);
    let server = server_task.await.unwrap();
    (client, server)
}

async fn assert_sustained_receive(
    carrier: &str,
    watch: MemTun,
    client: JoinHandle<anyhow::Result<()>>,
    server: JoinHandle<anyhow::Result<()>>,
) {
    let min_ok = PAYLOAD_TOTAL.saturating_sub(PACKET_CHUNK * 16);
    let ok = wait_for_bytes(&watch, min_ok, TEST_TIMEOUT).await;

    client.abort();
    server.abort();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = client.await;
        let _ = server.await;
    })
    .await;

    let got = watch.total_written_bytes().await;
    assert!(
        ok,
        "{carrier}: client tun received {got} bytes, expected >= {min_ok} \
         (planeb repro if crash ~0.8–2.5 MB; acceptance is {PAYLOAD_TOTAL} B)"
    );
}
