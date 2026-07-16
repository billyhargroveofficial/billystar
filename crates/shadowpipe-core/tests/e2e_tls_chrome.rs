//! shadowpipe PQ+AEAD session running INSIDE the Chrome-JA4 TLS transport.
//! On the wire this is a genuine TLS connection (Chrome ClientHello); the
//! shadowpipe handshake and frames live inside it. Proves the boring-front
//! integration end to end (review H6 / boring-front). Needs the default
//! `tls-chrome` feature.
#![cfg(feature = "tls-chrome")]

use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::proto::{CamouflageMode, FrameFlags, PaddingProfile};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use shadowpipe_core::tls;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pq_session_inside_chrome_tls() {
    let state = Arc::new(ServerState::generate());
    let acceptor = Arc::new(tls::self_signed_acceptor().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_fingerprint = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = Arc::new(credential.authorized_clients().unwrap());

    let server_state = Arc::clone(&state);
    let acc = Arc::clone(&acceptor);
    let server_authorized = Arc::clone(&authorized);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Terminate the Chrome-JA4 TLS, then run the shadowpipe server handshake
        // INSIDE it — exactly what the real server will do.
        let mut tls = tls::accept(&acc, tcp).await.unwrap();
        let (mut session, _, _) = AuthenticatedSession::server_accept(
            &mut tls,
            &server_state,
            &server_authorized,
            CamouflageMode::Raw,
        )
        .await
        .unwrap();
        loop {
            match session.recv(&mut tls).await {
                Ok((_, flags, _, _)) if flags.contains(FrameFlags::FIN) => break,
                Ok((sid, _, payload, _)) => {
                    session
                        .send(&mut tls, sid, FrameFlags::DATA, &payload)
                        .await
                        .unwrap();
                }
                Err(_) => break,
            }
        }
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    // Client speaks a real Chrome ClientHello (JA4 t13d1516h2_8daaf6152771_…).
    let mut tls = tls::chrome_connect(tcp, "example.com").await.unwrap();
    let config = ClientConfig {
        camouflage: shadowpipe_core::proto::CamouflageMode::Raw,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint,
        client_credential: credential,
    };
    let (mut session, _) = AuthenticatedSession::client_connect(&mut tls, &config)
        .await
        .unwrap();

    // Small PQ-encrypted echo, all inside the TLS record layer.
    session
        .send(&mut tls, 0, FrameFlags::DATA, b"through chrome tls")
        .await
        .unwrap();
    let (_, flags, reply, _) = session.recv(&mut tls).await.unwrap();
    assert!(flags.contains(FrameFlags::DATA));
    assert_eq!(reply, b"through chrome tls");

    // Larger payload: exercises TLS record fragmentation + AEAD framing together.
    let big = vec![0x5Au8; 50_000];
    session
        .send(&mut tls, 0, FrameFlags::DATA, &big)
        .await
        .unwrap();
    let (_, _, reply2, _) = session.recv(&mut tls).await.unwrap();
    assert_eq!(reply2, big, "large payload corrupted through TLS+AEAD");

    session
        .send(&mut tls, 0, FrameFlags::FIN, b"")
        .await
        .unwrap();
    server.await.unwrap();
}

/// run_tunnel does `tokio::io::split(stream)` and reads+writes concurrently.
/// Validate that works over a boring SslStream (TLS is full-duplex post-
/// handshake) by pushing a download through run_tunnel on BOTH ends over TLS —
/// the real tunnel path the deployed server will use. Needs `test-util` (MemTun).
#[cfg(feature = "test-util")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_tunnel_over_chrome_tls() {
    use shadowpipe_core::mux::MuxConfig;
    use shadowpipe_core::tun_dev::{MemTun, TunnelIo};
    use shadowpipe_core::tunnel::run_tunnel;
    use std::time::Duration;

    const TOTAL: usize = 256 * 1024;
    const CHUNK: usize = 1200;

    let state = Arc::new(ServerState::generate());
    let acceptor = Arc::new(tls::self_signed_acceptor().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_fingerprint = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = Arc::new(credential.authorized_clients().unwrap());
    let mux = MuxConfig {
        stream_count: 24,
        max_chunk_size: 1024,
    };
    let mtu = 1280u16;

    let server_state = Arc::clone(&state);
    let acc = Arc::clone(&acceptor);
    let server_mux = mux.clone();
    let server_authorized = Arc::clone(&authorized);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = tls::accept(&acc, tcp).await.unwrap();
        let (session, _, _) = AuthenticatedSession::server_accept(
            &mut tls,
            &server_state,
            &server_authorized,
            CamouflageMode::Raw,
        )
        .await
        .unwrap();
        let tun = MemTun::new();
        let feed = tun.clone();
        tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < TOTAL {
                let n = CHUNK.min(TOTAL - sent);
                feed.inject_packet(vec![0xABu8; n]).await;
                sent += n;
            }
        });
        // run_tunnel splits `tls` and forwards concurrently — the path under test.
        let _ = run_tunnel(TunnelIo::Mem(tun), tls, session, server_mux, mtu).await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = tls::chrome_connect(tcp, "example.com").await.unwrap();
    let (session, _) = AuthenticatedSession::client_connect(
        &mut tls,
        &ClientConfig::pinned(server_fingerprint, credential),
    )
    .await
    .unwrap();
    let client_tun = MemTun::new();
    let watch = client_tun.clone();
    let client =
        tokio::spawn(
            async move { run_tunnel(TunnelIo::Mem(client_tun), tls, session, mux, mtu).await },
        );

    let min_ok = TOTAL.saturating_sub(CHUNK * 8);
    let mut got = 0usize;
    for _ in 0..150 {
        got = watch.total_written_bytes().await;
        if got >= min_ok {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    client.abort();
    server.abort();
    assert!(
        got >= min_ok,
        "run_tunnel over TLS delivered {got}/{TOTAL} bytes (concurrent split over SslStream?)"
    );
}
