//! End-to-end: the REALITY carrier as it is actually wired into the binaries.
//!
//! These exercise the full stack the way client/server `main.rs` do:
//!   - `reality_connect` / `reality_accept` give back a `RealityStream` byte
//!     channel, and the real shadowpipe PQ `AuthenticatedSession` (v3 hybrid auth,
//!     key-pinned, AEAD-framed) runs INSIDE it. Proves the two layers compose —
//!     undetectable carrier outside, post-quantum confidentiality inside.
//!   - a peer that can't authenticate is transparently forwarded to the cover and
//!     receives the cover's bytes (the anti-probe property), with no tell.

use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::proto::{CamouflageMode, CarrierBinding, FrameFlags, PaddingProfile};
use shadowpipe_core::reality::{
    build_authed_client_hello, default_grease, generate_static_secret, reality_accept,
    reality_connect, unix_now, PublicKey, RealityServerConfig, ReplayCache,
};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A REALITY client authenticates, the PQ session handshakes INSIDE the REALITY
/// stream, and an application frame round-trips — proving the carrier + inner
/// session compose exactly as the binaries wire them.
#[tokio::test]
async fn reality_carrier_carries_a_pq_session_end_to_end() {
    let sk = generate_static_secret();
    let server_pub = PublicKey::from(&sk).to_bytes();
    let short_id = vec![0xab, 0xcd];

    let reality_cfg = Arc::new(RealityServerConfig {
        static_secret: sk,
        short_ids: vec![short_id.clone()],
        cover: "127.0.0.1:1".into(), // never dialed on the authed path
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

    let srv_cfg = reality_cfg.clone();
    let srv_state = state.clone();
    let srv_authorized = Arc::clone(&authorized);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Outer REALITY accept → inner PQ session over the resulting byte stream.
        let mut stream = reality_accept(tcp, &srv_cfg)
            .await
            .unwrap()
            .expect("client should authenticate");
        let (mut session, _hello, _sid) = AuthenticatedSession::server_accept_bound(
            &mut stream,
            &srv_state,
            &srv_authorized,
            CamouflageMode::Raw,
            CarrierBinding::RealityTcp,
        )
        .await
        .unwrap();
        // Echo one frame, reversed, to prove bidirectional payload flow.
        let (sid, _flags, payload, _wire) = session.recv(&mut stream).await.unwrap();
        let echoed: Vec<u8> = payload.iter().rev().copied().collect();
        session
            .send(&mut stream, sid, FrameFlags::DATA, &echoed)
            .await
            .unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut stream = reality_connect(tcp, &server_pub, &short_id, "www.example.com")
        .await
        .expect("reality handshake + into_stream");
    let cfg = ClientConfig {
        camouflage: CamouflageMode::Raw,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: server_fp, // pin the inner ML-KEM key too
        client_credential: credential,
    };
    let (mut session, _sid) =
        AuthenticatedSession::client_connect_bound(&mut stream, &cfg, CarrierBinding::RealityTcp)
            .await
            .unwrap();

    session
        .send(&mut stream, 0, FrameFlags::DATA, b"through reality + pq")
        .await
        .unwrap();
    let (_sid, _flags, reply, _wire) = session.recv(&mut stream).await.unwrap();
    assert_eq!(reply, b"qp + ytilaer hguorht", "payload round-tripped");

    server.await.unwrap();
}

/// A peer that does not hold the server's static key (here: a real REALITY
/// ClientHello sealed to the WRONG static key — like an active prober) is
/// transparently spliced to the cover and receives the cover's bytes verbatim.
#[tokio::test]
async fn unauthenticated_peer_is_forwarded_to_the_cover() {
    // Stub "cover site": accept one connection, reply, close.
    let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cover_addr = cover_listener.local_addr().unwrap();
    let cover = tokio::spawn(async move {
        let (mut s, _) = cover_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(b"COVER-OK").await.unwrap();
        s.flush().await.unwrap();
        buf[..n].to_vec()
    });

    let sk = generate_static_secret();
    let reality_cfg = Arc::new(RealityServerConfig {
        static_secret: sk,
        short_ids: vec![vec![0x01]],
        cover: cover_addr.to_string(),
        max_time_skew_secs: Some(120),
        replay_cache: ReplayCache::in_memory_for_tests(),
        cover_profile: None,
    });
    let state = Arc::new(ServerState::generate());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_cfg = reality_cfg.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // reality_accept returns None when the peer is forwarded to the cover.
        let outcome = reality_accept(tcp, &srv_cfg).await.unwrap();
        assert!(
            outcome.is_none(),
            "non-authed peer must be forwarded, not authed"
        );
        let _ = state; // ML-KEM state unused on the forward path
    });

    // A genuine Chrome ClientHello whose REALITY token is sealed to a DIFFERENT
    // static key → the server can't open it → forwards to the cover.
    let wrong_pub = [0x42u8; 32];
    let (hello, _eph, _ak) = build_authed_client_hello(
        "www.example.com",
        &wrong_pub,
        &[0x01],
        unix_now(),
        &default_grease(),
        517,
    )
    .expect("test server public key is contributory");
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(&hello).await.unwrap();
    tcp.flush().await.unwrap();
    let mut got = Vec::new();
    tcp.read_to_end(&mut got).await.unwrap();
    drop(tcp); // close so the server's copy_bidirectional finishes

    assert_eq!(got, b"COVER-OK", "prober received the cover's bytes");
    let cover_saw = cover.await.unwrap();
    assert_eq!(
        cover_saw[0], 0x16,
        "cover received a forwarded TLS ClientHello"
    );
    server.await.unwrap();
}

/// Cover profiling is best-effort: an unreachable cover yields `None` (the server
/// still starts, just without authed-flight mimicry) — it must not hang or panic.
/// (The success path is proven by the reality crate's `profiles_a_server_flight`.)
#[tokio::test]
async fn cover_profiling_falls_back_when_cover_unreachable() {
    let profile = shadowpipe_core::reality::profile_cover_best_effort("127.0.0.1:1").await;
    assert!(
        profile.is_none(),
        "unreachable cover ⇒ None, server still starts"
    );
}
