//! End-to-end: mux chunking + PQ session over TCP (no root / no TUN).
//! Simulates what tunnel mode does on the wire.

use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::mux::{encode_packet, MuxConfig, Reassembler};
use shadowpipe_core::proto::{CamouflageMode, FrameFlags};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn mux_over_encrypted_session_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = ServerState::generate();
    let server_fingerprint = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = credential.authorized_clients().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut session, _, _) = AuthenticatedSession::server_accept(
            &mut stream,
            &state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
        .unwrap();

        let mut reasm = Reassembler::new();
        let mut assembled = None;
        while assembled.is_none() {
            let (_, flags, payload, _) = session.recv(&mut stream).await.unwrap();
            if flags.contains(FrameFlags::FIN) {
                return;
            }
            if let Some(packet) = reasm.feed(&payload).unwrap() {
                assembled = Some(packet);
            }
        }

        let packet = assembled.unwrap();
        let frames = encode_packet(
            &packet,
            99,
            &MuxConfig {
                stream_count: 24,
                max_chunk_size: 4096,
            },
        )
        .unwrap();
        for (sid, frame) in frames {
            session
                .send(&mut stream, sid, FrameFlags::DATA, &frame)
                .await
                .unwrap();
        }
        // Wait for the client's FIN before dropping the socket, so the client's
        // FIN write can't race a peer close (loopback would otherwise RST it).
        // Error-tolerant: a closed peer just ends the loop — never hangs.
        loop {
            match session.recv(&mut stream).await {
                Ok((_, flags, _, _)) if flags.contains(FrameFlags::FIN) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut session, _) = AuthenticatedSession::client_connect(
        &mut stream,
        &ClientConfig::pinned(server_fingerprint, credential),
    )
    .await
    .unwrap();

    let original: Vec<u8> = (0..9000u16).map(|i| (i % 251) as u8).collect();
    let mux = MuxConfig {
        stream_count: 24,
        max_chunk_size: 4096,
    };

    let frames = encode_packet(&original, 1, &mux).unwrap();
    assert!(
        frames.len() > 1,
        "large packet must split into multiple frames"
    );

    for (stream_id, payload) in &frames {
        session
            .send(&mut stream, *stream_id, FrameFlags::DATA, payload)
            .await
            .unwrap();
    }

    let mut reasm = Reassembler::new();
    let mut result = None;
    for _ in 0..frames.len() * 2 {
        let (_, flags, payload, _) = session.recv(&mut stream).await.unwrap();
        if flags.contains(FrameFlags::FIN) {
            break;
        }
        if let Some(packet) = reasm.feed(&payload).unwrap() {
            result = Some(packet);
            break;
        }
    }

    session
        .send(&mut stream, 0, FrameFlags::FIN, b"")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();

    server.await.unwrap();
    assert_eq!(result.unwrap(), original);
}

#[tokio::test]
async fn echo_mode_smoke() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = ServerState::generate();
    let server_fingerprint = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = credential.authorized_clients().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut session, _, _) = AuthenticatedSession::server_accept(
            &mut stream,
            &state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
        .unwrap();
        let (_, _, payload, _) = session.recv(&mut stream).await.unwrap();
        session
            .send(&mut stream, 0, FrameFlags::DATA, &payload)
            .await
            .unwrap();
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut session, _) = AuthenticatedSession::client_connect(
        &mut stream,
        &ClientConfig::pinned(server_fingerprint, credential),
    )
    .await
    .unwrap();
    session
        .send(&mut stream, 0, FrameFlags::DATA, b"ping")
        .await
        .unwrap();
    let (_, _, reply, _) = session.recv(&mut stream).await.unwrap();
    assert_eq!(reply, b"ping");
}
