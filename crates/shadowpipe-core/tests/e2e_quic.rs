//! End-to-end: the QUIC carrier as it is wired into the binaries.
//!
//! Loopback-only — these prove the QUIC bidirectional stream is a faithful
//! duplex byte channel that the post-quantum `AuthenticatedSession` + bulk traffic ride
//! inside, exactly as `--tls`/`--reality` do over TCP. The QUIC TLS auth is
//! skipped (accept-any verifier client-side, ephemeral self-signed server cert);
//! the real authentication is the inner ML-KEM `--server-fp` pin, pinned here.
//!
//! Mandatory v3 starts with the client's fixed-width access key id, so the
//! CLIENT opens and materializes the bidirectional stream. Tests drive their raw
//! control client-first and close with the same FIN exchange the real echo path
//! uses — a graceful close so the responder never tears down the QUIC connection
//! with a reply still in flight.
//!
//! This is a raw QUIC lab carrier, not HTTP/3. It negotiates the private
//! `shadowpipe-lab/1` ALPN; the regression below checks the actual completed
//! handshake so the carrier cannot silently return to falsely advertising `h3`.
//!
//! ⚠️ The anti-DPI premise (UDP/QUIC traverses the RU TSPU better than TCP) is a
//! wire property NOT exercised here — it needs a real host on the censored path.
//! These tests cover correctness, not stealth.
#![cfg(feature = "quic")]

use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::proto::{CamouflageMode, CarrierBinding, FrameFlags, PaddingProfile};
use shadowpipe_core::quic::{quic_connect, QuicListener, LAB_QUIC_ALPN};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("QUIC loopback E2E exceeded its monotonic 15-second bound")
}

/// Wire-truth regression: both peers negotiate the private raw-carrier ALPN,
/// and the lab carrier never claims the standard HTTP/3 `h3` protocol.
#[tokio::test]
async fn quic_lab_carrier_does_not_advertise_h3() {
    within(async {
        assert_eq!(LAB_QUIC_ALPN, b"shadowpipe-lab/1");
        assert_ne!(LAB_QUIC_ALPN, b"h3");

        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let connecting = listener.accept().await.expect("incoming connection");
            let mut stream = connecting.establish().await.expect("handshake + bi-stream");
            assert_eq!(
                stream.negotiated_alpn().as_deref(),
                Some(LAB_QUIC_ALPN),
                "server negotiated the private raw-carrier ALPN"
            );
            let mut materialize = [0u8; 1];
            stream.read_exact(&mut materialize).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut stream = quic_connect(addr, "localhost").await.expect("quic connect");
        assert_eq!(
            stream.negotiated_alpn().as_deref(),
            Some(LAB_QUIC_ALPN),
            "client negotiated the private raw-carrier ALPN"
        );
        stream.write_all(&[0]).await.unwrap();
        stream.shutdown().await.unwrap();

        server.await.unwrap();
    })
    .await;
}

/// Raw bytes over a QUIC bi-stream, client-first (matching mandatory v3): the
/// client writes a greeting, the server reads it and returns a reply, then each
/// side finishes its send half. Proves `QuicStream` behaves as a plain
/// `AsyncRead + AsyncWrite` duplex with no stream-open deadlock.
#[tokio::test]
async fn quic_carrier_raw_duplex() {
    within(async {
        const GREETING: &[u8] = b"ping from client";
        const REPLY: &[u8] = b"pong from server";

        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let connecting = listener.accept().await.expect("incoming connection");
            let mut stream = connecting.establish().await.expect("handshake + bi-stream");
            let mut greeting = vec![0u8; GREETING.len()];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(REPLY).await.unwrap();
            stream.flush().await.unwrap();
            let mut eof = Vec::new();
            stream.read_to_end(&mut eof).await.unwrap();
            assert!(eof.is_empty());
            stream.shutdown().await.unwrap();
            greeting
        });

        let mut stream = quic_connect(addr, "localhost").await.expect("quic connect");
        stream.write_all(GREETING).await.unwrap();
        let mut reply = vec![0u8; REPLY.len()];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, REPLY);
        stream.shutdown().await.unwrap();

        assert_eq!(server.await.unwrap(), GREETING);
    })
    .await;
}

/// The PQ `AuthenticatedSession` (v3 hybrid client auth, key-pinned, AEAD-framed) handshakes
/// INSIDE the QUIC stream and an application frame round-trips — proving the two
/// layers compose exactly as the binaries wire them (QUIC outside, post-quantum
/// confidentiality inside). Closes with a FIN frame like the real echo path.
#[tokio::test]
async fn quic_carrier_carries_a_pq_session_end_to_end() {
    within(async {
        let state = Arc::new(ServerState::generate());
        let server_fp = state.fingerprint();
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = Arc::new(credential.authorized_clients().unwrap());

        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_state = state.clone();
        let srv_authorized = Arc::clone(&authorized);
        let server = tokio::spawn(async move {
            let connecting = listener.accept().await.expect("incoming connection");
            let mut stream = connecting.establish().await.expect("handshake + bi-stream");
            let (mut session, _hello, _sid) = AuthenticatedSession::server_accept_bound(
                &mut stream,
                &srv_state,
                &srv_authorized,
                CamouflageMode::Raw,
                CarrierBinding::QuicRaw,
            )
            .await
            .unwrap();
            let (sid, _flags, payload, _wire) = session.recv(&mut stream).await.unwrap();
            let echoed: Vec<u8> = payload.iter().rev().copied().collect();
            session
                .send(&mut stream, sid, FrameFlags::DATA, &echoed)
                .await
                .unwrap();
            // Wait for the client's FIN before returning: a graceful close so we
            // don't drop the QUIC connection with the echo still in flight.
            let (_sid, flags, _p, _w) = session.recv(&mut stream).await.unwrap();
            assert!(flags.contains(FrameFlags::FIN), "client closes with FIN");
        });

        let mut stream = quic_connect(addr, "localhost").await.expect("quic connect");
        let cfg = ClientConfig {
            camouflage: CamouflageMode::Raw,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: server_fp, // pin the inner ML-KEM key
            client_credential: credential,
        };
        let (mut session, _sid) =
            AuthenticatedSession::client_connect_bound(&mut stream, &cfg, CarrierBinding::QuicRaw)
                .await
                .unwrap();
        session
            .send(&mut stream, 0, FrameFlags::DATA, b"through quic + pq")
            .await
            .unwrap();
        let (_sid, _flags, reply, _wire) = session.recv(&mut stream).await.unwrap();
        assert_eq!(reply, b"qp + ciuq hguorht", "payload round-tripped");
        session
            .send(&mut stream, 0, FrameFlags::FIN, b"bye")
            .await
            .unwrap();

        server.await.unwrap();
    })
    .await;
}

/// Sustained bidirectional bulk flow over the QUIC carrier: 64 frames of 4 KiB
/// each echoed back through the PQ session — representative of the tunnel's
/// packet stream, and exercises the `QuicStream` poll loop across many records.
#[tokio::test]
async fn quic_carrier_streams_sustained_bulk_traffic() {
    within(async {
        const FRAMES: usize = 64;
        const FRAME_LEN: usize = 4096;

        let state = Arc::new(ServerState::generate());
        let server_fp = state.fingerprint();
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = Arc::new(credential.authorized_clients().unwrap());

        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_state = state.clone();
        let srv_authorized = Arc::clone(&authorized);
        let server = tokio::spawn(async move {
            let connecting = listener.accept().await.expect("incoming connection");
            let mut stream = connecting.establish().await.expect("handshake + bi-stream");
            let (mut session, _hello, _sid) = AuthenticatedSession::server_accept_bound(
                &mut stream,
                &srv_state,
                &srv_authorized,
                CamouflageMode::Raw,
                CarrierBinding::QuicRaw,
            )
            .await
            .unwrap();
            for _ in 0..FRAMES {
                let (sid, _flags, payload, _wire) = session.recv(&mut stream).await.unwrap();
                session
                    .send(&mut stream, sid, FrameFlags::DATA, &payload)
                    .await
                    .unwrap();
            }
            let (_sid, flags, _p, _w) = session.recv(&mut stream).await.unwrap();
            assert!(flags.contains(FrameFlags::FIN), "client closes with FIN");
        });

        let mut stream = quic_connect(addr, "localhost").await.expect("quic connect");
        let cfg = ClientConfig {
            camouflage: CamouflageMode::Raw,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: server_fp,
            client_credential: credential,
        };
        let (mut session, _sid) =
            AuthenticatedSession::client_connect_bound(&mut stream, &cfg, CarrierBinding::QuicRaw)
                .await
                .unwrap();

        for i in 0..FRAMES {
            let payload = vec![(i & 0xff) as u8; FRAME_LEN];
            session
                .send(&mut stream, 0, FrameFlags::DATA, &payload)
                .await
                .unwrap();
            let (_sid, _flags, reply, _wire) = session.recv(&mut stream).await.unwrap();
            assert_eq!(reply, payload, "frame {i} round-tripped intact");
        }
        session
            .send(&mut stream, 0, FrameFlags::FIN, b"bye")
            .await
            .unwrap();

        server.await.unwrap();
    })
    .await;
}
