#![cfg(feature = "http-stream")]

use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::http_stream::{self, HttpStreamRoute};
use shadowpipe_core::proto::{CamouflageMode, CarrierBinding, FrameFlags, PaddingProfile};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn route() -> HttpStreamRoute {
    HttpStreamRoute::new(
        "example.com",
        "/api/events/0123456789abcdef0123456789abcdef",
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_http2_stream_carries_bound_pq_session() {
    let state = Arc::new(ServerState::generate());
    let server_fp = state.fingerprint();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = Arc::new(credential.authorized_clients().unwrap());
    let server_state = Arc::clone(&state);
    let server_authorized = Arc::clone(&authorized);
    let server_route = route();
    let (client_wire, server_wire) = tokio::io::duplex(1 << 20);

    let mut server = tokio::spawn(async move {
        let mut stream = http_stream::server_accept(server_wire, &server_route)
            .await
            .unwrap();
        let (mut session, _, _) = AuthenticatedSession::server_accept_bound(
            &mut stream,
            &server_state,
            &server_authorized,
            CamouflageMode::Raw,
            CarrierBinding::Http2Tls,
        )
        .await
        .unwrap();
        let (stream_id, _, payload, _) = session.recv(&mut stream).await.unwrap();
        session
            .send(&mut stream, stream_id, FrameFlags::DATA, &payload)
            .await
            .unwrap();
    });

    let mut stream = http_stream::client_connect(client_wire, &route())
        .await
        .unwrap();
    let config = ClientConfig {
        camouflage: CamouflageMode::Raw,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint: server_fp,
        client_credential: credential,
    };
    let handshake_result = {
        let client_handshake = AuthenticatedSession::client_connect_bound(
            &mut stream,
            &config,
            CarrierBinding::Http2Tls,
        );
        tokio::pin!(client_handshake);
        tokio::select! {
            result = &mut client_handshake => result,
            result = &mut server => panic!("HTTP/2 server ended before the client handshake: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                panic!("HTTP/2 client handshake timed out; server_finished={}", server.is_finished())
            }
        }
    };
    let (mut session, _) = handshake_result.unwrap();
    session
        .send(
            &mut stream,
            7,
            FrameFlags::DATA,
            b"shadowpipe over genuine HTTP/2",
        )
        .await
        .unwrap();
    let (_, _, reply, _) = session.recv(&mut stream).await.unwrap();
    assert_eq!(reply, b"shadowpipe over genuine HTTP/2");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_path_gets_cover_response_and_no_inner_stream() {
    let expected = route();
    let wrong = HttpStreamRoute::new(
        "example.com",
        "/api/events/ffffffffffffffffffffffffffffffff",
    )
    .unwrap();
    let (client_wire, server_wire) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        let error = http_stream::server_accept(server_wire, &expected)
            .await
            .err()
            .expect("wrong path unexpectedly reached an inner stream");
        assert!(error.to_string().contains("404"));
    });
    let error = http_stream::client_connect(client_wire, &wrong)
        .await
        .err()
        .expect("wrong path unexpectedly received HTTP 200");
    assert!(error.to_string().contains("404"));
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_bridge_survives_bidirectional_backpressure() {
    const TOTAL: usize = 4 * 1024 * 1024;
    let (client_wire, server_wire) = tokio::io::duplex(64 * 1024);
    let server_route = route();
    let server = tokio::spawn(async move {
        let mut stream = http_stream::server_accept(server_wire, &server_route)
            .await
            .unwrap();
        let mut received = 0usize;
        let mut buffer = vec![0u8; 8192];
        while received < TOTAL {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            received += count;
            stream.write_all(&buffer[..count]).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        received
    });
    let client = http_stream::client_connect(client_wire, &route())
        .await
        .unwrap();
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let writer = tokio::spawn(async move {
        let chunk = vec![0xA5; 8192];
        for _ in 0..(TOTAL / chunk.len()) {
            client_write.write_all(&chunk).await.unwrap();
        }
        client_write.shutdown().await.unwrap();
    });
    let reader = tokio::spawn(async move {
        let mut echoed = 0usize;
        let mut buffer = vec![0u8; 8192];
        loop {
            let count = client_read.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            assert!(buffer[..count].iter().all(|byte| *byte == 0xA5));
            echoed += count;
        }
        echoed
    });
    writer.await.unwrap();
    assert_eq!(reader.await.unwrap(), TOTAL);
    assert_eq!(server.await.unwrap(), TOTAL);
}
