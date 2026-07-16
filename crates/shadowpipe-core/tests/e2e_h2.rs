//! H2 carrier + echo over camouflaged transport.

use shadowpipe_core::carrier::{client_connect, server_accept};
use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::proto::{CamouflageMode, FrameFlags, PaddingProfile};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::test]
async fn h2_camouflage_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = ServerState::generate();
    let server_fingerprint = state.fingerprint();
    let client_credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = client_credential.authorized_clients().unwrap();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = server_accept(tcp).await.unwrap();
        assert_eq!(stream.mode(), CamouflageMode::H2Chunk);
        let (mut session, _, _) = AuthenticatedSession::server_accept(
            &mut stream,
            &state,
            &authorized,
            CamouflageMode::H2Chunk,
        )
        .await
        .unwrap();
        let (_, _, payload, _) = session.recv(&mut stream).await.unwrap();
        session
            .send(&mut stream, 0, FrameFlags::DATA, &payload)
            .await
            .unwrap();
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stream = client_connect(tcp, CamouflageMode::H2Chunk).await.unwrap();
    let config = ClientConfig {
        camouflage: CamouflageMode::H2Chunk,
        padding_profile: PaddingProfile::Balanced,
        server_fingerprint,
        client_credential,
    };
    let (mut session, _) = AuthenticatedSession::client_connect(&mut stream, &config)
        .await
        .unwrap();
    session
        .send(&mut stream, 0, FrameFlags::DATA, b"h2-works")
        .await
        .unwrap();
    let (_, _, reply, _) = session.recv(&mut stream).await.unwrap();
    assert_eq!(reply, b"h2-works");
}
