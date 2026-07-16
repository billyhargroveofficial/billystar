//! Volume guard byte budget triggers on realistic frame sizes.

use shadowpipe_core::client_auth::ClientCredential;
use shadowpipe_core::proto::{CamouflageMode, FrameFlags};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use shadowpipe_core::volume_guard::{VolumeGuard, VolumeGuardConfig};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::test]
async fn volume_guard_triggers_on_wire_budget() {
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
        loop {
            let (_, flags, _, _) = session.recv(&mut stream).await.unwrap();
            if flags.contains(FrameFlags::FIN) {
                break;
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

    let guard = VolumeGuard::new(VolumeGuardConfig {
        threshold: 1024,
        enabled: true,
    });
    let payload = vec![0u8; 300];
    let mut triggered = false;
    for _ in 0..50 {
        let wire = session
            .send(&mut stream, 0, FrameFlags::DATA, &payload)
            .await
            .unwrap();
        if guard.record_sent(wire).is_err() {
            triggered = true;
            break;
        }
    }
    assert!(
        triggered,
        "guard should fire before 50x300B frames at 1KB threshold"
    );
}
