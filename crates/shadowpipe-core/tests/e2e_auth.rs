//! Mandatory v3 server pinning plus hybrid per-device client authorization.

use shadowpipe_core::client_auth::{
    AuthFailed, AuthorizedClients, ClientCredential, CLIENT_ACCESS_HELLO_LEN,
    CLIENT_ACCESS_PROOF_LEN, SERVER_ACCESS_PROOF_LEN,
};
use shadowpipe_core::proto::CamouflageMode;
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerPins, ServerState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const SERVER_KEY_WIRE_LEN: usize = 2 + 1184;
const CLIENT_HELLO_WIRE_LEN: usize = 4 + 1 + 16 + 32 + 2 + 1088 + 1 + 1;
const SERVER_HELLO_WIRE_LEN: usize = 16 + 32 + 8;
const CLIENT_FINISHED_WIRE_LEN: usize = 1 + 16 + 64 + 32 + 16;
const SERVER_FINISHED_WIRE_LEN: usize = 1 + 32 + 16;

#[derive(Debug)]
struct CapturedHandshake {
    server_access_proof: Vec<u8>,
    client_access_proof: Vec<u8>,
    client_finished: Vec<u8>,
}

async fn relay_exact(from: &mut DuplexStream, to: &mut DuplexStream, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    from.read_exact(&mut bytes).await.unwrap();
    to.write_all(&bytes).await.unwrap();
    to.flush().await.unwrap();
    bytes
}

async fn captured_valid_handshake(
    state: Arc<ServerState>,
    credential: Arc<ClientCredential>,
    authorized: AuthorizedClients,
) -> CapturedHandshake {
    let (mut client_io, mut proxy_client) = tokio::io::duplex(512 * 1024);
    let (mut proxy_server, mut server_io) = tokio::io::duplex(512 * 1024);
    let server_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        AuthenticatedSession::server_accept(
            &mut server_io,
            &server_state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
    });
    let config = ClientConfig::pinned(state.fingerprint(), credential);
    let client =
        tokio::spawn(
            async move { AuthenticatedSession::client_connect(&mut client_io, &config).await },
        );
    let proxy = tokio::spawn(async move {
        relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_ACCESS_HELLO_LEN,
        )
        .await;
        let server_access_proof = relay_exact(
            &mut proxy_server,
            &mut proxy_client,
            SERVER_ACCESS_PROOF_LEN,
        )
        .await;
        let client_access_proof = relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_ACCESS_PROOF_LEN,
        )
        .await;
        relay_exact(&mut proxy_server, &mut proxy_client, SERVER_KEY_WIRE_LEN).await;
        relay_exact(&mut proxy_client, &mut proxy_server, CLIENT_HELLO_WIRE_LEN).await;
        relay_exact(&mut proxy_server, &mut proxy_client, SERVER_HELLO_WIRE_LEN).await;
        let captured = relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_FINISHED_WIRE_LEN,
        )
        .await;
        relay_exact(
            &mut proxy_server,
            &mut proxy_client,
            SERVER_FINISHED_WIRE_LEN,
        )
        .await;
        CapturedHandshake {
            server_access_proof,
            client_access_proof,
            client_finished: captured,
        }
    });
    let captured = proxy.await.unwrap();
    let client_session = client.await.unwrap().unwrap().0;
    let server_session = server.await.unwrap().unwrap().0;
    assert_eq!(
        client_session.client_key_id(),
        server_session.client_key_id()
    );
    captured
}

#[derive(Clone, Copy)]
enum AdversarialProxy {
    Replay,
    BitFlip,
    MutateTranscript,
    Truncate,
    ReflectClientFinished,
}

async fn adversarial_handshake(
    state: Arc<ServerState>,
    credential: Arc<ClientCredential>,
    authorized: AuthorizedClients,
    captured_client_finished: &[u8],
    action: AdversarialProxy,
) -> (anyhow::Result<()>, anyhow::Result<()>) {
    let (mut client_io, mut proxy_client) = tokio::io::duplex(512 * 1024);
    let (mut proxy_server, mut server_io) = tokio::io::duplex(512 * 1024);
    let server_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        AuthenticatedSession::server_accept(
            &mut server_io,
            &server_state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
        .map(|_| ())
    });
    let config = ClientConfig::pinned(state.fingerprint(), credential);
    let client = tokio::spawn(async move {
        AuthenticatedSession::client_connect(&mut client_io, &config)
            .await
            .map(|_| ())
    });
    let replay = captured_client_finished.to_vec();
    let proxy = tokio::spawn(async move {
        relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_ACCESS_HELLO_LEN,
        )
        .await;
        relay_exact(
            &mut proxy_server,
            &mut proxy_client,
            SERVER_ACCESS_PROOF_LEN,
        )
        .await;
        relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_ACCESS_PROOF_LEN,
        )
        .await;
        relay_exact(&mut proxy_server, &mut proxy_client, SERVER_KEY_WIRE_LEN).await;
        let mut hello = vec![0u8; CLIENT_HELLO_WIRE_LEN];
        proxy_client.read_exact(&mut hello).await.unwrap();
        if matches!(action, AdversarialProxy::MutateTranscript) {
            // Last byte is the valid padding-profile enum: Balanced(0) ->
            // PreferAscii(1). The client's canonical view remains unchanged.
            hello[CLIENT_HELLO_WIRE_LEN - 1] = 1;
        }
        proxy_server.write_all(&hello).await.unwrap();
        proxy_server.flush().await.unwrap();
        relay_exact(&mut proxy_server, &mut proxy_client, SERVER_HELLO_WIRE_LEN).await;
        let mut fresh = vec![0u8; CLIENT_FINISHED_WIRE_LEN];
        proxy_client.read_exact(&mut fresh).await.unwrap();
        if matches!(action, AdversarialProxy::ReflectClientFinished) {
            // Reflect a correctly sized prefix of the client's encrypted
            // Finished record back as if it were ServerFinished. Independent
            // directional keys and role-specific AAD must make this fail.
            proxy_client
                .write_all(&fresh[..SERVER_FINISHED_WIRE_LEN])
                .await
                .unwrap();
            proxy_client.flush().await.unwrap();
            return;
        }
        let mut sent = match action {
            AdversarialProxy::Replay => replay,
            _ => fresh,
        };
        if matches!(action, AdversarialProxy::BitFlip) {
            sent[CLIENT_FINISHED_WIRE_LEN / 2] ^= 1;
        }
        if matches!(action, AdversarialProxy::Truncate) {
            sent.pop();
        }
        proxy_server.write_all(&sent).await.unwrap();
        proxy_server.flush().await.unwrap();
        // EOF makes a fixed-length truncated Finished terminal and also wakes
        // the client after the server rejects replay/tamper without replying.
    });
    proxy.await.unwrap();
    let server_result = tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("adversarial server handshake hung")
        .unwrap();
    let client_result = tokio::time::timeout(std::time::Duration::from_secs(2), client)
        .await
        .expect("adversarial client handshake hung")
        .unwrap();
    (server_result, client_result)
}

async fn handshake_with(
    state: Arc<ServerState>,
    pin: [u8; 32],
    client: Arc<ClientCredential>,
    authorized: AuthorizedClients,
) -> Result<(), String> {
    let (mut client_io, mut server_io) = tokio::io::duplex(256 * 1024);
    let server_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        AuthenticatedSession::server_accept(
            &mut server_io,
            &server_state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
    });
    let config = ClientConfig::pinned(pin, client);
    let client_result = AuthenticatedSession::client_connect(&mut client_io, &config)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string());
    drop(client_io);
    let server_result = tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("server handshake did not terminate")
        .expect("server handshake task panicked");
    if client_result.is_ok() {
        assert!(
            server_result.is_ok(),
            "server rejected a client that completed"
        );
    }
    client_result
}

/// Drive only the fixed-width access gate as an untrusted peer. The returned
/// byte count is what the server emitted after the submitted client proof. A
/// fail-closed pre-key rejection must return EOF (`0`) rather than even the
/// first byte of the stable ML-KEM public-key flight.
async fn submit_access_proof(
    state: Arc<ServerState>,
    authorized: AuthorizedClients,
    key_id: [u8; CLIENT_ACCESS_HELLO_LEN],
    client_proof: &[u8],
) -> (Vec<u8>, anyhow::Result<()>, usize) {
    assert_eq!(client_proof.len(), CLIENT_ACCESS_PROOF_LEN);
    let (mut peer_io, mut server_io) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn(async move {
        AuthenticatedSession::server_accept(
            &mut server_io,
            &state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
        .map(|_| ())
    });

    peer_io.write_all(&key_id).await.unwrap();
    peer_io.flush().await.unwrap();
    let mut server_access_proof = vec![0u8; SERVER_ACCESS_PROOF_LEN];
    peer_io.read_exact(&mut server_access_proof).await.unwrap();
    peer_io.write_all(client_proof).await.unwrap();
    peer_io.flush().await.unwrap();

    let mut first_post_gate_byte = [0u8; 1];
    let emitted = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        peer_io.read(&mut first_post_gate_byte),
    )
    .await
    .expect("server neither rejected access nor emitted a key byte")
    .unwrap();
    drop(peer_io);
    let server_result = tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("server did not terminate after access proof")
        .unwrap();
    (server_access_proof, server_result, emitted)
}

#[tokio::test]
async fn correct_server_pin_and_both_client_proofs_authenticate() {
    let state = Arc::new(ServerState::generate());
    let client = Arc::new(ClientCredential::generate().unwrap());
    let authorized = client.authorized_clients().unwrap();
    let fp = state.fingerprint();
    handshake_with(state, fp, client, authorized)
        .await
        .expect("correct server pin and authorized hybrid device must complete");
}

#[tokio::test]
async fn replayed_client_access_proof_on_fresh_challenge_emits_zero_mlkem_bytes() {
    let state = Arc::new(ServerState::generate());
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let captured = captured_valid_handshake(
        Arc::clone(&state),
        Arc::clone(&credential),
        credential.authorized_clients().unwrap(),
    )
    .await;

    let (fresh_server_proof, result, emitted) = submit_access_proof(
        state,
        credential.authorized_clients().unwrap(),
        credential.key_id(),
        &captured.client_access_proof,
    )
    .await;
    assert_ne!(
        &fresh_server_proof[..32],
        &captured.server_access_proof[..32],
        "the replay test requires a fresh server challenge"
    );
    assert_eq!(emitted, 0, "server disclosed ML-KEM bytes before access");
    let error = result.expect_err("replayed access proof authenticated");
    assert!(error.downcast_ref::<AuthFailed>().is_some(), "{error:#}");
}

#[tokio::test]
async fn unknown_kid_and_arbitrary_proof_emit_zero_mlkem_bytes() {
    let state = Arc::new(ServerState::generate());
    let enrolled = ClientCredential::generate().unwrap();
    let unknown = ClientCredential::generate().unwrap();
    let (_dummy_server_proof, result, emitted) = submit_access_proof(
        state,
        enrolled.authorized_clients().unwrap(),
        unknown.key_id(),
        &[0u8; CLIENT_ACCESS_PROOF_LEN],
    )
    .await;
    assert_eq!(emitted, 0, "unknown kid reached the ML-KEM key flight");
    let error = result.expect_err("unknown kid authenticated with arbitrary proof");
    assert!(error.downcast_ref::<AuthFailed>().is_some(), "{error:#}");
}

#[tokio::test]
async fn tampered_fresh_client_access_proof_emits_zero_mlkem_bytes() {
    let state = Arc::new(ServerState::generate());
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = credential.authorized_clients().unwrap();
    let (mut client_io, mut proxy_client) = tokio::io::duplex(256 * 1024);
    let (mut proxy_server, mut server_io) = tokio::io::duplex(256 * 1024);
    let server_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        AuthenticatedSession::server_accept(
            &mut server_io,
            &server_state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
    });
    let config = ClientConfig::pinned(state.fingerprint(), Arc::clone(&credential));
    let client =
        tokio::spawn(
            async move { AuthenticatedSession::client_connect(&mut client_io, &config).await },
        );
    let proxy = tokio::spawn(async move {
        relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_ACCESS_HELLO_LEN,
        )
        .await;
        relay_exact(
            &mut proxy_server,
            &mut proxy_client,
            SERVER_ACCESS_PROOF_LEN,
        )
        .await;
        let mut proof = vec![0u8; CLIENT_ACCESS_PROOF_LEN];
        proxy_client.read_exact(&mut proof).await.unwrap();
        proof[CLIENT_ACCESS_PROOF_LEN - 1] ^= 1;
        proxy_server.write_all(&proof).await.unwrap();
        proxy_server.flush().await.unwrap();

        let mut first_key_byte = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            proxy_server.read(&mut first_key_byte),
        )
        .await
        .expect("server did not terminate after tampered access proof")
        .unwrap()
    });
    let emitted = proxy.await.unwrap();
    assert_eq!(emitted, 0, "tampered proof reached the ML-KEM key flight");
    let error = match server.await.unwrap() {
        Ok(_) => panic!("tampered access proof authenticated"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<AuthFailed>().is_some(), "{error:#}");
    assert!(client.await.unwrap().is_err());
}

#[tokio::test]
async fn fake_server_without_psk_receives_no_client_access_proof() {
    let state = ServerState::generate();
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let (mut client_io, mut fake_server_io) = tokio::io::duplex(256 * 1024);
    let fake_server = tokio::spawn(async move {
        let mut access_hello = [0u8; CLIENT_ACCESS_HELLO_LEN];
        fake_server_io.read_exact(&mut access_hello).await.unwrap();
        // Structurally exact but unauthenticated challenge+MAC.
        let mut forged_server_proof = [0u8; SERVER_ACCESS_PROOF_LEN];
        forged_server_proof[..32].fill(0xA5);
        fake_server_io
            .write_all(&forged_server_proof)
            .await
            .unwrap();
        fake_server_io.flush().await.unwrap();
        let mut received = Vec::new();
        fake_server_io.read_to_end(&mut received).await.unwrap();
        (access_hello, received)
    });
    let config = ClientConfig::pinned(state.fingerprint(), Arc::clone(&credential));
    let error = match AuthenticatedSession::client_connect(&mut client_io, &config).await {
        Ok(_) => panic!("client accepted a server access proof without the PSK"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<AuthFailed>().is_some(), "{error:#}");
    drop(client_io);
    let (access_hello, received) = fake_server.await.unwrap();
    assert_eq!(access_hello, credential.key_id());
    assert!(
        received.is_empty(),
        "client emitted {} access-proof bytes to a fake server",
        received.len()
    );
}

#[tokio::test]
async fn wrong_server_pin_is_rejected_before_client_finished() {
    let state = Arc::new(ServerState::generate());
    let client = Arc::new(ClientCredential::generate().unwrap());
    let authorized = client.authorized_clients().unwrap();
    let mut bad = state.fingerprint();
    bad[0] ^= 0xff;
    let error = handshake_with(state, bad, client, authorized)
        .await
        .expect_err("a mismatched server pin must be rejected");
    assert!(error.contains("pin mismatch") || error.to_lowercase().contains("mitm"));
}

#[tokio::test]
async fn unknown_or_revoked_device_gets_only_generic_auth_failure() {
    for label in ["unknown", "revoked"] {
        let state = Arc::new(ServerState::generate());
        let enrolled = ClientCredential::generate().unwrap();
        let connecting = Arc::new(ClientCredential::generate().unwrap());
        let authorized = enrolled.authorized_clients().unwrap();
        let (mut client_io, mut server_io) = tokio::io::duplex(256 * 1024);
        let server_state = Arc::clone(&state);
        let server = tokio::spawn(async move {
            AuthenticatedSession::server_accept(
                &mut server_io,
                &server_state,
                &authorized,
                CamouflageMode::Raw,
            )
            .await
        });
        let config = ClientConfig::pinned(state.fingerprint(), connecting);
        let client_result = AuthenticatedSession::client_connect(&mut client_io, &config).await;
        // An unknown client intentionally emits no client access proof after
        // rejecting the dummy-PSK server MAC. Close its transport so the
        // server's fixed-width read terminates instead of waiting forever.
        drop(client_io);
        let server_error = match server.await.unwrap() {
            Ok(_) => panic!("unauthorized device unexpectedly authenticated"),
            Err(error) => error,
        };
        assert!(
            server_error.downcast_ref::<AuthFailed>().is_some(),
            "{label}: {server_error:#}"
        );
        assert!(
            client_result.is_err(),
            "{label}: client accepted missing ServerFinished"
        );
    }
}

#[tokio::test]
async fn retiring_and_active_server_pin_overlap_has_no_protocol_fallback() {
    let state = Arc::new(ServerState::generate());
    let active = state.fingerprint();
    let unrelated = ServerState::generate().fingerprint();
    let pins = ServerPins::new(&[unrelated, active]).unwrap();
    let client = Arc::new(ClientCredential::generate().unwrap());
    let authorized = client.authorized_clients().unwrap();
    let (mut client_io, mut server_io) = tokio::io::duplex(256 * 1024);
    let server_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        AuthenticatedSession::server_accept(
            &mut server_io,
            &server_state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
        .unwrap()
    });

    let config = ClientConfig::pinned(unrelated, client);
    let (session, _) = AuthenticatedSession::client_connect_pins(&mut client_io, &config, &pins)
        .await
        .expect("active identity in authenticated overlap set must work");
    let server_session = server.await.unwrap();
    assert_eq!(session.client_key_id(), server_session.0.client_key_id());
}

#[tokio::test]
async fn v2_client_hello_is_rejected_without_negotiation_or_fallback() {
    let state = Arc::new(ServerState::generate());
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let authorized = credential.authorized_clients().unwrap();
    let (mut client_io, mut proxy_client) = tokio::io::duplex(256 * 1024);
    let (mut proxy_server, mut server_io) = tokio::io::duplex(256 * 1024);
    let server_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        AuthenticatedSession::server_accept(
            &mut server_io,
            &server_state,
            &authorized,
            CamouflageMode::Raw,
        )
        .await
    });
    let config = ClientConfig::pinned(state.fingerprint(), credential);
    let client =
        tokio::spawn(
            async move { AuthenticatedSession::client_connect(&mut client_io, &config).await },
        );
    let proxy = tokio::spawn(async move {
        relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_ACCESS_HELLO_LEN,
        )
        .await;
        relay_exact(
            &mut proxy_server,
            &mut proxy_client,
            SERVER_ACCESS_PROOF_LEN,
        )
        .await;
        relay_exact(
            &mut proxy_client,
            &mut proxy_server,
            CLIENT_ACCESS_PROOF_LEN,
        )
        .await;
        relay_exact(&mut proxy_server, &mut proxy_client, SERVER_KEY_WIRE_LEN).await;
        let mut hello = vec![0u8; CLIENT_HELLO_WIRE_LEN];
        proxy_client.read_exact(&mut hello).await.unwrap();
        // ClientHello is magic[4] || version[1] || ... . Mutating only this
        // byte exercises strict v3 rejection after a valid access gate.
        hello[4] = 2;
        proxy_server.write_all(&hello).await.unwrap();
        proxy_server.flush().await.unwrap();
    });
    proxy.await.unwrap();
    let error = match server.await.unwrap() {
        Ok(_) => panic!("v2 must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unsupported version 2"));
    assert!(client.await.unwrap().is_err());
}

#[tokio::test]
async fn captured_client_finished_replay_fails_against_fresh_server_hello() {
    let state = Arc::new(ServerState::generate());
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let captured = captured_valid_handshake(
        Arc::clone(&state),
        Arc::clone(&credential),
        credential.authorized_clients().unwrap(),
    )
    .await;
    let (server, client) = adversarial_handshake(
        state,
        Arc::clone(&credential),
        credential.authorized_clients().unwrap(),
        &captured.client_finished,
        AdversarialProxy::Replay,
    )
    .await;
    let error = server.expect_err("captured Finished replay authenticated");
    assert!(error.downcast_ref::<AuthFailed>().is_some(), "{error:#}");
    assert!(client.is_err());
}

#[tokio::test]
async fn encrypted_finished_bitflip_and_pretranscript_mutation_fail_before_session() {
    let state = Arc::new(ServerState::generate());
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let captured = captured_valid_handshake(
        Arc::clone(&state),
        Arc::clone(&credential),
        credential.authorized_clients().unwrap(),
    )
    .await;
    for action in [
        AdversarialProxy::BitFlip,
        AdversarialProxy::MutateTranscript,
    ] {
        let (server, client) = adversarial_handshake(
            Arc::clone(&state),
            Arc::clone(&credential),
            credential.authorized_clients().unwrap(),
            &captured.client_finished,
            action,
        )
        .await;
        let error = server.expect_err("tampered handshake produced a typed session");
        assert!(error.downcast_ref::<AuthFailed>().is_some(), "{error:#}");
        assert!(client.is_err());
    }
}

#[tokio::test]
async fn truncated_fixed_finished_fails_without_application_session() {
    let state = Arc::new(ServerState::generate());
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let (server, client) = adversarial_handshake(
        state,
        Arc::clone(&credential),
        credential.authorized_clients().unwrap(),
        &[],
        AdversarialProxy::Truncate,
    )
    .await;
    assert!(server.is_err());
    assert!(client.is_err());
}

#[tokio::test]
async fn reflected_client_finished_cannot_authenticate_as_server_finished() {
    let state = Arc::new(ServerState::generate());
    let credential = Arc::new(ClientCredential::generate().unwrap());
    let (server, client) = adversarial_handshake(
        state,
        Arc::clone(&credential),
        credential.authorized_clients().unwrap(),
        &[],
        AdversarialProxy::ReflectClientFinished,
    )
    .await;
    assert!(
        server.is_err(),
        "server accepted a handshake without ClientFinished"
    );
    assert!(
        client.is_err(),
        "client accepted reflected ClientFinished bytes"
    );
}

#[tokio::test]
async fn low_order_x25519_shares_cannot_remove_the_classical_hybrid_component() {
    #[derive(Clone, Copy)]
    enum MutatedShare {
        Client,
        Server,
    }

    for mutation in [MutatedShare::Client, MutatedShare::Server] {
        let state = Arc::new(ServerState::generate());
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = credential.authorized_clients().unwrap();
        let (mut client_io, mut proxy_client) = tokio::io::duplex(256 * 1024);
        let (mut proxy_server, mut server_io) = tokio::io::duplex(256 * 1024);
        let server_state = Arc::clone(&state);
        let server = tokio::spawn(async move {
            AuthenticatedSession::server_accept(
                &mut server_io,
                &server_state,
                &authorized,
                CamouflageMode::Raw,
            )
            .await
        });
        let config = ClientConfig::pinned(state.fingerprint(), credential);
        let client = tokio::spawn(async move {
            AuthenticatedSession::client_connect(&mut client_io, &config).await
        });
        let proxy = tokio::spawn(async move {
            relay_exact(
                &mut proxy_client,
                &mut proxy_server,
                CLIENT_ACCESS_HELLO_LEN,
            )
            .await;
            relay_exact(
                &mut proxy_server,
                &mut proxy_client,
                SERVER_ACCESS_PROOF_LEN,
            )
            .await;
            relay_exact(
                &mut proxy_client,
                &mut proxy_server,
                CLIENT_ACCESS_PROOF_LEN,
            )
            .await;
            relay_exact(&mut proxy_server, &mut proxy_client, SERVER_KEY_WIRE_LEN).await;

            let mut client_hello = vec![0u8; CLIENT_HELLO_WIRE_LEN];
            proxy_client.read_exact(&mut client_hello).await.unwrap();
            if matches!(mutation, MutatedShare::Client) {
                // magic[4] || version[1] || random[16] || X25519[32]
                client_hello[21..53].fill(0);
            }
            proxy_server.write_all(&client_hello).await.unwrap();
            proxy_server.flush().await.unwrap();

            if matches!(mutation, MutatedShare::Server) {
                let mut server_hello = vec![0u8; SERVER_HELLO_WIRE_LEN];
                proxy_server.read_exact(&mut server_hello).await.unwrap();
                // server_random[16] || X25519[32] || session_id[8]
                server_hello[16..48].fill(0);
                proxy_client.write_all(&server_hello).await.unwrap();
                proxy_client.flush().await.unwrap();
            }
        });
        proxy.await.unwrap();
        let server_result = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server hung after a non-contributory X25519 share")
            .unwrap();
        let client_result = tokio::time::timeout(std::time::Duration::from_secs(2), client)
            .await
            .expect("client hung after a non-contributory X25519 share")
            .unwrap();

        match mutation {
            MutatedShare::Client => {
                let error = match server_result {
                    Ok(_) => panic!("server accepted a non-contributory client X25519 share"),
                    Err(error) => error,
                };
                assert!(error.to_string().contains("non-contributory"), "{error:#}");
                assert!(client_result.is_err());
            }
            MutatedShare::Server => {
                let error = match client_result {
                    Ok(_) => panic!("client accepted a non-contributory server X25519 share"),
                    Err(error) => error,
                };
                assert!(error.to_string().contains("non-contributory"), "{error:#}");
                assert!(server_result.is_err());
            }
        }
    }
}

#[test]
fn fingerprint_is_stable_and_distinct() {
    let a = ServerState::generate();
    let b = ServerState::generate();
    assert_eq!(a.fingerprint(), a.fingerprint());
    assert_ne!(a.fingerprint(), b.fingerprint());
}
