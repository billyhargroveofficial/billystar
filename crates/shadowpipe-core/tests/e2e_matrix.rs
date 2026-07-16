//! Camouflage × padding matrix + profile seed derivation.

mod common;

use common::profiles::{ProfileGenerator, Service};
use common::{echo_roundtrip, mux_echo_roundtrip, EchoStack};
use shadowpipe_core::profile::derive_profile;
use shadowpipe_core::proto::{CamouflageMode, PaddingProfile};
use shadowpipe_core::session::ClientConfig;

#[tokio::test]
async fn camouflage_raw_and_h2_both_work() {
    for camo in [CamouflageMode::Raw, CamouflageMode::H2Chunk] {
        let stack = EchoStack::start(camo).await;
        let (mut session, mut stream) = stack.connect(camo).await;
        let reply = echo_roundtrip(&mut session, &mut stream, b"matrix-smoke").await;
        assert_eq!(reply, b"matrix-smoke");
    }
}

#[tokio::test]
async fn padding_profiles_all_work() {
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    for profile in [
        PaddingProfile::Balanced,
        PaddingProfile::PreferAscii,
        PaddingProfile::PreferEntropy,
    ] {
        let tcp = tokio::net::TcpStream::connect(stack.addr).await.unwrap();
        let mut stream = shadowpipe_core::carrier::client_connect(tcp, CamouflageMode::H2Chunk)
            .await
            .unwrap();
        let config = ClientConfig {
            camouflage: CamouflageMode::H2Chunk,
            padding_profile: profile,
            server_fingerprint: stack.server_fingerprint,
            client_credential: std::sync::Arc::clone(&stack.client_credential),
        };
        let (mut session, _) =
            shadowpipe_core::session::AuthenticatedSession::client_connect(&mut stream, &config)
                .await
                .unwrap();
        let reply = echo_roundtrip(&mut session, &mut stream, b"pad").await;
        assert_eq!(reply, b"pad");
    }
}

#[tokio::test]
async fn profile_seed_changes_mux_params() {
    let a = derive_profile(b"subscriber-alpha-32-bytes-long!!");
    let b = derive_profile(b"subscriber-beta-32-bytes-long!!!");
    assert!(
        a.mux.stream_count != b.mux.stream_count || a.mux.max_chunk_size != b.mux.max_chunk_size
    );
}

#[tokio::test]
async fn derived_profile_youtube_still_roundtrips() {
    let profile = derive_profile(b"youtube-user-seed-test-1234567890");
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::H2Chunk).await;
    let mut gen = ProfileGenerator::new(Service::Youtube, 5);
    let blob = gen.large_download(128);
    let got = mux_echo_roundtrip(&mut session, &mut stream, &blob, &profile.mux, 0).await;
    assert_eq!(got, blob);
}

#[tokio::test]
async fn derived_profile_all_services_roundtrip() {
    let profile = derive_profile(b"matrix-subscriber-seed-32bytes!!");
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::H2Chunk).await;
    for (i, service) in common::profiles::all_services().into_iter().enumerate() {
        let mut gen = ProfileGenerator::new(service, i as u64);
        let chunk = gen.session().into_iter().next().unwrap().bytes;
        let got =
            mux_echo_roundtrip(&mut session, &mut stream, &chunk, &profile.mux, i as u32).await;
        assert_eq!(got, chunk);
    }
}
