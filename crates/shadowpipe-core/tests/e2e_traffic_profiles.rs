//! Service-shaped traffic (YouTube, ChatGPT, Claude, Gemini) over mux + encryption.

mod common;

use common::profiles::{all_services, service_name, ProfileGenerator, Service};
use common::{default_mux, mux_echo_roundtrip, EchoStack};
use shadowpipe_core::proto::CamouflageMode;

#[tokio::test]
async fn youtube_profile_mux_roundtrip_raw() {
    service_mux_roundtrip(Service::Youtube, CamouflageMode::Raw, 42).await;
}

#[tokio::test]
async fn youtube_profile_mux_roundtrip_h2() {
    service_mux_roundtrip(Service::Youtube, CamouflageMode::H2Chunk, 42).await;
}

#[tokio::test]
async fn chatgpt_profile_mux_roundtrip_h2() {
    service_mux_roundtrip(Service::ChatGpt, CamouflageMode::H2Chunk, 7).await;
}

#[tokio::test]
async fn claude_profile_mux_roundtrip_h2() {
    service_mux_roundtrip(Service::Claude, CamouflageMode::H2Chunk, 99).await;
}

#[tokio::test]
async fn gemini_profile_mux_roundtrip_h2() {
    service_mux_roundtrip(Service::Gemini, CamouflageMode::H2Chunk, 13).await;
}

#[tokio::test]
async fn chatgpt_profile_mux_roundtrip_raw() {
    service_mux_roundtrip(Service::ChatGpt, CamouflageMode::Raw, 7).await;
}

#[tokio::test]
async fn claude_profile_mux_roundtrip_raw() {
    service_mux_roundtrip(Service::Claude, CamouflageMode::Raw, 99).await;
}

#[tokio::test]
async fn gemini_profile_mux_roundtrip_raw() {
    service_mux_roundtrip(Service::Gemini, CamouflageMode::Raw, 13).await;
}

#[tokio::test]
async fn gemini_full_session_smoke_h2() {
    service_mux_roundtrip_limited(Service::Gemini, CamouflageMode::H2Chunk, 3, 12).await;
}

#[tokio::test]
async fn all_services_smoke_matrix() {
    for service in all_services() {
        service_mux_roundtrip_limited(service, CamouflageMode::H2Chunk, 1, 6).await;
    }
}

async fn service_mux_roundtrip(service: Service, camouflage: CamouflageMode, seed: u64) {
    service_mux_roundtrip_limited(service, camouflage, seed, usize::MAX).await;
}

async fn service_mux_roundtrip_limited(
    service: Service,
    camouflage: CamouflageMode,
    seed: u64,
    max_chunks: usize,
) {
    let stack = EchoStack::start(camouflage).await;
    let (mut session, mut stream) = stack.connect(camouflage).await;
    let mux = default_mux();
    let mut gen = ProfileGenerator::new(service, seed);

    for (i, chunk) in gen.session().into_iter().take(max_chunks).enumerate() {
        let got = mux_echo_roundtrip(&mut session, &mut stream, &chunk.bytes, &mux, i as u32).await;
        assert_eq!(
            got,
            chunk.bytes,
            "{} chunk {} len {}",
            service_name(service),
            i,
            chunk.bytes.len()
        );
    }
}

#[tokio::test]
async fn youtube_large_segment_64kb() {
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::H2Chunk).await;
    let mux = default_mux();
    let mut gen = ProfileGenerator::new(Service::Youtube, 0);
    let blob = gen.large_download(64);
    let got = mux_echo_roundtrip(&mut session, &mut stream, &blob, &mux, 1000).await;
    assert_eq!(got, blob);
}

#[tokio::test]
async fn claude_large_context_post_32kb() {
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::H2Chunk).await;
    let mux = default_mux();
    let post: Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
    let got = mux_echo_roundtrip(&mut session, &mut stream, &post, &mux, 2000).await;
    assert_eq!(got.len(), 32768);
}
