//! Volume guard under service-shaped sustained downloads.

mod common;

use common::profiles::{ProfileGenerator, Service};
use common::{default_mux, mux_echo_roundtrip, pump_with_volume_guard, strict_guard, EchoStack};
use shadowpipe_core::proto::CamouflageMode;
use shadowpipe_core::tunnel::RotateConnection;

fn assert_large_segment_exceeds_guard(service: Service, seed: u64, min_wire: u64) {
    use shadowpipe_core::mux::encode_packet;
    use shadowpipe_core::volume_guard::estimate_frame_wire_bytes;
    let mux = default_mux();
    let mut gen = ProfileGenerator::new(service, seed);
    let blob = gen
        .session()
        .into_iter()
        .map(|c| c.bytes)
        .chain(std::iter::once(gen.large_download(8)))
        .find(|b| b.len() >= 4096)
        .expect("profile should include a large chunk");
    let frames = encode_packet(&blob, 1, &mux).unwrap();
    let wire: u64 = frames
        .iter()
        .map(|(sid, f)| estimate_frame_wire_bytes(f.len(), 0, *sid))
        .sum();
    assert!(
        wire > min_wire,
        "{:?} wire {} should exceed {}",
        service,
        wire,
        min_wire
    );
    assert!(frames.len() > 1, "{:?} should mux-split", service);
}

#[test]
fn youtube_segment_exceeds_volume_guard_threshold() {
    assert_large_segment_exceeds_guard(Service::Youtube, 1, 4096);
}

#[test]
fn chatgpt_post_exceeds_volume_guard_threshold() {
    assert_large_segment_exceeds_guard(Service::ChatGpt, 2, 4096);
}

#[test]
fn claude_context_exceeds_volume_guard_threshold() {
    assert_large_segment_exceeds_guard(Service::Claude, 99, 4096);
}

#[test]
fn gemini_upload_exceeds_volume_guard_threshold() {
    assert_large_segment_exceeds_guard(Service::Gemini, 3, 4096);
}

#[tokio::test]
async fn claude_sse_many_chunks_roundtrip() {
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::H2Chunk).await;
    let mux = default_mux();
    let mut gen = ProfileGenerator::new(Service::Claude, 5);
    let chunks: Vec<_> = gen.session().into_iter().skip(1).take(20).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let got = mux_echo_roundtrip(&mut session, &mut stream, &chunk.bytes, &mux, i as u32).await;
        assert_eq!(got, chunk.bytes);
    }
}

#[tokio::test]
async fn chatgpt_sse_many_small_chunks_roundtrip() {
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::H2Chunk).await;
    let mux = default_mux();
    let mut gen = ProfileGenerator::new(Service::ChatGpt, 2);
    let chunks: Vec<_> = gen.session().into_iter().filter(|c| !c.upstream).collect();
    assert!(chunks.len() > 50, "sse should have many events");
    for (i, chunk) in chunks.iter().enumerate() {
        let got = mux_echo_roundtrip(&mut session, &mut stream, &chunk.bytes, &mux, i as u32).await;
        assert_eq!(got, chunk.bytes);
    }
}

#[tokio::test]
async fn gemini_bidirectional_mixed_sizes() {
    let stack = EchoStack::start(CamouflageMode::H2Chunk).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::H2Chunk).await;
    let mux = default_mux();
    let mut gen = ProfileGenerator::new(Service::Gemini, 3);
    // Representative mix: small API chunks + one medium binary blob
    for (i, size) in [256usize, 512, 1024, 4096, 8192].iter().enumerate() {
        let blob: Vec<u8> = (0..*size).map(|j| ((i + j) % 251) as u8).collect();
        let got = mux_echo_roundtrip(&mut session, &mut stream, &blob, &mux, i as u32).await;
        assert_eq!(got, blob);
    }
    let _ = gen.large_download(4); // generator smoke
}

#[tokio::test]
async fn guard_pump_echo_rotates_on_budget() {
    let stack = EchoStack::start(CamouflageMode::Raw).await;
    let (mut session, mut stream) = stack.connect(CamouflageMode::Raw).await;
    let guard = strict_guard(2048);
    let chunk = vec![0u8; 800];
    let chunks: Vec<Vec<u8>> = (0..30).map(|_| chunk.clone()).collect();
    let result = pump_with_volume_guard(&mut session, &mut stream, &chunks, &guard).await;
    assert_eq!(result, Err(RotateConnection));
}
