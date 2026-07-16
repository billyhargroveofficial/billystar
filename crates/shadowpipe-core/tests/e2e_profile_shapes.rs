//! Unit tests for synthetic service traffic profiles (no network).

mod common;

use common::profiles::{all_services, service_name, ProfileGenerator, Service};

#[test]
fn profiles_are_deterministic_for_same_seed() {
    for service in all_services() {
        let a = ProfileGenerator::new(service, 42).session();
        let b = ProfileGenerator::new(service, 42).session();
        assert_eq!(a.len(), b.len(), "{}", service_name(service));
        for (i, (ca, cb)) in a.iter().zip(b.iter()).enumerate() {
            assert_eq!(ca.bytes, cb.bytes, "{} chunk {}", service_name(service), i);
            assert_eq!(ca.upstream, cb.upstream);
        }
    }
}

#[test]
fn profiles_differ_across_seeds() {
    for service in all_services() {
        let a = ProfileGenerator::new(service, 1).session();
        let b = ProfileGenerator::new(service, 2).session();
        let any_diff = a.iter().zip(b.iter()).any(|(ca, cb)| ca.bytes != cb.bytes);
        assert!(any_diff, "{} should vary by seed", service_name(service));
    }
}

#[test]
fn youtube_has_large_downstream_segments() {
    let chunks = ProfileGenerator::new(Service::Youtube, 0).session();
    let large: Vec<_> = chunks
        .iter()
        .filter(|c| c.bytes.len() >= 8 * 1024)
        .collect();
    assert!(large.len() >= 4, "youtube profile needs video segments");
    assert!(large.iter().all(|c| !c.upstream));
}

#[test]
fn chatgpt_has_many_sse_events() {
    let chunks = ProfileGenerator::new(Service::ChatGpt, 0).session();
    let sse: Vec<_> = chunks.iter().filter(|c| !c.upstream).collect();
    assert!(sse.len() >= 80, "chatgpt SSE stream");
    assert!(sse.iter().all(|c| c.bytes.len() < 512));
    assert!(
        chunks.first().unwrap().bytes.len() >= 2048,
        "chatgpt POST body"
    );
}

#[test]
fn claude_has_large_post_and_sse() {
    let chunks = ProfileGenerator::new(Service::Claude, 0).session();
    assert!(chunks.first().unwrap().bytes.len() >= 2048);
    let sse: Vec<_> = chunks.iter().skip(1).filter(|c| !c.upstream).collect();
    assert!(sse.len() >= 70);
}

#[test]
fn gemini_has_multimodal_upload_and_mixed_chunks() {
    let chunks = ProfileGenerator::new(Service::Gemini, 0).session();
    assert!(chunks.first().unwrap().bytes.len() >= 8 * 1024);
    assert!(chunks.first().unwrap().upstream);
    let sizes: Vec<_> = chunks.iter().map(|c| c.bytes.len()).collect();
    assert!(sizes.iter().any(|&n| n >= 4096), "gemini large chunks");
    assert!(sizes.iter().any(|&n| n < 512), "gemini small chunks");
}

#[test]
fn large_download_sizes_match_request() {
    let mut gen = ProfileGenerator::new(Service::Youtube, 99);
    for kb in [1, 8, 64, 128] {
        assert_eq!(gen.large_download(kb).len(), kb * 1024);
    }
}
