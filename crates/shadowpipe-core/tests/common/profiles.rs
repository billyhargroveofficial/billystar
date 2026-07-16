//! Synthetic traffic shapes matching real service patterns (wire-level, no HTTP parse).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Debug, Clone, Copy)]
pub enum Service {
    Youtube,
    ChatGpt,
    Claude,
    Gemini,
}

#[derive(Debug, Clone)]
pub struct TrafficChunk {
    pub upstream: bool,
    pub bytes: Vec<u8>,
}

/// Named profile with deterministic RNG for reproducible tests.
pub struct ProfileGenerator {
    service: Service,
    rng: StdRng,
}

impl ProfileGenerator {
    pub fn new(service: Service, seed: u64) -> Self {
        Self {
            service,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Full session transcript as ordered chunks (simulate one page load / chat turn).
    pub fn session(&mut self) -> Vec<TrafficChunk> {
        match self.service {
            Service::Youtube => self.youtube_watch_session(),
            Service::ChatGpt => self.chatgpt_sse_session(),
            Service::Claude => self.claude_sse_session(),
            Service::Gemini => self.gemini_stream_session(),
        }
    }

    /// Single large downstream blob (video segment / model weights chunk).
    pub fn large_download(&mut self, total_kb: usize) -> Vec<u8> {
        let n = total_kb * 1024;
        let mut buf = vec![0u8; n];
        self.rng.fill(&mut buf[..]);
        buf
    }

    fn youtube_watch_session(&mut self) -> Vec<TrafficChunk> {
        let mut out = Vec::new();
        // Initial page/API (googlevideo redirect, youtubei.googleapis.com)
        out.push(TrafficChunk {
            upstream: true,
            bytes: b"GET /youtubei/v1/player?prettyPrint=false HTTP/1.1\r\nHost: youtube.com\r\n"
                .to_vec(),
        });
        out.push(TrafficChunk {
            upstream: false,
            bytes: {
                let mut b = vec![0u8; 4096];
                self.rng.fill(&mut b[..]);
                b
            },
        });
        // Video segment pulls — scaled for tests (pattern: large down, tiny up)
        for _ in 0..4 {
            out.push(TrafficChunk {
                upstream: false,
                bytes: self.large_download(8),
            });
            out.push(TrafficChunk {
                upstream: true,
                bytes: vec![0u8; self.rng.gen_range(200..512)],
            });
        }
        // Heartbeat / stats beacon
        out.push(TrafficChunk {
            upstream: true,
            bytes: b"POST /api/stats/qoe HTTP/1.1\r\nContent-Length: 120\r\n\r\n".to_vec(),
        });
        out
    }

    fn chatgpt_sse_session(&mut self) -> Vec<TrafficChunk> {
        let mut out = Vec::new();
        // POST conversation (JSON body 2–8 KB)
        let post_len = self.rng.gen_range(2048..8192);
        let mut post = vec![b'{'; post_len];
        for b in &mut post {
            *b = self.rng.gen();
        }
        out.push(TrafficChunk {
            upstream: true,
            bytes: post,
        });
        // SSE stream: many small `data:` lines
        for _ in 0..80 {
            let mut line = b"data: ".to_vec();
            let payload_len = self.rng.gen_range(40..380);
            line.extend((0..payload_len.min(32)).map(|_| self.rng.gen::<u8>()));
            line.truncate(6 + payload_len);
            line.extend_from_slice(b"\n\n");
            out.push(TrafficChunk {
                upstream: false,
                bytes: line,
            });
        }
        out.push(TrafficChunk {
            upstream: false,
            bytes: b"data: [DONE]\n\n".to_vec(),
        });
        out
    }

    fn claude_sse_session(&mut self) -> Vec<TrafficChunk> {
        let mut out = Vec::new();
        // Anthropic API — larger context POST (8–32 KB typical)
        let post_len = self.rng.gen_range(2048..8192);
        out.push(TrafficChunk {
            upstream: true,
            bytes: (0..post_len).map(|_| self.rng.gen()).collect(),
        });
        // SSE events, slightly larger than ChatGPT
        for _ in 0..70 {
            let n = self.rng.gen_range(80..600);
            out.push(TrafficChunk {
                upstream: false,
                bytes: (0..n).map(|_| self.rng.gen()).collect(),
            });
        }
        out
    }

    fn gemini_stream_session(&mut self) -> Vec<TrafficChunk> {
        let mut out = Vec::new();
        // Multimodal upload stub (high entropy binary)
        out.push(TrafficChunk {
            upstream: true,
            bytes: self.large_download(8),
        });
        // Mixed chunk sizes — protobuf-like stream
        for _ in 0..40 {
            let n = if self.rng.gen_bool(0.15) {
                self.rng.gen_range(4096..16384)
            } else {
                self.rng.gen_range(64..512)
            };
            let upstream = self.rng.gen_bool(0.08);
            out.push(TrafficChunk {
                upstream,
                bytes: (0..n).map(|_| self.rng.gen()).collect(),
            });
        }
        out
    }
}

pub fn all_services() -> [Service; 4] {
    [
        Service::Youtube,
        Service::ChatGpt,
        Service::Claude,
        Service::Gemini,
    ]
}

pub fn service_name(s: Service) -> &'static str {
    match s {
        Service::Youtube => "youtube",
        Service::ChatGpt => "chatgpt",
        Service::Claude => "claude",
        Service::Gemini => "gemini",
    }
}
