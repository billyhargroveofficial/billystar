//! POLYMORPH-lite: per-subscriber parameters derived from a profile seed (ZATMENIE B-plane).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::mux::MuxConfig;
use crate::pacing::PacerConfig;
use crate::volume_guard::{VolumeGuardConfig, DEFAULT_THRESHOLD};

const PROFILE_INFO: &[u8] = b"zatmenie-profile-v1";

#[derive(Debug, Clone)]
pub struct TunnelProfile {
    pub mux: MuxConfig,
    pub volume_guard: VolumeGuardConfig,
    /// Degradation-symmetric pacer (off by default; opt-in via `--pace`). NOT
    /// randomized by `derive_profile` — a per-subscriber pacing rate would itself
    /// be a fingerprint, so it stays operator-controlled.
    pub pacer: PacerConfig,
}

impl Default for TunnelProfile {
    fn default() -> Self {
        Self {
            mux: MuxConfig {
                stream_count: 24,
                max_chunk_size: 1024,
            },
            volume_guard: VolumeGuardConfig {
                threshold: DEFAULT_THRESHOLD,
                enabled: true,
            },
            pacer: PacerConfig::default(),
        }
    }
}

/// Derive mux + guard knobs from a subscription/profile seed (32+ bytes ideal).
pub fn derive_profile(seed: &[u8]) -> TunnelProfile {
    if seed.is_empty() {
        return TunnelProfile::default();
    }

    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut material = [0u8; 32];
    if hk.expand(PROFILE_INFO, &mut material).is_err() {
        return TunnelProfile::default();
    }

    let stream_count = 16 + (u32::from(material[0]) % 17); // 16..32
    let max_chunk_size = 512 + (usize::from(material[1]) * 8); // 512..2552, step 8
    let max_chunk_size = max_chunk_size.clamp(512, 2048);
    let threshold = 6_000 + u64::from(material[2]) * 16; // 6000..~10000
    let threshold = threshold.clamp(6_000, 10_000);

    TunnelProfile {
        mux: MuxConfig {
            stream_count,
            max_chunk_size,
        },
        volume_guard: VolumeGuardConfig {
            threshold,
            enabled: true,
        },
        // Operator-controlled, never seed-derived (see struct docs).
        pacer: PacerConfig::default(),
    }
}

/// Parse `SHADOWPIPE_PROFILE_SEED` env (hex) or return default profile.
pub fn profile_from_env() -> TunnelProfile {
    match std::env::var("SHADOWPIPE_PROFILE_SEED") {
        Ok(hex) => {
            if let Ok(bytes) = hex::decode(hex.trim()) {
                return derive_profile(&bytes);
            }
            TunnelProfile::default()
        }
        Err(_) => TunnelProfile::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let seed = b"test-subscriber-seed-32-bytes!!";
        let a = derive_profile(seed);
        let b = derive_profile(seed);
        assert_eq!(a.mux.stream_count, b.mux.stream_count);
        assert_eq!(a.mux.max_chunk_size, b.mux.max_chunk_size);
        assert_eq!(a.volume_guard.threshold, b.volume_guard.threshold);
    }

    #[test]
    fn different_seeds_differ() {
        let a = derive_profile(b"seed-a");
        let b = derive_profile(b"seed-b");
        assert!(
            a.mux.stream_count != b.mux.stream_count
                || a.mux.max_chunk_size != b.mux.max_chunk_size
                || a.volume_guard.threshold != b.volume_guard.threshold
        );
    }
}
