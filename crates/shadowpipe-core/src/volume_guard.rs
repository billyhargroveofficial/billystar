//! Per-TCP-connection byte budget tracker (ZATMENIE / Zephyr Volume Guard).
//!
//! **Unverified countermeasure:** assumes TSPU meters per 5-tuple (src/dst IP+port/proto),
//! so a fresh TCP to the same dest IP resets the budget. If metering is per-dest-IP or
//! bidirectional, serial reconnect to one NL VPS is ineffective — measure with planeb first.
//!
//! Known accounting gaps (see review/01): handshake bytes and h2 carrier overhead are not
//! fully counted; sent/recv are separate budgets (up to ~2× threshold on one 5-tuple).

use std::sync::atomic::{AtomicU64, Ordering};

/// Default stay-well-below observed 15–20 KB trigger (Zephyr/ZATMENIE research).
pub const DEFAULT_THRESHOLD: u64 = 8_192;

#[derive(Debug, Clone, Copy)]
pub struct VolumeGuardConfig {
    pub threshold: u64,
    pub enabled: bool,
}

impl Default for VolumeGuardConfig {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            enabled: true,
        }
    }
}

#[derive(Debug)]
pub struct VolumeGuard {
    config: VolumeGuardConfig,
    sent: AtomicU64,
    recv: AtomicU64,
}

impl VolumeGuard {
    pub fn new(config: VolumeGuardConfig) -> Self {
        Self {
            config,
            sent: AtomicU64::new(0),
            recv: AtomicU64::new(0),
        }
    }

    pub fn disabled() -> Self {
        Self::new(VolumeGuardConfig {
            enabled: false,
            ..Default::default()
        })
    }

    pub fn record_sent(&self, wire_bytes: u64) -> Result<(), RotateSignal> {
        if !self.config.enabled {
            return Ok(());
        }
        let total = self.sent.fetch_add(wire_bytes, Ordering::Relaxed) + wire_bytes;
        if total >= self.config.threshold {
            return Err(RotateSignal);
        }
        Ok(())
    }

    pub fn record_recv(&self, wire_bytes: u64) -> Result<(), RotateSignal> {
        if !self.config.enabled {
            return Ok(());
        }
        let total = self.recv.fetch_add(wire_bytes, Ordering::Relaxed) + wire_bytes;
        if total >= self.config.threshold {
            return Err(RotateSignal);
        }
        Ok(())
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn recv(&self) -> u64 {
        self.recv.load(Ordering::Relaxed)
    }
}

/// TCP connection should be rotated (new 5-tuple + handshake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotateSignal;

/// Approximate on-wire size of a written frame (header blob + payload + padding).
pub fn estimate_frame_wire_bytes(payload_len: usize, padding_len: usize, stream_id: u32) -> u64 {
    let mut header_len = 0usize;
    header_len += uvarint_len(stream_id as u64);
    header_len += 1; // flags
    header_len += uvarint_len(payload_len as u64);
    let total = 2 + header_len + payload_len + padding_len;
    total as u64
}

fn uvarint_len(mut value: u64) -> usize {
    let mut n = 1;
    while value >= 0x80 {
        n += 1;
        value >>= 7;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_at_threshold() {
        let g = VolumeGuard::new(VolumeGuardConfig {
            threshold: 100,
            enabled: true,
        });
        assert!(g.record_sent(50).is_ok());
        assert!(g.record_sent(49).is_ok());
        assert_eq!(g.record_sent(2), Err(RotateSignal));
    }

    #[test]
    fn disabled_never_rotates() {
        let g = VolumeGuard::disabled();
        assert!(g.record_sent(1_000_000).is_ok());
    }
}
