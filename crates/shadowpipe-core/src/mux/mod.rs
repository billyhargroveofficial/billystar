use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Spread IP packets into mux frames (MTU fragmentation only — does not affect TCP 5-tuple metering).
#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub stream_count: u32,
    pub max_chunk_size: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            stream_count: 24,
            max_chunk_size: 4096,
        }
    }
}

const MSG_IP_DATA: u8 = 1;

/// One encrypted frame payload: type + packet_id + fragment meta + chunk bytes.
pub fn encode_packet(
    packet: &[u8],
    packet_id: u32,
    cfg: &MuxConfig,
) -> Result<Vec<(u32, Vec<u8>)>> {
    if packet.is_empty() {
        return Ok(Vec::new());
    }
    if cfg.stream_count == 0 {
        return Err(anyhow!("stream_count must be > 0"));
    }
    if cfg.max_chunk_size == 0 {
        return Err(anyhow!("max_chunk_size must be > 0"));
    }

    let chunks: Vec<&[u8]> = packet.chunks(cfg.max_chunk_size).collect();
    let frag_total = chunks.len().min(u16::MAX as usize) as u16;

    let mut out = Vec::with_capacity(chunks.len());
    for (frag_idx, chunk) in chunks.into_iter().enumerate() {
        let stream_id = (packet_id.wrapping_add(frag_idx as u32)) % cfg.stream_count;
        let mut payload = Vec::with_capacity(9 + chunk.len());
        payload.push(MSG_IP_DATA);
        payload.extend_from_slice(&packet_id.to_be_bytes());
        payload.extend_from_slice(&(frag_idx as u16).to_be_bytes());
        payload.extend_from_slice(&frag_total.to_be_bytes());
        payload.extend_from_slice(chunk);
        out.push((stream_id, payload));
    }
    Ok(out)
}

pub struct Reassembler {
    pending: HashMap<u32, PendingPacket>,
    total_bytes: usize,
}

const MAX_PENDING_PACKETS: usize = 256;
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
const MAX_FRAG_TOTAL: u16 = 512;

struct PendingPacket {
    frag_total: u16,
    frags: HashMap<u16, Vec<u8>>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            total_bytes: 0,
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self.pending.keys().copied().min() {
            if let Some(entry) = self.pending.remove(&oldest) {
                self.total_bytes = self
                    .total_bytes
                    .saturating_sub(entry.frags.values().map(|v| v.len()).sum::<usize>());
            }
        }
    }

    pub fn feed(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(None);
        }
        if payload[0] != MSG_IP_DATA {
            return Err(anyhow!("unknown mux message type {}", payload[0]));
        }
        if payload.len() < 9 {
            return Err(anyhow!("mux payload too short"));
        }

        let packet_id = u32::from_be_bytes(payload[1..5].try_into()?);
        let frag_idx = u16::from_be_bytes(payload[5..7].try_into()?);
        let frag_total = u16::from_be_bytes(payload[7..9].try_into()?);
        let data = payload[9..].to_vec();

        if frag_total == 0 || frag_idx >= frag_total || frag_total > MAX_FRAG_TOTAL {
            return Err(anyhow!("invalid fragment {frag_idx}/{frag_total}"));
        }

        while self.pending.len() >= MAX_PENDING_PACKETS
            || self.total_bytes + data.len() > MAX_PENDING_BYTES
        {
            self.evict_oldest();
            if self.pending.is_empty() {
                break;
            }
        }

        let entry = self.pending.entry(packet_id).or_insert(PendingPacket {
            frag_total,
            frags: HashMap::new(),
        });

        if entry.frag_total != frag_total {
            return Err(anyhow!("fragment total mismatch for packet {packet_id}"));
        }

        let data_len = data.len();
        let replaced = entry.frags.insert(frag_idx, data);
        self.total_bytes += data_len;
        if let Some(old) = replaced {
            // Duplicate fragment index: don't double-count. Otherwise an attacker
            // (or a retransmit) resending one fragment inflates total_bytes and
            // evicts legitimate in-flight packets — a cheap DoS on reassembly.
            self.total_bytes = self.total_bytes.saturating_sub(old.len());
        }

        if entry.frags.len() != frag_total as usize {
            return Ok(None);
        }

        let mut assembled = Vec::new();
        for idx in 0..frag_total {
            let part = entry
                .frags
                .remove(&idx)
                .ok_or_else(|| anyhow!("missing fragment {idx}"))?;
            self.total_bytes = self.total_bytes.saturating_sub(part.len());
            assembled.extend_from_slice(&part);
        }
        self.pending.remove(&packet_id);
        Ok(Some(assembled))
    }

    #[cfg(test)]
    fn buffered_bytes(&self) -> usize {
        self.total_bytes
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_fragment() {
        let cfg = MuxConfig::default();
        let packet = b"hello-ip-packet".to_vec();
        let frames = encode_packet(&packet, 42, &cfg).unwrap();
        assert_eq!(frames.len(), 1);

        let mut reasm = Reassembler::new();
        let out = reasm.feed(&frames[0].1).unwrap().unwrap();
        assert_eq!(out, packet);
    }

    #[test]
    fn roundtrip_multi_fragment() {
        let cfg = MuxConfig {
            stream_count: 8,
            max_chunk_size: 4,
        };
        let packet = (0u8..20).collect::<Vec<_>>();
        let frames = encode_packet(&packet, 7, &cfg).unwrap();
        assert_eq!(frames.len(), 5);

        let mut reasm = Reassembler::new();
        let mut out = None;
        for (_, payload) in frames {
            out = reasm.feed(&payload).unwrap().or(out);
        }
        assert_eq!(out.unwrap(), packet);
    }

    #[test]
    fn duplicate_fragment_does_not_inflate_buffer() {
        // 8-byte packet at 4-byte chunks = 2 fragments.
        let cfg = MuxConfig {
            stream_count: 8,
            max_chunk_size: 4,
        };
        let packet = (0u8..8).collect::<Vec<_>>();
        let frames = encode_packet(&packet, 1, &cfg).unwrap();
        assert_eq!(frames.len(), 2);

        let mut reasm = Reassembler::new();
        // Resend fragment 0 ten times before fragment 1 arrives.
        for _ in 0..10 {
            assert!(reasm.feed(&frames[0].1).unwrap().is_none());
        }
        // Must account for ONE copy (4 data bytes), not ten — the old code
        // double-counted and would report 40 here, evicting real packets early.
        assert_eq!(reasm.buffered_bytes(), 4);

        // Completing the packet still works and fully drains the buffer.
        let out = reasm.feed(&frames[1].1).unwrap().unwrap();
        assert_eq!(out, packet);
        assert_eq!(reasm.buffered_bytes(), 0);
    }

    #[test]
    fn rejects_oversized_frag_total() {
        // frag_total beyond MAX_FRAG_TOTAL is rejected, not buffered.
        let mut payload = vec![MSG_IP_DATA];
        payload.extend_from_slice(&7u32.to_be_bytes()); // packet_id
        payload.extend_from_slice(&0u16.to_be_bytes()); // frag_idx
        payload.extend_from_slice(&(MAX_FRAG_TOTAL + 1).to_be_bytes()); // frag_total
        payload.extend_from_slice(b"data");
        let mut reasm = Reassembler::new();
        assert!(reasm.feed(&payload).is_err());
    }
}
