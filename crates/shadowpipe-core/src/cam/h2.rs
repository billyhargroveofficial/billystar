//! Fake HTTP/2 DATA framing for passive DPI camouflage.

use anyhow::{anyhow, Result};
use std::io::Read;

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER: usize = 9;
const MAX_H2_PAYLOAD: usize = 16_384 - 1;
const MAX_DECODER_BUF: usize = 4 * 1024 * 1024;

/// Client-side: preface + empty SETTINGS.
pub fn client_bootstrap() -> Vec<u8> {
    let mut out = Vec::from(PREFACE);
    out.extend_from_slice(&encode_frame(0x4, 0, 0, &[])); // SETTINGS
    out
}

/// Server-side: SETTINGS ACK (empty SETTINGS with ACK flag).
pub fn server_bootstrap() -> Vec<u8> {
    encode_frame(0x4, 0x1, 0, &[]) // SETTINGS + ACK
}

pub fn encode_data(stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in payload.chunks(MAX_H2_PAYLOAD) {
        out.extend_from_slice(&encode_frame(0x0, 0, stream_id, chunk));
    }
    out
}

fn encode_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_H2_PAYLOAD);
    let mut hdr = [0u8; FRAME_HEADER];
    hdr[0] = ((payload.len() >> 16) & 0xff) as u8;
    hdr[1] = ((payload.len() >> 8) & 0xff) as u8;
    hdr[2] = (payload.len() & 0xff) as u8;
    hdr[3] = frame_type;
    hdr[4] = flags;
    hdr[5..9].copy_from_slice(&stream_id.to_be_bytes());
    let mut out = Vec::with_capacity(FRAME_HEADER + payload.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out
}

pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        if self.buf.len() + data.len() > MAX_DECODER_BUF {
            // Refuse to buffer unboundedly. In honest operation `buf` never
            // approaches this (frames are <= MAX_H2_PAYLOAD and drained
            // promptly), so hitting it means a malformed/oversized stream.
            // Surface a hard error so the carrier tears down and reconnects
            // cleanly — the old behavior (clear() then keep parsing) discarded a
            // partial frame mid-stream and desynced the frame parser, turning
            // recoverable backpressure into silent corruption.
            return Err(anyhow!(
                "h2 decoder buffer overflow: {} + {} > {}",
                self.buf.len(),
                data.len(),
                MAX_DECODER_BUF
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Returns next inner payload from a DATA frame (type 0x0).
    pub fn next_data_payload(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if self.buf.len() < FRAME_HEADER {
                return Ok(None);
            }
            let len = ((self.buf[0] as usize) << 16)
                | ((self.buf[1] as usize) << 8)
                | (self.buf[2] as usize);
            let frame_type = self.buf[3];
            // Our encoder never emits a frame larger than MAX_H2_PAYLOAD; a
            // header claiming more is malformed (or a tamper/DoS attempt to make
            // us buffer up to 16 MB). Reject before accumulating — this is what
            // actually bounds the decode buffer.
            if len > MAX_H2_PAYLOAD {
                return Err(anyhow!(
                    "h2 frame length {len} exceeds max {MAX_H2_PAYLOAD}"
                ));
            }
            let total = FRAME_HEADER + len;
            if self.buf.len() < total {
                return Ok(None);
            }
            let payload = self.buf[FRAME_HEADER..total].to_vec();
            self.buf.drain(..total);

            match frame_type {
                0x0 => return Ok(Some(payload)), // DATA
                0x4 | 0x8 | 0x9 => continue,     // SETTINGS, WINDOW_UPDATE, CONTINUATION
                _ => continue,                   // ignore other control frames
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Read exactly `n` bytes from preface verification.
pub fn read_preface(mut read: impl Read) -> Result<()> {
    let mut got = [0u8; 24];
    read.read_exact(&mut got)?;
    if got != PREFACE {
        return Err(anyhow!("invalid h2 preface"));
    }
    Ok(())
}

/// Skip client SETTINGS frame after preface.
pub fn consume_bootstrap_frames(decoder: &mut Decoder) -> Result<()> {
    // Drain SETTINGS until we see DATA or buffer empty
    while decoder.buf.len() >= FRAME_HEADER {
        let len = ((decoder.buf[0] as usize) << 16)
            | ((decoder.buf[1] as usize) << 8)
            | (decoder.buf[2] as usize);
        let frame_type = decoder.buf[3];
        if len > MAX_H2_PAYLOAD {
            return Err(anyhow!(
                "h2 bootstrap frame length {len} exceeds max {MAX_H2_PAYLOAD}"
            ));
        }
        let total = FRAME_HEADER + len;
        if decoder.buf.len() < total {
            break;
        }
        if frame_type == 0x0 {
            break;
        }
        decoder.buf.drain(..total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_roundtrip() {
        let payload = b"encrypted-shadowpipe-frame";
        let wire = encode_data(1, payload);
        let mut dec = Decoder::new();
        dec.push(&wire).unwrap();
        assert_eq!(dec.next_data_payload().unwrap().unwrap(), payload);
    }

    #[test]
    fn large_payload_splits() {
        let payload = vec![0xABu8; 20_000];
        let wire = encode_data(3, &payload);
        let mut dec = Decoder::new();
        dec.push(&wire).unwrap();
        let mut got = Vec::new();
        while let Some(chunk) = dec.next_data_payload().unwrap() {
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, payload);
    }

    #[test]
    fn rejects_oversized_frame_length() {
        // A header claiming a 16 MB frame is malformed for our protocol; the
        // decoder must error immediately, NOT buffer up to 16 MB waiting for it.
        let mut dec = Decoder::new();
        let hdr = [0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1]; // len=0xFFFFFF, DATA
        dec.push(&hdr).unwrap();
        assert!(
            dec.next_data_payload().is_err(),
            "oversized frame length must be rejected"
        );
    }

    #[test]
    fn push_errors_on_overflow_instead_of_corrupting() {
        // Pushing past MAX_DECODER_BUF must hard-error (clean teardown), not
        // silently clear the buffer and desync the frame parser.
        let mut dec = Decoder::new();
        let huge = vec![0u8; MAX_DECODER_BUF + 1];
        assert!(dec.push(&huge).is_err(), "overflow must be a hard error");
    }
}
