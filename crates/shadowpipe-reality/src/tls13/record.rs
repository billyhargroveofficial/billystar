//! TLS 1.3 AEAD record protection (RFC 8446 §5.2).
//!
//! Supports the two SHA-256 suites Chrome offers: AES-128-GCM and
//! ChaCha20-Poly1305 (both 12-byte nonce, 16-byte tag; key 16 vs 32). From a
//! traffic secret we derive [write_key, write_iv]; each record's nonce is
//! `iv XOR seq` (sequence right-aligned, big-endian). The protected record is a
//! TLSCiphertext: header `0x17 0x0303 len` || AEAD(content || real_type), with the
//! 5-byte header as the AEAD AAD.
//!
//! (AES-256-GCM is SHA-384 — it changes the *hash*, not just the AEAD, so it needs
//! the key schedule generalized over hash length; tracked separately.)

use super::kdf::{hkdf_expand_label, Hash};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

/// A TLS 1.3 cipher suite. The two SHA-256 suites (AES-128-GCM, ChaCha20-Poly1305)
/// share the SHA-256 key schedule; AES-256-GCM uses SHA-384 (see [`Suite::hash`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite {
    Aes128GcmSha256,
    ChaCha20Poly1305Sha256,
    Aes256GcmSha384,
}

impl Suite {
    /// Map a wire `cipher_suite` id to a supported suite (None = unsupported).
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    /// The wire `cipher_suite` id.
    pub fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    /// The key-schedule hash this suite uses (SHA-384 for AES-256-GCM, else SHA-256).
    pub fn hash(self) -> Hash {
        match self {
            Self::Aes256GcmSha384 => Hash::Sha384,
            _ => Hash::Sha256,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::ChaCha20Poly1305Sha256 => 32,
            Self::Aes256GcmSha384 => 32,
        }
    }
}

/// The AEAD cipher, key-scheduled once at session setup. Boxed so the three
/// variants don't blow up the enum to the largest key schedule.
enum RecordAead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

pub struct RecordCrypto {
    aead: RecordAead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordCrypto {
    /// Derive key+iv from a TLS 1.3 traffic secret for `suite` (the secret length
    /// and the HKDF hash both follow `suite.hash()`).
    pub fn new(traffic_secret: &[u8], suite: Suite) -> Self {
        let h = suite.hash();
        let key = hkdf_expand_label(traffic_secret, b"key", b"", suite.key_len(), h);
        let iv: [u8; 12] = hkdf_expand_label(traffic_secret, b"iv", b"", 12, h)
            .try_into()
            .expect("hkdf-expand-label(iv, 12) returns exactly 12 bytes");
        // The key length is fixed by the suite (`suite.key_len()` fed the same
        // `hkdf_expand_label`), so `new_from_slice` is infallible by construction.
        // Building the AEAD once here keeps the per-record seal/open path free of
        // key scheduling AND of any fallible construction.
        let aead = match suite {
            Suite::Aes128GcmSha256 => RecordAead::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).expect("16-byte AES-128 key"),
            )),
            Suite::Aes256GcmSha384 => RecordAead::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&key).expect("32-byte AES-256 key"),
            )),
            Suite::ChaCha20Poly1305Sha256 => RecordAead::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&key).expect("32-byte ChaCha20 key"),
            )),
        };
        Self { aead, iv, seq: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    fn aead_seal(&self, nonce: &[u8; 12], inner: &[u8], header: &[u8]) -> Vec<u8> {
        let payload = Payload {
            msg: inner,
            aad: header,
        };
        // A single TLS record is bounded far below the AEAD plaintext limit
        // (2^36 B for GCM), so sealing our own bounded record cannot fail.
        match &self.aead {
            RecordAead::Aes128(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            RecordAead::Aes256(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            RecordAead::ChaCha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload),
        }
        .expect("AEAD seal of a bounded TLS record is infallible")
    }

    fn aead_open(&self, nonce: &[u8; 12], ct: &[u8], header: &[u8]) -> Option<Vec<u8>> {
        let payload = Payload {
            msg: ct,
            aad: header,
        };
        match &self.aead {
            RecordAead::Aes128(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            RecordAead::Aes256(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            RecordAead::ChaCha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload),
        }
        .ok()
    }

    /// Seal `content` (with its TLS content type) into one wire record.
    pub fn seal(&mut self, content_type: u8, content: &[u8]) -> Vec<u8> {
        self.seal_padded(content_type, content, 0)
    }

    /// Seal `content` into one wire record with `pad` bytes of TLS 1.3 record
    /// padding (RFC 8446 §5.4: zero bytes after the content type). The peer's
    /// [`open`](Self::open) strips the trailing zeros, so padding is invisible to
    /// the application — it only lets the caller set the *wire record length*
    /// independently of the data size (used to shape the record-length sequence
    /// against first-N-packet traffic classifiers). For any `content_type != 0`
    /// (always true: 0x17/0x16/0x15) the open-side scan stops at the type byte, so
    /// content keeping its own trailing zeros is recovered intact.
    pub fn seal_padded(&mut self, content_type: u8, content: &[u8], pad: usize) -> Vec<u8> {
        let mut inner = Vec::with_capacity(content.len() + 1 + pad);
        inner.extend_from_slice(content);
        inner.push(content_type); // TLSInnerPlaintext.type
        inner.resize(inner.len() + pad, 0); // zero padding

        let total = inner.len() + 16; // + AEAD tag
        let mut header = vec![0x17, 0x03, 0x03];
        header.extend_from_slice(&(total as u16).to_be_bytes());

        let nonce = self.nonce();
        let ct = self.aead_seal(&nonce, &inner, &header);
        self.seq += 1;

        let mut rec = header;
        rec.extend_from_slice(&ct);
        rec
    }

    /// Open a wire record (5-byte header + ciphertext) → (real content type,
    /// content). Returns None on AEAD failure or malformed input.
    pub fn open(&mut self, record: &[u8]) -> Option<(u8, Vec<u8>)> {
        if record.len() < 5 + 16 {
            return None;
        }
        let header = &record[..5];
        let ct = &record[5..];
        let nonce = self.nonce();
        let mut inner = self.aead_open(&nonce, ct, header)?;
        self.seq += 1;

        // Strip TLSInnerPlaintext zero padding; the last non-zero byte is the type.
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let content_type = inner.pop()?;
        Some((content_type, inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_padded_round_trips_through_open() {
        let secret = [7u8; 32];
        let mut tx = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        let mut rx = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        // Content with BOTH internal and trailing zero bytes: the open() zero-strip
        // must remove only the padding and stop at the (non-zero) type byte, never
        // eating into the content's own trailing zeros.
        let data = b"ab\x00\x00cd-trailing\x00";
        let pad = 1000;
        let rec = tx.seal_padded(0x17, data, pad);
        assert_eq!(
            rec.len(),
            5 + data.len() + 1 + pad + 16,
            "wire = header(5) + content + type(1) + pad + tag(16)"
        );
        let (ct, pt) = rx.open(&rec).expect("open padded record");
        assert_eq!(ct, 0x17);
        assert_eq!(
            pt, data,
            "padding stripped; content (incl its zeros) intact"
        );
    }

    #[test]
    fn unpadded_seal_and_padded_seal_zero_agree() {
        let s = [9u8; 32];
        let mut a = RecordCrypto::new(&s, Suite::ChaCha20Poly1305Sha256);
        let mut b = RecordCrypto::new(&s, Suite::ChaCha20Poly1305Sha256);
        assert_eq!(
            a.seal(0x17, b"hello world"),
            b.seal_padded(0x17, b"hello world", 0)
        );
    }
}
