//! TLS 1.3 key-derivation primitives (RFC 8446 §7.1): HKDF-Extract,
//! HKDF-Expand-Label, Derive-Secret, and a running transcript hash.
//!
//! Generalized over the negotiated hash: SHA-256 (TLS_AES_128_GCM_SHA256 /
//! TLS_CHACHA20_POLY1305_SHA256) or SHA-384 (TLS_AES_256_GCM_SHA384). The hash
//! sets the secret length (32 vs 48 bytes), so secrets are `Vec<u8>`.

use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha384};

/// The negotiated key-schedule hash. Drives every secret length below.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    /// Output length in bytes (32 / 48) — the length of every key-schedule secret.
    #[allow(clippy::len_without_is_empty)] // a hash output is never "empty"
    pub fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }
}

/// SHA-256 output length — retained for the SHA-256 suites' record-layer tests and
/// external references. The key schedule itself is length-driven by [`Hash::len`].
pub const HASH_LEN: usize = 32;

/// HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM), for the chosen hash.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8], hash: Hash) -> Vec<u8> {
    match hash {
        Hash::Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
        Hash::Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
    }
}

/// HKDF-Expand-Label(Secret, Label, Context, Length) with the TLS 1.3 HkdfLabel
/// struct: { uint16 length; opaque label = "tls13 "+Label; opaque context }.
pub fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
    hash: Hash,
) -> Vec<u8> {
    let mut full = Vec::with_capacity(6 + label.len());
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);

    let mut info = Vec::with_capacity(3 + full.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut out = vec![0u8; len];
    match hash {
        Hash::Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .expect("valid PRK length")
            .expand(&info, &mut out)
            .expect("valid output length"),
        Hash::Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .expect("valid PRK length")
            .expand(&info, &mut out)
            .expect("valid output length"),
    }
    out
}

/// Derive-Secret(Secret, Label, Messages) — Context is the transcript hash;
/// output length = the hash length.
pub fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8], hash: Hash) -> Vec<u8> {
    hkdf_expand_label(secret, label, transcript_hash, hash.len(), hash)
}

/// Hash of `data` for the chosen hash.
pub fn hash_bytes(hash: Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => Sha256::digest(data).to_vec(),
        Hash::Sha384 => Sha384::digest(data).to_vec(),
    }
}

/// Hash of the empty string (Transcript-Hash("") in the key schedule).
pub fn hash_empty(hash: Hash) -> Vec<u8> {
    hash_bytes(hash, b"")
}

/// Running Transcript-Hash over handshake messages (the message bytes only — not
/// TLS record headers). Clone-to-finalize so the hash can be read mid-handshake.
#[derive(Clone)]
pub enum Transcript {
    S256(Sha256),
    S384(Sha384),
}

impl Transcript {
    pub fn new(hash: Hash) -> Self {
        match hash {
            Hash::Sha256 => Transcript::S256(Sha256::new()),
            Hash::Sha384 => Transcript::S384(Sha384::new()),
        }
    }
    /// Feed one complete handshake message (e.g. the ClientHello body).
    pub fn update(&mut self, handshake_msg: &[u8]) {
        match self {
            Transcript::S256(h) => h.update(handshake_msg),
            Transcript::S384(h) => h.update(handshake_msg),
        }
    }
    pub fn hash(&self) -> Vec<u8> {
        match self {
            Transcript::S256(h) => h.clone().finalize().to_vec(),
            Transcript::S384(h) => h.clone().finalize().to_vec(),
        }
    }
}
