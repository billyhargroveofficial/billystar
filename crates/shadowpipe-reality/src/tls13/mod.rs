//! From-scratch TLS 1.3 (RFC 8446) primitives for the REALITY carrier.
//!
//! We implement TLS ourselves because REALITY needs control no off-the-shelf
//! Rust stack exposes (the ClientHello session_id auth, the key_share ephemeral,
//! and — server side — splicing a cover site's handshake). This module is the
//! crypto core: the key schedule, the AEAD record layer, and the Finished MAC.
//!
//! Cipher suites: all three Chrome offers — TLS_AES_128_GCM_SHA256,
//! TLS_CHACHA20_POLY1305_SHA256 (SHA-256), and TLS_AES_256_GCM_SHA384 (SHA-384,
//! 48-byte secrets via the hash-generalized key schedule). The client
//! auto-negotiates from the ServerHello; the server selects.

pub mod asio;
pub mod client;
pub mod kdf;
pub mod record;
pub mod schedule;
pub mod server;
pub mod stream;

pub use client::{client_handshake, CertVerify, ClientConnection};
pub use kdf::{
    derive_secret, hash_bytes, hash_empty, hkdf_expand_label, hkdf_extract, Hash, Transcript,
    HASH_LEN,
};
pub use record::{RecordCrypto, Suite};
pub use schedule::{derive_handshake, finished_verify_data, HandshakeSecrets};
pub use server::{server_handshake, ServerConnection};
pub use stream::RealityStream;

/// TLS_AES_128_GCM_SHA256
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS_AES_256_GCM_SHA384 (SHA-384 key schedule).
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_secret_matches_the_tls13_constant() {
        // The well-known TLS 1.3 (SHA-256, no PSK) Early Secret = HKDF-Extract(0,0).
        // A fixed protocol constant — validates our HKDF-Extract wiring exactly.
        let early = hkdf_extract(&[0u8; 32], &[0u8; 32], Hash::Sha256);
        assert_eq!(
            hex::encode(early),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );
    }

    #[test]
    fn early_secret_sha384_known_answer() {
        // TLS 1.3 SHA-384 Early Secret = HKDF-Extract(0_48, 0_48): a fixed protocol
        // constant (RFC 8446 §7.1) that pins the SHA-384 HKDF wiring exactly.
        let early = hkdf_extract(&[0u8; 48], &[0u8; 48], Hash::Sha384);
        assert_eq!(early.len(), 48, "SHA-384 secret is 48 bytes");
        assert_eq!(
            hex::encode(&early),
            "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5"
        );
    }

    #[test]
    fn record_layer_round_trips_and_advances_sequence() {
        let secret = [7u8; 32];
        let mut tx = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        let r1 = tx.seal(0x16, b"hello handshake");
        let r2 = tx.seal(0x17, b"application data");

        let mut rx = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        assert_eq!(rx.open(&r1).unwrap(), (0x16, b"hello handshake".to_vec()));
        assert_eq!(rx.open(&r2).unwrap(), (0x17, b"application data".to_vec()));

        // The per-record nonce mixes in the sequence number: a fresh receiver
        // (seq=0) cannot open the second record (sealed at seq=1).
        let mut rx_reset = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        assert!(rx_reset.open(&r2).is_none());
    }

    #[test]
    fn record_layer_round_trips_with_chacha20() {
        let secret = [9u8; 32];
        let mut tx = RecordCrypto::new(&secret, Suite::ChaCha20Poly1305Sha256);
        let r = tx.seal(0x17, b"chacha payload");

        let mut rx = RecordCrypto::new(&secret, Suite::ChaCha20Poly1305Sha256);
        assert_eq!(rx.open(&r).unwrap(), (0x17, b"chacha payload".to_vec()));

        // The same traffic secret under the wrong suite must NOT open the record.
        let mut rx_aes = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        assert!(rx_aes.open(&r).is_none());
    }

    #[test]
    fn key_schedule_is_deterministic_and_well_shaped() {
        let ecdhe = [9u8; 32];
        let th_hs = hash_bytes(Hash::Sha256, b"ClientHello||ServerHello");
        let a = derive_handshake(&ecdhe, &th_hs, Hash::Sha256);
        let b = derive_handshake(&ecdhe, &th_hs, Hash::Sha256);
        assert_eq!(a.client_hs_traffic, b.client_hs_traffic, "deterministic");
        assert_ne!(a.client_hs_traffic, a.server_hs_traffic, "c/s differ");

        let th_app = hash_bytes(Hash::Sha256, b"ClientHello..server Finished");
        let (c_ap, s_ap) = a.application_secrets(&th_app);
        assert_ne!(c_ap, s_ap);
        assert_ne!(c_ap, a.client_hs_traffic, "app secret != hs secret");

        // Finished verify_data is a deterministic HMAC of the transcript hash.
        let fin = finished_verify_data(&a.server_hs_traffic, &th_hs, Hash::Sha256);
        assert_eq!(
            fin,
            finished_verify_data(&a.server_hs_traffic, &th_hs, Hash::Sha256)
        );
        assert_ne!(fin, vec![0u8; 32]);
    }
}
