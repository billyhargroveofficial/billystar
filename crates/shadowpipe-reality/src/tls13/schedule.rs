//! TLS 1.3 key schedule (RFC 8446 §7.1): the Early → Handshake → Master secret
//! chain and the traffic secrets, plus the Finished verify_data MAC. Generalized
//! over the negotiated [`Hash`] (SHA-256 / SHA-384).

use super::kdf::{derive_secret, hash_empty, hkdf_expand_label, hkdf_extract, Hash};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

/// Handshake-phase traffic secrets, plus the Handshake Secret needed to advance
/// to the Master Secret. All secrets are `hash.len()` bytes.
pub struct HandshakeSecrets {
    pub client_hs_traffic: Vec<u8>,
    pub server_hs_traffic: Vec<u8>,
    handshake_secret: Vec<u8>,
    hash: Hash,
}

/// Derive handshake secrets from the ECDHE shared secret and the
/// ClientHello..ServerHello transcript hash, under `hash`.
pub fn derive_handshake(ecdhe: &[u8], th_ch_sh: &[u8], hash: Hash) -> HandshakeSecrets {
    let zero = vec![0u8; hash.len()];
    let early = hkdf_extract(&zero, &zero, hash);
    let derived = derive_secret(&early, b"derived", &hash_empty(hash), hash);
    let handshake_secret = hkdf_extract(&derived, ecdhe, hash);
    HandshakeSecrets {
        client_hs_traffic: derive_secret(&handshake_secret, b"c hs traffic", th_ch_sh, hash),
        server_hs_traffic: derive_secret(&handshake_secret, b"s hs traffic", th_ch_sh, hash),
        handshake_secret,
        hash,
    }
}

impl HandshakeSecrets {
    /// Derive (client, server) application traffic secrets from the
    /// ClientHello..server-Finished transcript hash.
    pub fn application_secrets(&self, th_ch_sfin: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let h = self.hash;
        let derived = derive_secret(&self.handshake_secret, b"derived", &hash_empty(h), h);
        let master = hkdf_extract(&derived, &vec![0u8; h.len()], h);
        (
            derive_secret(&master, b"c ap traffic", th_ch_sfin, h),
            derive_secret(&master, b"s ap traffic", th_ch_sfin, h),
        )
    }
}

/// Finished verify_data = HMAC(finished_key, transcript_hash), where
/// finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", HashLen). The
/// MAC uses the suite's hash.
pub fn finished_verify_data(traffic_secret: &[u8], transcript_hash: &[u8], hash: Hash) -> Vec<u8> {
    let fk = hkdf_expand_label(traffic_secret, b"finished", b"", hash.len(), hash);
    match hash {
        Hash::Sha256 => {
            let mut mac =
                <Hmac<Sha256> as Mac>::new_from_slice(&fk).expect("hmac accepts any key length");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
        Hash::Sha384 => {
            let mut mac =
                <Hmac<Sha384> as Mac>::new_from_slice(&fk).expect("hmac accepts any key length");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
    }
}
