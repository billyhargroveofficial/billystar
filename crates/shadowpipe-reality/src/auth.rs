//! REALITY authentication channel: a short ciphertext hidden in the ClientHello
//! `legacy_session_id`, keyed by ECDH between the client's key_share ephemeral and
//! the server's static X25519 key.
//!
//! The key insight (and why this needs our own TLS stack): the session_id is part
//! of the ClientHello, which TLS 1.3 folds into the transcript hash. So the
//! ciphertext must be the session_id the TLS stack actually uses — not a wire
//! splice after the fact. We build the ClientHello, then seal here, so both ends'
//! transcripts agree on the same bytes.
//!
//! Scheme (matches XTLS/REALITY so a server could be probed/compared faithfully):
//!   key   = HKDF-SHA256(ikm = ECDH, salt = ClientHello.random[..20], info = "REALITY")
//!   nonce = ClientHello.random[20..32]
//!   aad   = the ClientHello handshake message with the 32-byte session_id zeroed
//!   sid   = AES-256-GCM-Seal(key, nonce, plaintext[16], aad)   // 16 ct + 16 tag

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha512 = Hmac<Sha512>;

pub const REALITY_INFO: &[u8] = b"REALITY";
pub const SESSION_ID_LEN: usize = 32;
/// Sealed plaintext length; +16 GCM tag fills the 32-byte session_id.
pub const AUTH_PLAINTEXT_LEN: usize = 16;
/// Bytes of the TLS record header skipped to reach the handshake message (the AAD).
const RECORD_HEADER: usize = 5;

/// X25519 ECDH shared secret, rejecting non-contributory low-order peer keys.
///
/// RFC 7748 permits implementations to check the all-zero shared secret.  This
/// is mandatory for REALITY: accepting it would make the carrier-auth HMAC key
/// public and would also let a low-order TLS key share bypass the intended
/// relationship to the configured static public key.
pub fn ecdh(secret: &StaticSecret, peer_pub: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_pub));
    shared.was_contributory().then(|| shared.to_bytes())
}

/// HKDF-SHA256(ikm = ecdh, salt = random[..20], info = "REALITY") -> 32-byte key.
pub fn derive_auth_key(ecdh_shared: &[u8; 32], client_random: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), ecdh_shared);
    let mut key = [0u8; 32];
    hk.expand(REALITY_INFO, &mut key)
        .expect("32 is a valid HKDF-SHA256 output length");
    key
}

/// Lay out the 16-byte auth plaintext: version(3) + reserved(1) + unix_time(4, BE)
/// + shortId(<=8). Mirrors REALITY's session_id payload.
pub fn auth_plaintext(
    version: [u8; 3],
    unix_time: u32,
    short_id: &[u8],
) -> [u8; AUTH_PLAINTEXT_LEN] {
    let mut p = [0u8; AUTH_PLAINTEXT_LEN];
    p[0..3].copy_from_slice(&version);
    p[4..8].copy_from_slice(&unix_time.to_be_bytes());
    let n = short_id.len().min(8);
    p[8..8 + n].copy_from_slice(&short_id[..n]);
    p
}

fn cipher(auth_key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key))
}

/// Seal `plaintext` into the session_id at `sid_off` of the full ClientHello
/// record `hello`, with AAD = the handshake message (record body) carrying a
/// zeroed session_id. Overwrites the 32 session_id bytes in place.
pub fn seal_into_session_id(
    hello: &mut [u8],
    sid_off: usize,
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
    plaintext: &[u8; AUTH_PLAINTEXT_LEN],
) {
    for b in &mut hello[sid_off..sid_off + SESSION_ID_LEN] {
        *b = 0; // zero so the server reconstructs the same AAD
    }
    let nonce = Nonce::from_slice(&client_random[20..32]);
    let ct = cipher(auth_key)
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &hello[RECORD_HEADER..],
            },
        )
        .expect("aes-256-gcm seal");
    debug_assert_eq!(ct.len(), SESSION_ID_LEN);
    hello[sid_off..sid_off + SESSION_ID_LEN].copy_from_slice(&ct);
}

/// Server side: recover the auth plaintext, or `None` if the GCM tag fails — i.e.
/// the peer is a normal client / active prober (which the server then forwards to
/// the cover site). Reconstructs the same zeroed-session_id AAD as the seal.
pub fn open_session_id(
    hello: &[u8],
    sid_off: usize,
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
) -> Option<[u8; AUTH_PLAINTEXT_LEN]> {
    let ct = &hello[sid_off..sid_off + SESSION_ID_LEN];
    let mut aad = hello[RECORD_HEADER..].to_vec();
    let z = sid_off - RECORD_HEADER;
    for b in &mut aad[z..z + SESSION_ID_LEN] {
        *b = 0;
    }
    let nonce = Nonce::from_slice(&client_random[20..32]);
    let pt = cipher(auth_key)
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .ok()?;
    let mut out = [0u8; AUTH_PLAINTEXT_LEN];
    out.copy_from_slice(&pt);
    Some(out)
}

/// The server→client half of REALITY auth: `HMAC-SHA512(auth_key, leaf_pub)`.
///
/// The TLS 1.3 Finished MAC alone only proves the peer did *some* ECDHE — anyone
/// can. To prove it is the *real* REALITY server (holds the static secret), the
/// server returns this HMAC as its CertificateVerify "signature" over a
/// per-connection ephemeral leaf key; the client recomputes it from the same
/// `auth_key` and rejects a mismatch. Both the leaf and this tag travel inside the
/// TLS-1.3-encrypted Certificate flight, so a passive observer never sees them,
/// and `auth_key` (salted by this handshake's ClientHello.random) binds the tag to
/// this connection — a tag from another session is over a different key.
pub fn reality_cert_hmac(auth_key: &[u8; 32], leaf_pub: &[u8; 32]) -> [u8; 64] {
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(leaf_pub);
    let mut out = [0u8; 64];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_rejects_non_contributory_low_order_peer_keys() {
        let secret = StaticSecret::from([0x42; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        for peer in [[0u8; 32], one] {
            assert!(
                ecdh(&secret, &peer).is_none(),
                "low-order peer key {peer:02x?} produced an accepted shared secret"
            );
        }
    }
}
