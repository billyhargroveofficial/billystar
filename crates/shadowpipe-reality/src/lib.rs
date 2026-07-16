//! shadowpipe-reality — a from-scratch TLS 1.3 + REALITY implementation in Rust.
//!
//! Why from scratch: REALITY needs control that neither `boring` nor `rustls`
//! exposes — it sets the ClientHello `legacy_session_id` to an auth ciphertext
//! that must be *transcript-consistent*, and it needs the client's X25519
//! key_share ephemeral PRIVATE key to derive the auth key (ECDH with the
//! server's static key). A wire splice can't work (TLS 1.3 binds the whole
//! ClientHello into the transcript hash, so client/server byte divergence breaks
//! the Finished MAC), and boring-sys 4.22 exposes no client session_id setter, no
//! keyshare-private access, and no custom-ext API. So we build the handshake
//! ourselves and own every byte.
//!
//! Milestone M0 (this file): emit a Chrome-JA4 ClientHello with a caller-chosen
//! 32-byte `session_id` and a caller-provided X25519 key_share public key.
//! Validated by piping `sp-reality-hello`'s output into `tools/ja4-gate`.

pub mod auth;
pub mod cover;
pub mod parse;
pub mod reality;
mod replay;
pub mod tls13;
mod wire;
pub use parse::{extract_client_hello_fields, HelloFields};
pub use replay::{ReplayCache, ReplayStoreOwner, DEFAULT_REPLAY_CACHE_CAPACITY};
pub use wire::Writer;

use rand::RngCore;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

/// Byte offset of the 32-byte `legacy_session_id` within the ClientHello record
/// produced by [`build_client_hello`]: 5 (record hdr) + 4 (handshake hdr) + 2
/// (legacy_version) + 32 (random) + 1 (session_id length) = 44.
pub const SID_OFFSET: usize = 44;

/// shadowpipe's REALITY client version, carried in the auth plaintext.
pub const CLIENT_VERSION: [u8; 3] = [0, 1, 0];

/// TLS GREASE values (RFC 8701): both bytes equal, low nibble `a`.
pub const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

// Chrome (TLS 1.3, ~v120 profile) — matches our validated JA4
// `t13d1516h2_8daaf6152771_e5627efa2ab1`: 15 ciphers, X25519+secp256r1+secp384r1
// in supported_groups (ECDHE stays X25519 for REALITY auth). old ALPS 0x4469,
// brotli cert-compression, no ECH-GREASE. A GREASE value is prepended to the
// cipher list at build time (16 on the wire, 15 for JA4).
const CIPHERS: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const SIGALGS: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
// supported_groups after a leading GREASE: X25519, secp256r1, secp384r1.
const GROUPS: [u16; 3] = [0x001d, 0x0017, 0x0018];

const X25519: u16 = 0x001d;

/// One GREASE value per slot Chrome places GREASE in.
#[derive(Clone, Copy)]
pub struct Grease {
    pub cipher: u16,
    /// Shared by supported_groups AND key_share: a key_share group must be one
    /// offered in supported_groups (RFC 8446 §4.2.8), so the GREASE value must match.
    pub group: u16,
    pub ext_lead: u16,
    pub version: u16,
    pub ext_trail: u16,
}

/// Write an extension: type, then its body inside a u16 length.
fn ext(w: &mut Writer, ext_type: u16, body: impl FnOnce(&mut Writer)) {
    w.u16(ext_type);
    w.len16(body);
}

/// Build a full TLS-record-framed Chrome ClientHello.
///
/// `session_id` and `x25519_pub` are caller-owned: in REALITY the session_id is
/// the auth ciphertext and the X25519 key is one whose private half the caller
/// keeps (to ECDH with the server's static key). `record_len` is the target total
/// record size; the trailing `padding` extension is sized to hit it (like Chrome).
pub fn build_client_hello(
    sni: &str,
    random: &[u8; 32],
    session_id: &[u8; 32],
    x25519_pub: &[u8; 32],
    g: &Grease,
    record_len: usize,
) -> Vec<u8> {
    // 1) Build every extension EXCEPT the trailing padding, so we can size it.
    let mut e = Writer::new();
    ext(&mut e, g.ext_lead, |_w| {}); // GREASE (empty)
    ext(&mut e, 0x0000, |w| {
        // server_name: ServerNameList { host_name(0) : sni }
        w.len16(|w| {
            w.u8(0);
            w.len16(|w| w.raw(sni.as_bytes()));
        });
    });
    ext(&mut e, 0x0017, |_w| {}); // extended_master_secret
    ext(&mut e, 0xff01, |w| w.u8(0)); // renegotiation_info (empty)
    ext(&mut e, 0x000a, |w| {
        // supported_groups
        w.len16(|w| {
            w.u16(g.group);
            for x in GROUPS {
                w.u16(x);
            }
        });
    });
    ext(&mut e, 0x000b, |w| w.len8(|w| w.u8(0))); // ec_point_formats: uncompressed
    ext(&mut e, 0x0023, |_w| {}); // session_ticket (empty)
    ext(&mut e, 0x0010, |w| {
        // ALPN: h2, http/1.1
        w.len16(|w| {
            w.len8(|w| w.raw(b"h2"));
            w.len8(|w| w.raw(b"http/1.1"));
        });
    });
    ext(&mut e, 0x0005, |w| {
        // status_request (OCSP), empty responder/extensions
        w.u8(1);
        w.u16(0);
        w.u16(0);
    });
    ext(&mut e, 0x000d, |w| {
        // signature_algorithms
        w.len16(|w| {
            for x in SIGALGS {
                w.u16(x);
            }
        });
    });
    ext(&mut e, 0x0012, |_w| {}); // signed_certificate_timestamp (empty)
    ext(&mut e, 0x0033, |w| {
        // key_share: GREASE share (1-byte key, same GREASE group as
        // supported_groups) + X25519 share (our pubkey)
        w.len16(|w| {
            w.u16(g.group);
            w.len16(|w| w.u8(0));
            w.u16(X25519);
            w.len16(|w| w.raw(x25519_pub));
        });
    });
    ext(&mut e, 0x002d, |w| w.len8(|w| w.u8(1))); // psk_key_exchange_modes: psk_dhe_ke
    ext(&mut e, 0x002b, |w| {
        // supported_versions: GREASE, TLS 1.3, TLS 1.2
        w.len8(|w| {
            w.u16(g.version);
            w.u16(0x0304);
            w.u16(0x0303);
        });
    });
    ext(&mut e, 0x001b, |w| w.len8(|w| w.u16(0x0002))); // compress_certificate: brotli
    ext(&mut e, 0x4469, |w| w.len16(|w| w.len8(|w| w.raw(b"h2")))); // ALPS (old codepoint)
    ext(&mut e, g.ext_trail, |w| w.u8(0)); // GREASE (1-byte body, Chrome-style)
    let exts_wo_pad = e.buf;

    // 2) Size the padding extension so the whole record == record_len.
    //    total = 118 + exts_wo_pad.len() + pad  (see breakdown below).
    let cipher_bytes = 2 + 2 * (CIPHERS.len() + 1); // list len + (15 ciphers + 1 GREASE)
    let fixed = 5  // record header
        + 4        // handshake header
        + 2        // legacy_version
        + 32       // random
        + 33       // session_id (len + 32)
        + cipher_bytes
        + 2        // compression (len + null)
        + 2        // extensions list length
        + exts_wo_pad.len()
        + 4; // padding ext header (type + len)
    let pad = record_len.saturating_sub(fixed).max(1);

    // 3) Assemble the record.
    let mut w = Writer::new();
    w.u8(0x16); // handshake record
    w.u16(0x0301); // record version (TLS 1.0 for compat, as Chrome sends)
    w.len16(|w| {
        w.u8(0x01); // ClientHello
        w.len24(|w| {
            w.u16(0x0303); // legacy_version (TLS 1.2)
            w.raw(random);
            w.len8(|w| w.raw(session_id)); // legacy_session_id (32 bytes, caller-owned)
            w.len16(|w| {
                w.u16(g.cipher); // GREASE first
                for c in CIPHERS {
                    w.u16(c);
                }
            });
            w.len8(|w| w.u8(0)); // compression methods: null
            w.len16(|w| {
                w.raw(&exts_wo_pad);
                ext(w, 0x0015, |w| w.raw(&vec![0u8; pad])); // padding
            });
        });
    });
    w.buf
}

/// Build a Chrome ClientHello whose `session_id` carries the REALITY auth token
/// for `server_static_pub`. Returns the wire bytes, the client's X25519 ephemeral
/// secret (kept for the TLS session key schedule), and the derived `auth_key` —
/// the client keeps the last to later verify the server's HMAC leaf
/// ([`tls13::CertVerify::RealityHmac`]). The JA4 is identical to
/// [`build_client_hello`] — the auth lives entirely in the session_id, which JA4
/// ignores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonContributoryPublicKey;

impl fmt::Display for NonContributoryPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("non-contributory low-order X25519 public key")
    }
}

impl std::error::Error for NonContributoryPublicKey {}

pub fn build_authed_client_hello(
    sni: &str,
    server_static_pub: &[u8; 32],
    short_id: &[u8],
    unix_time: u32,
    g: &Grease,
    record_len: usize,
) -> Result<(Vec<u8>, StaticSecret, [u8; 32]), NonContributoryPublicKey> {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let eph = StaticSecret::random_from_rng(&mut rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();

    // Build with a zeroed session_id, then seal the auth token into it.
    let mut hello = build_client_hello(sni, &random, &[0u8; 32], &eph_pub, g, record_len);
    let shared = auth::ecdh(&eph, server_static_pub).ok_or(NonContributoryPublicKey)?;
    let key = auth::derive_auth_key(&shared, &random);
    let pt = auth::auth_plaintext(CLIENT_VERSION, unix_time, short_id);
    auth::seal_into_session_id(&mut hello, SID_OFFSET, &key, &random, &pt);
    Ok((hello, eph, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_structurally_valid_client_hello() {
        let g = Grease {
            cipher: 0x0a0a,
            group: 0x1a1a,
            ext_lead: 0x2a2a,
            version: 0x4a4a,
            ext_trail: 0x5a5a,
        };
        let hello = build_client_hello(
            "example.com",
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            &g,
            517,
        );
        assert_eq!(hello[0], 0x16, "handshake record type");
        assert_eq!(&hello[1..3], &[0x03, 0x01], "record version");
        let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(rec_len, hello.len() - 5, "record length self-consistent");
        assert_eq!(hello[5], 0x01, "ClientHello handshake type");
        assert_eq!(hello.len(), 517, "padded to target record length");
        // session_id sits at 5(rec hdr)+4(hs hdr)+2(ver)+32(random)+1(sid len) = 44.
        assert_eq!(&hello[43], &0x20, "session_id length is 32");
        assert_eq!(
            &hello[44..76],
            &[0x22u8; 32][..],
            "our session_id is on the wire"
        );
    }

    #[test]
    fn reality_auth_roundtrips_and_gates_on_the_server_key() {
        let mut rng = rand::thread_rng();
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let short_id = [0xab, 0xcd, 0xef, 0x01];
        let now = 1_900_000_000u32;
        let g = Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[4],
            ext_trail: GREASE[5],
        };

        let (hello, _eph, _auth_key) =
            build_authed_client_hello("www.example.com", &server_pub, &short_id, now, &g, 517)
                .expect("generated server public key is contributory");

        // Server parses the ClientHello fields straight off the wire ...
        let f = extract_client_hello_fields(&hello).expect("parse client hello");
        // ... and recomputes the SAME key via ECDH(server_priv, client_keyshare_pub).
        let shared = auth::ecdh(&server_static, &f.x25519_pub)
            .expect("generated client key share is contributory");
        let key = auth::derive_auth_key(&shared, &f.random);
        let pt = auth::open_session_id(&hello, SID_OFFSET, &key, &f.random)
            .expect("auth opens for the matching key");
        assert_eq!(&pt[0..3], &CLIENT_VERSION);
        assert_eq!(u32::from_be_bytes(pt[4..8].try_into().unwrap()), now);
        assert_eq!(&pt[8..12], &short_id);

        // A different server key must NOT open it — this is the gate that makes a
        // prober (who lacks the key) just another forwarded, indistinguishable peer.
        let wrong = StaticSecret::random_from_rng(&mut rng);
        let ws =
            auth::ecdh(&wrong, &f.x25519_pub).expect("generated client key share is contributory");
        let wk = auth::derive_auth_key(&ws, &f.random);
        assert!(auth::open_session_id(&hello, SID_OFFSET, &wk, &f.random).is_none());
    }

    #[test]
    fn authed_client_hello_rejects_low_order_static_server_keys_before_wire_io() {
        let g = Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        };
        let mut one = [0u8; 32];
        one[0] = 1;
        for server_public in [[0u8; 32], one] {
            let result = build_authed_client_hello(
                "www.example.com",
                &server_public,
                &[0x11; 8],
                1_900_000_000,
                &g,
                517,
            );
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("low-order static server key was accepted"),
            };
            assert_eq!(error, NonContributoryPublicKey);
        }
    }
}
