//! Emit one from-scratch Chrome ClientHello and print it as hex, so its JA4 can
//! be scored by `tools/ja4-gate fingerprint --hex <...>` (the same validation
//! flow we used for the boring front). Proves our Rust builder reaches Chrome
//! parity AND that we control the session_id + X25519 key share.

use rand::{Rng, RngCore};
use shadowpipe_reality::{build_client_hello, Grease, GREASE};
use x25519_dalek::{PublicKey, StaticSecret};

fn pick(rng: &mut impl Rng) -> u16 {
    GREASE[rng.gen_range(0..GREASE.len())]
}

fn main() {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    // A random session_id here; in REALITY this is the AEAD auth ciphertext (M1).
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut session_id);
    // A real X25519 ephemeral — we keep the secret (for M1's auth ECDH).
    let secret = StaticSecret::random_from_rng(&mut rng);
    let x25519_pub = PublicKey::from(&secret).to_bytes();

    let g = Grease {
        cipher: pick(&mut rng),
        group: pick(&mut rng),
        ext_lead: pick(&mut rng),
        version: pick(&mut rng),
        ext_trail: pick(&mut rng),
    };

    let hello = build_client_hello(
        "www.example.com",
        &random,
        &session_id,
        &x25519_pub,
        &g,
        517,
    );
    eprintln!("built {} byte ClientHello record", hello.len());
    println!("{}", hex::encode(&hello));
}
