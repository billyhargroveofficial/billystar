//! Generate a REALITY static X25519 keypair.
//!
//! The server is configured with `private`; clients are configured with `public`
//! (the REALITY `publicKey`). The auth ECDH binds the two: only the holder of
//! `private` can open a client's session_id token, and only a server that holds
//! it can produce the HMAC leaf the client verifies.
//!
//! Usage: sp-reality-keygen

use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    // Generate the raw 32-byte scalar ourselves so we can print it without
    // depending on x25519-dalek's `static_secrets` serialization feature.
    let mut sk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk);
    let secret = StaticSecret::from(sk);
    let public = PublicKey::from(&secret);

    println!("private = {}", hex::encode(sk));
    println!("public  = {}", hex::encode(public.to_bytes()));
}
