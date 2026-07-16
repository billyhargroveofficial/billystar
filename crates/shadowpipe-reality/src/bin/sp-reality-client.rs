//! A standalone REALITY client: build a Chrome-JA4 ClientHello carrying a REALITY
//! auth token for the server's static public key, complete the TLS 1.3 handshake,
//! verify the server via its HMAC leaf (so a MITM without the static key is
//! rejected), then send a line and print the echo.
//!
//! Usage:
//!   sp-reality-client <host:port> <server_public_hex> [sni] [short_id_hex] [message]
//! Example:
//!   sp-reality-client 127.0.0.1:8443 <pub> www.microsoft.com 0123abcd "hello"

use rand::Rng;
use shadowpipe_reality::tls13::{client_handshake, CertVerify};
use shadowpipe_reality::{build_authed_client_hello, Grease, GREASE};
use std::net::TcpStream;

fn pick(rng: &mut impl Rng) -> u16 {
    GREASE[rng.gen_range(0..GREASE.len())]
}

fn main() {
    let mut a = std::env::args().skip(1);
    let usage =
        "usage: sp-reality-client <host:port> <server_public_hex> [sni] [short_id_hex] [message]";
    let addr = a.next().expect(usage);
    let pub_hex = a.next().expect(usage);
    let sni = a.next().unwrap_or_else(|| "www.microsoft.com".into());
    let short_id_hex = a.next().unwrap_or_default();
    let msg = a.next().unwrap_or_else(|| "shadowpipe-reality\n".into());

    let server_pub: [u8; 32] = hex::decode(&pub_hex)
        .expect("server_public_hex must be hex")
        .try_into()
        .expect("server_public must be 32 bytes");
    let short_id = if short_id_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(&short_id_hex).expect("short_id_hex must be hex")
    };

    let mut rng = rand::thread_rng();
    let g = Grease {
        cipher: pick(&mut rng),
        group: pick(&mut rng),
        ext_lead: pick(&mut rng),
        version: pick(&mut rng),
        ext_trail: pick(&mut rng),
    };
    // Stamp the token with the current time; the server enforces a skew window.
    let unix_time = shadowpipe_reality::reality::unix_now();
    let (hello, eph, auth_key) =
        build_authed_client_hello(&sni, &server_pub, &short_id, unix_time, &g, 517)
            .expect("server REALITY public key must be contributory");

    let tcp = TcpStream::connect(&addr).expect("connect");
    let mut conn = match client_handshake(tcp, &hello, &eph, CertVerify::RealityHmac(auth_key)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("REALITY HANDSHAKE FAILED: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("REALITY HANDSHAKE OK -> {addr} (server HMAC verified)");

    conn.send(msg.as_bytes()).expect("send");
    let reply = conn.recv().expect("recv");
    eprintln!("sent: {msg:?}");
    eprintln!("recv: {:?}", String::from_utf8_lossy(&reply));
    println!("REALITY ECHO OK: {} bytes round-tripped", reply.len());
}
