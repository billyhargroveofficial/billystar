//! Drive a full TLS 1.3 handshake with our from-scratch client against a real
//! server, then exchange application data — the interop gate that proves the
//! whole stack (ClientHello + key schedule + record layer) is byte-correct.
//!
//! Usage: sp-reality-handshake <host:port> [sni] [message]
//! Test partner: `openssl s_server -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
//!                -rev -accept <port> -cert c.pem -key k.pem -quiet`

use rand::{Rng, RngCore};
use shadowpipe_reality::tls13::{client_handshake, CertVerify};
use shadowpipe_reality::{build_client_hello, Grease, GREASE};
use std::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

fn pick(rng: &mut impl Rng) -> u16 {
    GREASE[rng.gen_range(0..GREASE.len())]
}

fn main() {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:48443".into());
    let sni = args.next().unwrap_or_else(|| "example.com".into());
    let msg = args.next().unwrap_or_else(|| "shadowpipe-reality\n".into());

    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut session_id);
    let eph = StaticSecret::random_from_rng(&mut rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let g = Grease {
        cipher: pick(&mut rng),
        group: pick(&mut rng),
        ext_lead: pick(&mut rng),
        version: pick(&mut rng),
        ext_trail: pick(&mut rng),
    };

    let hello = build_client_hello(&sni, &random, &session_id, &eph_pub, &g, 517);

    let tcp = TcpStream::connect(&addr).expect("connect");
    let mut conn = match client_handshake(tcp, &hello, &eph, CertVerify::Skip) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("HANDSHAKE FAILED: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("HANDSHAKE OK (TLS 1.3, TLS_AES_128_GCM_SHA256) -> {addr}");

    conn.send(msg.as_bytes()).expect("send");
    let reply = conn.recv().expect("recv");
    eprintln!("sent:  {:?}", msg);
    eprintln!("recv:  {:?}", String::from_utf8_lossy(&reply));
    println!("INTEROP OK: {} bytes app-data round-tripped", reply.len());
}
