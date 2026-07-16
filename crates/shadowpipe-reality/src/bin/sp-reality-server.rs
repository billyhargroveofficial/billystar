//! A loopback-only REALITY laboratory server: accept a valid REALITY carrier
//! token (then echo data as a demo payload), or transparently forward everyone
//! else to a cover. Token acceptance does not establish a client identity.
//!
//! Thread-per-connection, blocking. This binary is deliberately unusable as a
//! public daemon: it requires an explicit lab acknowledgement and a literal
//! loopback listener. Production uses `shadowpipe-server --reality`, whose
//! mandatory inner device authentication and root-owned selector ACL are not
//! optional.
//!
//! Usage:
//!   sp-reality-server --insecure-lab-echo <loopback:port> <static_private_hex> <cover_host:port> <private_replay_store> <16_lower_hex_short_id> [...]
//! Example:
//!   sp-reality-server --insecure-lab-echo 127.0.0.1:8443 <priv> www.microsoft.com:443 ./replay.bin 0123456789abcdef

use shadowpipe_reality::reality::{
    reality_accept, RealityAccept, RealityServerConfig, ReplayCache,
};
use shadowpipe_reality::ReplayStoreOwner;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use x25519_dalek::StaticSecret;

fn main() {
    let mut args = std::env::args().skip(1);
    let usage = "usage: sp-reality-server --insecure-lab-echo <loopback:port> <64_lower_hex_private> <cover_host:port> <private_replay_store> <16_lower_hex_short_id> [...]";
    assert_eq!(
        args.next().as_deref(),
        Some("--insecure-lab-echo"),
        "{usage}"
    );
    let listen: SocketAddr = args
        .next()
        .expect(usage)
        .parse()
        .expect("lab listener must be a literal loopback socket address");
    assert!(
        listen.ip().is_loopback(),
        "sp-reality-server is a loopback-only unauthenticated echo laboratory binary; use shadowpipe-server --reality for production"
    );
    let priv_hex = args.next().expect(usage);
    let cover = args.next().expect(usage);
    let replay_store = args.next().expect(usage);
    let encoded_short_ids = args.collect::<Vec<_>>();
    assert!(
        (1..=16).contains(&encoded_short_ids.len()),
        "lab short_id ACL must contain 1..=16 entries"
    );
    assert!(
        encoded_short_ids.windows(2).all(|pair| pair[0] < pair[1]),
        "lab short_id ACL must be strictly sorted and unique"
    );
    let short_ids = encoded_short_ids
        .into_iter()
        .map(|encoded| {
            assert!(
                encoded.len() == 16
                    && encoded
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "lab short_id must be exactly 16 lowercase hex characters"
            );
            hex::decode(encoded).expect("validated short_id hex")
        })
        .collect();

    assert!(
        priv_hex.len() == 64
            && priv_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "static_private_hex must be exactly 64 lowercase hex characters"
    );
    let sk: [u8; 32] = hex::decode(&priv_hex)
        .expect("validated static_private_hex")
        .try_into()
        .expect("static_private must be 32 bytes");

    let static_secret = StaticSecret::from(sk);
    let replay_cache = ReplayCache::open_persistent(
        Path::new(&replay_store),
        &static_secret,
        ReplayStoreOwner::EffectiveUser,
    )
    .expect("open explicit private durable lab replay store before bind");
    if let Some(reason) = replay_cache.fail_forward_reason() {
        eprintln!("sp-reality-server: replay store is fail-forward only until repaired: {reason}");
    }
    let cfg = Arc::new(RealityServerConfig {
        static_secret,
        short_ids,
        cover: cover.clone(),
        max_time_skew_secs: Some(120), // ±2 min clock-skew tolerance (anti-replay)
        replay_cache,
        cover_profile: None, // TODO: profile_cover(&cover, sni) at startup, cached
    });

    let listener = TcpListener::bind(listen).expect("bind loopback lab listener");
    eprintln!(
        "sp-reality-server: listening on {listen} | cover={cover} | short_ids={}",
        cfg.short_ids.len()
    );

    for conn in listener.incoming() {
        let sock = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let cfg = Arc::clone(&cfg);
        std::thread::spawn(move || {
            let peer = sock.peer_addr().ok();
            match reality_accept(sock, &cfg) {
                Ok(RealityAccept::TokenAccepted(mut conn)) => {
                    eprintln!("[{peer:?}] TOKEN ACCEPTED (NO CLIENT IDENTITY) — echoing");
                    loop {
                        match conn.recv() {
                            Ok(data) if !data.is_empty() => {
                                if conn.send(&data).is_err() {
                                    break;
                                }
                            }
                            _ => break, // peer closed or error
                        }
                    }
                    eprintln!("[{peer:?}] closed");
                }
                Ok(RealityAccept::Forwarded) => eprintln!("[{peer:?}] forwarded to cover"),
                Err(e) => eprintln!("[{peer:?}] error: {e}"),
            }
        });
    }
}
