//! REALITY server: the anti-probe accept path that ties the auth channel
//! ([`crate::auth`]) to the from-scratch TLS 1.3 server ([`crate::tls13`]).
//!
//! On each connection we read the ClientHello and try to open the REALITY auth
//! token hidden in its `legacy_session_id`, keyed by ECDH(server_static,
//! client_keyshare):
//!   - **opens + a known short_id → TOKEN ACCEPTED:** we take over with our own
//!     ServerHello and an HMAC-bound ephemeral leaf (the client verifies it via
//!     [`crate::tls13::CertVerify::RealityHmac`]).
//!   - **anything else** (a normal browser, an active prober, garbage) **→
//!     FORWARDED:** we transparently splice the whole TCP connection — replaying
//!     the ClientHello we already read — to a real cover site, so the peer gets
//!     the cover's genuine TLS handshake and certificate.
//!
//! That forward path is the entire point of REALITY: a prober who lacks the key
//! cannot tell our server apart from the cover site it fronts. There is no
//! distinct "this is a proxy" signature to find — probe us and you reach the
//! cover, exactly as if you'd connected to it directly.

use crate::auth;
use crate::cover::CoverProfile;
use crate::parse::extract_client_hello_fields;
#[cfg(test)]
use crate::replay::REPLAY_PRUNE_BUDGET;
use crate::tls13::asio::{self, AsyncServerConnection};
use crate::tls13::client::read_record;
use crate::tls13::server::drive_server;
use crate::tls13::{ServerConnection, Suite};
pub use crate::ReplayCache;
use crate::{Writer, SID_OFFSET};
use rand::RngCore;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Mutex;
use std::time::Duration;
use subtle::{Choice, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream as TokioTcpStream;
use x25519_dalek::StaticSecret;

/// REALITY server configuration.
pub struct RealityServerConfig {
    /// Long-term X25519 static secret; its public half is the client's `publicKey`.
    pub static_secret: StaticSecret,
    /// Accepted short IDs (1..=16 strictly sorted unique entries, each 1..=8
    /// bytes). Empty or invalid configuration accepts no token. Production
    /// supplies exactly eight-byte entries from its root-owned canonical ACL.
    pub short_ids: Vec<Vec<u8>>,
    /// Cover-site `host:port` for peers whose token is not accepted.
    pub cover: String,
    /// Max allowed skew (seconds) between the token's unix_time and now; a token
    /// outside the window is forwarded (anti-replay). `None` disables the check.
    pub max_time_skew_secs: Option<u64>,
    /// Exact-replay cache for session_ids (only consulted when a skew window is
    /// set). Production must use a durable [`ReplayCache::open_persistent`].
    pub replay_cache: ReplayCache,
    /// Optional measured profile of the cover (see [`crate::cover`]). When set,
    /// the accepted-token path mimics the cover's cipher + flight size (#9).
    /// When `None`, that path uses AES-128-GCM and an unpadded flight.
    pub cover_profile: Option<CoverProfile>,
}

/// Outcome of [`reality_accept`].
pub enum RealityAccept {
    /// The REALITY token passed carrier policy; no client identity is established.
    TokenAccepted(ServerConnection<TcpStream>),
    /// The token was not accepted; the peer was proxied to the cover.
    Forwarded,
}

/// Build the REALITY Certificate handshake message carrying a raw 32-byte
/// ephemeral leaf key as the sole cert_data. (TLS 1.3 encrypts the whole
/// Certificate flight, so this never appears on the wire in clear; it only needs
/// to be a 32-byte value the client can HMAC over — not a real X.509 cert, since
/// only our own client ever completes this path. Probers get the cover's real
/// cert via the forward path.)
fn reality_cert_msg(leaf_pub: &[u8; 32], pad_len: usize) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0x0b); // Certificate
    w.len24(|w| {
        w.u8(0); // certificate_request_context: empty
        w.len24(|w| {
            // entry 0: the real 32-byte leaf — the client HMAC-verifies this one.
            w.len24(|w| w.raw(leaf_pub));
            w.u16(0); // no extensions
                      // entry 1 (optional): filler so the encrypted flight matches the
                      // cover's size (#9 P2). The client reads only entry 0, so this is
                      // inert; it travels inside the TLS-1.3-encrypted Certificate.
            if pad_len > 0 {
                let pad = vec![0u8; pad_len];
                w.len24(|w| w.raw(&pad));
                w.u16(0);
            }
        });
    });
    w.buf
}

/// From the (optional) cover profile, choose the AEAD suite to present and how
/// many filler bytes to add to the Certificate so the accepted-token flight matches the
/// cover's measured size. `None` profile ⇒ AES-128-GCM, no padding.
fn mimic_params(cfg: &RealityServerConfig) -> (Suite, usize) {
    match &cfg.cover_profile {
        Some(p) => {
            // Match the cover's cipher if we support it, else AES-128-GCM. A cover
            // that selects AES-256-GCM (0x1302) is now mirrored faithfully — it used
            // to be silently downgraded to AES-128, a passive distinguisher.
            let suite = Suite::from_id(p.cipher).unwrap_or(Suite::Aes128GcmSha256);
            // Everything in our flight except the Certificate filler — ServerHello
            // record + CCS + EncryptedExtensions + CertificateVerify + Finished +
            // record overhead — is ~270 B (SHA-384's Finished adds 16 B); pad the
            // rest to the cover's flight size. Clamp to the record limit.
            let overhead = 270 + (suite.hash().len() - 32);
            let pad = p.flight_len.saturating_sub(overhead).min(16_000);
            (suite, pad)
        }
        None => (Suite::Aes128GcmSha256, 0),
    }
}

/// Plaintext chunk sizes to split the accepted-token flight into, mimicking the cover's
/// record structure (#9). Derived from the cover's measured records: skip the
/// ServerHello (first record) and the 6-byte CCS, then map each remaining wire
/// length to a plaintext size (−22 B = 5-byte header + 1-byte inner type + 16-byte
/// AEAD tag). Empty (⇒ one coalesced record, the prior behaviour) with no profile.
fn flight_record_plan(cfg: &RealityServerConfig) -> Vec<usize> {
    match &cfg.cover_profile {
        Some(p) => p
            .record_lens
            .iter()
            .skip(1)
            .filter(|&&l| l != 6)
            .map(|&l| l.saturating_sub(22).max(1))
            .collect(),
        None => Vec::new(),
    }
}

/// Build the REALITY CertificateVerify carrying the HMAC as the "signature"
/// (algorithm ed25519 0x0807 — a 64-byte signature, structurally identical to a
/// real Ed25519 one on the wire).
fn reality_certverify_msg(auth_key: &[u8; 32], leaf_pub: &[u8; 32]) -> Vec<u8> {
    let sig = auth::reality_cert_hmac(auth_key, leaf_pub);
    let mut w = Writer::new();
    w.u8(0x0f); // CertificateVerify
    w.len24(|w| {
        w.u16(0x0807); // ed25519
        w.len16(|w| w.raw(&sig));
    });
    w.buf
}

/// Current Unix time in seconds (saturating into the u32 range REALITY uses for
/// the auth token's timestamp). Used by the client to stamp tokens and the server
/// to bound their age.
pub fn unix_now() -> u32 {
    unix_now_secs().min(u32::MAX as u64) as u32
}

fn unix_now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Does the opened auth plaintext carry one of the configured short IDs?
/// The short_id lives in `pt[8..16]`, right-zero-padded to its real length.
fn short_id_ok(cfg: &RealityServerConfig, pt: &[u8; auth::AUTH_PLAINTEXT_LEN]) -> bool {
    if !(1..=16).contains(&cfg.short_ids.len())
        || cfg.short_ids.iter().any(|id| !(1..=8).contains(&id.len()))
        || !cfg.short_ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return false;
    }
    let mut accepted = Choice::from(0u8);
    for id in &cfg.short_ids {
        let n = id.len();
        let mut padded = [0u8; 8];
        padded[..n].copy_from_slice(id);
        accepted |= padded.ct_eq(&pt[8..16]);
    }
    bool::from(accepted)
}

#[derive(Clone, Copy)]
struct TokenAuthorization {
    now: u64,
    valid_until: Option<u64>,
}

/// Is a successfully-opened token actually authorized? Checks (1) the protocol
/// version and canonical reserved byte, (2) the short_id allowlist, and (3) the
/// time window. Any failure is forwarded exactly like a token that never opened.
///
/// `valid_until` is absolute (`token_time + window`), so a future-skew token
/// remains replay-protected for its complete acceptance interval rather than
/// only for a first-seen TTL.
fn token_authorized_at(
    cfg: &RealityServerConfig,
    pt: &[u8; auth::AUTH_PLAINTEXT_LEN],
    now: u64,
) -> Option<TokenAuthorization> {
    if pt[0..3] != crate::CLIENT_VERSION || pt[3] != 0 || !short_id_ok(cfg, pt) {
        return None;
    }
    let valid_until = if let Some(window) = cfg.max_time_skew_secs {
        let token_time = u32::from_be_bytes([pt[4], pt[5], pt[6], pt[7]]) as u64;
        if now.abs_diff(token_time) > window {
            return None;
        }
        Some(token_time.saturating_add(window))
    } else {
        None
    };
    Some(TokenAuthorization { now, valid_until })
}

fn token_authorized(
    cfg: &RealityServerConfig,
    pt: &[u8; auth::AUTH_PLAINTEXT_LEN],
) -> Option<TokenAuthorization> {
    token_authorized_at(cfg, pt, unix_now_secs())
}

/// Accept one connection whose REALITY token passes carrier policy, or forward
/// it to the cover. Token acceptance is not client identity authentication.
/// Blocks for the whole forwarded session in the forwarding case.
pub fn reality_accept(
    mut stream: TcpStream,
    cfg: &RealityServerConfig,
) -> io::Result<RealityAccept> {
    // Read the ClientHello. Anything that isn't a parseable TLS ClientHello is a
    // non-REALITY peer → forward it untouched (replaying what we read).
    let (t, ch_rec) = read_record(&mut stream)?;
    if t != 0x16 {
        return forward(stream, cfg, &ch_rec);
    }
    let Some(f) = extract_client_hello_fields(&ch_rec) else {
        return forward(stream, cfg, &ch_rec);
    };

    // Auth ECDH: server static × the client's key_share ephemeral, then the
    // same HKDF the client used. open_session_id fails (→ forward) unless the
    // peer sealed the token with the key only our static secret can derive.
    let Some(shared) = auth::ecdh(&cfg.static_secret, &f.x25519_pub) else {
        return forward(stream, cfg, &ch_rec);
    };
    let auth_key = auth::derive_auth_key(&shared, &f.random);
    match auth::open_session_id(&ch_rec, SID_OFFSET, &auth_key, &f.random) {
        Some(pt) => {
            let Some(authorization) = token_authorized(cfg, &pt) else {
                return forward(stream, cfg, &ch_rec);
            };
            // The durable insert + fdatasync is the commit point and completes
            // before any accepted-path ServerHello bytes are emitted.
            if let Some(valid_until) = authorization.valid_until {
                if !cfg
                    .replay_cache
                    .check_and_record(&f.session_id, authorization.now, valid_until)
                {
                    return forward(stream, cfg, &ch_rec);
                }
            }
            // TOKEN ACCEPTED — take over: mimic the cover's flight, then
            // our ServerHello + an HMAC-bound ephemeral leaf.
            let (suite, pad) = mimic_params(cfg);
            let mut leaf_pub = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut leaf_pub);
            let cert = reality_cert_msg(&leaf_pub, pad);
            let cv = reality_certverify_msg(&auth_key, &leaf_pub);
            let plan = flight_record_plan(cfg);
            let conn = drive_server(stream, &ch_rec, &f, &cert, &cv, suite, &plan)?;
            Ok(RealityAccept::TokenAccepted(conn))
        }
        _ => forward(stream, cfg, &ch_rec),
    }
}

/// Dial the cover site and splice the client onto it, replaying `prefix` (the
/// ClientHello we already consumed) so the cover sees a pristine handshake.
fn forward(
    client: TcpStream,
    cfg: &RealityServerConfig,
    prefix: &[u8],
) -> io::Result<RealityAccept> {
    let cover = TcpStream::connect(&cfg.cover)?;
    splice(client, cover, prefix)?;
    Ok(RealityAccept::Forwarded)
}

/// Bidirectional raw byte copy between `client` and `cover` until both close,
/// after first sending `prefix` to the cover.
fn splice(client: TcpStream, cover: TcpStream, prefix: &[u8]) -> io::Result<()> {
    let mut cover_w = cover.try_clone()?;
    cover_w.write_all(prefix)?;
    cover_w.flush()?;

    // client → cover, in its own thread.
    let mut client_r = client.try_clone()?;
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut cover_w);
        let _ = cover_w.shutdown(Shutdown::Write);
    });

    // cover → client, here.
    let mut cover_r = cover;
    let mut client_w = client;
    let _ = io::copy(&mut cover_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Both);
    let _ = up.join();
    Ok(())
}

// ----------------------------------------------------------- async (tokio) --

/// Async outcome of [`reality_accept_async`].
pub enum RealityAcceptAsync {
    /// The REALITY token passed carrier policy; no client identity is established.
    TokenAccepted(AsyncServerConnection<TokioTcpStream>),
    /// The token was not accepted and the ClientHello has been delivered to the
    /// cover. The caller must drive the returned splice outside its bounded
    /// classification/cover-connect deadline.
    Forwarded(ForwardedConnection),
}

/// An established forward-to-cover splice after the rejected ClientHello has
/// already been written and flushed to the cover. Keeping this separate from
/// [`reality_accept_async`] lets callers bound classification and cover setup
/// without imposing a distinctive short absolute lifetime on ordinary cover
/// HTTP/2 connections.
pub struct ForwardedConnection {
    client: TokioTcpStream,
    cover: TokioTcpStream,
}

fn idle_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "REALITY cover splice exceeded its bidirectional idle bound",
    )
}

fn activity_deadline(
    activity: &Mutex<tokio::time::Instant>,
    idle: Duration,
) -> io::Result<tokio::time::Instant> {
    activity
        .lock()
        .map(|last| *last + idle)
        .map_err(|_| io::Error::other("REALITY forward activity lock poisoned"))
}

fn note_activity(activity: &Mutex<tokio::time::Instant>) -> io::Result<()> {
    *activity
        .lock()
        .map_err(|_| io::Error::other("REALITY forward activity lock poisoned"))? =
        tokio::time::Instant::now();
    Ok(())
}

fn idle_really_elapsed(activity: &Mutex<tokio::time::Instant>, idle: Duration) -> io::Result<bool> {
    activity
        .lock()
        .map(|last| tokio::time::Instant::now().duration_since(*last) >= idle)
        .map_err(|_| io::Error::other("REALITY forward activity lock poisoned"))
}

async fn copy_with_shared_idle<R, W>(
    mut reader: R,
    mut writer: W,
    activity: std::sync::Arc<Mutex<tokio::time::Instant>>,
    idle: Duration,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let deadline = activity_deadline(&activity, idle)?;
        let count = match tokio::time::timeout_at(deadline, reader.read(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) if !idle_really_elapsed(&activity, idle)? => continue,
            Err(_) => return Err(idle_error()),
        };
        if count == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        note_activity(&activity)?;

        let mut written = 0usize;
        while written < count {
            let deadline = activity_deadline(&activity, idle)?;
            let progress = match tokio::time::timeout_at(
                deadline,
                writer.write(&buffer[written..count]),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) if !idle_really_elapsed(&activity, idle)? => continue,
                Err(_) => return Err(idle_error()),
            };
            if progress == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            written += progress;
            copied = copied.saturating_add(progress as u64);
            note_activity(&activity)?;
        }
    }
}

impl ForwardedConnection {
    /// Drive the cover splice until both halves close or neither direction
    /// makes read/write progress for `idle`. Activity in either direction resets
    /// the shared monotonic deadline, matching long-lived asymmetric downloads.
    pub async fn run_with_idle_timeout(self, idle: Duration) -> io::Result<()> {
        if idle.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "REALITY forward idle timeout must be positive",
            ));
        }
        let activity = std::sync::Arc::new(Mutex::new(tokio::time::Instant::now()));
        let (client_read, client_write) = tokio::io::split(self.client);
        let (cover_read, cover_write) = tokio::io::split(self.cover);
        tokio::try_join!(
            copy_with_shared_idle(
                client_read,
                cover_write,
                std::sync::Arc::clone(&activity),
                idle,
            ),
            copy_with_shared_idle(cover_read, client_write, activity, idle),
        )?;
        Ok(())
    }
}

/// Async accept-token-or-forward over a Tokio stream. On forward, this returns
/// an established splice after cover connect and ClientHello write/flush; the
/// caller must drive it under its own sliding idle policy.
pub async fn reality_accept_async(
    mut stream: TokioTcpStream,
    cfg: &RealityServerConfig,
) -> io::Result<RealityAcceptAsync> {
    let (t, ch_rec) = asio::read_record(&mut stream).await?;
    if t != 0x16 {
        return forward_async(stream, cfg, &ch_rec).await;
    }
    let Some(f) = extract_client_hello_fields(&ch_rec) else {
        return forward_async(stream, cfg, &ch_rec).await;
    };
    let Some(shared) = auth::ecdh(&cfg.static_secret, &f.x25519_pub) else {
        return forward_async(stream, cfg, &ch_rec).await;
    };
    let auth_key = auth::derive_auth_key(&shared, &f.random);
    match auth::open_session_id(&ch_rec, SID_OFFSET, &auth_key, &f.random) {
        Some(pt) => {
            let Some(authorization) = token_authorized(cfg, &pt) else {
                return forward_async(stream, cfg, &ch_rec).await;
            };
            if let Some(valid_until) = authorization.valid_until {
                if !cfg
                    .replay_cache
                    .check_and_record(&f.session_id, authorization.now, valid_until)
                {
                    return forward_async(stream, cfg, &ch_rec).await;
                }
            }
            let (suite, pad) = mimic_params(cfg);
            let mut leaf_pub = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut leaf_pub);
            let cert = reality_cert_msg(&leaf_pub, pad);
            let cv = reality_certverify_msg(&auth_key, &leaf_pub);
            let plan = flight_record_plan(cfg);
            let conn = asio::drive_server(stream, &ch_rec, &f, &cert, &cv, suite, &plan).await?;
            Ok(RealityAcceptAsync::TokenAccepted(conn))
        }
        _ => forward_async(stream, cfg, &ch_rec).await,
    }
}

async fn forward_async(
    client: TokioTcpStream,
    cfg: &RealityServerConfig,
    prefix: &[u8],
) -> io::Result<RealityAcceptAsync> {
    let mut cover = TokioTcpStream::connect(&cfg.cover).await?;
    cover.write_all(prefix).await?;
    cover.flush().await?;
    Ok(RealityAcceptAsync::Forwarded(ForwardedConnection {
        client,
        cover,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::{client_handshake, server_handshake, CertVerify};
    use crate::{build_authed_client_hello, build_client_hello, Grease, GREASE};
    use std::io::Read;
    use std::net::{SocketAddr, TcpListener};
    use x25519_dalek::PublicKey;

    fn grease() -> Grease {
        Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        }
    }

    /// Stub "cover site": accept one connection, read the first chunk, reply with
    /// `reply`, then close. The handle yields the bytes it received (so a test can
    /// prove the client→cover direction actually carried the ClientHello).
    fn spawn_cover(reply: &'static [u8]) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap();
            s.write_all(reply).unwrap();
            s.flush().unwrap();
            buf[..n].to_vec()
        });
        (addr, h)
    }

    /// REALITY server that accepts one connection and reports whether it forwarded.
    fn spawn_forwarding_server(
        cfg: RealityServerConfig,
    ) -> (SocketAddr, std::thread::JoinHandle<bool>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (sock, _) = l.accept().unwrap();
            matches!(
                reality_accept(sock, &cfg).unwrap(),
                RealityAccept::Forwarded
            )
        });
        (addr, h)
    }

    /// Connect, send `hello`, read everything sent back (mimics a peer/prober).
    fn probe(addr: SocketAddr, hello: &[u8]) -> Vec<u8> {
        let mut tcp = TcpStream::connect(addr).unwrap();
        tcp.write_all(hello).unwrap();
        tcp.flush().unwrap();
        let mut got = Vec::new();
        tcp.read_to_end(&mut got).unwrap();
        got
    }

    /// A REALITY token is accepted and data is exchanged; independently, the
    /// client verifies the server via the HMAC leaf.
    #[test]
    fn accepted_token_completes_reality_handshake_with_server_verification() {
        let mut rng = rand::thread_rng();
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let short_id = vec![0xab, 0xcd, 0xef, 0x01];

        let cfg = RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![short_id.clone()],
            cover: "127.0.0.1:1".into(), // never dialed on accepted-token path
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            match reality_accept(sock, &cfg).unwrap() {
                RealityAccept::TokenAccepted(mut conn) => {
                    let got = conn.recv().unwrap();
                    let echoed: Vec<u8> = got.iter().rev().cloned().collect();
                    conn.send(&echoed).unwrap();
                    true
                }
                RealityAccept::Forwarded => false,
            }
        });

        let (hello, eph, auth_key) = build_authed_client_hello(
            "www.example.com",
            &server_pub,
            &short_id,
            1_900_000_000,
            &grease(),
            517,
        )
        .expect("generated server public key is contributory");
        let tcp = TcpStream::connect(addr).unwrap();
        let mut conn =
            client_handshake(tcp, &hello, &eph, CertVerify::RealityHmac(auth_key)).unwrap();
        conn.send(b"hello reality").unwrap();
        assert_eq!(conn.recv().unwrap(), b"ytilaer olleh");
        assert!(server.join().unwrap(), "server accepted the carrier token");
    }

    /// The anti-probe property: a peer that can't authenticate (here a plain
    /// Chrome ClientHello with a random session_id — like an active prober) is
    /// transparently spliced to the cover site and receives the COVER's bytes.
    #[test]
    fn unaccepted_token_prober_is_forwarded_to_cover_verbatim() {
        let (cover_addr, cover) = spawn_cover(b"COVER-SITE-RESPONSE");
        let mut rng = rand::thread_rng();
        let (addr, server) = spawn_forwarding_server(RealityServerConfig {
            static_secret: StaticSecret::random_from_rng(&mut rng),
            short_ids: vec![vec![0x99]],
            cover: cover_addr,
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let hello = build_client_hello("www.example.com", &random, &sid, &eph_pub, &grease(), 517);

        assert_eq!(
            probe(addr, &hello),
            b"COVER-SITE-RESPONSE",
            "prober got the cover's bytes"
        );
        let cover_saw = cover.join().unwrap();
        assert_eq!(
            cover_saw[0], 0x16,
            "cover received a forwarded TLS ClientHello"
        );
        assert!(
            cover_saw.len() > 100,
            "cover got the full ClientHello, not a fragment"
        );
        assert!(server.join().unwrap(), "server took the forward path");
    }

    #[test]
    fn forged_all_zero_auth_tokens_on_low_order_key_shares_fail_forward() {
        let mut one = [0u8; 32];
        one[0] = 1;
        for low_order_public in [[0u8; 32], one] {
            let (cover_addr, cover) = spawn_cover(b"LOW-ORDER-COVER");
            let (addr, server) = spawn_forwarding_server(RealityServerConfig {
                static_secret: StaticSecret::from([0x42; 32]),
                short_ids: vec![vec![0x51; 8]],
                cover: cover_addr,
                max_time_skew_secs: None,
                replay_cache: ReplayCache::in_memory_for_tests(),
                cover_profile: None,
            });

            // Without a contributory check, either low-order key share yields the
            // public all-zero ECDH value.  Build the exact token an attacker could
            // forge from that value and prove it still reaches only the cover.
            let mut random = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut random);
            let mut hello = build_client_hello(
                "www.example.com",
                &random,
                &[0u8; 32],
                &low_order_public,
                &grease(),
                517,
            );
            let public_auth_key = auth::derive_auth_key(&[0u8; 32], &random);
            let plaintext = auth::auth_plaintext(crate::CLIENT_VERSION, 1_900_000_000, &[0x51; 8]);
            auth::seal_into_session_id(
                &mut hello,
                SID_OFFSET,
                &public_auth_key,
                &random,
                &plaintext,
            );

            assert_eq!(probe(addr, &hello), b"LOW-ORDER-COVER");
            assert!(server.join().unwrap(), "low-order token was not forwarded");
            assert_eq!(cover.join().unwrap(), hello);
        }
    }

    /// A REALITY auth token sealed for the WRONG static key is indistinguishable
    /// from a prober: it fails to open, so it is forwarded — not rejected with a
    /// tell-tale error or timing a prober could measure.
    #[test]
    fn authed_token_for_the_wrong_static_key_is_forwarded() {
        let (cover_addr, cover) = spawn_cover(b"COVER");
        let mut rng = rand::thread_rng();
        let (addr, server) = spawn_forwarding_server(RealityServerConfig {
            static_secret: StaticSecret::random_from_rng(&mut rng),
            short_ids: vec![vec![0x01]],
            cover: cover_addr,
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        // Seal the token against a DIFFERENT static key than the server holds.
        let wrong_pub = PublicKey::from(&StaticSecret::random_from_rng(&mut rng)).to_bytes();
        let (hello, _eph, _ak) = build_authed_client_hello(
            "www.example.com",
            &wrong_pub,
            &[0x01],
            1_900_000_000,
            &grease(),
            517,
        )
        .expect("generated server public key is contributory");

        assert_eq!(probe(addr, &hello), b"COVER");
        assert!(server.join().unwrap(), "wrong-key token was forwarded");
        assert_eq!(cover.join().unwrap()[0], 0x16);
    }

    /// A correct key but an unknown short_id (not in the server's allowlist) is
    /// also forwarded — the gate enforces the short_id ACL, not just the key.
    #[test]
    fn unknown_short_id_is_forwarded() {
        let (cover_addr, cover) = spawn_cover(b"COVER");
        let mut rng = rand::thread_rng();
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let (addr, server) = spawn_forwarding_server(RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![vec![0xaa]], // server accepts only 0xaa
            cover: cover_addr,
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        let (hello, _eph, _ak) = build_authed_client_hello(
            "www.example.com",
            &server_pub,
            &[0xbb],
            1_900_000_000,
            &grease(),
            517,
        )
        .expect("generated server public key is contributory");

        assert_eq!(probe(addr, &hello), b"COVER");
        assert!(server.join().unwrap(), "unknown short_id was forwarded");
        assert_eq!(cover.join().unwrap()[0], 0x16);
    }

    /// A 0x16 record that is not a parseable ClientHello must be forwarded, never
    /// panic the server — a prober throwing garbage learns nothing.
    #[test]
    fn malformed_clienthello_is_forwarded_not_crashed() {
        let (cover_addr, cover) = spawn_cover(b"COVER");
        let mut rng = rand::thread_rng();
        let (addr, server) = spawn_forwarding_server(RealityServerConfig {
            static_secret: StaticSecret::random_from_rng(&mut rng),
            short_ids: vec![],
            cover: cover_addr,
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        // Valid TLS record framing (0x16) but a junk handshake body.
        let junk = [0x16u8, 0x03, 0x01, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00];
        assert_eq!(probe(addr, &junk), b"COVER");
        assert!(
            server.join().unwrap(),
            "malformed ClientHello was forwarded"
        );
        assert_eq!(cover.join().unwrap()[0], 0x16);
    }

    /// The server→client direction is authenticated too: a server that completes
    /// a correct TLS 1.3 handshake but presents an HMAC computed with the wrong
    /// key (it does NOT hold the static secret) is rejected by the client.
    #[test]
    fn client_rejects_a_server_whose_hmac_is_wrong() {
        let leaf = [0x42u8; 32];
        let real_auth_key = [7u8; 32];
        let wrong_auth_key = [9u8; 32];
        let cert = reality_cert_msg(&leaf, 0);
        let cv = reality_certverify_msg(&wrong_auth_key, &leaf); // signed with the wrong key

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            // The server side may error when the client bails after the policy
            // check — expected; only the client's verdict matters here.
            let _ = server_handshake(sock, &cert, &cv);
        });

        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let hello = build_client_hello("www.example.com", &random, &sid, &eph_pub, &grease(), 517);

        let tcp = TcpStream::connect(addr).unwrap();
        let e = match client_handshake(tcp, &hello, &eph, CertVerify::RealityHmac(real_auth_key)) {
            Ok(_) => panic!("client must reject a wrong-HMAC server"),
            Err(e) => e,
        };
        assert!(
            e.to_string().contains("HMAC mismatch"),
            "unexpected error: {e}"
        );
        let _ = server.join();
    }

    /// Anti-replay: a token whose timestamp is far outside the server's window is
    /// forwarded — a ClientHello captured and replayed later looks like a probe.
    #[test]
    fn stale_token_is_forwarded() {
        let (cover_addr, cover) = spawn_cover(b"COVER");
        let mut rng = rand::thread_rng();
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let (addr, server) = spawn_forwarding_server(RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![vec![0x01]],
            cover: cover_addr,
            max_time_skew_secs: Some(60),
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        // Correct key + short_id, but a timestamp ~28 hours in the past.
        let stale = unix_now().saturating_sub(100_000);
        let (hello, _eph, _ak) = build_authed_client_hello(
            "www.example.com",
            &server_pub,
            &[0x01],
            stale,
            &grease(),
            517,
        )
        .expect("generated server public key is contributory");

        assert_eq!(probe(addr, &hello), b"COVER");
        assert!(server.join().unwrap(), "stale token was forwarded");
        assert_eq!(cover.join().unwrap()[0], 0x16);
    }

    /// A fresh token within the window is accepted by carrier policy.
    #[test]
    fn fresh_token_within_window_is_accepted() {
        let mut rng = rand::thread_rng();
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let short_id = vec![0x07];
        let cfg = RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![short_id.clone()],
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: Some(60),
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            matches!(
                reality_accept(sock, &cfg).unwrap(),
                RealityAccept::TokenAccepted(_)
            )
        });

        let (hello, eph, auth_key) = build_authed_client_hello(
            "www.example.com",
            &server_pub,
            &short_id,
            unix_now(),
            &grease(),
            517,
        )
        .expect("generated server public key is contributory");
        let tcp = TcpStream::connect(addr).unwrap();
        // .unwrap() proves the client side completed (handshake + HMAC verify);
        // server.join()==true proves the gate admitted the fresh token.
        let _conn = client_handshake(tcp, &hello, &eph, CertVerify::RealityHmac(auth_key)).unwrap();
        assert!(
            server.join().unwrap(),
            "fresh token accepted within the window"
        );
    }

    /// A captured accepted-token ClientHello replayed within the window is
    /// forwarded, thanks to the session_id replay cache.
    #[test]
    fn replayed_clienthello_within_window_is_forwarded() {
        let (cover_addr, cover) = spawn_cover(b"COVER");
        let mut rng = rand::thread_rng();
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let cfg = std::sync::Arc::new(RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![vec![0x01]],
            cover: cover_addr,
            max_time_skew_secs: Some(60),
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg2 = cfg.clone();
        let server = std::thread::spawn(move || {
            let (s1, _) = listener.accept().unwrap();
            let first = matches!(
                reality_accept(s1, &cfg2).unwrap(),
                RealityAccept::TokenAccepted(_)
            );
            let (s2, _) = listener.accept().unwrap();
            let second = matches!(reality_accept(s2, &cfg2).unwrap(), RealityAccept::Forwarded);
            (first, second)
        });

        let (hello, eph, auth_key) = build_authed_client_hello(
            "www.example.com",
            &server_pub,
            &[0x01],
            unix_now(),
            &grease(),
            517,
        )
        .expect("generated server public key is contributory");
        // First connection: token accepted (records the session_id).
        let tcp1 = TcpStream::connect(addr).unwrap();
        let c1 = client_handshake(tcp1, &hello, &eph, CertVerify::RealityHmac(auth_key)).unwrap();
        drop(c1);
        // Replay the exact same ClientHello → forwarded to the cover.
        assert_eq!(probe(addr, &hello), b"COVER");

        let (first, second) = server.join().unwrap();
        assert!(first, "first connection token accepted");
        assert!(second, "replay was forwarded, not accepted again");
        assert_eq!(cover.join().unwrap()[0], 0x16);
    }

    #[test]
    fn replay_cache_is_capacity_bounded_and_prunes_only_a_fixed_budget() {
        let capacity = REPLAY_PRUNE_BUDGET + 2;
        let cache = ReplayCache::with_capacity_for_tests(capacity);
        for index in 0..capacity {
            let mut sid = [0u8; 32];
            sid[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(cache.check_and_record(&sid, 10, 70));
        }
        assert_eq!(cache.len_for_tests(), capacity);

        let saturated = [0xf0; 32];
        assert!(
            !cache.check_and_record(&saturated, 10, 70),
            "a full replay cache must fail forward without growing"
        );
        assert_eq!(cache.len_for_tests(), capacity);

        let after_expiry = [0xf1; 32];
        assert!(cache.check_and_record(&after_expiry, 100, 160));
        assert_eq!(
            cache.len_for_tests(),
            capacity - REPLAY_PRUNE_BUDGET + 1,
            "one admission may prune at most the fixed expiry-work budget"
        );
    }

    #[test]
    fn replay_cache_boundary_expiry_and_poison_fail_closed() {
        let cache = ReplayCache::with_capacity_for_tests(2);
        let sid = [0x42; 32];
        assert!(cache.check_and_record(&sid, 100, 160));
        assert!(!cache.check_and_record(&sid, 160, 160));
        assert!(
            cache.check_and_record(&sid, 161, 221),
            "an entry expires only after the complete inclusive replay window"
        );

        let poisoned = std::sync::Arc::new(ReplayCache::with_capacity_for_tests(2));
        let poisoner = std::sync::Arc::clone(&poisoned);
        assert!(std::thread::spawn(move || poisoner.poison_mutex_for_test())
            .join()
            .is_err());
        assert!(
            !poisoned.check_and_record(&[0x24; 32], 200, 260),
            "a poisoned cache must fail forward instead of panicking the daemon"
        );
    }

    #[test]
    fn nonzero_reserved_token_byte_is_noncanonical_and_fails_forward() {
        let cfg = RealityServerConfig {
            static_secret: StaticSecret::from([0x31; 32]),
            short_ids: vec![vec![0x70; 8]],
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: Some(120),
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        };
        let mut plaintext = auth::auth_plaintext(crate::CLIENT_VERSION, 1_000, &[0x70; 8]);
        assert!(
            token_authorized_at(&cfg, &plaintext, 1_000).is_some(),
            "canonical reserved byte must remain accepted"
        );
        plaintext[3] = 1;
        assert!(
            token_authorized_at(&cfg, &plaintext, 1_000).is_none(),
            "nonzero reserved byte must fail forward"
        );
    }

    #[test]
    fn future_skew_token_reports_absolute_valid_until() {
        let cfg = RealityServerConfig {
            static_secret: StaticSecret::from([0x32; 32]),
            short_ids: vec![vec![0x71; 8]],
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: Some(120),
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        };
        let plaintext = auth::auth_plaintext(crate::CLIENT_VERSION, 1_120, &[0x71; 8]);
        let authorization = token_authorized_at(&cfg, &plaintext, 1_000)
            .expect("future-skew boundary token is valid");
        assert_eq!(authorization.valid_until, Some(1_240));
    }

    #[test]
    fn empty_oversized_and_malformed_short_id_acls_accept_nothing() {
        let mut cfg = RealityServerConfig {
            static_secret: StaticSecret::random_from_rng(rand::thread_rng()),
            short_ids: Vec::new(),
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        };
        let mut plaintext = [0u8; auth::AUTH_PLAINTEXT_LEN];
        plaintext[8..16].copy_from_slice(&[0x70; 8]);

        assert!(!short_id_ok(&cfg, &plaintext));
        cfg.short_ids = vec![Vec::new()];
        assert!(!short_id_ok(&cfg, &plaintext));
        cfg.short_ids = vec![vec![0x70; 9]];
        assert!(!short_id_ok(&cfg, &plaintext));
        cfg.short_ids = vec![vec![0x70; 8], Vec::new()];
        assert!(
            !short_id_ok(&cfg, &plaintext),
            "one malformed entry must invalidate the complete ACL"
        );
        cfg.short_ids = vec![vec![0x70; 8]; 17];
        assert!(!short_id_ok(&cfg, &plaintext));
        cfg.short_ids = vec![vec![0x71; 8], vec![0x70; 8]];
        assert!(!short_id_ok(&cfg, &plaintext));
        cfg.short_ids = vec![vec![0x70; 8], vec![0x70; 8]];
        assert!(!short_id_ok(&cfg, &plaintext));
        cfg.short_ids = vec![vec![0x70; 8]];
        assert!(short_id_ok(&cfg, &plaintext));
    }

    #[test]
    fn cert_msg_padding_grows_the_message() {
        let leaf = [0u8; 32];
        let unpadded = reality_cert_msg(&leaf, 0).len();
        let padded = reality_cert_msg(&leaf, 2000).len();
        assert!(
            unpadded < 60,
            "unpadded cert is just the 32-byte leaf entry"
        );
        assert!(
            padded >= unpadded + 2000,
            "padding adds ~pad_len filler bytes"
        );
    }

    #[test]
    fn mimic_params_mirrors_an_aes256_cover() {
        let mut rng = rand::thread_rng();
        let cfg = RealityServerConfig {
            static_secret: StaticSecret::random_from_rng(&mut rng),
            short_ids: vec![],
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: Some(crate::cover::CoverProfile {
                cipher: 0x1302, // AES-256-GCM-SHA384
                flight_len: 3000,
                record_lens: vec![3000],
            }),
        };
        let (suite, _pad) = mimic_params(&cfg);
        assert_eq!(
            suite,
            Suite::Aes256GcmSha384,
            "a 0x1302 cover is mirrored, not downgraded to AES-128"
        );
    }

    /// With a cover profile, the accepted-token path selects the profile's cipher
    /// (ChaCha20 here) and pads the flight — and the handshake still completes and
    /// HMAC-verifies (the client decrypts the padded flight and reads leaf entry 0).
    #[test]
    fn accepted_token_path_mimics_cover_cipher_and_pads_flight() {
        let mut rng = rand::thread_rng();
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let short_id = vec![0x55];
        let cfg = std::sync::Arc::new(RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![short_id.clone()],
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: Some(crate::cover::CoverProfile {
                cipher: 0x1303,   // pretend the cover selects ChaCha20-Poly1305
                flight_len: 3000, // and sends a ~3 KB flight
                record_lens: vec![3000],
            }),
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg2 = cfg.clone();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            matches!(
                reality_accept(sock, &cfg2).unwrap(),
                RealityAccept::TokenAccepted(_)
            )
        });

        let (hello, eph, auth_key) =
            build_authed_client_hello("www.example.com", &server_pub, &short_id, 0, &grease(), 517)
                .expect("generated server public key is contributory");
        let tcp = TcpStream::connect(addr).unwrap();
        // .unwrap() proves the client negotiated ChaCha20, decrypted the padded
        // flight, extracted leaf entry 0, and HMAC-verified the server.
        let _conn = client_handshake(tcp, &hello, &eph, CertVerify::RealityHmac(auth_key)).unwrap();
        assert!(
            server.join().unwrap(),
            "accepted-token flight used the cover's cipher and padding"
        );
    }

    // ------------------------------------------------------- async (tokio) --

    /// Async end-to-end: token acceptance plus HMAC-verified server identity.
    #[tokio::test]
    async fn async_accepted_token_completes_reality_handshake() {
        use tokio::net::{TcpListener, TcpStream};
        let server_static = StaticSecret::random_from_rng(rand::thread_rng());
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let short_id = vec![0xab, 0xcd];
        let cfg = std::sync::Arc::new(RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![short_id.clone()],
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg2 = cfg.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            match reality_accept_async(sock, &cfg2).await.unwrap() {
                RealityAcceptAsync::TokenAccepted(mut conn) => {
                    let got = conn.recv().await.unwrap();
                    let echoed: Vec<u8> = got.iter().rev().cloned().collect();
                    conn.send(&echoed).await.unwrap();
                    true
                }
                RealityAcceptAsync::Forwarded(_) => false,
            }
        });

        let (hello, eph, auth_key) =
            build_authed_client_hello("www.example.com", &server_pub, &short_id, 0, &grease(), 517)
                .expect("generated server public key is contributory");
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut conn = crate::tls13::asio::client_handshake(
            tcp,
            &hello,
            &eph,
            CertVerify::RealityHmac(auth_key),
        )
        .await
        .unwrap();
        conn.send(b"hello async").await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), b"cnysa olleh");
        assert!(server.await.unwrap(), "server accepted the carrier token");
    }

    /// Async anti-probe: a peer without an accepted token is returned as an
    /// established splice and receives the cover's bytes while it is driven.
    #[tokio::test]
    async fn async_unaccepted_token_prober_is_forwarded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_addr = cover_listener.local_addr().unwrap();
        let cover = tokio::spawn(async move {
            let (mut s, _) = cover_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(b"COVER-ASYNC").await.unwrap();
            s.flush().await.unwrap();
            buf[..n].to_vec()
        });

        let cfg = std::sync::Arc::new(RealityServerConfig {
            static_secret: StaticSecret::random_from_rng(rand::thread_rng()),
            short_ids: vec![vec![0x99]],
            cover: cover_addr.to_string(),
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg2 = cfg.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            match reality_accept_async(sock, &cfg2).await.unwrap() {
                RealityAcceptAsync::Forwarded(forwarded) => {
                    forwarded
                        .run_with_idle_timeout(Duration::from_secs(2))
                        .await
                        .unwrap();
                    true
                }
                RealityAcceptAsync::TokenAccepted(_) => false,
            }
        });

        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let hello = build_client_hello("www.example.com", &random, &sid, &eph_pub, &grease(), 517);

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&hello).await.unwrap();
        tcp.flush().await.unwrap();
        let mut got = Vec::new();
        tcp.read_to_end(&mut got).await.unwrap();
        drop(tcp); // close so both forwarding halves observe EOF

        assert_eq!(got, b"COVER-ASYNC", "prober got the cover's bytes");
        assert!(server.await.unwrap(), "server forwarded");
        let cover_saw = cover.await.unwrap();
        assert_eq!(cover_saw[0], 0x16, "cover received a forwarded ClientHello");
    }

    #[tokio::test]
    async fn async_forged_all_zero_auth_tokens_on_low_order_key_shares_fail_forward() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let mut one = [0u8; 32];
        one[0] = 1;
        for low_order_public in [[0u8; 32], one] {
            let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let cover_addr = cover_listener.local_addr().unwrap();
            let cover = tokio::spawn(async move {
                let (mut stream, _) = cover_listener.accept().await.unwrap();
                let mut hello = vec![0u8; 2048];
                let count = stream.read(&mut hello).await.unwrap();
                stream.write_all(b"LOW-ORDER-ASYNC-COVER").await.unwrap();
                stream.shutdown().await.unwrap();
                hello.truncate(count);
                hello
            });
            let cfg = std::sync::Arc::new(RealityServerConfig {
                static_secret: StaticSecret::from([0x42; 32]),
                short_ids: vec![vec![0x51; 8]],
                cover: cover_addr.to_string(),
                max_time_skew_secs: None,
                replay_cache: ReplayCache::in_memory_for_tests(),
                cover_profile: None,
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let RealityAcceptAsync::Forwarded(forwarded) =
                    reality_accept_async(stream, &cfg).await.unwrap()
                else {
                    panic!("forged low-order token reached the accepted path")
                };
                forwarded
                    .run_with_idle_timeout(Duration::from_secs(2))
                    .await
                    .unwrap();
            });

            let mut random = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut random);
            let mut hello = build_client_hello(
                "www.example.com",
                &random,
                &[0u8; 32],
                &low_order_public,
                &grease(),
                517,
            );
            let public_auth_key = auth::derive_auth_key(&[0u8; 32], &random);
            let plaintext = auth::auth_plaintext(crate::CLIENT_VERSION, 1_900_000_000, &[0x51; 8]);
            auth::seal_into_session_id(
                &mut hello,
                SID_OFFSET,
                &public_auth_key,
                &random,
                &plaintext,
            );
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(&hello).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"LOW-ORDER-ASYNC-COVER");
            server.await.unwrap();
            assert_eq!(cover.await.unwrap(), hello);
        }
    }

    #[tokio::test]
    async fn established_cover_splice_outlives_outer_setup_deadline_but_drip_is_bounded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_addr = cover_listener.local_addr().unwrap();
        let cover = tokio::spawn(async move {
            let (mut stream, _) = cover_listener.accept().await.unwrap();
            let mut hello = vec![0u8; 2048];
            let count = stream.read(&mut hello).await.unwrap();
            assert!(count > 100);
            stream.write_all(b"READY").await.unwrap();
            let mut ping = [0u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"PING");
            stream.write_all(b"PONG").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let cfg = std::sync::Arc::new(RealityServerConfig {
            static_secret: StaticSecret::random_from_rng(rand::thread_rng()),
            short_ids: vec![vec![0x99]],
            cover: cover_addr.to_string(),
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = std::sync::Arc::clone(&cfg);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let outcome = tokio::time::timeout(
                Duration::from_millis(250),
                reality_accept_async(stream, &server_cfg),
            )
            .await
            .expect("classification and cover setup exceeded outer deadline")
            .unwrap();
            let RealityAcceptAsync::Forwarded(forwarded) = outcome else {
                panic!("ordinary ClientHello reached accepted-token path")
            };
            forwarded
                .run_with_idle_timeout(Duration::from_secs(2))
                .await
                .unwrap();
        });

        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut random);
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let hello = build_client_hello(
            "www.example.com",
            &random,
            &sid,
            &PublicKey::from(&eph).to_bytes(),
            &grease(),
            517,
        );
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&hello).await.unwrap();
        let mut ready = [0u8; 5];
        client.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"READY");
        tokio::time::sleep(Duration::from_millis(350)).await;
        client.write_all(b"PING").await.unwrap();
        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"PONG");
        client.shutdown().await.unwrap();
        server.await.unwrap();
        cover.await.unwrap();

        let drip_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let drip_addr = drip_listener.local_addr().unwrap();
        let drip_cfg = cfg;
        let drip_server = tokio::spawn(async move {
            let (stream, _) = drip_listener.accept().await.unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    reality_accept_async(stream, &drip_cfg),
                )
                .await
                .is_err(),
                "partial pre-classification record escaped its absolute deadline"
            );
        });
        let mut dripper = TcpStream::connect(drip_addr).await.unwrap();
        dripper
            .write_all(&[0x16, 0x03, 0x01, 0x00, 0x0a, 0x01])
            .await
            .unwrap();
        drip_server.await.unwrap();
    }
}
