//! REALITY carrier facade.
//!
//! Re-exports the [`shadowpipe_reality`] types the binaries need and adds two
//! convenience helpers that hand back a [`RealityStream`] — the post-handshake
//! byte channel that the inner PQ [`AuthenticatedSession`](crate::session::AuthenticatedSession) and the
//! [`tunnel`](crate::tunnel) run over, exactly as they run over a TLS `SslStream`
//! or a [`CarrierStream`](crate::carrier) today.
//!
//! Layering (option a): REALITY is the OUTER carrier — its TLS 1.3 handshake is
//! the on-wire camouflage, with forward-on-fail to a real cover site for any peer
//! whose REALITY token is not accepted. The existing shadowpipe PQ session (ML-KEM + X25519,
//! key-pinned, AEAD-framed) runs INSIDE it unchanged, so we keep post-quantum
//! confidentiality and the server-key pin on top of REALITY's X25519 auth.

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::session::{
    atomic_create_private_file, atomic_write_private_file, is_not_found,
    read_private_file_to_string, CreatePrivateFileOutcome,
};

pub use shadowpipe_reality::cover::{
    profile_cover, CoverProfile, CoverProfileLimits, MAX_COVER_PROFILE_ADDRESSES,
};
pub use shadowpipe_reality::reality::{
    reality_accept_async, unix_now, ForwardedConnection, RealityAcceptAsync, RealityServerConfig,
};
pub use shadowpipe_reality::tls13::{CertVerify, RealityStream};
pub use shadowpipe_reality::{build_authed_client_hello, Grease, GREASE};
pub use shadowpipe_reality::{ReplayCache, ReplayStoreOwner};
pub use x25519_dalek::{PublicKey, StaticSecret};

/// Chrome-style GREASE assignment — one value per slot Chrome greases. Fixed
/// (not random) so the emitted ClientHello matches our validated JA4.
pub fn default_grease() -> Grease {
    Grease {
        cipher: GREASE[0],
        group: GREASE[1],
        ext_lead: GREASE[2],
        version: GREASE[3],
        ext_trail: GREASE[4],
    }
}

/// Perform a REALITY client handshake over an already-connected `tcp`,
/// authenticating to the server's X25519 static `server_pub` with `short_id`
/// (ClientHello SNI = `sni`), and return the post-handshake byte stream.
///
/// The server's HMAC leaf is verified ([`CertVerify::RealityHmac`]), so a wrong or
/// absent static key — i.e. anything that isn't the real server — fails the
/// handshake instead of silently downgrading.
pub async fn reality_connect(
    tcp: TcpStream,
    server_pub: &[u8; 32],
    short_id: &[u8],
    sni: &str,
) -> Result<RealityStream<TcpStream>> {
    let (hello, eph, auth_key) = build_authed_client_hello(
        sni,
        server_pub,
        short_id,
        unix_now(),
        &default_grease(),
        517,
    )
    .context("REALITY static public key")?;
    let conn = shadowpipe_reality::tls13::asio::client_handshake(
        tcp,
        &hello,
        &eph,
        CertVerify::RealityHmac(auth_key),
    )
    .await
    .context("reality client handshake")?;
    Ok(conn.into_stream())
}

/// Result of the bounded REALITY classification/cover-setup phase. Forwarded
/// traffic is intentionally returned as a live splice so the caller can drive
/// it outside the outer-handshake absolute deadline.
pub enum RealityCarrierAccept {
    TokenAccepted(RealityStream<TcpStream>),
    Forwarded(ForwardedConnection),
}

pub async fn reality_accept_start(
    tcp: TcpStream,
    cfg: &RealityServerConfig,
) -> Result<RealityCarrierAccept> {
    match reality_accept_async(tcp, cfg)
        .await
        .context("reality accept")?
    {
        RealityAcceptAsync::TokenAccepted(conn) => {
            Ok(RealityCarrierAccept::TokenAccepted(conn.into_stream()))
        }
        RealityAcceptAsync::Forwarded(forwarded) => Ok(RealityCarrierAccept::Forwarded(forwarded)),
    }
}

/// Compatibility helper for tests and library callers that want the historical
/// `Option` shape. Production server code uses [`reality_accept_start`] and its
/// independently configured forwarding-idle policy. This helper uses a
/// five-minute bidirectional idle bound rather than an outer-handshake bound.
pub async fn reality_accept(
    tcp: TcpStream,
    cfg: &RealityServerConfig,
) -> Result<Option<RealityStream<TcpStream>>> {
    match reality_accept_start(tcp, cfg).await? {
        RealityCarrierAccept::TokenAccepted(stream) => Ok(Some(stream)),
        RealityCarrierAccept::Forwarded(forwarded) => {
            forwarded
                .run_with_idle_timeout(std::time::Duration::from_secs(5 * 60))
                .await
                .context("reality cover forwarding")?;
            Ok(None)
        }
    }
}

/// A one-paste connection descriptor for the REALITY carrier:
///
/// `shadowpipe://<reality_pubkey_hex>@<host:port>?sni=<domain>&sid=<short_id_hex>&fp=<mlkem_fp_hex>`
///
/// The production server emits this descriptor only from explicit `--print-uri`;
/// ordinary daemon startup never prints a token-bearing URI. This generic
/// library parser remains permissive (`sid` up to 8 bytes; unknown query keys
/// ignored), but `shadowpipe-client` applies a strict closed-query preflight.
/// Manual production/tunnel URI deployments should use a private `--uri-file`:
/// exactly one `sni`, `sid`, and `fp`; `sid` is exactly 8 bytes encoded as 16
/// lowercase hex characters; and the REALITY server public key must be
/// contributory. Diagnostic `--uri` and individual selector flags expose the
/// carrier token in process argv.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityUri {
    /// Server endpoint the client dials, `host:port`.
    pub host: String,
    /// Server's REALITY X25519 static public key.
    pub pubkey: [u8; 32],
    /// ClientHello SNI (cover domain).
    pub sni: String,
    /// REALITY short_id (≤8 bytes); empty if none. Production client policy is
    /// stricter and requires exactly 8 bytes.
    pub short_id: Vec<u8>,
    /// Required pinned inner ML-KEM fingerprint (SHA-256).
    pub server_fp: [u8; 32],
}

const URI_SCHEME: &str = "shadowpipe://";

impl RealityUri {
    /// Parse a `shadowpipe://…` URI. Errors on a missing scheme/userinfo/host or a
    /// malformed pubkey/short_id/fp.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .trim()
            .strip_prefix(URI_SCHEME)
            .ok_or_else(|| anyhow::anyhow!("uri must start with {URI_SCHEME}"))?;
        let (userinfo, authority) = rest
            .split_once('@')
            .ok_or_else(|| anyhow::anyhow!("uri missing '<pubkey>@' userinfo"))?;
        let pubkey = parse_x25519_32(userinfo).context("uri pubkey")?;
        let (host, query) = match authority.split_once('?') {
            Some((h, q)) => (h.to_string(), q),
            None => (authority.to_string(), ""),
        };
        if host.is_empty() {
            anyhow::bail!("uri missing host:port");
        }
        let (mut sni, mut short_id, mut server_fp) = (None, Vec::new(), None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("malformed uri query param {pair:?}"))?;
            match k {
                "sni" => sni = Some(v.to_string()),
                "sid" if v.is_empty() => {}
                "sid" => short_id = hex::decode(v).context("uri sid hex")?,
                "fp" => server_fp = Some(parse_fixed_32(v).context("uri fp")?),
                _ => {} // ignore unknown keys (forward-compat)
            }
        }
        if short_id.len() > 8 {
            anyhow::bail!("uri sid must be ≤ 8 bytes, got {}", short_id.len());
        }
        // Default SNI to the host (sans :port) when not given.
        let sni = sni.unwrap_or_else(|| {
            host.rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| host.clone())
        });
        let server_fp = server_fp.ok_or_else(|| {
            anyhow::anyhow!("shadowpipe URI requires fp=<64-hex ML-KEM server fingerprint>")
        })?;
        Ok(Self {
            host,
            pubkey,
            sni,
            short_id,
            server_fp,
        })
    }

    /// Render this descriptor as a `shadowpipe://…` URI (round-trips with [`parse`]).
    pub fn to_uri(&self) -> String {
        format!(
            "{}{}@{}?sni={}&sid={}&fp={}",
            URI_SCHEME,
            hex::encode(self.pubkey),
            self.host,
            self.sni,
            hex::encode(&self.short_id),
            hex::encode(self.server_fp),
        )
    }
}

/// Parse one or more `shadowpipe://` URIs from a string — entries separated by
/// commas, whitespace, or newlines (so `--uri "a,b"` and a multi-line list both
/// work). Empties are skipped; a malformed entry errors. Returns the pool in
/// order; the client rotates through it on connect/handshake failure (anti-IP-block
/// — a pool of cheap endpoints, since CDN-fronting is dead in RU).
pub fn parse_uri_list(s: &str) -> Result<Vec<RealityUri>> {
    let mut out = Vec::new();
    for tok in s.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        out.push(RealityUri::parse(tok)?);
    }
    Ok(out)
}

fn parse_fixed_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("decode 32-byte hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes (64 hex chars), got {}", bytes.len()))
}

/// Parse a server X25519 public key from 64 hex chars and reject encodings that
/// produce an all-zero shared secret. Generic 32-byte fingerprints and private
/// scalar encodings intentionally use [`parse_fixed_32`] instead.
pub fn parse_x25519_32(hex_str: &str) -> Result<[u8; 32]> {
    let public_key = parse_fixed_32(hex_str)?;
    anyhow::ensure!(
        reality_public_key_is_contributory(&public_key),
        "non-contributory low-order X25519 public key"
    );
    Ok(public_key)
}

/// Reject X25519 encodings that collapse every clamped scalar onto the all-zero
/// shared secret. Length-only validation is insufficient for REALITY's static
/// authenticator because a low-order peer key makes its HMAC key public.
pub fn reality_public_key_is_contributory(public_key: &[u8; 32]) -> bool {
    x25519_dalek::x25519([0xa5; 32], *public_key) != [0u8; 32]
}

/// Generate a fresh REALITY X25519 static secret (the server's long-term key).
pub fn generate_static_secret() -> StaticSecret {
    StaticSecret::random_from_rng(rand::thread_rng())
}

/// Hex of the public half of a static secret — the value clients pass to
/// `--reality-pubkey`.
pub fn static_public_hex(sk: &StaticSecret) -> String {
    hex::encode(PublicKey::from(sk).to_bytes())
}

/// Crash-atomically replace a static secret with a same-directory, synced 0600
/// file. The final pathname is never opened for writing, so a symlink at that
/// path is replaced rather than followed. Unix also syncs the parent directory.
pub fn save_static_secret(path: &std::path::Path, sk: &StaticSecret) -> Result<()> {
    let encoded = Zeroizing::new(hex::encode(sk.to_bytes()));
    atomic_write_private_file(path, encoded.as_bytes())
}

fn load_static_secret(path: &std::path::Path) -> Result<StaticSecret> {
    let encoded = read_private_file_to_string(path)?;
    Ok(StaticSecret::from(parse_fixed_32(encoded.trim())?))
}

/// Load the REALITY X25519 static secret, or create it without clobbering a
/// concurrent first-start winner. The fully synced 0600 temp is hard-linked at
/// the final name as the atomic publication point, matching ML-KEM identity
/// creation. A disappearing concurrent winner is retried with a fixed bound.
pub fn load_or_generate_static_secret(path: &std::path::Path) -> Result<StaticSecret> {
    match load_static_secret(path) {
        Ok(secret) => return Ok(secret),
        Err(error) if is_not_found(&error) => {}
        Err(error) => return Err(error),
    }

    let candidate = generate_static_secret();
    let encoded = Zeroizing::new(hex::encode(candidate.to_bytes()));
    for _ in 0..16 {
        match atomic_create_private_file(path, encoded.as_bytes())? {
            CreatePrivateFileOutcome::Created => return Ok(candidate),
            CreatePrivateFileOutcome::AlreadyExists => match load_static_secret(path) {
                Ok(winner) => return Ok(winner),
                Err(error) if is_not_found(&error) => continue,
                Err(error) => return Err(error),
            },
        }
    }
    anyhow::bail!(
        "REALITY private-key path kept disappearing during first-run generation: {}",
        path.display()
    )
}

const COVER_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const COVER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const COVER_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const COVER_WORKER_INTERNAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const COVER_WORKER_OUTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

fn cover_sni(cover: &str) -> Result<String> {
    let cover = cover.trim();
    let host = if let Some(bracketed) = cover.strip_prefix('[') {
        bracketed
            .split_once("]:")
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow::anyhow!("bracketed cover address must include :port"))?
    } else {
        cover
            .rsplit_once(':')
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow::anyhow!("cover address must be host:port"))?
    };
    anyhow::ensure!(!host.is_empty(), "cover host is empty");
    Ok(host.to_string())
}

fn bounded_unique_cover_addresses(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    let mut bounded = Vec::with_capacity(MAX_COVER_PROFILE_ADDRESSES);
    for address in addresses {
        if !bounded.contains(&address) {
            bounded.push(address);
            if bounded.len() == MAX_COVER_PROFILE_ADDRESSES {
                break;
            }
        }
    }
    bounded
}

/// Best-effort cover profiling for accepted-token-path mimicry (#9). Resolution
/// is asynchronous and monotonic-time-bounded before a strictly bounded set of
/// concrete addresses enters the blocking worker. That worker uses standard
/// `TcpStream::connect_timeout`, inactivity deadlines and an absolute deadline
/// while measuring cleartext TLS record framing.
///
/// Returns `None` (logged) if the cover can't be reached/measured in time — the
/// server still starts, just without flight mimicry. Timing out a Tokio
/// `spawn_blocking` join does **not** cancel its OS thread. Therefore the outer
/// deadline is only a startup wait bound; the worker's own shorter absolute and
/// per-socket deadlines are what guarantee the detached thread finishes soon.
/// Likewise, dropping a timed-out `lookup_host` future may not cancel an OS
/// resolver already running in Tokio's blocking pool, but startup no longer
/// waits for it and no resolved-address work is launched afterward.
pub async fn profile_cover_best_effort(cover: &str) -> Option<CoverProfile> {
    let addr = cover.to_string();
    let sni = match cover_sni(&addr) {
        Ok(sni) => sni,
        Err(error) => {
            tracing::warn!(%error, cover = %addr, "cover profiling rejected malformed authority");
            return None;
        }
    };
    let resolved =
        match tokio::time::timeout(COVER_RESOLVE_TIMEOUT, tokio::net::lookup_host(addr.clone()))
            .await
        {
            Ok(Ok(addresses)) => bounded_unique_cover_addresses(addresses),
            Ok(Err(error)) => {
                tracing::warn!(%error, cover = %addr, "cover profiling DNS resolution failed");
                return None;
            }
            Err(_) => {
                tracing::warn!(
                    cover = %addr,
                    timeout_ms = COVER_RESOLVE_TIMEOUT.as_millis() as u64,
                    "cover profiling DNS deadline expired; underlying OS lookup may finish later"
                );
                return None;
            }
        };
    if resolved.is_empty() {
        tracing::warn!(cover = %addr, "cover profiling DNS returned no addresses");
        return None;
    }
    let limits = CoverProfileLimits::new(
        COVER_CONNECT_TIMEOUT,
        COVER_IO_TIMEOUT,
        COVER_WORKER_INTERNAL_TIMEOUT,
    )
    .expect("constant cover-profile limits are valid");
    let probe = tokio::task::spawn_blocking(move || profile_cover(&resolved, &sni, limits));
    let probe = tokio::time::timeout(COVER_WORKER_OUTER_TIMEOUT, probe).await;
    match probe {
        Ok(Ok(Ok(p))) => {
            tracing::info!(
                cipher = format!("{:#06x}", p.cipher),
                flight_len = p.flight_len,
                records = p.record_lens.len(),
                "cover profiled — accepted-token carrier flight will mimic it"
            );
            Some(p)
        }
        Ok(Ok(Err(error))) => {
            tracing::warn!(%error, "cover profiling failed; accepted-token flight will not mimic the cover");
            None
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "cover profiling task failed");
            None
        }
        Err(_) => {
            tracing::warn!(
                outer_timeout_ms = COVER_WORKER_OUTER_TIMEOUT.as_millis() as u64,
                internal_timeout_ms = limits.overall_timeout().as_millis() as u64,
                "cover profiling outer deadline expired; blocking worker is detached but internally bounded"
            );
            None
        }
    }
}

/// Parse a list of REALITY short_ids (each hex, ≤8 bytes); blanks are skipped.
pub fn parse_short_ids(items: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for s in items {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let b = hex::decode(s).with_context(|| format!("decode short_id {s}"))?;
        if b.len() > 8 {
            anyhow::bail!(
                "short_id {s} must be ≤ 8 bytes (16 hex chars), got {}",
                b.len()
            );
        }
        out.push(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempSecretFile(std::path::PathBuf);

    impl TempSecretFile {
        fn new(label: &str) -> Self {
            let nonce: [u8; 8] = rand::random();
            Self(std::env::temp_dir().join(format!(
                "shadowpipe-reality-{label}-{}-{}.key",
                std::process::id(),
                hex::encode(nonce)
            )))
        }
    }

    impl Drop for TempSecretFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn static_secret_roundtrip_is_private_and_stable() {
        let path = TempSecretFile::new("roundtrip");
        let secret = generate_static_secret();
        let public = static_public_hex(&secret);
        save_static_secret(&path.0, &secret).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path.0).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            static_public_hex(&load_static_secret(&path.0).unwrap()),
            public
        );
    }

    #[test]
    fn concurrent_static_secret_generation_returns_one_identity() {
        use std::sync::{Arc, Barrier};

        let path = TempSecretFile::new("concurrent");
        let workers = 16;
        let barrier = Arc::new(Barrier::new(workers));
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let path = path.0.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    static_public_hex(&load_or_generate_static_secret(&path).unwrap())
                })
            })
            .collect();
        let identities: Vec<String> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert!(identities.iter().all(|identity| identity == &identities[0]));
        assert_eq!(
            static_public_hex(&load_static_secret(&path.0).unwrap()),
            identities[0]
        );
    }

    #[test]
    fn reality_uri_round_trips() {
        let u = RealityUri {
            host: "vpn.example.com:443".into(),
            pubkey: [0x11; 32],
            sni: "www.microsoft.com".into(),
            short_id: vec![0xab, 0xcd],
            server_fp: [0x22; 32],
        };
        let parsed = RealityUri::parse(&u.to_uri()).unwrap();
        assert_eq!(parsed, u, "to_uri → parse is identity");
    }

    #[test]
    fn reality_uri_parses_a_hand_written_string() {
        let pk = "11".repeat(32);
        let fp = "22".repeat(32);
        let s = format!("shadowpipe://{pk}@1.2.3.4:8443?sni=cdn.example.net&sid=ab&fp={fp}");
        let u = RealityUri::parse(&s).unwrap();
        assert_eq!(u.host, "1.2.3.4:8443");
        assert_eq!(u.pubkey, [0x11; 32]);
        assert_eq!(u.sni, "cdn.example.net");
        assert_eq!(u.short_id, vec![0xab]);
        assert_eq!(u.server_fp, [0x22; 32]);
    }

    #[test]
    fn reality_uri_requires_fp_before_use() {
        let pk = "33".repeat(32);
        let err = RealityUri::parse(&format!("shadowpipe://{pk}@host.tld:443"))
            .expect_err("an unpinned URI must be rejected");
        assert!(err.to_string().contains("requires fp="));
        let u = RealityUri::parse(&format!(
            "shadowpipe://{pk}@host.tld:443?fp={}",
            "44".repeat(32)
        ))
        .unwrap();
        assert_eq!(u.sni, "host.tld", "sni defaults to host sans :port");
        assert!(u.short_id.is_empty());
        assert_eq!(u.server_fp, [0x44; 32]);
    }

    #[test]
    fn reality_uri_list_parses_comma_and_newline_separated() {
        let pk = "11".repeat(32);
        let fp = "22".repeat(32);
        let s = format!(
            "shadowpipe://{pk}@1.1.1.1:443?sni=a.com&fp={fp}\n shadowpipe://{pk}@2.2.2.2:8443?sni=b.com&fp={fp} , shadowpipe://{pk}@3.3.3.3:9443?fp={fp}"
        );
        let pool = parse_uri_list(&s).unwrap();
        assert_eq!(pool.len(), 3, "comma + whitespace + newline all split");
        assert_eq!(pool[0].host, "1.1.1.1:443");
        assert_eq!(pool[1].host, "2.2.2.2:8443");
        assert_eq!(
            pool[2].sni, "3.3.3.3",
            "no-query entry defaults sni to host"
        );
        assert!(
            parse_uri_list("   \n  ").unwrap().is_empty(),
            "blank list is empty"
        );
        assert!(
            parse_uri_list(&format!("{s} , https://nope")).is_err(),
            "a malformed entry fails the whole list"
        );
    }

    #[test]
    fn reality_uri_rejects_garbage() {
        assert!(
            RealityUri::parse("https://example.com").is_err(),
            "wrong scheme"
        );
        assert!(
            RealityUri::parse("shadowpipe://deadbeef@host:443").is_err(),
            "short pubkey"
        );
        let pk = "44".repeat(32);
        assert!(
            RealityUri::parse(&format!("shadowpipe://{pk}")).is_err(),
            "missing @host"
        );
        assert!(
            RealityUri::parse(&format!("shadowpipe://{pk}@host:443?sid=zz")).is_err(),
            "non-hex sid"
        );
    }

    #[test]
    fn reality_public_parser_and_uri_reject_low_order_keys_but_fingerprint_is_opaque() {
        let fingerprint = "00".repeat(32);
        let good_public = "11".repeat(32);
        let mut one = [0u8; 32];
        one[0] = 1;
        for low_order in [[0u8; 32], one] {
            let encoded = hex::encode(low_order);
            assert!(parse_x25519_32(&encoded).is_err());
            assert!(
                RealityUri::parse(&format!(
                    "shadowpipe://{encoded}@host:443?sid={}&fp={fingerprint}",
                    "11".repeat(8)
                ))
                .is_err(),
                "URI accepted a non-contributory REALITY public key"
            );
        }
        let parsed = RealityUri::parse(&format!(
            "shadowpipe://{good_public}@host:443?sid={}&fp={fingerprint}",
            "11".repeat(8)
        ))
        .expect("an all-zero fingerprint is opaque data, not an X25519 key");
        assert_eq!(parsed.server_fp, [0u8; 32]);
    }

    #[test]
    fn cover_authority_parsing_handles_dns_and_bracketed_ipv6() {
        assert_eq!(cover_sni("cover.example:443").unwrap(), "cover.example");
        assert_eq!(cover_sni("[::1]:443").unwrap(), "::1");
        assert!(cover_sni("cover-without-port").is_err());
        assert!(cover_sni("[]:443").is_err());
    }

    #[test]
    fn resolved_cover_addresses_are_deduplicated_and_hard_bounded() {
        let addresses = (1..=32).flat_map(|port| {
            let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            [address, address]
        });
        let bounded = bounded_unique_cover_addresses(addresses);
        assert_eq!(bounded.len(), MAX_COVER_PROFILE_ADDRESSES);
        assert_eq!(bounded[0], "127.0.0.1:1".parse().unwrap());
        assert_eq!(bounded[7], "127.0.0.1:8".parse().unwrap());
    }

    #[tokio::test]
    async fn malformed_cover_authority_fails_best_effort_without_lookup() {
        assert!(profile_cover_best_effort("missing-port").await.is_none());
    }

    #[tokio::test]
    async fn best_effort_profile_integrates_bounded_lookup_and_worker() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cover = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut client_hello = [0u8; 2048];
            let _ = socket.read(&mut client_hello).unwrap();

            // Minimal parseable TLS ServerHello record. The profiler needs only
            // cleartext framing, the handshake type, session-id length and suite.
            let mut message = vec![0x02, 0, 0, 40, 0x03, 0x03];
            message.extend_from_slice(&[7u8; 32]);
            message.push(0); // legacy_session_id_echo length
            message.extend_from_slice(&0x1301u16.to_be_bytes());
            message.push(0); // legacy_compression_method
            message.extend_from_slice(&0u16.to_be_bytes()); // extensions length
            let mut record = vec![0x16, 0x03, 0x03];
            record.extend_from_slice(&(message.len() as u16).to_be_bytes());
            record.extend_from_slice(&message);
            socket.write_all(&record).unwrap();
        });

        let profile = profile_cover_best_effort(&format!("127.0.0.1:{port}"))
            .await
            .expect("loopback cover should profile");
        assert_eq!(profile.cipher, 0x1301);
        assert_eq!(profile.record_lens, vec![49]);
        cover.join().unwrap();
    }
}
