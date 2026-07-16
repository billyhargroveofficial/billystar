//! QUIC carrier (Hysteria2-class) — off-by-default `quic` cargo feature.
//!
//! A UDP/QUIC transport that carries the post-quantum [`AuthenticatedSession`] + tunnel
//! inside a single bidirectional stream, exactly as `--tls`/`--reality` carry it
//! over TCP. Structurally:
//!
//! ```text
//!   quinn QUIC (UDP) ── one bi-stream ──> AuthenticatedSession (v3 hybrid auth) ──> tunnel
//! ```
//!
//! Trust model: the QUIC TLS 1.3 handshake authentication is **intentionally
//! skipped** (a custom accept-any certificate verifier on the client, an
//! ephemeral self-signed cert on the server) — exactly like the `--tls`
//! carrier. The real peer authentication is the inner ML-KEM `--server-fp` pin
//! inside the [`AuthenticatedSession`], not the QUIC cert. ALPN is `h3` on both sides
//! so the handshake blends with ordinary HTTP/3 rather than carrying a custom
//! tell.
//!
//! ⚠️ **Anti-DPI premise is NOT validated here.** The reason a QUIC carrier is
//! interesting in RU is that UDP/QUIC has historically traversed the TSPU
//! better than TCP-class TLS — but that is a *wire/DPI* property that can only
//! be confirmed on a real host on the censored path. These are loopback-correct
//! primitives; the on-the-wire stealth claim is unproven on the build machine
//! (same posture as the kill-switch).
//!
//! [`AuthenticatedSession`]: crate::session::AuthenticatedSession

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig,
    TransportConfig,
};
use rcgen::CertifiedKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// ALPN advertised on both ends. `h3` blends with legitimate HTTP/3 — a custom
/// token would itself be a trivial DPI fingerprint. Both sides MUST match or the
/// QUIC TLS handshake aborts with a no-application-protocol alert.
const ALPN_H3: &[u8] = b"h3";
/// Drop a silent connection after this long; keep-alive is set well below it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE: Duration = Duration::from_secs(10);

/// A QUIC bidirectional stream presented as one duplex byte channel.
///
/// Wraps `tokio::io::join(recv, send)` and — crucially — owns the [`Connection`]
/// (and, on the client, the [`Endpoint`]) as keep-alive guards: quinn closes a
/// `Connection` the instant its last handle drops, and dropping a client
/// `Endpoint` tears down its driver task, so losing either would silently kill
/// the carrier mid-session. Holding them here ties their lifetime to the stream.
///
/// `AsyncRead + AsyncWrite + Unpin + Send + 'static`, so the PQ
/// [`AuthenticatedSession`](crate::session::AuthenticatedSession) and
/// [`run_tunnel`](crate::tunnel::run_tunnel) ride inside it unchanged.
pub struct QuicStream {
    inner: tokio::io::Join<RecvStream, SendStream>,
    _conn: Connection,
    _endpoint: Option<Endpoint>,
}

impl QuicStream {
    /// A cloneable live path-feedback handle for the degradation pacer. quinn's
    /// `Connection` is itself a cheap `Clone` (an `Arc` inside), so this stays
    /// valid for the whole session even after the stream is consumed by
    /// `tokio::io::split`. Capture it in the caller BEFORE moving the stream into
    /// `run_tunnel_guarded` (the generic fn can no longer reach the concrete type).
    pub fn path_stats_handle(&self) -> QuicPathStats {
        QuicPathStats(self._conn.clone())
    }
}

/// Live QUIC path stats source for the pacer (`quinn::Connection::stats().path`).
pub struct QuicPathStats(Connection);

impl crate::pacing::PathStatsSource for QuicPathStats {
    fn sample(&self) -> crate::pacing::PathSample {
        let s = self.0.stats();
        // cwnd/rtt is the path's deliverable-rate estimate; the congestion window
        // already encodes loss/RTT degradation, so the pacer needs nothing else.
        crate::pacing::PathSample {
            rtt: s.path.rtt,
            cwnd: s.path.cwnd,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The ring `CryptoProvider`, built explicitly so we never depend on a
/// process-wide `install_default()` (which rustls 0.23's no-arg builders
/// otherwise require, panicking if absent). Pinned to ring to match quinn's
/// default provider and the `ring` already in the lock — never aws-lc-rs.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Shared transport tuning: idle timeout + keep-alive so an idle tunnel stays up.
fn transport_config() -> Result<Arc<TransportConfig>> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        IdleTimeout::try_from(IDLE_TIMEOUT).context("quic idle timeout")?,
    ));
    t.keep_alive_interval(Some(KEEPALIVE));
    Ok(Arc::new(t))
}

/// Accepts ANY server certificate. INSECURE by design: the QUIC cert is not the
/// trust anchor here — the inner ML-KEM pin is (see module docs). This mirrors
/// the canonical quinn `insecure_connection.rs` verifier. The signature checks
/// still run (via the ring provider's algorithms); only the certificate
/// chain/identity check is skipped.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(ring_provider()))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Dial a QUIC server, open one bidirectional stream, and return it as a duplex
/// byte channel. `server_name` is the QUIC TLS SNI (verification is skipped, so
/// any value works; pass the configured `--sni`).
///
/// The returned stream owns its connection + endpoint, so it is the sole handle
/// the caller needs to keep alive.
pub async fn quic_connect(addr: SocketAddr, server_name: &str) -> Result<QuicStream> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .context("rustls client protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN_H3.to_vec()];

    let quic_crypto = QuicClientConfig::try_from(crypto).context("build quic client crypto")?;
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(transport_config()?);

    // Bind an ephemeral local UDP port in the same family as the target.
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("static v6 bind")
    } else {
        "0.0.0.0:0".parse().expect("static v4 bind")
    };
    let mut endpoint = Endpoint::client(bind).context("bind quic client endpoint")?;
    endpoint.set_default_client_config(client_config);

    let connection: Connection = endpoint
        .connect(addr, server_name)
        .context("quic connect")?
        .await
        .context("quic handshake")?;
    // Mandatory v3 starts with the client's fixed-width access key id. The
    // client must therefore OPEN the stream: a QUIC stream does not materialize
    // at its peer until the opener transmits. Opening on the server would leave
    // the server waiting to read while the client waits in accept_bi forever.
    let (send, recv) = connection.open_bi().await.context("quic open_bi")?;
    Ok(QuicStream {
        inner: tokio::io::join(recv, send),
        _conn: connection,
        _endpoint: Some(endpoint),
    })
}

/// Build the server's rustls config: an ephemeral self-signed cert (the client
/// doesn't validate it — see module docs) + the matching ALPN.
fn server_crypto() -> Result<rustls::ServerConfig> {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("generate self-signed quic cert")?;
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut crypto = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .context("rustls server protocol versions")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("rustls server single cert")?;
    crypto.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(crypto)
}

/// A bound QUIC server endpoint. UDP, so it lives as its own listener task
/// alongside (not inside) the server's TCP accept loop.
pub struct QuicListener {
    endpoint: Endpoint,
}

impl QuicListener {
    /// Bind a QUIC server on `addr` (UDP). Uses an ephemeral self-signed cert.
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let crypto = server_crypto()?;
        let quic_crypto = QuicServerConfig::try_from(crypto).context("build quic server crypto")?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        server_config.transport_config(transport_config()?);
        let endpoint =
            Endpoint::server(server_config, addr).context("bind quic server endpoint")?;
        Ok(Self { endpoint })
    }

    /// The bound local address (useful when binding to port 0 in tests).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().context("quic local_addr")
    }

    /// Await the next incoming connection. Returns `None` when the endpoint is
    /// closed. The handshake itself is deferred to [`QuicConnecting::establish`]
    /// so the caller can run it in a spawned task and avoid head-of-line
    /// blocking the accept loop.
    pub async fn accept(&self) -> Option<QuicConnecting> {
        self.endpoint.accept().await.map(QuicConnecting)
    }
}

/// An accepted-but-not-yet-handshaken QUIC connection. Finish it with
/// [`establish`](Self::establish) inside a spawned task.
pub struct QuicConnecting(quinn::Incoming);

impl QuicConnecting {
    /// Complete the QUIC handshake and ACCEPT the bidirectional stream the
    /// session rides on. Mandatory v3 is client-first: the client's access-key
    /// id materializes the stream at this endpoint before inner authentication.
    pub async fn establish(self) -> Result<QuicStream> {
        let connection = self.0.await.context("quic accept handshake")?;
        let (send, recv) = connection.accept_bi().await.context("quic accept_bi")?;
        Ok(QuicStream {
            inner: tokio::io::join(recv, send),
            _conn: connection,
            // The endpoint is owned by the listener task; only the client side
            // needs to carry it as a guard.
            _endpoint: None,
        })
    }
}

/// Resolve a `host:port` (or `ip:port`) string to a `SocketAddr` for quinn,
/// which — unlike `TcpStream::connect` — needs a resolved address, not a string.
pub fn resolve_quic_addr(server: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    server
        .to_socket_addrs()
        .with_context(|| format!("resolve quic server address: {server}"))?
        .next()
        .ok_or_else(|| anyhow!("no address resolved for {server}"))
}
