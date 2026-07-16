//! TLS-chrome transport: a BoringSSL front whose ClientHello matches a real
//! Chrome JA4 (`t13d1516h2_8daaf6152771_e5627efa2ab1`), so on the wire the
//! connection looks like genuine HTTPS instead of shadowpipe's own framing
//! (this is what subsumes the fake-h2 DPI tell, review H6).
//!
//! The shadowpipe PQ+AEAD protocol runs INSIDE this TLS stream. TLS here is pure
//! camouflage: the client does NOT verify the server certificate — authentication
//! is the ML-KEM static-key pin (review B1). The exact JA4 parity of this
//! connector is validated out-of-tree by `tools/ja4-gate` + `tools/boring-front`.

use anyhow::{anyhow, Context, Result};
use boring::pkey::PKey;
use boring::ssl::{
    SslAcceptor, SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use foreign_types::ForeignType; // brings `as_ptr` for Ssl / SslContext
use tokio::net::TcpStream;
use tokio_boring::SslStream;

// Chrome (TLS 1.3 era): 12 TLS1.2 ciphers; BoringSSL adds the 3 TLS1.3 suites
// => 15 total, matching Chrome's JA4_b 8daaf6152771.
const CHROME_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:\
AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

// h2 then http/1.1, wire-encoded (length-prefixed) for ALPN.
const ALPN_H2_HTTP11: &[u8] = b"\x02h2\x08http/1.1";

/// Bounded sink: writes the reconstructed certificate into BoringSSL's
/// pre-sized output buffer and refuses to spill past `uncompressed_len`, so a
/// malformed or oversized brotli stream can't overflow it (decompression-bomb
/// safe — we never allocate or write more than the peer's declared length).
struct CertSink<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl std::io::Write for CertSink<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let end = self
            .pos
            .checked_add(data.len())
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::WriteZero, "cert decompress overflow")
            })?;
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Decompress a brotli-compressed server certificate, exactly as Chrome does.
/// We advertise `compress_certificate: brotli` for JA4 parity, so to keep the
/// camouflage airtight we must actually honour it: a peer that replies with a
/// CompressedCertificate (e.g. a real HTTPS server, or an active TLS-MITM probe
/// fingerprinting the client) must get a completed handshake — not the
/// `CERT_DECOMPRESSION_FAILED` that a no-op stub produces and real Chrome never
/// would. Returns 1 on success, with `*out` owning a fresh CRYPTO_BUFFER.
unsafe extern "C" fn brotli_decompress(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut boring_sys::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> std::os::raw::c_int {
    if out.is_null() || in_.is_null() {
        return 0;
    }
    let mut data: *mut u8 = std::ptr::null_mut();
    let buf = boring_sys::CRYPTO_BUFFER_alloc(&mut data, uncompressed_len);
    if buf.is_null() || data.is_null() {
        return 0;
    }
    let input = std::slice::from_raw_parts(in_, in_len);
    let dst = std::slice::from_raw_parts_mut(data, uncompressed_len);
    let mut sink = CertSink { buf: dst, pos: 0 };
    let mut src = std::io::Cursor::new(input);
    // Must reconstruct EXACTLY uncompressed_len bytes (BoringSSL rejects a
    // length mismatch too, but we also fail closed here).
    match brotli::BrotliDecompress(&mut src, &mut sink) {
        Ok(()) if sink.pos == uncompressed_len => {
            *out = buf;
            1
        }
        _ => {
            boring_sys::CRYPTO_BUFFER_free(buf);
            0
        }
    }
}

fn chrome_builder() -> Result<SslConnectorBuilder> {
    let mut b = SslConnector::builder(SslMethod::tls())?;
    // Camouflage only — the ML-KEM pin authenticates the server (review B1).
    b.set_verify(SslVerifyMode::NONE);
    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_grease_enabled(true);
    b.set_cipher_list(CHROME_CIPHERS)?;
    b.set_sigalgs_list(CHROME_SIGALGS)?;
    b.set_curves_list("X25519:P-256:P-384")?;
    b.set_alpn_protos(ALPN_H2_HTTP11)?;
    b.enable_signed_cert_timestamps();
    b.enable_ocsp_stapling();
    // compress_certificate (0x001b) advertising brotli — not in boring's safe API.
    unsafe {
        boring_sys::SSL_CTX_add_cert_compression_alg(
            b.as_ptr(),
            boring_sys::TLSEXT_cert_compression_brotli as u16,
            None,                    // compress: a client only needs decompress
            Some(brotli_decompress), // decompress: real brotli, like Chrome
        );
    }
    Ok(b)
}

/// Open a Chrome-JA4 TLS connection to an already-connected `tcp`, sending `sni`
/// as the server name. The returned stream is the inside of the camouflage —
/// run the shadowpipe carrier/session over it.
pub async fn chrome_connect(tcp: TcpStream, sni: &str) -> Result<SslStream<TcpStream>> {
    let connector = chrome_builder()?.build();
    let config = connector.configure()?;
    let ssl = config.into_ssl(sni)?;
    // ALPS (application_settings, 0x4469) is per-connection; set before handshake.
    unsafe {
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            2,
            std::ptr::null(),
            0,
        );
    }
    tokio_boring::SslStreamBuilder::new(ssl, tcp)
        .connect()
        .await
        .map_err(|e| anyhow!("tls-chrome connect: {e}"))
}

/// Opaque server TLS acceptor (a boring `SslAcceptor` + its self-signed cert),
/// so callers don't have to name BoringSSL types. Build once, share across
/// connections.
pub struct TlsAcceptor(SslAcceptor);

/// Server acceptor with an ephemeral self-signed certificate. The client does
/// not verify it (TLS is camouflage; auth is the ML-KEM pin), and the cert is
/// generated per-process so it isn't a static cross-deployment fingerprint.
fn self_signed_acceptor_builder() -> Result<boring::ssl::SslAcceptorBuilder> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("rcgen self-signed cert")?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();
    let x509 = X509::from_der(&cert_der).context("load self-signed cert")?;
    let pkey = PKey::private_key_from_pkcs8(&key_der).context("load self-signed key")?;

    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    b.set_private_key(&pkey)?;
    b.set_certificate(&x509)?;
    b.check_private_key()?;
    b.set_alpn_protos(ALPN_H2_HTTP11)?;
    Ok(b)
}

pub fn self_signed_acceptor() -> Result<TlsAcceptor> {
    Ok(TlsAcceptor(self_signed_acceptor_builder()?.build()))
}

/// Terminate a TLS connection on an already-accepted `tcp`.
pub async fn accept(acceptor: &TlsAcceptor, tcp: TcpStream) -> Result<SslStream<TcpStream>> {
    tokio_boring::accept(&acceptor.0, tcp)
        .await
        .map_err(|e| anyhow!("tls accept: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The Chrome connector and the self-signed acceptor complete a real TLS
    /// handshake and exchange bytes end to end. (JA4 parity itself is validated
    /// by tools/ja4-gate + tools/boring-front, which share this exact config.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chrome_client_and_self_signed_server_roundtrip() {
        let acceptor = Arc::new(self_signed_acceptor().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let acc = Arc::clone(&acceptor);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept(&acc, tcp).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(&buf).await.unwrap();
            tls.flush().await.unwrap();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = chrome_connect(tcp, "example.com").await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = [0u8; 5];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"hello");
        server.await.unwrap();
    }

    /// Test-only: brotli-COMPRESS the server certificate into BoringSSL's CBB,
    /// so the server emits a CompressedCertificate the client must decompress.
    unsafe extern "C" fn test_brotli_compress(
        _ssl: *mut boring_sys::SSL,
        out: *mut boring_sys::CBB,
        in_: *const u8,
        in_len: usize,
    ) -> std::os::raw::c_int {
        let input = std::slice::from_raw_parts(in_, in_len);
        let mut compressed = Vec::new();
        {
            use std::io::Write;
            let mut w = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            if w.write_all(input).is_err() {
                return 0;
            }
        } // drop finalizes the brotli stream
        if boring_sys::CBB_add_bytes(out, compressed.as_ptr(), compressed.len()) == 1 {
            1
        } else {
            0
        }
    }

    /// A server that brotli-compresses its certificate (what an active TLS-MITM
    /// probe would do to fingerprint a fake Chrome). With the old no-op stub this
    /// handshake dies with CERT_DECOMPRESSION_FAILED — verified by reverting
    /// `brotli_decompress` to `0`. With real decompression it completes and the
    /// stream carries bytes end to end, exactly as a genuine Chrome would.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chrome_client_decompresses_brotli_compressed_certificate() {
        let b = self_signed_acceptor_builder().unwrap();
        unsafe {
            boring_sys::SSL_CTX_add_cert_compression_alg(
                b.as_ptr(),
                boring_sys::TLSEXT_cert_compression_brotli as u16,
                Some(test_brotli_compress), // server compresses its cert ...
                None,                       // ... and never needs to decompress
            );
        }
        let acceptor = Arc::new(TlsAcceptor(b.build()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let acc = Arc::clone(&acceptor);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept(&acc, tcp).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(&buf).await.unwrap();
            tls.flush().await.unwrap();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        // Must SUCCEED: the certificate arrives brotli-compressed, and the client
        // decompresses it the way Chrome does (the whole point of this change).
        let mut tls = chrome_connect(tcp, "example.com").await.unwrap();
        tls.write_all(b"world").await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = [0u8; 5];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");
        server.await.unwrap();
    }
}
