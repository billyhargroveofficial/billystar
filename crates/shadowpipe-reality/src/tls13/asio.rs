//! Async (tokio) TLS 1.3 handshake drivers — the `AsyncRead + AsyncWrite` twin of
//! `client.rs` / `server.rs`. The crypto core (key schedule, record layer,
//! Finished, ServerHello/Certificate parsing) is pure-compute and shared verbatim;
//! only the byte I/O differs (`read_exact().await` / `write_all().await`).
//!
//! Kept as a parallel implementation so the blocking path (standalone bins,
//! interop tests) stays untouched. A future cleanup could unify both behind a
//! sans-I/O handshake state machine; for now the duplication is deliberate and
//! low-risk.

use super::client::{
    extract_certverify_sig, extract_leaf_pub, parse_server_hello, take_hs_msg, CertVerify,
};
use super::server::{build_server_hello, split_for_records};
use super::{
    derive_handshake, finished_verify_data, RealityStream, RecordCrypto, Suite, Transcript,
};
use crate::parse::{extract_client_hello_fields, HelloFields};
use rand::RngCore;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

fn err(m: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}

/// Read one TLS record (header + body). Mirrors `client::read_record`, async.
pub(crate) async fn read_record<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut rec = vec![0u8; 5 + len];
    rec[..5].copy_from_slice(&hdr);
    s.read_exact(&mut rec[5..]).await?;
    Ok((hdr[0], rec))
}

// ---------------------------------------------------------------- client ----

/// Established async client connection (application-data send/recv).
pub struct AsyncClientConnection<S> {
    stream: S,
    client_app: RecordCrypto,
    server_app: RecordCrypto,
}

/// Drive a full TLS 1.3 client handshake over an async `stream`. Async mirror of
/// [`crate::tls13::client_handshake`].
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    hello_record: &[u8],
    client_eph: &StaticSecret,
    verify: CertVerify,
) -> io::Result<AsyncClientConnection<S>> {
    // The transcript hash uses the negotiated hash, only known from the
    // ServerHello cipher — send ClientHello, read ServerHello, pick the suite,
    // THEN build the transcript and feed both messages in order.
    stream.write_all(hello_record).await?;
    stream.flush().await?;

    // ServerHello.
    let (sh_outer, sh_rec) = read_record(&mut stream).await?;
    if sh_outer != 0x16 {
        return Err(err("expected a ServerHello handshake record"));
    }
    let sh_msg = &sh_rec[5..];
    let (cipher, server_pub) = parse_server_hello(sh_msg).ok_or_else(|| err("bad ServerHello"))?;
    let suite =
        Suite::from_id(cipher).ok_or_else(|| err("server selected an unsupported cipher suite"))?;
    let hash = suite.hash();

    let mut tr = Transcript::new(hash);
    tr.update(&hello_record[5..]);
    tr.update(sh_msg);

    // ECDHE → handshake secrets.
    let shared = client_eph.diffie_hellman(&PublicKey::from(server_pub));
    if !shared.was_contributory() {
        return Err(err("non-contributory low-order server X25519 key share"));
    }
    let ecdhe = shared.to_bytes();
    let th_ch_sh = tr.hash();
    let hs = derive_handshake(&ecdhe, &th_ch_sh, hash);
    let mut server_hs = RecordCrypto::new(&hs.server_hs_traffic, suite);

    // Read+decrypt the server flight, yielding the server Finished message.
    let mut hs_buf: Vec<u8> = Vec::new();
    let mut cert_msg: Option<Vec<u8>> = None;
    let mut certverify_msg: Option<Vec<u8>> = None;
    let server_fin_msg: Vec<u8> = 'flight: loop {
        while let Some((mtype, msg, used)) = take_hs_msg(&hs_buf) {
            if mtype == 0x14 {
                hs_buf.drain(..used);
                break 'flight msg;
            }
            if mtype == 0x0b {
                cert_msg = Some(msg.clone());
            } else if mtype == 0x0f {
                certverify_msg = Some(msg.clone());
            }
            tr.update(&msg);
            hs_buf.drain(..used);
        }
        let (outer, rec) = read_record(&mut stream).await?;
        match outer {
            0x14 => continue,
            0x17 => {
                let (ct, pt) = server_hs
                    .open(&rec)
                    .ok_or_else(|| err("decrypt server flight"))?;
                if ct != 0x16 {
                    return Err(err("non-handshake content in server flight"));
                }
                hs_buf.extend_from_slice(&pt);
            }
            0x15 => return Err(err("server sent a TLS alert during handshake")),
            _ => return Err(err("unexpected record type in server flight")),
        }
    };

    // Verify server Finished over ClientHello..CertificateVerify.
    let th_before_fin = tr.hash();
    let expected = finished_verify_data(&hs.server_hs_traffic, &th_before_fin, hash);
    if server_fin_msg[4..] != expected[..] {
        return Err(err("server Finished verification failed"));
    }

    // REALITY server authentication (HMAC over the leaf), if requested.
    if let CertVerify::RealityHmac(auth_key) = &verify {
        let cert = cert_msg
            .as_deref()
            .ok_or_else(|| err("REALITY: server sent no Certificate"))?;
        let cv = certverify_msg
            .as_deref()
            .ok_or_else(|| err("REALITY: server sent no CertificateVerify"))?;
        let leaf = extract_leaf_pub(cert).ok_or_else(|| err("REALITY: bad Certificate"))?;
        let sig =
            extract_certverify_sig(cv).ok_or_else(|| err("REALITY: bad CertificateVerify"))?;
        let expect = crate::auth::reality_cert_hmac(auth_key, &leaf);
        if sig.as_slice() != expect.as_slice() {
            return Err(err("REALITY: server HMAC mismatch — not the real server"));
        }
    }
    tr.update(&server_fin_msg);

    // Application secrets, then client CCS + client Finished.
    let th_app = tr.hash();
    let (c_ap, s_ap) = hs.application_secrets(&th_app);
    stream
        .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await?;
    let mut client_hs = RecordCrypto::new(&hs.client_hs_traffic, suite);
    let cfin_vd = finished_verify_data(&hs.client_hs_traffic, &th_app, hash);
    let mut cfin_msg = vec![0x14, 0x00, 0x00, cfin_vd.len() as u8];
    cfin_msg.extend_from_slice(&cfin_vd);
    let rec = client_hs.seal(0x16, &cfin_msg);
    stream.write_all(&rec).await?;
    stream.flush().await?;

    Ok(AsyncClientConnection {
        stream,
        client_app: RecordCrypto::new(&c_ap, suite),
        server_app: RecordCrypto::new(&s_ap, suite),
    })
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncClientConnection<S> {
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let rec = self.client_app.seal(0x17, data);
        self.stream.write_all(&rec).await?;
        self.stream.flush().await
    }

    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let (outer, rec) = read_record(&mut self.stream).await?;
            match outer {
                0x17 => {
                    let (ct, pt) = self
                        .server_app
                        .open(&rec)
                        .ok_or_else(|| err("decrypt application data"))?;
                    match ct {
                        0x17 => return Ok(pt),
                        0x16 => continue,
                        0x15 => return Err(err("server sent a TLS alert")),
                        _ => continue,
                    }
                }
                0x15 => return Err(err("server sent a plaintext alert")),
                _ => continue,
            }
        }
    }
}

impl<S> AsyncClientConnection<S> {
    /// Expose the established connection's application-data channel as a plain
    /// `AsyncRead + AsyncWrite` byte stream. The client seals outbound data with
    /// `client_app` and opens inbound records with `server_app`.
    pub fn into_stream(self) -> RealityStream<S> {
        RealityStream::new(self.stream, self.client_app, self.server_app)
    }
}

// ---------------------------------------------------------------- server ----

/// Established async server connection.
pub struct AsyncServerConnection<S> {
    stream: S,
    server_app: RecordCrypto,
    client_app: RecordCrypto,
}

/// Drive a TLS 1.3 server handshake reading the ClientHello itself. Async mirror
/// of [`crate::tls13::server_handshake`].
pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    cert_msg: &[u8],
    certverify_msg: &[u8],
) -> io::Result<AsyncServerConnection<S>> {
    let (t, ch_rec) = read_record(&mut stream).await?;
    if t != 0x16 {
        return Err(err("expected a ClientHello record"));
    }
    let f = extract_client_hello_fields(&ch_rec).ok_or_else(|| err("parse ClientHello"))?;
    drive_server(
        stream,
        &ch_rec,
        &f,
        cert_msg,
        certverify_msg,
        Suite::Aes128GcmSha256,
        &[],
    )
    .await
}

/// Async mirror of [`crate::tls13::server::drive_server`] — handshake given an
/// already-read ClientHello.
pub(crate) async fn drive_server<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    ch_rec: &[u8],
    f: &HelloFields,
    cert_msg: &[u8],
    certverify_msg: &[u8],
    suite: Suite,
    record_plan: &[usize],
) -> io::Result<AsyncServerConnection<S>> {
    let mut tr = Transcript::new(suite.hash());
    tr.update(&ch_rec[5..]);

    // Server ephemeral + ServerHello random, generated in a tight scope so the
    // (!Send) ThreadRng is dropped before any await — keeping the future Send for
    // tokio::spawn.
    let (server_eph, server_random) = {
        let mut rng = rand::thread_rng();
        let eph = StaticSecret::random_from_rng(&mut rng);
        let mut sr = [0u8; 32];
        rng.fill_bytes(&mut sr);
        (eph, sr)
    };
    let server_pub = PublicKey::from(&server_eph).to_bytes();
    let shared = server_eph.diffie_hellman(&PublicKey::from(f.x25519_pub));
    if !shared.was_contributory() {
        return Err(err("non-contributory low-order client X25519 key share"));
    }
    let ecdhe = shared.to_bytes();

    // ServerHello.
    let sh = build_server_hello(&server_random, &f.session_id, &server_pub, suite.id());
    tr.update(&sh[5..]);
    stream.write_all(&sh).await?;

    // Handshake secrets.
    let th_ch_sh = tr.hash();
    let hs = derive_handshake(&ecdhe, &th_ch_sh, suite.hash());
    let mut server_hs = RecordCrypto::new(&hs.server_hs_traffic, suite);

    // CCS then the encrypted flight (EE + Certificate + CertificateVerify + Finished).
    stream
        .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await?;
    let ee = [0x08u8, 0x00, 0x00, 0x02, 0x00, 0x00];
    tr.update(&ee);
    tr.update(cert_msg);
    tr.update(certverify_msg);
    let th_before_fin = tr.hash();
    let sfin_vd = finished_verify_data(&hs.server_hs_traffic, &th_before_fin, suite.hash());
    let mut sfin = vec![0x14, 0x00, 0x00, sfin_vd.len() as u8];
    sfin.extend_from_slice(&sfin_vd);

    let mut flight = Vec::new();
    flight.extend_from_slice(&ee);
    flight.extend_from_slice(cert_msg);
    flight.extend_from_slice(certverify_msg);
    flight.extend_from_slice(&sfin);
    // Split the flight into records tracking the cover's structure (#9); record
    // boundaries don't change message bytes, so the transcript/Finished hold.
    for chunk in split_for_records(&flight, record_plan) {
        let rec = server_hs.seal(0x16, chunk);
        stream.write_all(&rec).await?;
    }
    stream.flush().await?;
    tr.update(&sfin);

    // Application secrets over ClientHello..server Finished.
    let th_app = tr.hash();
    let (c_ap, s_ap) = hs.application_secrets(&th_app);

    // Read + verify the client Finished.
    let mut client_hs = RecordCrypto::new(&hs.client_hs_traffic, suite);
    let expected = finished_verify_data(&hs.client_hs_traffic, &th_app, suite.hash());
    loop {
        let (outer, rec) = read_record(&mut stream).await?;
        match outer {
            0x14 => continue,
            0x17 => {
                let (ct, pt) = client_hs
                    .open(&rec)
                    .ok_or_else(|| err("decrypt client Finished"))?;
                if ct != 0x16 {
                    return Err(err("expected client handshake content"));
                }
                let (mtype, msg, _) =
                    take_hs_msg(&pt).ok_or_else(|| err("partial client Finished"))?;
                if mtype != 0x14 {
                    return Err(err("expected Finished"));
                }
                if msg[4..] != expected[..] {
                    return Err(err("client Finished verification failed"));
                }
                break;
            }
            0x15 => return Err(err("client sent a TLS alert")),
            _ => return Err(err("unexpected record from client")),
        }
    }

    Ok(AsyncServerConnection {
        stream,
        server_app: RecordCrypto::new(&s_ap, suite),
        client_app: RecordCrypto::new(&c_ap, suite),
    })
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncServerConnection<S> {
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let rec = self.server_app.seal(0x17, data);
        self.stream.write_all(&rec).await?;
        self.stream.flush().await
    }

    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let (outer, rec) = read_record(&mut self.stream).await?;
            match outer {
                0x17 => {
                    let (ct, pt) = self
                        .client_app
                        .open(&rec)
                        .ok_or_else(|| err("decrypt application data"))?;
                    match ct {
                        0x17 => return Ok(pt),
                        0x16 => continue,
                        0x15 => return Err(err("client sent a TLS alert")),
                        _ => continue,
                    }
                }
                0x15 => return Err(err("client sent a plaintext alert")),
                _ => continue,
            }
        }
    }
}

impl<S> AsyncServerConnection<S> {
    /// Expose the established connection's application-data channel as a plain
    /// `AsyncRead + AsyncWrite` byte stream. The server seals outbound data with
    /// `server_app` and opens inbound records with `client_app`.
    pub fn into_stream(self) -> RealityStream<S> {
        RealityStream::new(self.stream, self.server_app, self.client_app)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_client_hello, Grease, GREASE};

    fn grease() -> Grease {
        Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        }
    }

    #[tokio::test]
    async fn async_client_rejects_low_order_server_key_shares() {
        let mut one = [0u8; 32];
        one[0] = 1;
        for low_order_public in [[0u8; 32], one] {
            let (client_io, mut fake_server_io) = tokio::io::duplex(4096);
            let fake_server = tokio::spawn(async move {
                let (_, client_hello) = read_record(&mut fake_server_io).await.unwrap();
                let fields = extract_client_hello_fields(&client_hello).unwrap();
                let server_hello = build_server_hello(
                    &[0x33; 32],
                    &fields.session_id,
                    &low_order_public,
                    Suite::Aes128GcmSha256.id(),
                );
                fake_server_io.write_all(&server_hello).await.unwrap();
            });
            let ephemeral = StaticSecret::from([0x42; 32]);
            let hello = build_client_hello(
                "example.com",
                &[0x11; 32],
                &[0x22; 32],
                &PublicKey::from(&ephemeral).to_bytes(),
                &grease(),
                517,
            );
            let error =
                match client_handshake(client_io, &hello, &ephemeral, CertVerify::Skip).await {
                    Err(error) => error,
                    Ok(_) => panic!("async client accepted a low-order server key share"),
                };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("non-contributory"));
            fake_server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn async_server_rejects_low_order_client_key_shares() {
        let mut one = [0u8; 32];
        one[0] = 1;
        for low_order_public in [[0u8; 32], one] {
            let (mut client_io, server_io) = tokio::io::duplex(4096);
            let hello = build_client_hello(
                "example.com",
                &[0x11; 32],
                &[0x22; 32],
                &low_order_public,
                &grease(),
                517,
            );
            client_io.write_all(&hello).await.unwrap();
            let error = match server_handshake(server_io, &[], &[]).await {
                Err(error) => error,
                Ok(_) => panic!("async server accepted a low-order client key share"),
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("non-contributory"));
        }
    }
}
