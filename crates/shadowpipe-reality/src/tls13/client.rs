//! TLS 1.3 client handshake driver (RFC 8446 §4), blocking over any `Read+Write`.
//!
//! Flow: send ClientHello → read ServerHello (parse key_share, cipher) → ECDHE →
//! handshake secrets → read+decrypt the server flight (EncryptedExtensions,
//! Certificate, CertificateVerify, Finished) → verify server Finished → send
//! client Finished → application secrets. Cipher suite TLS_AES_128_GCM_SHA256.
//!
//! Certificate trust is pluggable: `CertVerify::Skip` (interop tests against a
//! reference server) or — later — REALITY's HMAC-over-the-leaf-key check.

use super::{derive_handshake, finished_verify_data, RecordCrypto, Suite, Transcript};
use std::io::{self, Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};

/// How to treat the server's certificate.
pub enum CertVerify {
    /// Don't validate (interop testing against a reference TLS server).
    Skip,
    /// REALITY: require the server's CertificateVerify "signature" to equal
    /// `HMAC-SHA512(auth_key, leaf_pub)` — proof it holds the static secret. The
    /// `auth_key` is the one [`crate::build_authed_client_hello`] returned.
    RealityHmac([u8; 32]),
}

pub(crate) fn u24(b: &[u8], i: usize) -> Option<usize> {
    Some(u32::from_be_bytes([0, *b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?]) as usize)
}

/// Pull the 32-byte leaf "public key" (the first CertificateEntry's cert_data)
/// out of a TLS 1.3 Certificate message.
pub(crate) fn extract_leaf_pub(msg: &[u8]) -> Option<[u8; 32]> {
    // 0x0b len(3) | ctx_len(1) ctx | cert_list_len(3) | cert_data_len(3) cert_data ...
    let mut p = 4;
    let ctx_len = *msg.get(p)? as usize;
    p += 1 + ctx_len;
    let _list_len = u24(msg, p)?;
    p += 3;
    let cd_len = u24(msg, p)?;
    p += 3;
    msg.get(p..p + cd_len)?.try_into().ok()
}

/// Pull the signature bytes out of a TLS 1.3 CertificateVerify message.
pub(crate) fn extract_certverify_sig(msg: &[u8]) -> Option<Vec<u8>> {
    // 0x0f len(3) | algorithm(2) | sig_len(2) | signature
    let sig_len = u16::from_be_bytes([*msg.get(6)?, *msg.get(7)?]) as usize;
    msg.get(8..8 + sig_len).map(|s| s.to_vec())
}

/// An established TLS 1.3 connection: application-data send/recv over the
/// negotiated traffic keys.
pub struct ClientConnection<S> {
    stream: S,
    client_app: RecordCrypto,
    server_app: RecordCrypto,
}

fn err(m: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}

/// Read one TLS record; returns (outer content type, full record bytes incl. the
/// 5-byte header — the AEAD AAD needs it).
pub(crate) fn read_record<S: Read>(s: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr)?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut rec = vec![0u8; 5 + len];
    rec[..5].copy_from_slice(&hdr);
    s.read_exact(&mut rec[5..])?;
    Ok((hdr[0], rec))
}

/// Pull one complete handshake message (type + u24 len + body) off the front of
/// `buf`, returning (type, full message bytes, bytes consumed). None if partial.
pub(crate) fn take_hs_msg(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some((buf[0], buf[..4 + len].to_vec(), 4 + len))
}

/// Parse a ServerHello handshake message → (selected cipher, server X25519 pub).
pub(crate) fn parse_server_hello(msg: &[u8]) -> Option<(u16, [u8; 32])> {
    if *msg.first()? != 0x02 {
        return None;
    }
    let mut p = 4; // handshake type(1) + len(3)
    p += 2; // legacy_version
    p += 32; // random
    let sid_len = *msg.get(p)? as usize;
    p += 1 + sid_len;
    let cipher = u16::from_be_bytes([*msg.get(p)?, *msg.get(p + 1)?]);
    p += 2;
    p += 1; // legacy_compression_method
    let ext_len = u16::from_be_bytes([*msg.get(p)?, *msg.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = (p + ext_len).min(msg.len());
    let mut server_pub: Option<[u8; 32]> = None;
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([msg[p], msg[p + 1]]);
        let elen = u16::from_be_bytes([msg[p + 2], msg[p + 3]]) as usize;
        let ds = p + 4;
        let de = ds + elen;
        if de > msg.len() {
            return None;
        }
        if etype == 0x0033 && elen >= 4 {
            // server KeyShareEntry: group(2) key_exchange<2>
            let group = u16::from_be_bytes([msg[ds], msg[ds + 1]]);
            let klen = u16::from_be_bytes([msg[ds + 2], msg[ds + 3]]) as usize;
            if group == 0x001d && klen == 32 {
                server_pub = msg.get(ds + 4..ds + 4 + 32)?.try_into().ok();
            }
        }
        p = de;
    }
    Some((cipher, server_pub?))
}

/// Drive a full TLS 1.3 client handshake over `stream`. `hello_record` is the
/// ClientHello (full TLS record) built by `build_client_hello`, and `client_eph`
/// is the X25519 secret whose public is in that hello's key_share.
pub fn client_handshake<S: Read + Write>(
    mut stream: S,
    hello_record: &[u8],
    client_eph: &StaticSecret,
    verify: CertVerify,
) -> io::Result<ClientConnection<S>> {
    // The transcript hash uses the negotiated hash, which we only learn from the
    // ServerHello's cipher — so send the ClientHello, read the ServerHello, pick
    // the suite, THEN build the transcript and feed both messages in order.
    stream.write_all(hello_record)?;
    stream.flush()?;

    // ServerHello (plaintext handshake record).
    let (sh_outer, sh_rec) = read_record(&mut stream)?;
    if sh_outer != 0x16 {
        return Err(err("expected a ServerHello handshake record"));
    }
    let sh_msg = &sh_rec[5..];
    let (cipher, server_pub) = parse_server_hello(sh_msg).ok_or_else(|| err("bad ServerHello"))?;
    let suite =
        Suite::from_id(cipher).ok_or_else(|| err("server selected an unsupported cipher suite"))?;
    let hash = suite.hash();

    let mut tr = Transcript::new(hash);
    tr.update(&hello_record[5..]); // ClientHello body (handshake message, not record)
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
                break 'flight msg; // Finished — verify_data is its body (msg[4..])
            }
            // EncryptedExtensions / Certificate / CertificateVerify → transcript;
            // keep the Certificate + CertificateVerify for the REALITY HMAC check.
            if mtype == 0x0b {
                cert_msg = Some(msg.clone());
            } else if mtype == 0x0f {
                certverify_msg = Some(msg.clone());
            }
            tr.update(&msg);
            hs_buf.drain(..used);
        }
        let (outer, rec) = read_record(&mut stream)?;
        match outer {
            0x14 => continue, // ChangeCipherSpec (middlebox compat) — ignore
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

    // Verify the server Finished over transcript ClientHello..CertificateVerify.
    let th_before_fin = tr.hash();
    let expected = finished_verify_data(&hs.server_hs_traffic, &th_before_fin, hash);
    if server_fin_msg[4..] != expected[..] {
        return Err(err("server Finished verification failed"));
    }

    // REALITY server authentication: the CertificateVerify "signature" must be
    // HMAC-SHA512(auth_key, leaf_pub). Only a server holding the static secret
    // (so deriving the same auth_key) can produce it. (Skip = interop testing.)
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

    // Application secrets over ClientHello..server Finished.
    let th_app = tr.hash();
    let (c_ap, s_ap) = hs.application_secrets(&th_app);

    // Client CCS (compat) then client Finished under the client handshake key.
    stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])?;
    let mut client_hs = RecordCrypto::new(&hs.client_hs_traffic, suite);
    let cfin_vd = finished_verify_data(&hs.client_hs_traffic, &th_app, hash);
    let mut cfin_msg = vec![0x14, 0x00, 0x00, cfin_vd.len() as u8];
    cfin_msg.extend_from_slice(&cfin_vd);
    let rec = client_hs.seal(0x16, &cfin_msg);
    stream.write_all(&rec)?;
    stream.flush()?;

    Ok(ClientConnection {
        stream,
        client_app: RecordCrypto::new(&c_ap, suite),
        server_app: RecordCrypto::new(&s_ap, suite),
    })
}

impl<S: Read + Write> ClientConnection<S> {
    /// Send application data.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let rec = self.client_app.seal(0x17, data);
        self.stream.write_all(&rec)?;
        self.stream.flush()
    }

    /// Receive the next application-data payload, skipping post-handshake
    /// messages (NewSessionTicket, key update) that arrive under the app keys.
    pub fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let (outer, rec) = read_record(&mut self.stream)?;
            match outer {
                0x17 => {
                    let (ct, pt) = self
                        .server_app
                        .open(&rec)
                        .ok_or_else(|| err("decrypt application data"))?;
                    match ct {
                        0x17 => return Ok(pt), // application_data
                        0x16 => continue,      // NewSessionTicket / post-handshake — skip
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
