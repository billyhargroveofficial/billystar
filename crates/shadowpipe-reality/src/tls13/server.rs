//! TLS 1.3 server handshake driver (RFC 8446 §4), the mirror of `client.rs`.
//!
//! Flow: read ClientHello → pick X25519 ephemeral, ECDHE → send ServerHello →
//! handshake secrets → send the encrypted flight (EncryptedExtensions,
//! Certificate, CertificateVerify, Finished) → read+verify the client Finished →
//! application secrets. The cipher suite is selected by the caller from the
//! three implemented TLS 1.3 suites; ECDHE remains X25519-only.
//!
//! The `cert_msg`/`certverify_msg` are supplied by the caller: for REALITY they
//! carry the HMAC-"signed" ephemeral leaf; here they are caller-built handshake
//! messages, kept generic so the REALITY server (next) just plugs in its own.

use super::client::{read_record, take_hs_msg};
use super::{derive_handshake, finished_verify_data, RecordCrypto, Suite, Transcript};
use crate::parse::{extract_client_hello_fields, HelloFields};
use crate::Writer;
use rand::RngCore;
use std::io::{self, Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};

fn err(m: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}

/// An established server-side TLS 1.3 connection.
pub struct ServerConnection<S> {
    stream: S,
    server_app: RecordCrypto,
    client_app: RecordCrypto,
}

/// Build a ServerHello record selecting the caller-provided TLS 1.3 cipher plus
/// X25519, echoing the client's legacy_session_id and advertising the server's
/// key_share.
pub(crate) fn build_server_hello(
    server_random: &[u8; 32],
    sid_echo: &[u8],
    server_pub: &[u8; 32],
    cipher: u16,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0x16);
    w.u16(0x0303);
    w.len16(|w| {
        w.u8(0x02); // ServerHello
        w.len24(|w| {
            w.u16(0x0303); // legacy_version
            w.raw(server_random);
            w.len8(|w| w.raw(sid_echo)); // legacy_session_id_echo
            w.u16(cipher);
            w.u8(0); // legacy_compression_method
            w.len16(|w| {
                // supported_versions: selected_version = TLS 1.3
                w.u16(0x002b);
                w.len16(|w| w.u16(0x0304));
                // key_share: server KeyShareEntry (X25519)
                w.u16(0x0033);
                w.len16(|w| {
                    w.u16(0x001d);
                    w.len16(|w| w.raw(server_pub));
                });
            });
        });
    });
    w.buf
}

/// Split the server's handshake flight into record-sized plaintext chunks. With
/// an empty `plan` the flight is one record (chunked only if it would exceed the
/// 16 KB TLS record limit). With a `plan` (per-record plaintext sizes derived from
/// the cover's measured records), the flight is chopped to resemble the cover's
/// record structure (#9). Every chunk is ≤ 16384 and the chunks concatenate back
/// to `flight`, so the transcript and Finished are unaffected by the split.
pub(crate) fn split_for_records<'a>(flight: &'a [u8], plan: &[usize]) -> Vec<&'a [u8]> {
    const MAX: usize = 16384;
    if plan.is_empty() {
        return if flight.is_empty() {
            vec![&flight[..0]]
        } else {
            flight.chunks(MAX).collect()
        };
    }
    let mut out = Vec::new();
    let mut off = 0;
    for &want in plan {
        if off >= flight.len() {
            break;
        }
        let take = want.clamp(1, MAX).min(flight.len() - off);
        out.push(&flight[off..off + take]);
        off += take;
    }
    // Flight longer than the plan ⇒ emit the remainder as more ≤MAX records.
    while off < flight.len() {
        let take = (flight.len() - off).min(MAX);
        out.push(&flight[off..off + take]);
        off += take;
    }
    out
}

/// Drive a full TLS 1.3 server handshake over `stream`, reading the ClientHello
/// itself. Thin wrapper over [`drive_server`] for callers that don't need to
/// inspect the ClientHello first (the REALITY accept path does — see
/// [`crate::reality`] — so it reads the record, gates on auth, then calls
/// `drive_server` directly).
pub fn server_handshake<S: Read + Write>(
    mut stream: S,
    cert_msg: &[u8],
    certverify_msg: &[u8],
) -> io::Result<ServerConnection<S>> {
    let (t, ch_rec) = read_record(&mut stream)?;
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
}

/// Drive a TLS 1.3 server handshake given an already-read ClientHello record
/// `ch_rec` and its parsed `f`ields. The TLS ECDHE here (server ephemeral ×
/// client key_share) is independent of any REALITY auth ECDH the caller did.
pub(crate) fn drive_server<S: Read + Write>(
    mut stream: S,
    ch_rec: &[u8],
    f: &HelloFields,
    cert_msg: &[u8],
    certverify_msg: &[u8],
    suite: Suite,
    record_plan: &[usize],
) -> io::Result<ServerConnection<S>> {
    let mut tr = Transcript::new(suite.hash());
    tr.update(&ch_rec[5..]);

    // Server ephemeral + ECDHE.
    let mut rng = rand::thread_rng();
    let server_eph = StaticSecret::random_from_rng(&mut rng);
    let server_pub = PublicKey::from(&server_eph).to_bytes();
    let shared = server_eph.diffie_hellman(&PublicKey::from(f.x25519_pub));
    if !shared.was_contributory() {
        return Err(err("non-contributory low-order client X25519 key share"));
    }
    let ecdhe = shared.to_bytes();

    // ServerHello.
    let mut server_random = [0u8; 32];
    rng.fill_bytes(&mut server_random);
    let sh = build_server_hello(&server_random, &f.session_id, &server_pub, suite.id());
    tr.update(&sh[5..]);
    stream.write_all(&sh)?;

    // Handshake secrets.
    let th_ch_sh = tr.hash();
    let hs = derive_handshake(&ecdhe, &th_ch_sh, suite.hash());
    let mut server_hs = RecordCrypto::new(&hs.server_hs_traffic, suite);

    // CCS (middlebox compat) then the encrypted flight, coalesced in one record.
    stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])?;
    let ee = [0x08u8, 0x00, 0x00, 0x02, 0x00, 0x00]; // EncryptedExtensions, empty
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
    // Split the flight into records tracking the cover's structure (#9). Boundaries
    // don't change the message bytes, so the transcript/Finished are unaffected.
    for chunk in split_for_records(&flight, record_plan) {
        let rec = server_hs.seal(0x16, chunk);
        stream.write_all(&rec)?;
    }
    stream.flush()?;
    tr.update(&sfin);

    // Application secrets over ClientHello..server Finished.
    let th_app = tr.hash();
    let (c_ap, s_ap) = hs.application_secrets(&th_app);

    // Read + verify the client Finished (under client handshake keys).
    let mut client_hs = RecordCrypto::new(&hs.client_hs_traffic, suite);
    let expected = finished_verify_data(&hs.client_hs_traffic, &th_app, suite.hash());
    loop {
        let (outer, rec) = read_record(&mut stream)?;
        match outer {
            0x14 => continue, // ChangeCipherSpec — ignore
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

    Ok(ServerConnection {
        stream,
        server_app: RecordCrypto::new(&s_ap, suite),
        client_app: RecordCrypto::new(&c_ap, suite),
    })
}

impl<S: Read + Write> ServerConnection<S> {
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let rec = self.server_app.seal(0x17, data);
        self.stream.write_all(&rec)?;
        self.stream.flush()
    }

    pub fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let (outer, rec) = read_record(&mut self.stream)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::{client_handshake, CertVerify};
    use crate::{build_client_hello, Grease, GREASE};
    use std::net::{TcpListener, TcpStream};

    /// A structurally valid (but un-trusted) Certificate handshake message; the
    /// client verifies via CertVerify::Skip here, so only its bytes (for the
    /// transcript) matter — exactly what the REALITY HMAC-leaf cert will replace.
    fn dummy_cert_msg() -> Vec<u8> {
        let leaf = [0xde, 0xad, 0xbe, 0xef];
        let mut list = Vec::new();
        list.extend_from_slice(&(leaf.len() as u32).to_be_bytes()[1..]); // cert_data<3>
        list.extend_from_slice(&leaf);
        list.extend_from_slice(&[0, 0]); // extensions<2>
        let mut body = vec![0x00]; // certificate_request_context<1> = empty
        body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]); // certificate_list<3>
        body.extend_from_slice(&list);
        let mut msg = vec![0x0b];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    fn dummy_certverify_msg() -> Vec<u8> {
        let sig = [0u8; 64];
        let mut body = vec![0x08, 0x07]; // ed25519
        body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        body.extend_from_slice(&sig);
        let mut msg = vec![0x0f];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn our_client_and_our_server_complete_a_handshake_and_exchange_data() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut conn =
                server_handshake(sock, &dummy_cert_msg(), &dummy_certverify_msg()).unwrap();
            let got = conn.recv().unwrap();
            let echoed: Vec<u8> = got.iter().rev().cloned().collect();
            conn.send(&echoed).unwrap();
        });

        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let g = Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        };
        let hello = build_client_hello("example.com", &random, &sid, &eph_pub, &g, 517);

        let tcp = TcpStream::connect(addr).unwrap();
        let mut conn = client_handshake(tcp, &hello, &eph, CertVerify::Skip).unwrap();
        conn.send(b"shadowpipe-reality").unwrap();
        let reply = conn.recv().unwrap();
        assert_eq!(reply, b"ytilaer-epipwodahs");
        server.join().unwrap();
    }

    #[test]
    fn blocking_client_rejects_low_order_server_key_shares() {
        let mut one = [0u8; 32];
        one[0] = 1;
        for low_order_public in [[0u8; 32], one] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let fake_server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (_, client_hello) = read_record(&mut stream).unwrap();
                let fields = extract_client_hello_fields(&client_hello).unwrap();
                let server_hello = build_server_hello(
                    &[0x33; 32],
                    &fields.session_id,
                    &low_order_public,
                    Suite::Aes128GcmSha256.id(),
                );
                stream.write_all(&server_hello).unwrap();
            });

            let mut rng = rand::thread_rng();
            let ephemeral = StaticSecret::random_from_rng(&mut rng);
            let hello = build_client_hello(
                "example.com",
                &[0x11; 32],
                &[0x22; 32],
                &PublicKey::from(&ephemeral).to_bytes(),
                &Grease {
                    cipher: GREASE[0],
                    group: GREASE[1],
                    ext_lead: GREASE[2],
                    version: GREASE[3],
                    ext_trail: GREASE[4],
                },
                517,
            );
            let stream = TcpStream::connect(addr).unwrap();
            let error = match client_handshake(stream, &hello, &ephemeral, CertVerify::Skip) {
                Err(error) => error,
                Ok(_) => panic!("blocking client accepted a low-order server key share"),
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("non-contributory"));
            fake_server.join().unwrap();
        }
    }

    #[test]
    fn blocking_server_rejects_low_order_client_key_shares() {
        let mut one = [0u8; 32];
        one[0] = 1;
        for low_order_public in [[0u8; 32], one] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                match server_handshake(stream, &dummy_cert_msg(), &dummy_certverify_msg()) {
                    Err(error) => error,
                    Ok(_) => panic!("blocking server accepted a low-order client key share"),
                }
            });
            let hello = build_client_hello(
                "example.com",
                &[0x11; 32],
                &[0x22; 32],
                &low_order_public,
                &Grease {
                    cipher: GREASE[0],
                    group: GREASE[1],
                    ext_lead: GREASE[2],
                    version: GREASE[3],
                    ext_trail: GREASE[4],
                },
                517,
            );
            let mut client = TcpStream::connect(addr).unwrap();
            client.write_all(&hello).unwrap();
            let error = server.join().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("non-contributory"));
        }
    }

    /// Our client and server complete a handshake on ChaCha20-Poly1305 (the server
    /// selects 0x1303; the client auto-negotiates from the ServerHello cipher).
    #[test]
    fn client_and_server_negotiate_chacha20() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (_t, ch) = read_record(&mut sock).unwrap();
            let f = extract_client_hello_fields(&ch).unwrap();
            let mut conn = drive_server(
                sock,
                &ch,
                &f,
                &dummy_cert_msg(),
                &dummy_certverify_msg(),
                Suite::ChaCha20Poly1305Sha256,
                &[],
            )
            .unwrap();
            let got = conn.recv().unwrap();
            let echoed: Vec<u8> = got.iter().rev().cloned().collect();
            conn.send(&echoed).unwrap();
        });

        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let g = Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        };
        let hello = build_client_hello("example.com", &random, &sid, &eph_pub, &g, 517);

        let tcp = TcpStream::connect(addr).unwrap();
        let mut conn = client_handshake(tcp, &hello, &eph, CertVerify::Skip).unwrap();
        conn.send(b"chacha-suite").unwrap();
        assert_eq!(conn.recv().unwrap(), b"etius-ahcahc");
        server.join().unwrap();
    }

    /// Full sync handshake on AES-256-GCM-SHA384: the server selects 0x1302 and the
    /// client auto-negotiates, exercising the whole SHA-384 key schedule + Finished.
    #[test]
    fn client_and_server_negotiate_aes256_sha384() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (_t, ch) = read_record(&mut sock).unwrap();
            let f = extract_client_hello_fields(&ch).unwrap();
            let mut conn = drive_server(
                sock,
                &ch,
                &f,
                &dummy_cert_msg(),
                &dummy_certverify_msg(),
                Suite::Aes256GcmSha384,
                &[],
            )
            .unwrap();
            let got = conn.recv().unwrap();
            let echoed: Vec<u8> = got.iter().rev().cloned().collect();
            conn.send(&echoed).unwrap();
        });

        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let g = Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        };
        let hello = build_client_hello("example.com", &random, &sid, &eph_pub, &g, 517);

        let tcp = TcpStream::connect(addr).unwrap();
        let mut conn = client_handshake(tcp, &hello, &eph, CertVerify::Skip).unwrap();
        conn.send(b"aes256-suite").unwrap();
        assert_eq!(conn.recv().unwrap(), b"etius-652sea");
        server.join().unwrap();
    }

    #[test]
    fn split_for_records_chops_to_plan_and_preserves_bytes() {
        let flight: Vec<u8> = (0..100u8).collect();
        // Empty plan → one record (small flight).
        let one = split_for_records(&flight, &[]);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0], &flight[..]);
        // A plan → chunks track it and concatenate back to the flight exactly.
        let parts = split_for_records(&flight, &[30, 40]);
        assert_eq!(parts.len(), 3, "30 + 40 + 30-byte remainder");
        assert_eq!(
            (parts[0].len(), parts[1].len(), parts[2].len()),
            (30, 40, 30)
        );
        assert_eq!(parts.concat(), flight, "split preserves every byte");
    }

    /// A flight chopped into several records (mimicking a cover's record structure,
    /// #9) still completes — the client reassembles across record boundaries.
    #[test]
    fn client_reassembles_a_split_server_flight() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (_t, ch) = read_record(&mut sock).unwrap();
            let f = extract_client_hello_fields(&ch).unwrap();
            let mut conn = drive_server(
                sock,
                &ch,
                &f,
                &dummy_cert_msg(),
                &dummy_certverify_msg(),
                Suite::Aes128GcmSha256,
                &[16, 16, 16, 16], // tiny plan → many records
            )
            .unwrap();
            let got = conn.recv().unwrap();
            let echoed: Vec<u8> = got.iter().rev().cloned().collect();
            conn.send(&echoed).unwrap();
        });

        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let g = Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        };
        let hello = build_client_hello("example.com", &random, &sid, &eph_pub, &g, 517);

        let tcp = TcpStream::connect(addr).unwrap();
        let mut conn = client_handshake(tcp, &hello, &eph, CertVerify::Skip).unwrap();
        conn.send(b"split-flight").unwrap();
        assert_eq!(conn.recv().unwrap(), b"thgilf-tilps");
        server.join().unwrap();
    }
}
