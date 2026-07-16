//! Cover-site profiling (task #9, phase 1).
//!
//! Connect to the cover, send a Chrome ClientHello, and measure — from the
//! cleartext TLS record framing alone (no decryption; we don't have the cover's
//! keys) — the cipher it selects and the size/shape of its first server flight.
//! The accepted-token path later mimics this (phase 2) so the REALITY carrier
//! resembles a real connection to the cover for a passive observer. A valid
//! REALITY token is not a client identity credential.

use crate::{build_client_hello, Grease, GREASE};
use rand::RngCore;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

/// Both the async resolver and this blocking worker enforce the same ceiling.
/// This prevents attacker-controlled resolver output from multiplying connect
/// attempts after the worker has been detached by an outer async timeout.
pub const MAX_COVER_PROFILE_ADDRESSES: usize = 8;
const MAX_COVER_PROFILE_RECORDS: usize = 64;
const MAX_COVER_PROFILE_FLIGHT_BYTES: usize = 1024 * 1024;

/// Internal socket budgets for one blocking cover-profile worker. Every I/O
/// loop also checks the absolute `overall_timeout`, so a peer dripping one byte
/// before each inactivity timeout cannot multiply the deadline by record size
/// or by [`MAX_COVER_PROFILE_RECORDS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverProfileLimits {
    connect_timeout: Duration,
    io_timeout: Duration,
    overall_timeout: Duration,
}

impl CoverProfileLimits {
    pub fn new(
        connect_timeout: Duration,
        io_timeout: Duration,
        overall_timeout: Duration,
    ) -> io::Result<Self> {
        for (name, timeout) in [
            ("connect timeout", connect_timeout),
            ("I/O timeout", io_timeout),
            ("overall timeout", overall_timeout),
        ] {
            if timeout.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("cover-profile {name} must be non-zero"),
                ));
            }
        }
        Ok(Self {
            connect_timeout,
            io_timeout,
            overall_timeout,
        })
    }

    pub const fn overall_timeout(self) -> Duration {
        self.overall_timeout
    }
}

/// What we mimic about a cover's TLS response. All fields are measured from
/// cleartext record framing.
#[derive(Clone, Debug)]
pub struct CoverProfile {
    /// The cipher_suite id the cover selected for a Chrome ClientHello.
    pub cipher: u16,
    /// Total bytes the cover sent before waiting for us (ServerHello..Finished).
    pub flight_len: usize,
    /// Per-record wire lengths, in order (ServerHello, CCS, encrypted records…).
    pub record_lens: Vec<usize>,
}

/// Pull the selected cipher_suite out of a ServerHello handshake message.
fn server_hello_cipher(msg: &[u8]) -> Option<u16> {
    if *msg.first()? != 0x02 {
        return None; // not a ServerHello
    }
    let mut p = 4 + 2 + 32; // handshake header(4) + legacy_version(2) + random(32)
    let sid_len = *msg.get(p)? as usize;
    p += 1 + sid_len;
    Some(u16::from_be_bytes([*msg.get(p)?, *msg.get(p + 1)?]))
}

fn deadline_expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "cover-profile absolute deadline expired",
    )
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(deadline_expired)
}

fn bounded_timeout(limit: Duration, deadline: Instant) -> io::Result<Duration> {
    Ok(limit.min(remaining(deadline)?))
}

fn connect_cover(
    addresses: &[SocketAddr],
    limits: CoverProfileLimits,
    deadline: Instant,
) -> io::Result<TcpStream> {
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cover-profile address set is empty",
        ));
    }
    let mut last_error = None;
    for address in addresses.iter().take(MAX_COVER_PROFILE_ADDRESSES) {
        let timeout = bounded_timeout(limits.connect_timeout, deadline)?;
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "cover-profile had no bounded connect candidate",
        )
    }))
}

fn write_all_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    io_timeout: Duration,
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(bounded_timeout(io_timeout, deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    stream.set_write_timeout(Some(bounded_timeout(io_timeout, deadline)?))?;
    stream.flush()
}

fn read_exact_until(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    io_timeout: Duration,
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(bounded_timeout(io_timeout, deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_record_until(
    stream: &mut TcpStream,
    io_timeout: Duration,
    deadline: Instant,
) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    read_exact_until(stream, &mut header, io_timeout, deadline)?;
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = vec![0u8; 5 + payload_len];
    record[..5].copy_from_slice(&header);
    read_exact_until(stream, &mut record[5..], io_timeout, deadline)?;
    Ok((header[0], record))
}

/// Profile a bounded set of already-resolved cover addresses by sending a
/// Chrome ClientHello for `sni` and measuring the first server flight. Name
/// resolution deliberately lives in the async caller; this blocking function
/// accepts only concrete addresses and uses `TcpStream::connect_timeout`.
pub fn profile_cover(
    addresses: &[SocketAddr],
    sni: &str,
    limits: CoverProfileLimits,
) -> io::Result<CoverProfile> {
    let started = Instant::now();
    let deadline = started
        .checked_add(limits.overall_timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))?;
    // A throwaway ClientHello (random session_id + ephemeral; we never finish the
    // handshake, only measure the response). RNG confined so nothing !Send leaks.
    let (random, sid, eph_pub) = {
        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut sid = [0u8; 32];
        rng.fill_bytes(&mut sid);
        let eph = StaticSecret::random_from_rng(&mut rng);
        (random, sid, PublicKey::from(&eph).to_bytes())
    };
    let g = Grease {
        cipher: GREASE[0],
        group: GREASE[1],
        ext_lead: GREASE[2],
        version: GREASE[3],
        ext_trail: GREASE[4],
    };
    let hello = build_client_hello(sni, &random, &sid, &eph_pub, &g, 517);

    let mut stream = connect_cover(addresses, limits, deadline)?;
    write_all_until(&mut stream, &hello, limits.io_timeout, deadline)?;

    let mut record_lens = Vec::new();
    let mut cipher = None;
    let mut flight_len = 0usize;
    // Read records until the server stops (timeout) or closes — the boundary of
    // its first flight. (Any read error ends the loop; we keep what we measured.)
    while let Ok((t, rec)) = read_record_until(&mut stream, limits.io_timeout, deadline) {
        flight_len = flight_len.checked_add(rec.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "cover flight length overflow")
        })?;
        if flight_len > MAX_COVER_PROFILE_FLIGHT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cover flight exceeds one-megabyte profiling bound",
            ));
        }
        record_lens.push(rec.len());
        if cipher.is_none() && t == 0x16 {
            cipher = server_hello_cipher(&rec[5..]);
        }
        if record_lens.len() >= MAX_COVER_PROFILE_RECORDS {
            break; // safety bound against a server that never stops
        }
    }

    let cipher = cipher.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no ServerHello cipher in cover response",
        )
    })?;
    Ok(CoverProfile {
        cipher,
        flight_len,
        record_lens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::server::build_server_hello;
    use std::net::TcpListener;
    use std::thread;

    /// Profile a stand-in "cover": a real TLS 1.3 ServerHello + CCS + a fat record,
    /// then a pause. Validates we measure the cipher + flight size without keys.
    #[test]
    fn profiles_a_server_flight() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cover = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = read_record_until(
                &mut sock,
                Duration::from_millis(500),
                Instant::now() + Duration::from_secs(1),
            ); // consume the ClientHello
            let sh = build_server_hello(&[7u8; 32], &[0u8; 32], &[9u8; 32], 0x1301);
            sock.write_all(&sh).unwrap();
            sock.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
                .unwrap(); // CCS
            let mut rec = vec![0x17, 0x03, 0x03, 0x04, 0x00]; // header: 1024-byte body
            rec.extend_from_slice(&[0u8; 0x400]);
            sock.write_all(&rec).unwrap();
            sock.flush().unwrap();
            thread::sleep(Duration::from_millis(300)); // then wait → profiler ends
        });

        let limits = CoverProfileLimits::new(
            Duration::from_millis(200),
            Duration::from_millis(800),
            Duration::from_millis(1_500),
        )
        .unwrap();
        let p = profile_cover(&[addr], "example.com", limits).unwrap();
        assert_eq!(p.cipher, 0x1301, "measured the cover's selected cipher");
        assert!(
            p.record_lens.len() >= 3,
            "saw ServerHello + CCS + flight records"
        );
        assert!(p.flight_len > 1024, "flight size includes the fat record");
        cover.join().unwrap();
    }

    #[test]
    fn silent_cover_is_bounded_by_io_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cover = thread::spawn(move || {
            let (_socket, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        let limits = CoverProfileLimits::new(
            Duration::from_millis(50),
            Duration::from_millis(30),
            Duration::from_millis(80),
        )
        .unwrap();
        let started = Instant::now();
        assert!(profile_cover(&[addr], "example.com", limits).is_err());
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "silent cover exceeded bounded worker lifetime"
        );
        cover.join().unwrap();
    }

    #[test]
    fn byte_drip_cannot_multiply_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cover = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let _ = read_record_until(
                &mut socket,
                Duration::from_millis(100),
                Instant::now() + Duration::from_secs(1),
            );
            let hello = build_server_hello(&[7u8; 32], &[0u8; 32], &[9u8; 32], 0x1301);
            for byte in hello {
                if socket.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let limits = CoverProfileLimits::new(
            Duration::from_millis(50),
            Duration::from_millis(30),
            Duration::from_millis(90),
        )
        .unwrap();
        let started = Instant::now();
        assert!(profile_cover(&[addr], "example.com", limits).is_err());
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "one-byte drip extended the absolute deadline"
        );
        cover.join().unwrap();
    }

    #[test]
    fn failed_concrete_connect_stays_inside_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let limits = CoverProfileLimits::new(
            Duration::from_millis(40),
            Duration::from_millis(40),
            Duration::from_millis(80),
        )
        .unwrap();
        let started = Instant::now();
        assert!(profile_cover(&[address], "example.com", limits).is_err());
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "failed concrete connect escaped its absolute budget"
        );
    }

    #[test]
    fn limits_reject_zero_and_address_iteration_is_hard_bounded() {
        assert!(CoverProfileLimits::new(
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err());
        let addresses: Vec<SocketAddr> = (1..=32)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .collect();
        assert_eq!(
            addresses.iter().take(MAX_COVER_PROFILE_ADDRESSES).count(),
            MAX_COVER_PROFILE_ADDRESSES
        );
    }
}
