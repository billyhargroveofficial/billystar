//! Bounded DNS A resolver for live endpoint refresh.
//!
//! The socket is UDP-`connect`ed to one explicitly configured resolver, so the
//! kernel filters datagrams from every other source.  The parser additionally
//! validates transaction ID, QR/opcode, the sole question, all packet bounds,
//! and a bounded CNAME chain.  It returns locator observations only; callers
//! must intersect every address with a pre-verified endpoint authority before
//! changing a firewall or route.
//!
//! [`resolve_a`] starts with UDP and falls back to DNS-over-TCP at the exact
//! same resolver only after the UDP response has passed source, transaction,
//! opcode, question and structural validation and carries `TC=1`.  TCP uses
//! RFC-style two-byte length framing with bounded connect/write/read deadlines.

use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const DNS_HEADER_LEN: usize = 12;
const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_SOA: u16 = 6;
const QCLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const RCODE_MASK: u16 = 0x000f;
const MAX_POINTER_HOPS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDnsConfig {
    /// UDP response deadline.
    pub timeout: Duration,
    pub tcp_connect_timeout: Duration,
    pub tcp_write_timeout: Duration,
    /// Applied independently to the two-byte prefix and declared body.
    pub tcp_read_timeout: Duration,
    pub max_packet_size: usize,
    pub max_resource_records: usize,
    pub max_cname_depth: usize,
    pub max_addresses: usize,
    pub default_negative_ttl_secs: u32,
}

impl Default for EndpointDnsConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            tcp_connect_timeout: Duration::from_secs(3),
            tcp_write_timeout: Duration::from_secs(3),
            tcp_read_timeout: Duration::from_secs(3),
            // Classic UDP plus EDNS-sized answers, still tightly bounded.
            max_packet_size: 4_096,
            max_resource_records: 64,
            max_cname_depth: 8,
            max_addresses: 16,
            default_negative_ttl_secs: 30,
        }
    }
}

impl EndpointDnsConfig {
    fn validate(&self) -> Result<(), EndpointDnsError> {
        if self.timeout.is_zero()
            || self.tcp_connect_timeout.is_zero()
            || self.tcp_write_timeout.is_zero()
            || self.tcp_read_timeout.is_zero()
        {
            return Err(EndpointDnsError::Configuration(
                "all DNS timeouts must be non-zero".into(),
            ));
        }
        if !(512..=65_535).contains(&self.max_packet_size) {
            return Err(EndpointDnsError::Configuration(
                "DNS max_packet_size must be in 512..=65535".into(),
            ));
        }
        if self.max_resource_records == 0 || self.max_cname_depth == 0 || self.max_addresses == 0 {
            return Err(EndpointDnsError::Configuration(
                "DNS record, CNAME and address bounds must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedARecord {
    pub ip: Ipv4Addr,
    /// Minimum TTL across the CNAME path and this A RR.
    pub ttl_secs: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedDnsAnswer {
    Positive(Vec<ParsedARecord>),
    NxDomain {
        negative_ttl_secs: u32,
    },
    NoData {
        negative_ttl_secs: u32,
    },
    /// SERVFAIL, REFUSED, or another non-terminal RCODE.  The coordinator must
    /// retain last-known-good candidates and apply retry backoff.
    TransientRcode {
        rcode: u8,
    },
}

#[derive(Debug)]
pub enum EndpointDnsError {
    Configuration(String),
    InvalidQueryName(String),
    Io(io::Error),
    Timeout,
    TransactionMismatch {
        expected: u16,
        actual: u16,
    },
    QuestionMismatch,
    TcpFallbackRequired,
    ShortTcpFrame {
        section: TcpFrameSection,
        expected: usize,
        received: usize,
    },
    TcpFrameTooLarge {
        declared: usize,
        maximum: usize,
    },
    Malformed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpFrameSection {
    LengthPrefix,
    Body,
}

impl fmt::Display for EndpointDnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => {
                write!(f, "invalid endpoint DNS configuration: {message}")
            }
            Self::InvalidQueryName(message) => write!(f, "invalid endpoint DNS name: {message}"),
            Self::Io(error) => write!(f, "endpoint DNS I/O: {error}"),
            Self::Timeout => write!(f, "endpoint DNS query timed out"),
            Self::TransactionMismatch { expected, actual } => write!(
                f,
                "endpoint DNS transaction mismatch: expected {expected:#06x}, got {actual:#06x}"
            ),
            Self::QuestionMismatch => write!(f, "endpoint DNS response question mismatch"),
            Self::TcpFallbackRequired => {
                write!(
                    f,
                    "endpoint DNS response is truncated; bounded TCP fallback required"
                )
            }
            Self::ShortTcpFrame {
                section,
                expected,
                received,
            } => write!(
                f,
                "short endpoint DNS TCP {section:?}: expected {expected} bytes, received {received}"
            ),
            Self::TcpFrameTooLarge { declared, maximum } => write!(
                f,
                "endpoint DNS TCP frame declares {declared} bytes, maximum is {maximum}"
            ),
            Self::Malformed(message) => write!(f, "malformed endpoint DNS response: {message}"),
        }
    }
}

impl std::error::Error for EndpointDnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for EndpointDnsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Resolve one A RRset through one explicit resolver.  `connect` on a UDP
/// socket does not create a stream; it binds the peer and makes `recv` discard
/// spoofed datagrams from other source addresses/ports.
pub async fn resolve_a_connected(
    resolver: SocketAddr,
    qname: &str,
    config: &EndpointDnsConfig,
) -> Result<ParsedDnsAnswer, EndpointDnsError> {
    let txid = rand::thread_rng().gen::<u16>();
    resolve_a_connected_with_txid(resolver, qname, config, txid).await
}

/// Deterministic transaction-ID variant, useful to a replay harness.
pub async fn resolve_a_connected_with_txid(
    resolver: SocketAddr,
    qname: &str,
    config: &EndpointDnsConfig,
    txid: u16,
) -> Result<ParsedDnsAnswer, EndpointDnsError> {
    config.validate()?;
    let query = build_a_query(qname, txid)?;
    let bind = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(resolver).await?;
    let sent = socket.send(&query).await?;
    if sent != query.len() {
        return Err(EndpointDnsError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "short UDP DNS send",
        )));
    }

    // One extra byte distinguishes an answer over our configured bound from an
    // exactly-full valid answer.  The kernel still bounds allocation strictly.
    let mut packet = vec![0u8; config.max_packet_size + 1];
    let received = timeout(config.timeout, socket.recv(&mut packet))
        .await
        .map_err(|_| EndpointDnsError::Timeout)??;
    if received > config.max_packet_size {
        return Err(EndpointDnsError::Malformed(format!(
            "response exceeds {}-byte configured bound",
            config.max_packet_size
        )));
    }
    packet.truncate(received);
    parse_a_response(&packet, txid, qname, config)
}

/// Resolve one A RRset with an RFC 7766-style TCP retry when, and only when,
/// the connected UDP response is a structurally valid response for this exact
/// transaction and question with `TC=1`.
///
/// TCP is connected to the same resolver socket address.  There is no referral
/// or redirect mechanism in this resolver.  All socket state is owned by this
/// future, so dropping/cancelling it closes the in-flight socket without
/// publishing a partial result.
pub async fn resolve_a(
    resolver: SocketAddr,
    qname: &str,
    config: &EndpointDnsConfig,
) -> Result<ParsedDnsAnswer, EndpointDnsError> {
    let txid = rand::thread_rng().gen::<u16>();
    resolve_a_with_txid(resolver, qname, config, txid).await
}

/// Deterministic transaction-ID variant of [`resolve_a`], useful to replay and
/// fault-injection harnesses.
pub async fn resolve_a_with_txid(
    resolver: SocketAddr,
    qname: &str,
    config: &EndpointDnsConfig,
    txid: u16,
) -> Result<ParsedDnsAnswer, EndpointDnsError> {
    match resolve_a_connected_with_txid(resolver, qname, config, txid).await {
        Err(EndpointDnsError::TcpFallbackRequired) => {
            resolve_a_tcp_with_txid(resolver, qname, config, txid).await
        }
        result => result,
    }
}

async fn resolve_a_tcp_with_txid(
    resolver: SocketAddr,
    qname: &str,
    config: &EndpointDnsConfig,
    txid: u16,
) -> Result<ParsedDnsAnswer, EndpointDnsError> {
    config.validate()?;
    let query = build_a_query(qname, txid)?;
    let query_len = u16::try_from(query.len())
        .map_err(|_| EndpointDnsError::Configuration("DNS query exceeds TCP frame bound".into()))?;

    let mut stream = timeout(config.tcp_connect_timeout, TcpStream::connect(resolver))
        .await
        .map_err(|_| EndpointDnsError::Timeout)??;

    timeout(config.tcp_write_timeout, async {
        stream.write_all(&query_len.to_be_bytes()).await?;
        stream.write_all(&query).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| EndpointDnsError::Timeout)??;

    let mut length_prefix = [0u8; 2];
    timeout(
        config.tcp_read_timeout,
        read_tcp_frame_section(
            &mut stream,
            &mut length_prefix,
            TcpFrameSection::LengthPrefix,
        ),
    )
    .await
    .map_err(|_| EndpointDnsError::Timeout)??;

    let declared = usize::from(u16::from_be_bytes(length_prefix));
    if declared > config.max_packet_size {
        return Err(EndpointDnsError::TcpFrameTooLarge {
            declared,
            maximum: config.max_packet_size,
        });
    }

    let mut packet = vec![0u8; declared];
    timeout(
        config.tcp_read_timeout,
        read_tcp_frame_section(&mut stream, &mut packet, TcpFrameSection::Body),
    )
    .await
    .map_err(|_| EndpointDnsError::Timeout)??;

    parse_a_response(&packet, txid, qname, config)
}

async fn read_tcp_frame_section(
    stream: &mut TcpStream,
    output: &mut [u8],
    section: TcpFrameSection,
) -> Result<(), EndpointDnsError> {
    let mut received = 0;
    while received < output.len() {
        let count = stream.read(&mut output[received..]).await?;
        if count == 0 {
            return Err(EndpointDnsError::ShortTcpFrame {
                section,
                expected: output.len(),
                received,
            });
        }
        received = received
            .checked_add(count)
            .ok_or_else(|| EndpointDnsError::Malformed("TCP frame offset overflow".into()))?;
    }
    Ok(())
}

pub fn build_a_query(qname: &str, txid: u16) -> Result<Vec<u8>, EndpointDnsError> {
    let canonical = canonical_qname(qname)?;
    let mut packet = Vec::with_capacity(DNS_HEADER_LEN + canonical.len() + 6);
    packet.extend_from_slice(&txid.to_be_bytes());
    packet.extend_from_slice(&FLAG_RD.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&canonical, &mut packet)?;
    packet.extend_from_slice(&QTYPE_A.to_be_bytes());
    packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(packet)
}

pub fn parse_a_response(
    packet: &[u8],
    expected_txid: u16,
    expected_qname: &str,
    config: &EndpointDnsConfig,
) -> Result<ParsedDnsAnswer, EndpointDnsError> {
    config.validate()?;
    if packet.len() < DNS_HEADER_LEN {
        return malformed("packet shorter than DNS header");
    }
    if packet.len() > config.max_packet_size {
        return malformed("packet exceeds configured bound");
    }
    let txid = read_u16(packet, 0)?;
    if txid != expected_txid {
        return Err(EndpointDnsError::TransactionMismatch {
            expected: expected_txid,
            actual: txid,
        });
    }
    let flags = read_u16(packet, 2)?;
    if flags & FLAG_QR == 0 {
        return malformed("QR is not set");
    }
    if (flags >> 11) & 0x0f != 0 {
        return malformed("non-zero DNS opcode");
    }
    if flags & 0x0040 != 0 {
        return malformed("reserved DNS Z bit is set");
    }
    let qdcount = usize::from(read_u16(packet, 4)?);
    let ancount = usize::from(read_u16(packet, 6)?);
    let nscount = usize::from(read_u16(packet, 8)?);
    let arcount = usize::from(read_u16(packet, 10)?);
    if qdcount != 1 {
        return malformed("response must contain exactly one question");
    }
    let rr_count = ancount
        .checked_add(nscount)
        .and_then(|count| count.checked_add(arcount))
        .ok_or_else(|| EndpointDnsError::Malformed("RR count overflow".into()))?;
    if rr_count > config.max_resource_records {
        return malformed("response exceeds resource-record bound");
    }

    let expected_qname = canonical_qname(expected_qname)?;
    let (question_name, mut cursor) = parse_name(packet, DNS_HEADER_LEN)?;
    let qtype = read_u16(packet, cursor)?;
    let qclass = read_u16(packet, cursor + 2)?;
    cursor = cursor
        .checked_add(4)
        .ok_or_else(|| EndpointDnsError::Malformed("question offset overflow".into()))?;
    if question_name != expected_qname || qtype != QTYPE_A || qclass != QCLASS_IN {
        return Err(EndpointDnsError::QuestionMismatch);
    }
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (rr, next) = parse_rr(packet, cursor)?;
        answers.push(rr);
        cursor = next;
    }
    let mut authority = Vec::with_capacity(nscount);
    for _ in 0..nscount {
        let (rr, next) = parse_rr(packet, cursor)?;
        authority.push(rr);
        cursor = next;
    }
    for _ in 0..arcount {
        let (_, next) = parse_rr(packet, cursor)?;
        cursor = next;
    }
    if cursor != packet.len() {
        return malformed("trailing bytes after declared DNS records");
    }
    if flags & FLAG_TC != 0 {
        return Err(EndpointDnsError::TcpFallbackRequired);
    }

    let rcode = (flags & RCODE_MASK) as u8;
    let negative_ttl =
        soa_negative_ttl(packet, &authority)?.unwrap_or(config.default_negative_ttl_secs);
    match rcode {
        3 => {
            return Ok(ParsedDnsAnswer::NxDomain {
                negative_ttl_secs: negative_ttl,
            })
        }
        0 => {}
        rcode => return Ok(ParsedDnsAnswer::TransientRcode { rcode }),
    }

    let records = follow_cname_chain(packet, &answers, &expected_qname, config)?;
    if records.is_empty() {
        Ok(ParsedDnsAnswer::NoData {
            negative_ttl_secs: negative_ttl,
        })
    } else {
        Ok(ParsedDnsAnswer::Positive(records))
    }
}

#[derive(Clone, Debug)]
struct ResourceRecord {
    owner: String,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata_start: usize,
    rdata_end: usize,
}

fn parse_rr(packet: &[u8], start: usize) -> Result<(ResourceRecord, usize), EndpointDnsError> {
    let (owner, cursor) = parse_name(packet, start)?;
    let rr_type = read_u16(packet, cursor)?;
    let class = read_u16(packet, cursor + 2)?;
    let ttl = read_u32(packet, cursor + 4)?;
    let rdlength = usize::from(read_u16(packet, cursor + 8)?);
    let rdata_start = cursor
        .checked_add(10)
        .ok_or_else(|| EndpointDnsError::Malformed("RDATA offset overflow".into()))?;
    let rdata_end = rdata_start
        .checked_add(rdlength)
        .ok_or_else(|| EndpointDnsError::Malformed("RDATA length overflow".into()))?;
    if rdata_end > packet.len() {
        return malformed("RDATA extends beyond packet");
    }
    Ok((
        ResourceRecord {
            owner,
            rr_type,
            class,
            ttl,
            rdata_start,
            rdata_end,
        },
        rdata_end,
    ))
}

fn follow_cname_chain(
    packet: &[u8],
    answers: &[ResourceRecord],
    qname: &str,
    config: &EndpointDnsConfig,
) -> Result<Vec<ParsedARecord>, EndpointDnsError> {
    let mut cnames = BTreeMap::<String, (String, u32)>::new();
    let mut address_records = BTreeMap::<String, Vec<ParsedARecord>>::new();
    for rr in answers {
        if rr.class != QCLASS_IN {
            continue;
        }
        match rr.rr_type {
            QTYPE_A => {
                if rr.rdata_end - rr.rdata_start != 4 {
                    return malformed("A RDATA length is not four bytes");
                }
                let ip = Ipv4Addr::new(
                    packet[rr.rdata_start],
                    packet[rr.rdata_start + 1],
                    packet[rr.rdata_start + 2],
                    packet[rr.rdata_start + 3],
                );
                address_records
                    .entry(rr.owner.clone())
                    .or_default()
                    .push(ParsedARecord {
                        ip,
                        ttl_secs: rr.ttl,
                    });
            }
            QTYPE_CNAME => {
                let (target, next) = parse_name(packet, rr.rdata_start)?;
                if next != rr.rdata_end {
                    return malformed("CNAME RDATA has trailing or truncated bytes");
                }
                match cnames.get_mut(&rr.owner) {
                    Some((existing, ttl)) if existing == &target => *ttl = (*ttl).min(rr.ttl),
                    Some(_) => return malformed("one owner has conflicting CNAME targets"),
                    None => {
                        cnames.insert(rr.owner.clone(), (target, rr.ttl));
                    }
                }
            }
            _ => {}
        }
    }

    for owner in cnames.keys() {
        if address_records.contains_key(owner) {
            return malformed("owner contains both CNAME and A records");
        }
    }

    let mut current = qname.to_string();
    let mut path_ttl = u32::MAX;
    let mut seen = BTreeSet::new();
    for depth in 0..=config.max_cname_depth {
        if !seen.insert(current.clone()) {
            return malformed("cyclic CNAME chain");
        }
        if let Some(records) = address_records.get(&current) {
            let mut dedup = BTreeMap::<Ipv4Addr, u32>::new();
            for record in records {
                let ttl = record.ttl_secs.min(path_ttl);
                dedup
                    .entry(record.ip)
                    .and_modify(|existing| *existing = (*existing).min(ttl))
                    .or_insert(ttl);
            }
            if dedup.len() > config.max_addresses {
                return malformed("A RRset exceeds address bound");
            }
            return Ok(dedup
                .into_iter()
                .map(|(ip, ttl_secs)| ParsedARecord { ip, ttl_secs })
                .collect());
        }
        let Some((target, ttl)) = cnames.get(&current) else {
            return Ok(Vec::new());
        };
        if depth == config.max_cname_depth {
            return malformed("CNAME chain exceeds configured depth");
        }
        path_ttl = path_ttl.min(*ttl);
        current = target.clone();
    }
    unreachable!("bounded CNAME loop always returns")
}

fn soa_negative_ttl(
    packet: &[u8],
    authority: &[ResourceRecord],
) -> Result<Option<u32>, EndpointDnsError> {
    let mut minimum = None;
    for rr in authority
        .iter()
        .filter(|rr| rr.class == QCLASS_IN && rr.rr_type == QTYPE_SOA)
    {
        let value = parse_soa_minimum(packet, rr)?;
        minimum = Some(minimum.map_or(value, |current: u32| current.min(value)));
    }
    Ok(minimum)
}

fn parse_soa_minimum(packet: &[u8], rr: &ResourceRecord) -> Result<u32, EndpointDnsError> {
    let (_, after_mname) = parse_name(packet, rr.rdata_start)?;
    if after_mname > rr.rdata_end {
        return malformed("SOA MNAME exceeds RDATA");
    }
    let (_, after_rname) = parse_name(packet, after_mname)?;
    let fixed_end = after_rname
        .checked_add(20)
        .ok_or_else(|| EndpointDnsError::Malformed("SOA offset overflow".into()))?;
    if fixed_end != rr.rdata_end {
        return malformed("SOA fixed fields have invalid length");
    }
    // serial, refresh, retry, expire, minimum
    let minimum = read_u32(packet, after_rname + 16)?;
    Ok(rr.ttl.min(minimum))
}

/// Parse a possibly compressed DNS name. `next` always points past the bytes at
/// the original cursor (not past a followed pointer target).
fn parse_name(packet: &[u8], start: usize) -> Result<(String, usize), EndpointDnsError> {
    if start >= packet.len() {
        return malformed("name starts outside packet");
    }
    let mut labels = Vec::new();
    let mut position = start;
    let mut next = None;
    let mut visited = BTreeSet::new();
    let mut expanded_len = 0usize;
    let mut pointer_hops = 0usize;

    loop {
        if position >= packet.len() {
            return malformed("name label starts outside packet");
        }
        if !visited.insert(position) {
            return malformed("cyclic DNS compression pointer");
        }
        let length = packet[position];
        match length & 0xc0 {
            0xc0 => {
                if position + 1 >= packet.len() {
                    return malformed("truncated DNS compression pointer");
                }
                let pointer = usize::from(length & 0x3f) << 8 | usize::from(packet[position + 1]);
                if pointer >= packet.len() {
                    return malformed("DNS compression pointer is outside packet");
                }
                pointer_hops += 1;
                if pointer_hops > MAX_POINTER_HOPS {
                    return malformed("DNS compression pointer chain exceeds bound");
                }
                next.get_or_insert(position + 2);
                position = pointer;
            }
            0x00 => {
                let length = usize::from(length);
                if length == 0 {
                    let next = next.unwrap_or(position + 1);
                    return Ok((labels.join("."), next));
                }
                if length > 63 {
                    return malformed("DNS label exceeds 63 bytes");
                }
                let label_start = position + 1;
                let label_end = label_start
                    .checked_add(length)
                    .ok_or_else(|| EndpointDnsError::Malformed("label length overflow".into()))?;
                if label_end > packet.len() {
                    return malformed("DNS label extends beyond packet");
                }
                let label = std::str::from_utf8(&packet[label_start..label_end])
                    .map_err(|_| EndpointDnsError::Malformed("non-UTF8 DNS label".into()))?;
                if !label.is_ascii() {
                    return malformed("non-ASCII DNS label");
                }
                expanded_len = expanded_len
                    .checked_add(length + usize::from(!labels.is_empty()))
                    .ok_or_else(|| EndpointDnsError::Malformed("expanded name overflow".into()))?;
                if expanded_len > 253 {
                    return malformed("expanded DNS name exceeds 253 bytes");
                }
                labels.push(label.to_ascii_lowercase());
                position = label_end;
            }
            _ => return malformed("reserved DNS label encoding"),
        }
    }
}

fn canonical_qname(qname: &str) -> Result<String, EndpointDnsError> {
    let qname = qname.trim_end_matches('.');
    if qname.is_empty() {
        return Err(EndpointDnsError::InvalidQueryName("name is empty".into()));
    }
    if qname.len() > 253 || !qname.is_ascii() {
        return Err(EndpointDnsError::InvalidQueryName(
            "name must be ASCII and at most 253 bytes".into(),
        ));
    }
    let mut canonical = Vec::new();
    for label in qname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(EndpointDnsError::InvalidQueryName(
                "label must contain 1..=63 bytes".into(),
            ));
        }
        if label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(EndpointDnsError::InvalidQueryName(
                "host labels may contain only alphanumerics and interior hyphens".into(),
            ));
        }
        canonical.push(label.to_ascii_lowercase());
    }
    Ok(canonical.join("."))
}

fn encode_name(name: &str, output: &mut Vec<u8>) -> Result<(), EndpointDnsError> {
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .map_err(|_| EndpointDnsError::InvalidQueryName("label is too long".into()))?;
        output.push(length);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, EndpointDnsError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| EndpointDnsError::Malformed("u16 offset overflow".into()))?;
    let bytes = packet
        .get(offset..end)
        .ok_or_else(|| EndpointDnsError::Malformed("truncated u16".into()))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, EndpointDnsError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| EndpointDnsError::Malformed("u32 offset overflow".into()))?;
    let bytes = packet
        .get(offset..end)
        .ok_or_else(|| EndpointDnsError::Malformed("truncated u32".into()))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn malformed<T>(message: impl Into<String>) -> Result<T, EndpointDnsError> {
    Err(EndpointDnsError::Malformed(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const TXID: u16 = 0x4a7b;

    fn response_header(flags: u16, answers: u16, authority: u16, additional: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&TXID.to_be_bytes());
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&answers.to_be_bytes());
        packet.extend_from_slice(&authority.to_be_bytes());
        packet.extend_from_slice(&additional.to_be_bytes());
        encode_name("vpn.example", &mut packet).unwrap();
        packet.extend_from_slice(&QTYPE_A.to_be_bytes());
        packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
        packet
    }

    fn push_rr(packet: &mut Vec<u8>, owner: &str, rr_type: u16, ttl: u32, rdata: &[u8]) {
        if owner == "@" {
            packet.extend_from_slice(&[0xc0, 0x0c]);
        } else {
            encode_name(owner, packet).unwrap();
        }
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
    }

    fn a_response(ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let mut packet = response_header(FLAG_QR | FLAG_RD, 1, 0, 0);
        push_rr(&mut packet, "@", QTYPE_A, ttl, &ip.octets());
        packet
    }

    fn response_for_query(
        query: &[u8],
        flags: u16,
        answers: u16,
        authority: u16,
        additional: u16,
    ) -> Vec<u8> {
        let (_, question_name_end) = parse_name(query, DNS_HEADER_LEN).unwrap();
        let question_end = question_name_end + 4;
        let mut packet = Vec::new();
        packet.extend_from_slice(&read_u16(query, 0).unwrap().to_be_bytes());
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&answers.to_be_bytes());
        packet.extend_from_slice(&authority.to_be_bytes());
        packet.extend_from_slice(&additional.to_be_bytes());
        packet.extend_from_slice(&query[DNS_HEADER_LEN..question_end]);
        packet
    }

    fn response_with_question(txid: u16, qname: &str, flags: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&txid.to_be_bytes());
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        encode_name(qname, &mut packet).unwrap();
        packet.extend_from_slice(&QTYPE_A.to_be_bytes());
        packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
        packet
    }

    async fn bind_udp_and_tcp() -> (UdpSocket, TcpListener, SocketAddr) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).await.unwrap();
        (udp, tcp, address)
    }

    async fn read_framed_query(stream: &mut TcpStream) -> Vec<u8> {
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut query).await.unwrap();
        query
    }

    async fn write_frame(stream: &mut TcpStream, packet: &[u8]) {
        let length = u16::try_from(packet.len()).unwrap();
        stream.write_all(&length.to_be_bytes()).await.unwrap();
        stream.write_all(packet).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    #[derive(Clone, Copy)]
    enum TcpFixtureReply {
        ValidA,
        Hold,
        ShortPrefix,
        ShortBody,
        Oversized,
        WrongTxid,
        WrongQuestion,
    }

    async fn spawn_tc_fixture(reply: TcpFixtureReply) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let (udp, tcp, address) = bind_udp_and_tcp().await;
        let task = tokio::spawn(async move {
            let mut udp_query = [0u8; 512];
            let (length, peer) = udp.recv_from(&mut udp_query).await.unwrap();
            let udp_query = udp_query[..length].to_vec();
            let truncated = response_for_query(&udp_query, FLAG_QR | FLAG_RD | FLAG_TC, 0, 0, 0);
            udp.send_to(&truncated, peer).await.unwrap();

            let (mut stream, _) = tcp.accept().await.unwrap();
            let tcp_query = read_framed_query(&mut stream).await;
            assert_eq!(tcp_query, udp_query);

            match reply {
                TcpFixtureReply::ValidA => {
                    let mut response = response_for_query(&tcp_query, FLAG_QR | FLAG_RD, 1, 0, 0);
                    push_rr(&mut response, "@", QTYPE_A, 19, &[9, 8, 7, 6]);
                    write_frame(&mut stream, &response).await;
                }
                TcpFixtureReply::Hold => {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                TcpFixtureReply::ShortPrefix => {
                    stream.write_all(&[0]).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
                TcpFixtureReply::ShortBody => {
                    stream.write_all(&10u16.to_be_bytes()).await.unwrap();
                    stream.write_all(&[1, 2, 3]).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
                TcpFixtureReply::Oversized => {
                    stream.write_all(&513u16.to_be_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
                TcpFixtureReply::WrongTxid => {
                    let mut response = response_for_query(&tcp_query, FLAG_QR | FLAG_RD, 0, 0, 0);
                    let wrong_txid = read_u16(&tcp_query, 0).unwrap().wrapping_add(1);
                    response[..2].copy_from_slice(&wrong_txid.to_be_bytes());
                    write_frame(&mut stream, &response).await;
                }
                TcpFixtureReply::WrongQuestion => {
                    let response = response_with_question(
                        read_u16(&tcp_query, 0).unwrap(),
                        "other.example",
                        FLAG_QR | FLAG_RD,
                    );
                    write_frame(&mut stream, &response).await;
                }
            }
        });
        (address, task)
    }

    fn soa_rdata(minimum: u32) -> Vec<u8> {
        let mut rdata = Vec::new();
        encode_name("ns.example", &mut rdata).unwrap();
        encode_name("hostmaster.example", &mut rdata).unwrap();
        for value in [1u32, 60, 60, 600, minimum] {
            rdata.extend_from_slice(&value.to_be_bytes());
        }
        rdata
    }

    #[test]
    fn query_is_bounded_canonical_and_well_formed() {
        let query = build_a_query("VPN.Example.", TXID).unwrap();
        assert_eq!(read_u16(&query, 0).unwrap(), TXID);
        assert_eq!(read_u16(&query, 2).unwrap(), FLAG_RD);
        let (name, cursor) = parse_name(&query, DNS_HEADER_LEN).unwrap();
        assert_eq!(name, "vpn.example");
        assert_eq!(read_u16(&query, cursor).unwrap(), QTYPE_A);
        assert_eq!(read_u16(&query, cursor + 2).unwrap(), QCLASS_IN);
    }

    #[test]
    fn invalid_names_are_rejected_before_io() {
        for name in [
            "",
            ".",
            "a..b",
            "-bad.example",
            "bad_.example",
            "bad-.example",
        ] {
            assert!(matches!(
                build_a_query(name, TXID),
                Err(EndpointDnsError::InvalidQueryName(_))
            ));
        }
        let long = format!("{}.example", "a".repeat(64));
        assert!(build_a_query(&long, TXID).is_err());
    }

    #[test]
    fn strict_a_response_parses_ttl() {
        let answer = parse_a_response(
            &a_response(Ipv4Addr::new(1, 1, 1, 1), 42),
            TXID,
            "vpn.example",
            &EndpointDnsConfig::default(),
        )
        .unwrap();
        assert_eq!(
            answer,
            ParsedDnsAnswer::Positive(vec![ParsedARecord {
                ip: Ipv4Addr::new(1, 1, 1, 1),
                ttl_secs: 42,
            }])
        );
    }

    #[test]
    fn cname_chain_uses_minimum_path_ttl() {
        let mut packet = response_header(FLAG_QR | FLAG_RD, 2, 0, 0);
        let mut cname = Vec::new();
        encode_name("edge.example", &mut cname).unwrap();
        push_rr(&mut packet, "@", QTYPE_CNAME, 120, &cname);
        push_rr(&mut packet, "edge.example", QTYPE_A, 30, &[8, 8, 8, 8]);
        assert_eq!(
            parse_a_response(&packet, TXID, "vpn.example", &EndpointDnsConfig::default()).unwrap(),
            ParsedDnsAnswer::Positive(vec![ParsedARecord {
                ip: Ipv4Addr::new(8, 8, 8, 8),
                ttl_secs: 30,
            }])
        );
    }

    #[test]
    fn unrelated_answer_a_is_not_accepted() {
        let mut packet = response_header(FLAG_QR | FLAG_RD, 1, 0, 0);
        push_rr(&mut packet, "attacker.example", QTYPE_A, 60, &[6, 6, 6, 6]);
        assert!(matches!(
            parse_a_response(&packet, TXID, "vpn.example", &EndpointDnsConfig::default()).unwrap(),
            ParsedDnsAnswer::NoData { .. }
        ));
    }

    #[test]
    fn cyclic_cname_chain_is_rejected() {
        let mut packet = response_header(FLAG_QR | FLAG_RD, 2, 0, 0);
        let mut edge = Vec::new();
        encode_name("edge.example", &mut edge).unwrap();
        push_rr(&mut packet, "@", QTYPE_CNAME, 60, &edge);
        let mut origin = Vec::new();
        encode_name("vpn.example", &mut origin).unwrap();
        push_rr(&mut packet, "edge.example", QTYPE_CNAME, 60, &origin);
        assert!(matches!(
            parse_a_response(
                &packet,
                TXID,
                "vpn.example",
                &EndpointDnsConfig::default()
            ),
            Err(EndpointDnsError::Malformed(message)) if message.contains("cyclic CNAME")
        ));
    }

    #[test]
    fn bounded_cname_depth_is_enforced() {
        let mut packet = response_header(FLAG_QR | FLAG_RD, 3, 0, 0);
        let mut one = Vec::new();
        encode_name("one.example", &mut one).unwrap();
        push_rr(&mut packet, "@", QTYPE_CNAME, 60, &one);
        let mut two = Vec::new();
        encode_name("two.example", &mut two).unwrap();
        push_rr(&mut packet, "one.example", QTYPE_CNAME, 60, &two);
        push_rr(&mut packet, "two.example", QTYPE_A, 60, &[1, 1, 1, 1]);
        let config = EndpointDnsConfig {
            max_cname_depth: 1,
            ..EndpointDnsConfig::default()
        };
        assert!(matches!(
            parse_a_response(&packet, TXID, "vpn.example", &config),
            Err(EndpointDnsError::Malformed(message)) if message.contains("CNAME chain")
        ));
    }

    #[test]
    fn compression_pointer_cycle_and_oob_are_rejected() {
        let mut cycle = Vec::new();
        cycle.extend_from_slice(&TXID.to_be_bytes());
        cycle.extend_from_slice(&(FLAG_QR | FLAG_RD).to_be_bytes());
        cycle.extend_from_slice(&1u16.to_be_bytes());
        cycle.extend_from_slice(&[0; 6]);
        cycle.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(matches!(
            parse_a_response(
                &cycle,
                TXID,
                "vpn.example",
                &EndpointDnsConfig::default()
            ),
            Err(EndpointDnsError::Malformed(message)) if message.contains("cyclic DNS compression")
        ));

        let mut oob = cycle;
        oob[12] = 0xff;
        oob[13] = 0xff;
        assert!(
            parse_a_response(&oob, TXID, "vpn.example", &EndpointDnsConfig::default()).is_err()
        );
    }

    #[test]
    fn transaction_and_question_mismatch_are_rejected() {
        let packet = a_response(Ipv4Addr::new(1, 1, 1, 1), 30);
        assert!(matches!(
            parse_a_response(
                &packet,
                TXID + 1,
                "vpn.example",
                &EndpointDnsConfig::default()
            ),
            Err(EndpointDnsError::TransactionMismatch { .. })
        ));
        assert!(matches!(
            parse_a_response(
                &packet,
                TXID,
                "other.example",
                &EndpointDnsConfig::default()
            ),
            Err(EndpointDnsError::QuestionMismatch)
        ));
    }

    #[test]
    fn qr_opcode_bounds_and_trailing_bytes_are_rejected() {
        let mut no_qr = a_response(Ipv4Addr::new(1, 1, 1, 1), 30);
        no_qr[2] &= 0x7f;
        assert!(
            parse_a_response(&no_qr, TXID, "vpn.example", &EndpointDnsConfig::default()).is_err()
        );

        let mut opcode = a_response(Ipv4Addr::new(1, 1, 1, 1), 30);
        opcode[2] |= 0x08;
        assert!(
            parse_a_response(&opcode, TXID, "vpn.example", &EndpointDnsConfig::default()).is_err()
        );

        let mut reserved_z = a_response(Ipv4Addr::new(1, 1, 1, 1), 30);
        reserved_z[3] |= 0x40;
        assert!(parse_a_response(
            &reserved_z,
            TXID,
            "vpn.example",
            &EndpointDnsConfig::default()
        )
        .is_err());

        let mut trailing = a_response(Ipv4Addr::new(1, 1, 1, 1), 30);
        trailing.push(0);
        assert!(parse_a_response(
            &trailing,
            TXID,
            "vpn.example",
            &EndpointDnsConfig::default()
        )
        .is_err());
    }

    #[test]
    fn truncated_packet_and_rdata_are_rejected() {
        let mut packet = a_response(Ipv4Addr::new(1, 1, 1, 1), 30);
        packet.pop();
        assert!(
            parse_a_response(&packet, TXID, "vpn.example", &EndpointDnsConfig::default()).is_err()
        );
        assert!(
            parse_a_response(&[0; 11], TXID, "vpn.example", &EndpointDnsConfig::default()).is_err()
        );
    }

    #[test]
    fn tc_bit_requires_explicit_tcp_fallback() {
        let packet = response_header(FLAG_QR | FLAG_RD | FLAG_TC, 0, 0, 0);
        assert!(matches!(
            parse_a_response(&packet, TXID, "vpn.example", &EndpointDnsConfig::default()),
            Err(EndpointDnsError::TcpFallbackRequired)
        ));
    }

    #[test]
    fn nxdomain_and_nodata_use_rfc2308_soa_minimum() {
        for (flags, nxdomain) in [(FLAG_QR | FLAG_RD | 3, true), (FLAG_QR | FLAG_RD, false)] {
            let mut packet = response_header(flags, 0, 1, 0);
            push_rr(&mut packet, "@", QTYPE_SOA, 120, &soa_rdata(30));
            let answer =
                parse_a_response(&packet, TXID, "vpn.example", &EndpointDnsConfig::default())
                    .unwrap();
            if nxdomain {
                assert_eq!(
                    answer,
                    ParsedDnsAnswer::NxDomain {
                        negative_ttl_secs: 30
                    }
                );
            } else {
                assert_eq!(
                    answer,
                    ParsedDnsAnswer::NoData {
                        negative_ttl_secs: 30
                    }
                );
            }
        }
    }

    #[test]
    fn malformed_soa_is_rejected_instead_of_becoming_default_negative_ttl() {
        let mut packet = response_header(FLAG_QR | FLAG_RD | 3, 0, 1, 0);
        push_rr(&mut packet, "@", QTYPE_SOA, 120, &[0]);
        assert!(matches!(
            parse_a_response(&packet, TXID, "vpn.example", &EndpointDnsConfig::default()),
            Err(EndpointDnsError::Malformed(_))
        ));
    }

    #[test]
    fn many_uncompressed_labels_are_not_confused_with_pointer_hops() {
        let name = vec!["a"; 40].join(".");
        let mut packet = build_a_query(&name, TXID).unwrap();
        packet[2..4].copy_from_slice(&(FLAG_QR | FLAG_RD).to_be_bytes());
        assert_eq!(
            parse_a_response(&packet, TXID, &name, &EndpointDnsConfig::default()).unwrap(),
            ParsedDnsAnswer::NoData {
                negative_ttl_secs: EndpointDnsConfig::default().default_negative_ttl_secs
            }
        );
    }

    #[test]
    fn servfail_is_transient_not_negative_or_empty() {
        let packet = response_header(FLAG_QR | FLAG_RD | 2, 0, 0, 0);
        assert_eq!(
            parse_a_response(&packet, TXID, "vpn.example", &EndpointDnsConfig::default()).unwrap(),
            ParsedDnsAnswer::TransientRcode { rcode: 2 }
        );
    }

    #[test]
    fn response_record_and_address_bounds_are_enforced() {
        let packet = a_response(Ipv4Addr::new(1, 1, 1, 1), 30);
        let config = EndpointDnsConfig {
            max_resource_records: 1,
            max_addresses: 1,
            ..EndpointDnsConfig::default()
        };
        parse_a_response(&packet, TXID, "vpn.example", &config).unwrap();

        let mut two = response_header(FLAG_QR | FLAG_RD, 2, 0, 0);
        push_rr(&mut two, "@", QTYPE_A, 30, &[1, 1, 1, 1]);
        push_rr(&mut two, "@", QTYPE_A, 30, &[8, 8, 8, 8]);
        assert!(parse_a_response(&two, TXID, "vpn.example", &config).is_err());
    }

    #[tokio::test]
    async fn connected_udp_round_trip_uses_strict_parser() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (length, peer) = server.recv_from(&mut query).await.unwrap();
            let query = &query[..length];
            let txid = read_u16(query, 0).unwrap();
            let (_, question_end) = parse_name(query, DNS_HEADER_LEN).unwrap();
            let question_end = question_end + 4;
            let mut response = Vec::new();
            response.extend_from_slice(&txid.to_be_bytes());
            response.extend_from_slice(&(FLAG_QR | FLAG_RD).to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&query[DNS_HEADER_LEN..question_end]);
            push_rr(&mut response, "@", QTYPE_A, 17, &[9, 9, 9, 9]);
            server.send_to(&response, peer).await.unwrap();
        });
        let answer = resolve_a_connected_with_txid(
            address,
            "vpn.example",
            &EndpointDnsConfig::default(),
            TXID,
        )
        .await
        .unwrap();
        assert_eq!(
            answer,
            ParsedDnsAnswer::Positive(vec![ParsedARecord {
                ip: Ipv4Addr::new(9, 9, 9, 9),
                ttl_secs: 17,
            }])
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn validated_udp_tc_falls_back_to_tcp_at_same_resolver() {
        let (address, task) = spawn_tc_fixture(TcpFixtureReply::ValidA).await;
        let answer = resolve_a(address, "vpn.example", &EndpointDnsConfig::default())
            .await
            .unwrap();
        assert_eq!(
            answer,
            ParsedDnsAnswer::Positive(vec![ParsedARecord {
                ip: Ipv4Addr::new(9, 8, 7, 6),
                ttl_secs: 19,
            }])
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_response_read_timeout_is_bounded() {
        let (address, task) = spawn_tc_fixture(TcpFixtureReply::Hold).await;
        let config = EndpointDnsConfig {
            tcp_read_timeout: Duration::from_millis(25),
            ..EndpointDnsConfig::default()
        };
        assert!(matches!(
            resolve_a_with_txid(address, "vpn.example", &config, TXID).await,
            Err(EndpointDnsError::Timeout)
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_short_prefix_and_body_report_exact_section_and_count() {
        for (reply, section, expected, received) in [
            (
                TcpFixtureReply::ShortPrefix,
                TcpFrameSection::LengthPrefix,
                2,
                1,
            ),
            (TcpFixtureReply::ShortBody, TcpFrameSection::Body, 10, 3),
        ] {
            let (address, task) = spawn_tc_fixture(reply).await;
            assert!(matches!(
                resolve_a_with_txid(
                    address,
                    "vpn.example",
                    &EndpointDnsConfig::default(),
                    TXID
                )
                .await,
                Err(EndpointDnsError::ShortTcpFrame {
                    section: actual_section,
                    expected: actual_expected,
                    received: actual_received,
                }) if actual_section == section
                    && actual_expected == expected
                    && actual_received == received
            ));
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn tcp_declared_length_is_rejected_before_body_allocation() {
        let (address, task) = spawn_tc_fixture(TcpFixtureReply::Oversized).await;
        let config = EndpointDnsConfig {
            max_packet_size: 512,
            ..EndpointDnsConfig::default()
        };
        assert!(matches!(
            resolve_a_with_txid(address, "vpn.example", &config, TXID).await,
            Err(EndpointDnsError::TcpFrameTooLarge {
                declared: 513,
                maximum: 512,
            })
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_fallback_reuses_strict_transaction_and_question_checks() {
        let (address, task) = spawn_tc_fixture(TcpFixtureReply::WrongTxid).await;
        assert!(matches!(
            resolve_a_with_txid(address, "vpn.example", &EndpointDnsConfig::default(), TXID).await,
            Err(EndpointDnsError::TransactionMismatch { expected: TXID, .. })
        ));
        task.await.unwrap();

        let (address, task) = spawn_tc_fixture(TcpFixtureReply::WrongQuestion).await;
        assert!(matches!(
            resolve_a_with_txid(address, "vpn.example", &EndpointDnsConfig::default(), TXID).await,
            Err(EndpointDnsError::QuestionMismatch)
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_tc_udp_response_does_not_authorize_tcp() {
        let (udp, tcp, address) = bind_udp_and_tcp().await;
        let server = tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (length, peer) = udp.recv_from(&mut query).await.unwrap();
            let mut response =
                response_for_query(&query[..length], FLAG_QR | FLAG_RD | FLAG_TC, 0, 0, 0);
            response.push(0);
            udp.send_to(&response, peer).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(75), tcp.accept())
                    .await
                    .is_err(),
                "malformed TC response unexpectedly authorized TCP"
            );
        });

        assert!(matches!(
            resolve_a_with_txid(
                address,
                "vpn.example",
                &EndpointDnsConfig::default(),
                TXID
            )
            .await,
            Err(EndpointDnsError::Malformed(message))
                if message.contains("trailing bytes")
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn non_tc_udp_response_never_opens_tcp() {
        let (udp, tcp, address) = bind_udp_and_tcp().await;
        let server = tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (length, peer) = udp.recv_from(&mut query).await.unwrap();
            let response = response_for_query(&query[..length], FLAG_QR | FLAG_RD | 2, 0, 0, 0);
            udp.send_to(&response, peer).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(75), tcp.accept())
                    .await
                    .is_err(),
                "non-TC response unexpectedly opened TCP"
            );
        });

        assert_eq!(
            resolve_a_with_txid(address, "vpn.example", &EndpointDnsConfig::default(), TXID)
                .await
                .unwrap(),
            ParsedDnsAnswer::TransientRcode { rcode: 2 }
        );
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn connected_udp_timeout_is_bounded() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let config = EndpointDnsConfig {
            timeout: Duration::from_millis(50),
            ..EndpointDnsConfig::default()
        };
        assert!(matches!(
            resolve_a_connected_with_txid(address, "vpn.example", &config, TXID).await,
            Err(EndpointDnsError::Timeout)
        ));
    }
}
