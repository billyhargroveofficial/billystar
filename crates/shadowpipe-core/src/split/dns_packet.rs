//! Minimal DNS packet helpers for split DNS (QNAME, A records, TTL).

use std::net::Ipv4Addr;

const HEADER_LEN: usize = 12;

pub fn parse_qname(packet: &[u8]) -> Option<String> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if qd == 0 {
        return None;
    }
    let mut i = HEADER_LEN;
    let mut labels = Vec::new();
    loop {
        if i >= packet.len() {
            return None;
        }
        let len = packet[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            return None;
        }
        if i + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[i..i + len]).into_owned());
        i += len;
    }
    Some(labels.join("."))
}

pub fn query_type(packet: &[u8]) -> Option<u16> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if qd == 0 {
        return None;
    }
    let mut i = HEADER_LEN;
    i = skip_name(packet, i)?;
    if i + 4 > packet.len() {
        return None;
    }
    Some(u16::from_be_bytes([packet[i], packet[i + 1]]))
}

pub fn response_code(packet: &[u8]) -> u8 {
    if packet.len() < 4 {
        return 0xff;
    }
    packet[3] & 0x0f
}

/// Build a standard query (RD=1) for `qname` / `qtype`.
pub fn build_query(qname: &str, qtype: u16) -> Vec<u8> {
    let mut p = vec![0u8; HEADER_LEN];
    p[0] = 0x12;
    p[2] = 0x01; // RD
    p[5] = 1; // QDCOUNT
    for label in qname
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // IN
    p
}

/// Build empty NOERROR response (sing-box AAAA kill / prefer IPv4 for proxy domains).
pub fn build_empty_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < HEADER_LEN {
        return None;
    }
    let mut p = query.to_vec();
    p[2] = 0x81; // QR + RD
    p[3] = 0x80; // RA
    p[6] = 0;
    p[7] = 0; // ANCOUNT
    p[8] = 0;
    p[9] = 0;
    p[10] = 0;
    p[11] = 0;
    Some(p)
}

/// CNAME targets from answer/authority/additional.
pub fn parse_cnames(packet: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok((answer, authority, additional)) = section_counts(packet) else {
        return out;
    };
    let mut i = skip_questions(packet, HEADER_LEN);
    for count in [answer, authority, additional] {
        for _ in 0..count {
            let Some((next, name, rtype)) = rr_meta(packet, i) else {
                break;
            };
            if rtype == 5 && !name.is_empty() {
                out.push(name);
            }
            i = next;
        }
    }
    out
}

/// Walk answer + authority + additional for A (type 1) records.
pub fn parse_a_records(packet: &[u8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let Ok((answer, authority, additional)) = section_counts(packet) else {
        return out;
    };
    let mut i = skip_questions(packet, HEADER_LEN);
    for count in [answer, authority, additional] {
        for _ in 0..count {
            let Some(next) = parse_rr(packet, i, &mut out) else {
                break;
            };
            i = next;
        }
    }
    out
}

/// Minimum TTL from answer RRs; defaults to 60s when absent.
pub fn min_answer_ttl(packet: &[u8], default_secs: u32) -> u32 {
    let Ok((answer, _, _)) = section_counts(packet) else {
        return default_secs;
    };
    let mut i = skip_questions(packet, HEADER_LEN);
    let mut min = None;
    for _ in 0..answer {
        let Some((next, ttl)) = rr_ttl(packet, i) else {
            break;
        };
        min = Some(min.map_or(ttl, |m: u32| m.min(ttl)));
        i = next;
    }
    min.unwrap_or(default_secs).max(1)
}

fn section_counts(packet: &[u8]) -> Result<(usize, usize, usize), ()> {
    if packet.len() < HEADER_LEN {
        return Err(());
    }
    Ok((
        u16::from_be_bytes([packet[6], packet[7]]) as usize,
        u16::from_be_bytes([packet[8], packet[9]]) as usize,
        u16::from_be_bytes([packet[10], packet[11]]) as usize,
    ))
}

fn skip_questions(packet: &[u8], mut i: usize) -> usize {
    let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    for _ in 0..qd {
        if let Some(next) = skip_name(packet, i) {
            i = next;
            if i + 4 <= packet.len() {
                i += 4;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    i
}

fn parse_rr(packet: &[u8], i: usize, out: &mut Vec<Ipv4Addr>) -> Option<usize> {
    let (next, rtype, data, rdlen) = rr_parts(packet, i)?;
    if rtype == 1 && rdlen == 4 {
        out.push(Ipv4Addr::new(
            packet[data],
            packet[data + 1],
            packet[data + 2],
            packet[data + 3],
        ));
    }
    Some(next)
}

fn rr_meta(packet: &[u8], i: usize) -> Option<(usize, String, u16)> {
    let (next, rtype, data, rdlen) = rr_parts(packet, i)?;
    let name = if rtype == 5 {
        read_domain_name(packet, data).unwrap_or_default()
    } else {
        String::new()
    };
    let _ = rdlen;
    Some((next, name, rtype))
}

fn rr_parts(packet: &[u8], i: usize) -> Option<(usize, u16, usize, usize)> {
    let i = skip_name(packet, i)?;
    if i + 10 > packet.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([packet[i], packet[i + 1]]);
    let rdlen = u16::from_be_bytes([packet[i + 8], packet[i + 9]]) as usize;
    let data = i + 10;
    if data + rdlen > packet.len() {
        return None;
    }
    Some((data + rdlen, rtype, data, rdlen))
}

fn read_domain_name(packet: &[u8], i: usize) -> Option<String> {
    read_domain_name_depth(packet, i, 0)
}

/// `depth` is threaded through compression-pointer recursion so a crafted packet
/// with cyclic or deeply-chained pointers (A→B→A…) is bounded instead of
/// recursing forever (stack-overflow DoS). The previous `jumps` counter was reset
/// on every recursive call, so it never actually capped anything.
fn read_domain_name_depth(packet: &[u8], mut i: usize, depth: usize) -> Option<String> {
    if depth > 12 {
        return None;
    }
    let mut labels = Vec::new();
    loop {
        if i >= packet.len() {
            return None;
        }
        let len = packet[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if i + 1 >= packet.len() {
                return None;
            }
            let ptr = u16::from_be_bytes([packet[i] & 0x3f, packet[i + 1]]) as usize;
            if let Some(rest) = read_domain_name_depth(packet, ptr, depth + 1) {
                if !rest.is_empty() {
                    labels.push(rest);
                }
            }
            break;
        }
        i += 1;
        if i + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[i..i + len]).into_owned());
        i += len;
    }
    Some(labels.join("."))
}

fn rr_ttl(packet: &[u8], i: usize) -> Option<(usize, u32)> {
    let i = skip_name(packet, i)?;
    if i + 10 > packet.len() {
        return None;
    }
    let ttl = u32::from_be_bytes([packet[i + 4], packet[i + 5], packet[i + 6], packet[i + 7]]);
    let rdlen = u16::from_be_bytes([packet[i + 8], packet[i + 9]]) as usize;
    Some((i + 10 + rdlen, ttl))
}

fn skip_name(packet: &[u8], mut i: usize) -> Option<usize> {
    loop {
        if i >= packet.len() {
            return None;
        }
        let len = packet[i] as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_domain_name_bounds_cyclic_compression_pointers() {
        // Pre-fix these recursed forever (stack-overflow DoS); now they must return
        // bounded without crashing. Reaching the asserts at all = no infinite recursion.
        let self_ref = vec![0xC0u8, 0x00]; // pointer at off0 → off0 (points to itself)
        let _ = read_domain_name(&self_ref, 0);
        let two_cycle = vec![0xC0u8, 0x02, 0xC0, 0x00]; // off0→off2, off2→off0
        let _ = read_domain_name(&two_cycle, 0);
        // A normal name still parses correctly.
        let name = vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ];
        assert_eq!(read_domain_name(&name, 0).as_deref(), Some("www.example"));
    }

    fn query_packet(qname: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p[4] = 0;
        p[5] = 1;
        for label in qname.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&[0, 1]); // IN
        p
    }

    fn response_with_a(qname: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut p = query_packet(qname, 1);
        p[2] = 0x81; // QR=1, RD=1
        p[6] = 0;
        p[7] = 1; // 1 answer
                  // Name pointer to question qname at offset 12.
        p.push(0xc0);
        p.push(12);
        p.extend_from_slice(&1u16.to_be_bytes()); // A
        p.extend_from_slice(&[0, 1]); // IN
        p.extend_from_slice(&ttl.to_be_bytes());
        p.extend_from_slice(&4u16.to_be_bytes());
        p.extend_from_slice(&ip);
        p
    }

    #[test]
    fn parse_qname_and_type() {
        let q = query_packet("www.example.com", 1);
        assert_eq!(parse_qname(&q).as_deref(), Some("www.example.com"));
        assert_eq!(query_type(&q), Some(1));
    }

    #[test]
    fn parse_a_and_ttl() {
        let r = response_with_a("api.anthropic.com", [104, 18, 32, 14], 120);
        assert_eq!(response_code(&r), 0);
        assert_eq!(parse_a_records(&r), vec![Ipv4Addr::new(104, 18, 32, 14)]);
        assert_eq!(min_answer_ttl(&r, 60), 120);
    }
}
