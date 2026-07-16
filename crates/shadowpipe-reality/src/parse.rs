//! Minimal forward parser pulling the fields a REALITY server needs out of a
//! ClientHello record: the client random, the legacy_session_id (the auth
//! ciphertext), and the X25519 key_share public key. Fully bounds-checked —
//! any malformed/truncated input returns `None` (the server then forwards it to
//! the cover site, like any non-REALITY peer).

/// Fields a REALITY server extracts from a ClientHello.
#[derive(Debug, Clone)]
pub struct HelloFields {
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub x25519_pub: [u8; 32],
}

fn u16at(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

/// Parse a full TLS-record-framed ClientHello.
pub fn extract_client_hello_fields(rec: &[u8]) -> Option<HelloFields> {
    // record: type(1)=0x16 ver(2) len(2) | handshake: type(1)=0x01 len(3) | body
    if *rec.first()? != 0x16 || *rec.get(5)? != 0x01 {
        return None;
    }
    let mut p = 9usize; // handshake body: 5 record header + 4 handshake header
    let _legacy_version = u16at(rec, p)?;
    p += 2;
    let random: [u8; 32] = rec.get(p..p + 32)?.try_into().ok()?;
    p += 32;
    let sid_len = *rec.get(p)? as usize;
    p += 1;
    if sid_len != 32 {
        return None;
    }
    let session_id: [u8; 32] = rec.get(p..p + 32)?.try_into().ok()?;
    p += 32;
    let cipher_len = u16at(rec, p)?;
    p += 2 + cipher_len;
    let comp_len = *rec.get(p)? as usize;
    p += 1 + comp_len;
    let ext_total = u16at(rec, p)?;
    p += 2;
    let ext_end = p + ext_total;
    if ext_end > rec.len() {
        return None;
    }
    let mut x25519_pub: Option<[u8; 32]> = None;
    while p + 4 <= ext_end {
        let etype = u16at(rec, p)?;
        let elen = u16at(rec, p + 2)?;
        let data_start = p + 4;
        let data_end = data_start + elen;
        if data_end > ext_end {
            return None;
        }
        if etype == 0x0033 {
            x25519_pub = parse_key_share(&rec[data_start..data_end]);
        }
        p = data_end;
    }
    Some(HelloFields {
        random,
        session_id,
        x25519_pub: x25519_pub?,
    })
}

/// key_share extension data: client_shares<2>[ group(2) key<2> ... ]. Return the
/// 32-byte X25519 (group 0x001d) public key if present.
fn parse_key_share(data: &[u8]) -> Option<[u8; 32]> {
    let total = u16at(data, 0)?;
    let mut p = 2usize;
    let end = (2 + total).min(data.len());
    while p + 4 <= end {
        let group = u16::from_be_bytes([data[p], data[p + 1]]);
        let klen = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        let kstart = p + 4;
        let kend = kstart + klen;
        if kend > data.len() {
            return None;
        }
        if group == 0x001d && klen == 32 {
            return data[kstart..kend].try_into().ok();
        }
        p = kend;
    }
    None
}
