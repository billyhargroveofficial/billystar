/// Fix IPv4 (and ICMP) checksums before injecting into TUN.
pub fn fix_ipv4_checksum(packet: &mut [u8]) {
    if packet.len() < 20 {
        return;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return;
    }
    if packet[9] == 1 && packet.len() >= ihl + 8 {
        fix_icmp_checksum(packet, ihl);
    }
    packet[10] = 0;
    packet[11] = 0;
    let sum = checksum16(&packet[..ihl]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn fix_icmp_checksum(packet: &mut [u8], ihl: usize) {
    let payload = &mut packet[ihl..];
    if payload.len() < 4 {
        return;
    }
    payload[2] = 0;
    payload[3] = 0;
    let sum = checksum16(payload);
    payload[2..4].copy_from_slice(&sum.to_be_bytes());
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixes_ping_like_packet() {
        // minimal valid IPv4 header (20 bytes) + dummy payload
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x08,
            0x00, 0x02, 0x08, 0x08, 0x08, 0x08,
        ];
        fix_ipv4_checksum(&mut pkt);
        assert_ne!(pkt[10], 0);
        assert_ne!(pkt[11], 0);
    }
}
