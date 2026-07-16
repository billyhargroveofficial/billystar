use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{MLKEM_CIPHERTEXT_SIZE, MLKEM_PUBLIC_KEY_SIZE};

pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
pub const MAX_PADDING: usize = 512;
const MAX_FRAME_HEADER: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CamouflageMode {
    Raw = 0,
    H2Chunk = 1,
    DnsChunk = 2,
}

impl CamouflageMode {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Raw),
            1 => Ok(Self::H2Chunk),
            2 => Ok(Self::DnsChunk),
            _ => Err(anyhow!("unknown camouflage mode {v}")),
        }
    }
}

/// Exact outer carrier identity authenticated by the inner access gate and
/// canonical handshake transcript.
///
/// This is deliberately separate from [`CamouflageMode`]. The camouflage mode
/// describes framing presented to the inner protocol, while several distinct
/// outer carriers terminate to the same raw byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CarrierBinding {
    DirectTcp = 0,
    RealityTcp = 1,
    BrowserTlsTcp = 2,
    QuicRaw = 3,
    Http2Tls = 4,
    Http3Quic = 5,
}

impl CarrierBinding {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::DirectTcp),
            1 => Ok(Self::RealityTcp),
            2 => Ok(Self::BrowserTlsTcp),
            3 => Ok(Self::QuicRaw),
            4 => Ok(Self::Http2Tls),
            5 => Ok(Self::Http3Quic),
            _ => Err(anyhow!("unknown carrier binding {v}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PaddingProfile {
    Balanced = 0,
    PreferAscii = 1,
    PreferEntropy = 2,
}

impl PaddingProfile {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Balanced),
            1 => Ok(Self::PreferAscii),
            2 => Ok(Self::PreferEntropy),
            _ => Err(anyhow!("unknown padding profile {v}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const DATA: Self = Self(1 << 0);
    pub const FIN: Self = Self(1 << 1);
    pub const PING: Self = Self(1 << 2);
    pub const PADDING: Self = Self(1 << 3);

    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub magic: u32,
    pub version: u8,
    pub client_random: [u8; 16],
    pub x25519_public: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub camouflage: CamouflageMode,
    pub padding_profile: PaddingProfile,
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub server_random: [u8; 16],
    pub x25519_public: [u8; 32],
    pub session_id: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub stream_id: u32,
    pub flags: FrameFlags,
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
}

pub async fn write_client_hello<W: AsyncWrite + Unpin>(
    w: &mut W,
    hello: &ClientHello,
) -> Result<()> {
    w.write_u32(hello.magic).await?;
    w.write_u8(hello.version).await?;
    w.write_all(&hello.client_random).await?;
    w.write_all(&hello.x25519_public).await?;
    if hello.mlkem_ciphertext.len() != MLKEM_CIPHERTEXT_SIZE {
        return Err(anyhow!(
            "ML-KEM ciphertext has length {}; expected {MLKEM_CIPHERTEXT_SIZE}",
            hello.mlkem_ciphertext.len()
        ));
    }
    write_blob16(w, &hello.mlkem_ciphertext).await?;
    w.write_u8(hello.camouflage as u8).await?;
    w.write_u8(hello.padding_profile as u8).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_client_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<ClientHello> {
    let magic = r.read_u32().await?;
    let version = r.read_u8().await?;
    let mut client_random = [0u8; 16];
    r.read_exact(&mut client_random).await?;
    let mut x25519_public = [0u8; 32];
    r.read_exact(&mut x25519_public).await?;
    let mlkem_ciphertext = read_blob16_exact(r, MLKEM_CIPHERTEXT_SIZE, "ML-KEM ciphertext").await?;
    let camouflage = CamouflageMode::from_u8(r.read_u8().await?)?;
    let padding_profile = PaddingProfile::from_u8(r.read_u8().await?)?;
    Ok(ClientHello {
        magic,
        version,
        client_random,
        x25519_public,
        mlkem_ciphertext,
        camouflage,
        padding_profile,
    })
}

pub async fn write_server_hello<W: AsyncWrite + Unpin>(
    w: &mut W,
    hello: &ServerHello,
) -> Result<()> {
    w.write_all(&hello.server_random).await?;
    w.write_all(&hello.x25519_public).await?;
    w.write_all(&hello.session_id).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_server_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<ServerHello> {
    let mut server_random = [0u8; 16];
    r.read_exact(&mut server_random).await?;
    let mut x25519_public = [0u8; 32];
    r.read_exact(&mut x25519_public).await?;
    let mut session_id = [0u8; 8];
    r.read_exact(&mut session_id).await?;
    Ok(ServerHello {
        server_random,
        x25519_public,
        session_id,
    })
}

pub async fn write_mlkem_public<W: AsyncWrite + Unpin>(w: &mut W, pk: &[u8]) -> Result<()> {
    if pk.len() != MLKEM_PUBLIC_KEY_SIZE {
        return Err(anyhow!(
            "ML-KEM public key has length {}; expected {MLKEM_PUBLIC_KEY_SIZE}",
            pk.len()
        ));
    }
    w.write_u16(pk.len() as u16).await?;
    w.write_all(pk).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_mlkem_public<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    read_blob16_exact(r, MLKEM_PUBLIC_KEY_SIZE, "ML-KEM public key").await
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    let mut header = Vec::new();
    write_uvarint(&mut header, frame.stream_id as u64);
    header.push(frame.flags.bits());
    write_uvarint(&mut header, frame.payload.len() as u64);
    write_blob16(w, &header).await?;
    if !frame.payload.is_empty() {
        w.write_all(&frame.payload).await?;
    }
    if !frame.padding.is_empty() {
        w.write_all(&frame.padding).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let header = read_blob16_bounded(r, MAX_FRAME_HEADER, "frame header").await?;
    let (stream_id, rest) = read_uvarint(&header).context("stream id")?;
    let stream_id = u32::try_from(stream_id).context("stream id exceeds u32")?;
    if rest.is_empty() {
        return Err(anyhow!("missing frame flags"));
    }
    let flags = FrameFlags::from_bits(rest[0]);
    if flags.bits()
        & !(FrameFlags::DATA.bits()
            | FrameFlags::FIN.bits()
            | FrameFlags::PING.bits()
            | FrameFlags::PADDING.bits())
        != 0
    {
        return Err(anyhow!("unknown frame flags: {:#04x}", flags.bits()));
    }
    let (payload_len, trailing) = read_uvarint(&rest[1..]).context("payload length")?;
    if !trailing.is_empty() {
        return Err(anyhow!(
            "non-canonical frame header: {} trailing byte(s)",
            trailing.len()
        ));
    }
    if payload_len > MAX_FRAME_PAYLOAD as u64 {
        return Err(anyhow!("payload too large: {payload_len}"));
    }

    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        r.read_exact(&mut payload).await?;
    }

    let padding = if flags.contains(FrameFlags::PADDING) {
        let mut len_buf = [0u8; 2];
        r.read_exact(&mut len_buf).await?;
        let pad_len = u16::from_be_bytes(len_buf) as usize;
        if pad_len == 0 {
            return Err(anyhow!(
                "non-canonical frame: PADDING flag requires non-empty padding"
            ));
        }
        if pad_len > MAX_PADDING {
            return Err(anyhow!("padding too large: {pad_len}"));
        }
        let mut padding = vec![0u8; pad_len];
        if pad_len > 0 {
            r.read_exact(&mut padding).await?;
        }
        padding
    } else {
        Vec::new()
    };

    Ok(Frame {
        stream_id,
        flags,
        payload,
        padding,
    })
}

async fn write_blob16<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > u16::MAX as usize {
        return Err(anyhow!("blob too large"));
    }
    w.write_u16(data.len() as u16).await?;
    if !data.is_empty() {
        w.write_all(data).await?;
    }
    Ok(())
}

async fn read_blob16_bounded<R: AsyncRead + Unpin>(
    r: &mut R,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let len = r.read_u16().await? as usize;
    if len > maximum {
        return Err(anyhow!("{label} length {len} exceeds maximum {maximum}"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn read_blob16_exact<R: AsyncRead + Unpin>(
    r: &mut R,
    expected: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let len = r.read_u16().await? as usize;
    if len != expected {
        return Err(anyhow!("{label} has length {len}; expected {expected}"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

fn write_uvarint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn read_uvarint(buf: &[u8]) -> Result<(u64, &[u8])> {
    let mut value = 0u64;
    for (i, &byte) in buf.iter().enumerate() {
        if i >= 10 || (i == 9 && byte & 0x7e != 0) {
            return Err(anyhow!("uvarint overflow"));
        }
        let payload = byte & 0x7f;
        value |= u64::from(payload) << (i * 7);
        if byte & 0x80 == 0 {
            if i > 0 && payload == 0 {
                return Err(anyhow!("non-canonical uvarint"));
            }
            return Ok((value, &buf[i + 1..]));
        }
    }
    if buf.len() >= 10 {
        Err(anyhow!("uvarint overflow"))
    } else {
        Err(anyhow!("truncated uvarint"))
    }
}

pub fn random_padding(profile: PaddingProfile) -> Result<Vec<u8>> {
    use rand::RngCore;
    let max = match profile {
        PaddingProfile::PreferAscii => 128,
        PaddingProfile::PreferEntropy => MAX_PADDING,
        PaddingProfile::Balanced => 256,
    };
    let n = rand::thread_rng().next_u32() as usize % (max + 1);
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    if profile == PaddingProfile::PreferAscii {
        for b in &mut buf {
            *b = b'A' + (*b % 26);
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn frame_error(header: &[u8]) -> String {
        let mut wire = Vec::with_capacity(2 + header.len());
        wire.extend_from_slice(&(header.len() as u16).to_be_bytes());
        wire.extend_from_slice(header);
        read_frame(&mut wire.as_slice())
            .await
            .expect_err("adversarial frame header must fail")
            .to_string()
    }

    #[test]
    fn uvarint_rejects_noncanonical_and_overflow_encodings() {
        assert!(read_uvarint(&[0x80, 0x00])
            .unwrap_err()
            .to_string()
            .contains("non-canonical"));
        assert!(read_uvarint(&[0xff; 10])
            .unwrap_err()
            .to_string()
            .contains("overflow"));
        assert!(
            read_uvarint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02])
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );

        let mut canonical = Vec::new();
        write_uvarint(&mut canonical, u64::MAX);
        assert_eq!(read_uvarint(&canonical).unwrap(), (u64::MAX, &[][..]));
    }

    #[tokio::test]
    async fn frame_rejects_trailing_header_bytes() {
        let error = frame_error(&[0x00, FrameFlags::DATA.bits(), 0x00, 0x00]).await;
        assert!(error.contains("trailing"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn frame_rejects_stream_id_above_u32() {
        let mut header = Vec::new();
        write_uvarint(&mut header, u64::from(u32::MAX) + 1);
        header.push(FrameFlags::DATA.bits());
        header.push(0);
        let error = frame_error(&header).await;
        assert!(error.contains("exceeds u32"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn frame_rejects_unknown_flag_bits() {
        let error = frame_error(&[0x00, 0x80, 0x00]).await;
        assert!(
            error.contains("unknown frame flags"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn declared_oversized_frame_header_fails_before_body_read() {
        let declared = (MAX_FRAME_HEADER as u16 + 1).to_be_bytes();
        let error = read_frame(&mut declared.as_slice()).await.unwrap_err();
        assert!(error.to_string().contains("frame header length"));
    }

    #[tokio::test]
    async fn padding_flag_with_zero_length_is_rejected_as_noncanonical() {
        let header = [0, FrameFlags::PADDING.bits(), 0];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(header.len() as u16).to_be_bytes());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&0u16.to_be_bytes());
        let error = read_frame(&mut wire.as_slice()).await.unwrap_err();
        assert!(error.to_string().contains("non-empty padding"));
    }

    #[tokio::test]
    async fn malformed_mlkem_lengths_fail_before_allocation_or_body_read() {
        let public_len = (MLKEM_PUBLIC_KEY_SIZE as u16 - 1).to_be_bytes();
        let error = read_mlkem_public(&mut public_len.as_slice())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ML-KEM public key has length"));

        let mut hello_prefix = Vec::new();
        hello_prefix.extend_from_slice(&0u32.to_be_bytes());
        hello_prefix.push(crate::PROTO_VERSION);
        hello_prefix.extend_from_slice(&[0u8; 16 + 32]);
        hello_prefix.extend_from_slice(&0u16.to_be_bytes());
        let error = read_client_hello(&mut hello_prefix.as_slice())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ML-KEM ciphertext has length"));
    }
}
