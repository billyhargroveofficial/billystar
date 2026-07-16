pub mod api;

use anyhow::{anyhow, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::cam::h2::{self, Decoder};
use crate::proto::CamouflageMode;

// Shadowpipe's H2-shaped carrier has one canonical bootstrap: the HTTP/2
// connection preface followed by an empty, non-ACK SETTINGS frame on stream 0.
// Keeping this exact also makes pre-auth memory use constant; an unauthenticated
// peer never controls a bootstrap allocation through the 24-bit frame length.
const CLIENT_SETTINGS_HEADER: [u8; 9] = [0, 0, 0, 0x04, 0, 0, 0, 0, 0];

/// Stream that replays `prefix` before reading from inner.
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_off: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_off: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix_off < self.prefix.len() {
            let remain = &self.prefix[self.prefix_off..];
            let n = remain.len().min(buf.remaining());
            buf.put_slice(&remain[..n]);
            self.prefix_off += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct CarrierStream<S> {
    inner: S,
    mode: CamouflageMode,
    h2_stream_id: u32,
    decoder: Decoder,
    read_pending: Vec<u8>,
    read_offset: usize,
    write_buf: Vec<u8>,
    /// Encoded h2 wire bytes not yet fully written to inner. MUST persist across Poll::Pending
    /// so a partial socket write never drops the tail (which would desync the peer's framing).
    flush_pending: Vec<u8>,
    flush_offset: usize,
}

impl<S> CarrierStream<S> {
    pub fn new(inner: S, mode: CamouflageMode) -> Self {
        Self {
            inner,
            mode,
            h2_stream_id: 1,
            decoder: Decoder::new(),
            read_pending: Vec::new(),
            read_offset: 0,
            write_buf: Vec::new(),
            flush_pending: Vec::new(),
            flush_offset: 0,
        }
    }

    pub fn mode(&self) -> CamouflageMode {
        self.mode
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> CarrierStream<S> {
    pub async fn client_bootstrap(inner: &mut S) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        inner.write_all(&h2::client_bootstrap()).await?;
        inner.flush().await?;
        Ok(())
    }

    pub async fn server_bootstrap(inner: &mut S) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut preface = [0u8; 24];
        inner.read_exact(&mut preface).await?;
        if preface != h2::PREFACE {
            return Err(anyhow!("invalid h2 preface"));
        }
        let mut hdr = [0u8; 9];
        inner.read_exact(&mut hdr).await?;
        if hdr != CLIENT_SETTINGS_HEADER {
            return Err(anyhow!(
                "invalid h2 bootstrap: expected canonical empty SETTINGS frame"
            ));
        }
        inner.write_all(&h2::server_bootstrap()).await?;
        inner.flush().await?;
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CarrierStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.mode == CamouflageMode::Raw || this.mode == CamouflageMode::DnsChunk {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.mode == CamouflageMode::Raw || this.mode == CamouflageMode::DnsChunk {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
        // Encode any newly-buffered plaintext, appending to the PERSISTENT pending wire.
        if !this.write_buf.is_empty() {
            let wire = h2::encode_data(this.h2_stream_id, &this.write_buf);
            this.write_buf.clear();
            this.flush_pending.extend_from_slice(&wire);
        }
        // Drain the pending wire to inner. On Poll::Pending the un-written tail stays in
        // flush_pending/flush_offset so the next poll resumes exactly where it stopped —
        // never dropping bytes (the old code cleared write_buf and lost the local `wire`).
        while this.flush_offset < this.flush_pending.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.flush_pending[this.flush_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => this.flush_offset += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.flush_pending.clear();
        this.flush_offset = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CarrierStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.mode == CamouflageMode::Raw || self.mode == CamouflageMode::DnsChunk {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        loop {
            if self.read_offset < self.read_pending.len() {
                let remain = &self.read_pending[self.read_offset..];
                let n = remain.len().min(buf.remaining());
                buf.put_slice(&remain[..n]);
                self.read_offset += n;
                if self.read_offset >= self.read_pending.len() {
                    self.read_pending.clear();
                    self.read_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match self.decoder.next_data_payload() {
                Ok(Some(payload)) => {
                    let n = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..n]);
                    if n < payload.len() {
                        self.read_pending = payload;
                        self.read_offset = n;
                    }
                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            }

            let mut tmp = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    if let Err(e) = self.decoder.push(read_buf.filled()) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                    // loop: drain any complete H2 DATA frames before polling inner again
                }
            }
        }
    }
}

pub type MaybePrefixedTcp = CarrierStream<PrefixedStream<tokio::net::TcpStream>>;

pub async fn client_connect(
    stream: tokio::net::TcpStream,
    mode: CamouflageMode,
) -> Result<CarrierStream<tokio::net::TcpStream>> {
    let mut stream = stream;
    if mode == CamouflageMode::H2Chunk {
        CarrierStream::client_bootstrap(&mut stream).await?;
    }
    Ok(CarrierStream::new(stream, mode))
}

pub async fn server_accept(stream: tokio::net::TcpStream) -> Result<MaybePrefixedTcp> {
    use std::time::Duration;

    let mut stream = stream;
    let mut peek = [0u8; 24];
    let n = match tokio::time::timeout(Duration::from_millis(200), stream.peek(&mut peek)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => 0,
    };

    if n >= 3 && &peek[..3] == b"PRI" {
        CarrierStream::server_bootstrap(&mut stream).await?;
        return Ok(CarrierStream::new(
            PrefixedStream::new(stream, Vec::new()),
            CamouflageMode::H2Chunk,
        ));
    }

    Ok(CarrierStream::new(
        PrefixedStream::new(stream, Vec::new()),
        CamouflageMode::Raw,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn h2_bootstrap_accepts_only_the_canonical_empty_settings_frame() {
        let (mut client, mut server) = tokio::io::duplex(128);
        client.write_all(&h2::client_bootstrap()).await.unwrap();

        CarrierStream::server_bootstrap(&mut server).await.unwrap();

        let mut response = [0u8; 9];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response.as_slice(), h2::server_bootstrap());
    }

    #[tokio::test]
    async fn h2_bootstrap_rejects_attacker_length_before_body_or_allocation() {
        let (mut attacker, mut server) = tokio::io::duplex(128);
        attacker.write_all(h2::PREFACE).await.unwrap();
        // 0x00ff_ffff is the largest HTTP/2 24-bit length. No body follows. A
        // vulnerable parser allocates it and blocks; the strict parser rejects
        // the nine-byte header synchronously.
        attacker
            .write_all(&[0xff, 0xff, 0xff, 0x04, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            CarrierStream::server_bootstrap(&mut server),
        )
        .await
        .expect("bootstrap parser waited for an attacker-sized body");
        let error = result.expect_err("oversized bootstrap was accepted");
        assert!(
            format!("{error:#}").contains("canonical empty SETTINGS"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn h2_bootstrap_rejects_wrong_type_flags_or_stream() {
        for header in [
            [0, 0, 0, 0x00, 0, 0, 0, 0, 0],
            [0, 0, 0, 0x04, 0x01, 0, 0, 0, 0],
            [0, 0, 0, 0x04, 0, 0, 0, 0, 1],
        ] {
            let (mut attacker, mut server) = tokio::io::duplex(128);
            attacker.write_all(h2::PREFACE).await.unwrap();
            attacker.write_all(&header).await.unwrap();
            assert!(CarrierStream::server_bootstrap(&mut server).await.is_err());
        }
    }

    /// Regression for the real RU->NL crash (planeb-02): under socket backpressure the h2
    /// carrier's poll_flush dropped the un-written tail of a frame, desyncing the peer's
    /// frame parser (=> aead::Error / EOF). A 16-byte duplex forces partial writes on every
    /// flush; all bytes must still arrive intact. Loopback TCP (Cursor's test) never triggers
    /// this because its send buffer swallows the small frames whole.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2_carrier_survives_write_backpressure() {
        let (a, b) = tokio::io::duplex(16); // tiny => guaranteed partial writes
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();

        let p = payload.clone();
        let writer = tokio::spawn(async move {
            let mut cs = CarrierStream::new(a, CamouflageMode::H2Chunk);
            for chunk in p.chunks(1300) {
                cs.write_all(chunk).await.unwrap();
                cs.flush().await.unwrap();
            }
            cs.shutdown().await.unwrap();
        });

        let mut cs = CarrierStream::new(b, CamouflageMode::H2Chunk);
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = cs.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        assert_eq!(
            got.len(),
            payload.len(),
            "byte count drifted under backpressure"
        );
        assert_eq!(
            got, payload,
            "carrier corrupted the stream under backpressure"
        );
    }
}
