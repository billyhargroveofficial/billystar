//! `RealityStream` — exposes an established REALITY/TLS-1.3 connection as a plain
//! `AsyncRead + AsyncWrite` byte stream.
//!
//! The REALITY handshake ([`super::asio`]) yields a message-oriented connection
//! (`send(&[u8])` / `recv() -> Vec<u8>`), but everything that rides the carrier in
//! shadowpipe (the PQ authenticated-session handshake and the
//! tunnel) is written against a byte stream. This adapter bridges the two.
//!
//! The trick (and why this is cheap): [`RecordCrypto::seal`]/`open` are pure
//! compute over whole wire records. So instead of fighting the `async fn`
//! `send`/`recv` from inside a `poll_*` method, we hold the post-handshake
//! application [`RecordCrypto`] pair directly and do the record framing ourselves
//! in `poll`-land — seal a chunk on write, accumulate-and-open a record on read.
//! `inner`'s own `poll_read`/`poll_write` provide the byte plumbing and natural
//! backpressure.

use super::RecordCrypto;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TLS 1.3 record plaintext cap (2^14). We never seal a larger fragment, so the
/// records we emit stay within spec and look like ordinary TLS records.
const MAX_PLAINTEXT: usize = 16384;

/// Number of leading application records whose wire length is shaped per
/// connection. First-N-packet ML classifiers key on the size+direction sequence
/// of roughly the first handful of records; shaping this prefix is what breaks
/// the fixed template.
const SHAPED_RECORDS: usize = 8;
/// Shaped target content sizes are drawn from `[SHAPE_MIN, SHAPE_MAX]` (bytes).
/// Bounded well under `MAX_PLAINTEXT` so `content+type+pad` stays in-spec and the
/// padding overhead on a short write is modest.
const SHAPE_MIN: usize = 512;
const SHAPE_MAX: usize = 8192;

/// Per-connection plan that varies the wire length of the first
/// [`SHAPED_RECORDS`] application records. Each connection draws a different
/// pseudo-random target sequence (seeded once at construction), so the
/// first-N-record length sequence a passive classifier sees matches no fixed
/// template and differs across connections — while every record stays a
/// well-formed TLS 1.3 record. Records are split down to (and short writes padded
/// up to) the target via [`RecordCrypto::seal_padded`], so the *wire* length is
/// the target regardless of how much real data was available.
struct RecordShaper {
    targets: [usize; SHAPED_RECORDS],
    idx: usize,
}

impl RecordShaper {
    fn new(seed: u64) -> Self {
        let mut s = seed ^ 0xA5A5_5A5A_C3C3_3C3C; // decorrelate trivial seeds
        let mut targets = [0usize; SHAPED_RECORDS];
        let span = (SHAPE_MAX - SHAPE_MIN + 1) as u64;
        for t in targets.iter_mut() {
            // SplitMix64-style step → well-distributed even for sequential seeds.
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            *t = SHAPE_MIN + (z % span) as usize;
        }
        Self { targets, idx: 0 }
    }

    /// Target content size for the next record, or `None` once past the shaped
    /// prefix (after which records take their natural size).
    fn next_target(&mut self) -> Option<usize> {
        let t = self.targets.get(self.idx).copied();
        if t.is_some() {
            self.idx += 1;
        }
        t
    }
}

/// A byte stream over an established REALITY connection's application-data
/// channel. `tx` seals what we write; `rx` opens what we read.
pub struct RealityStream<S> {
    inner: S,
    tx: RecordCrypto,
    rx: RecordCrypto,
    // Write side: one sealed record (or its un-written tail) awaiting `inner`.
    write_buf: Vec<u8>,
    write_off: usize,
    // Per-connection outer-record-length shaping plan (anti first-N-packet ML).
    shaper: RecordShaper,
    // Read side: raw bytes accumulating toward a full record, and decrypted
    // plaintext not yet handed to the caller.
    read_raw: Vec<u8>,
    read_plain: Vec<u8>,
    read_off: usize,
}

impl<S> RealityStream<S> {
    /// `tx` = the AEAD that seals our outbound application data; `rx` = the AEAD
    /// that opens inbound records. (Client: tx=client_app, rx=server_app; server:
    /// the mirror — see `into_stream` on the connection types.) The record-length
    /// shaper is seeded randomly per connection.
    pub(crate) fn new(inner: S, tx: RecordCrypto, rx: RecordCrypto) -> Self {
        Self::with_shaper_seed(inner, tx, rx, rand::random())
    }

    /// As [`new`](Self::new) but with an explicit shaper seed (deterministic
    /// record-length plan — for tests).
    pub(crate) fn with_shaper_seed(
        inner: S,
        tx: RecordCrypto,
        rx: RecordCrypto,
        seed: u64,
    ) -> Self {
        Self {
            inner,
            tx,
            rx,
            write_buf: Vec::new(),
            write_off: 0,
            shaper: RecordShaper::new(seed),
            read_raw: Vec::new(),
            read_plain: Vec::new(),
            read_off: 0,
        }
    }

    /// Recover the underlying transport (e.g. the TCP socket).
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Length of the complete record at the front of `raw`, if fully buffered.
fn full_record_len(raw: &[u8]) -> Option<usize> {
    if raw.len() < 5 {
        return None;
    }
    let body = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let total = 5 + body;
    (raw.len() >= total).then_some(total)
}

impl<S: AsyncWrite + Unpin> RealityStream<S> {
    /// Drain `write_buf` to `inner`. `Pending` leaves the un-written tail in place
    /// (tracked by `write_off`) so the next poll resumes exactly where it stopped —
    /// a partial socket write must never drop the tail or the peer's framing desyncs.
    fn flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_off < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_off..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "reality stream: underlying write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => self.write_off += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Finish flushing the previous record before sealing a new one — this is
        // the backpressure point and keeps at most one record buffered.
        match this.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Shape the first SHAPED_RECORDS records to the per-connection length plan
        // (split a long write down to the target; pad a short write up to it), then
        // fall back to natural fragment sizing. `take` real bytes are consumed
        // either way, so framing/backpressure are unchanged.
        let (take, pad) = match this.shaper.next_target() {
            Some(t) => {
                let take = buf.len().min(t);
                (take, t - take)
            }
            None => (buf.len().min(MAX_PLAINTEXT), 0),
        };
        this.write_buf = this.tx.seal_padded(0x17, &buf[..take], pad);
        this.write_off = 0;
        // Best-effort flush: if it returns Pending the bytes stay buffered and are
        // flushed by the next poll_write/poll_flush — we've still accepted `take`.
        if let Poll::Ready(Err(e)) = this.flush_write_buf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1. Hand out any decrypted plaintext we're still holding.
            if this.read_off < this.read_plain.len() {
                let remain = &this.read_plain[this.read_off..];
                let n = remain.len().min(buf.remaining());
                buf.put_slice(&remain[..n]);
                this.read_off += n;
                if this.read_off >= this.read_plain.len() {
                    this.read_plain.clear();
                    this.read_off = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. Open a fully-buffered record, if we have one.
            if let Some(rec_len) = full_record_len(&this.read_raw) {
                let rec: Vec<u8> = this.read_raw.drain(..rec_len).collect();
                match this.rx.open(&rec) {
                    // Application data: serve it on the next loop turn.
                    Some((0x17, pt)) => {
                        this.read_plain = pt;
                        this.read_off = 0;
                        continue;
                    }
                    // A close_notify (or any) alert ⇒ clean EOF for the caller.
                    Some((0x15, _)) => return Poll::Ready(Ok(())),
                    // Post-handshake handshake messages (tickets/key_update) or
                    // anything else: skip and read on.
                    Some(_) => continue,
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "reality stream: AEAD record open failed",
                        )))
                    }
                }
            }

            // 3. No full record yet — pull more bytes from inner.
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(())); // transport EOF
                    }
                    this.read_raw.extend_from_slice(rb.filled());
                    // loop to try framing/opening a record
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::reality::{
        reality_accept_async, RealityAcceptAsync, RealityServerConfig, ReplayCache,
    };
    use crate::tls13::asio::client_handshake;
    use crate::tls13::CertVerify;
    use crate::{build_authed_client_hello, Grease, GREASE};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn grease() -> Grease {
        Grease {
            cipher: GREASE[0],
            group: GREASE[1],
            ext_lead: GREASE[2],
            version: GREASE[3],
            ext_trail: GREASE[4],
        }
    }

    /// End-to-end over real TCP + a real REALITY handshake: wrap both sides in
    /// `RealityStream` and push a payload several TLS records long through each
    /// direction. Proves the adapter chunks on write and reassembles on read
    /// without dropping or corrupting a byte — the property the tunnel relies on.
    #[tokio::test]
    async fn reality_stream_round_trips_multi_record_payloads_both_ways() {
        const N: usize = 40_000; // > 2 * MAX_PLAINTEXT ⇒ forces ≥3 records each way

        let server_static = StaticSecret::random_from_rng(rand::thread_rng());
        let server_pub = PublicKey::from(&server_static).to_bytes();
        let short_id = vec![0x11, 0x22];
        let cfg = Arc::new(RealityServerConfig {
            static_secret: server_static,
            short_ids: vec![short_id.clone()],
            cover: "127.0.0.1:1".into(),
            max_time_skew_secs: None,
            replay_cache: ReplayCache::in_memory_for_tests(),
            cover_profile: None,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg2 = cfg.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let RealityAcceptAsync::TokenAccepted(conn) =
                reality_accept_async(sock, &cfg2).await.unwrap()
            else {
                panic!("expected the accepted-token path");
            };
            let mut s = conn.into_stream();
            let mut got = vec![0u8; N];
            s.read_exact(&mut got).await.unwrap();
            // Echo it straight back through the adapter.
            s.write_all(&got).await.unwrap();
            s.flush().await.unwrap();
            got
        });

        let (hello, eph, auth_key) =
            build_authed_client_hello("www.example.com", &server_pub, &short_id, 0, &grease(), 517)
                .expect("generated server public key is contributory");
        let tcp = TcpStream::connect(addr).await.unwrap();
        let conn = client_handshake(tcp, &hello, &eph, CertVerify::RealityHmac(auth_key))
            .await
            .unwrap();
        let mut s = conn.into_stream();

        let payload: Vec<u8> = (0..N as u32).map(|i| (i % 251) as u8).collect();
        s.write_all(&payload).await.unwrap();
        s.flush().await.unwrap();
        let mut back = vec![0u8; N];
        s.read_exact(&mut back).await.unwrap();

        assert_eq!(
            back, payload,
            "payload survived the RealityStream round-trip"
        );
        assert_eq!(server.await.unwrap(), payload, "server received it intact");
    }

    use super::{RealityStream, RecordShaper, SHAPED_RECORDS, SHAPE_MAX, SHAPE_MIN};
    use crate::tls13::record::{RecordCrypto, Suite};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    #[test]
    fn record_shaper_is_deterministic_bounded_and_diverges() {
        let (mut a, mut a2, mut b) = (
            RecordShaper::new(12345),
            RecordShaper::new(12345),
            RecordShaper::new(12346),
        );
        let (mut sa, mut sa2, mut sb) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..SHAPED_RECORDS {
            let t = a.next_target().unwrap();
            assert!((SHAPE_MIN..=SHAPE_MAX).contains(&t), "target {t} in band");
            sa.push(t);
            sa2.push(a2.next_target().unwrap());
            sb.push(b.next_target().unwrap());
        }
        assert_eq!(sa, sa2, "same seed ⇒ identical plan");
        assert_ne!(sa, sb, "different seed ⇒ different plan");
        assert_eq!(a.next_target(), None, "no shaping past the prefix");
    }

    // Minimal in-memory AsyncWrite sink so a test can inspect the emitted records.
    struct VecSink(Vec<u8>);
    impl tokio::io::AsyncWrite for VecSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.get_mut().0.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // Seal `payload` through a seeded RealityStream and return the outer wire-record
    // lengths (5-byte header + ciphertext body) in emission order.
    async fn emitted_record_lens(payload: &[u8], seed: u64) -> Vec<usize> {
        use tokio::io::AsyncWriteExt;
        let secret = [0x42u8; 32];
        let tx = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        let rx = RecordCrypto::new(&secret, Suite::Aes128GcmSha256);
        let mut s = RealityStream::with_shaper_seed(VecSink(Vec::new()), tx, rx, seed);
        s.write_all(payload).await.unwrap();
        s.flush().await.unwrap();
        let raw = s.into_inner().0;
        let mut lens = Vec::new();
        let mut i = 0;
        while i + 5 <= raw.len() {
            let body = u16::from_be_bytes([raw[i + 3], raw[i + 4]]) as usize;
            lens.push(5 + body);
            i += 5 + body;
        }
        lens
    }

    /// The anti-first-N-packet-ML property: two connections shape the first
    /// SHAPED_RECORDS records to *different* wire lengths (no fixed template), every
    /// shaped record sits in the planned band, and a given seed is reproducible.
    #[tokio::test]
    async fn record_shaper_varies_first_n_record_lengths_per_connection() {
        let payload = vec![0xABu8; SHAPED_RECORDS * SHAPE_MAX + 4096]; // ≥ N full records
        let a = emitted_record_lens(&payload, 1).await;
        let b = emitted_record_lens(&payload, 2).await;
        assert!(a.len() >= SHAPED_RECORDS && b.len() >= SHAPED_RECORDS);
        assert_ne!(
            a[..SHAPED_RECORDS],
            b[..SHAPED_RECORDS],
            "first-N record-length sequence must differ between connections"
        );
        for &l in a[..SHAPED_RECORDS].iter().chain(b[..SHAPED_RECORDS].iter()) {
            // shaped wire = target(content) + type(1) + tag(16) + header(5) = target + 22
            assert!(
                (SHAPE_MIN + 22..=SHAPE_MAX + 22).contains(&l),
                "shaped record len {l} outside the planned band"
            );
        }
        assert_eq!(
            a,
            emitted_record_lens(&payload, 1).await,
            "same seed ⇒ same lengths"
        );
    }
}
