//! Experimental degradation-response pacer (ZATMENIE A-plane primitive, Phase 1).
//!
//! Differential-degradation research (arXiv:2409.06247) motivates testing whether
//! a tunnel that ignores a degrading path becomes distinguishable from genuine
//! cover traffic. This pacer clamps the covert send rate using local path signals.
//! It is a bounded heuristic: it has not established cover-traffic equivalence,
//! censor resistance, or the mechanism behind any reported RU stall.
//!
//! Rate law (dual-regime, keeps `k` dimensionless and never starves a tiny path):
//! ```text
//!   covert_rate = k_frac · g · √(R0 / max(g, R0))
//! ```
//! — for goodput `g ≥ R0` this is `k_frac·√(g·R0)` (sub-linear: the covert share
//! shrinks as the path fattens); for `g < R0` it is `k_frac·g` (linear: covert is
//! a fixed fraction of a small path, never paced *above* capacity).
//!
//! **Goodput proxy `g = EWMA(cwnd / rtt)`** comes from quinn's QUIC path stats.
//! It responds to loss and delay through the transport's congestion controller,
//! but is not an exact application-goodput or cover-flow model. Because it is
//! sampled below this application pacer, it avoids the most direct self-throttling
//! feedback loop; shared queues and transport dynamics can still couple it.
//!
//! **Two feedback sources.** On a QUIC carrier the signal is the transport's own
//! `cwnd/rtt` (above). On a plain TCP carrier (Chrome-TLS / REALITY) there is no
//! portable userspace `cwnd`, so [`TcpAppRttProbe`] synthesizes an equivalent
//! `PathSample` from app-RTT over timestamped PING/reply frames, the rate the
//! *peer's* DATA bytes arrive, and reply absence. These are useful local signals,
//! not a robust censor detector: asymmetric traffic, application idleness,
//! backpressure, and peer failure can produce the same observation.
//!
//! ⚠️ **RU on-path effect is NOT validated** (same posture as `--kill-switch`,
//! `--quic`) — loopback-correct only. v2 pacer: tighter burst (~2 ms), per-gate
//! slice cap, and EWMA-smoothed rate transitions so constant goodput does not
//! emit in 8 ms lumps. Optional bounded jitter keeps the mean on the goodput
//! envelope while breaking the constant-rate line (FOCI'25).

use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// Token-bucket burst window (seconds). v1 used 8 ms, which let one `gate()` drain
/// a full lump at steady goodput; v2 tightens to ~2 ms.
const BURST_WINDOW_S: f64 = 0.002;
/// Max credit granted per `gate()` iteration — spreads large TUN frames across
/// several short sleeps instead of one burst draw.
const MAX_GATE_SLICE_S: f64 = 0.002;

pub const REFERENCE_RATE_BPS: f64 = 125_000.0;
/// Floor so the pacer never intentionally drives its own carrier fully idle.
pub const DEFAULT_MIN_RATE_BPS: f64 = 16_000.0;
/// Ceiling (100 Mbit/s); the live `cwnd/rtt` keeps it realistic.
pub const DEFAULT_MAX_RATE_BPS: f64 = 12_500_000.0;

/// Pacer knobs. `Copy`, lives in [`crate::profile::TunnelProfile`]. Default is
/// **disabled** (opt-in), mirroring [`crate::volume_guard::VolumeGuardConfig`].
#[derive(Debug, Clone, Copy)]
pub struct PacerConfig {
    pub enabled: bool,
    /// Dimensionless covert share at the reference rate (0.15–0.35; default 0.25).
    pub k_frac: f64,
    /// Rate-law normalization point `R0` in bytes/sec.
    pub reference_rate_bps: f64,
    /// EWMA smoothing of the goodput estimate (~8-tick memory at 0.125).
    pub ewma_alpha: f64,
    pub min_rate_bps: f64,
    pub max_rate_bps: f64,
    /// Sampler period (how often the QUIC path is read + rate recomputed).
    pub recompute_interval: Duration,
    /// Apply bounded random-walk jitter to the rate (anti-fingerprint). Off in
    /// tests for determinism; on in production.
    pub jitter: bool,
}

impl Default for PacerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            k_frac: 0.25,
            reference_rate_bps: REFERENCE_RATE_BPS,
            ewma_alpha: 0.125,
            min_rate_bps: DEFAULT_MIN_RATE_BPS,
            max_rate_bps: DEFAULT_MAX_RATE_BPS,
            recompute_interval: Duration::from_millis(100),
            jitter: true,
        }
    }
}

/// A live QUIC path-feedback snapshot. `cwnd/rtt` is the deliverable-rate estimate;
/// degradation is encoded in `cwnd` shrinking and `rtt` growing.
#[derive(Debug, Clone, Copy)]
pub struct PathSample {
    pub rtt: Duration,
    pub cwnd: u64,
}

/// A live source of [`PathSample`]s — implemented by the QUIC carrier
/// (`quinn::Connection::stats().path`). TCP carriers have no source, so the pacer
/// stays inert there.
pub trait PathStatsSource: Send + Sync {
    fn sample(&self) -> PathSample;
}

/// The pure rate law: `k_frac·g·√(R0/max(g,R0))`, clamped. Tested directly.
fn target_rate_bps(goodput_bps: f64, cfg: &PacerConfig) -> f64 {
    let g = goodput_bps.max(0.0);
    let r0 = cfg.reference_rate_bps.max(1.0);
    let base = cfg.k_frac * g * (r0 / g.max(r0)).sqrt();
    if base.is_finite() {
        base.clamp(cfg.min_rate_bps, cfg.max_rate_bps)
    } else {
        cfg.min_rate_bps
    }
}

struct Inner {
    // token bucket (bytes)
    tokens: f64,
    last_refill: Instant,
    rate_bps: f64,
    // goodput estimator
    last_recompute: Instant,
    goodput_ewma: f64,
    // anti-fingerprint random-walk multiplier
    jitter: f64,
    jitter_seed: u64,
}

impl Inner {
    fn new(cfg: &PacerConfig, now: Instant) -> Self {
        Self {
            tokens: 0.0,
            last_refill: now,
            // Start at the reference-derived rate so a fresh tunnel is not throttled
            // to the floor before the first cwnd/rtt sample arrives.
            rate_bps: target_rate_bps(cfg.reference_rate_bps, cfg),
            last_recompute: now,
            goodput_ewma: cfg.reference_rate_bps,
            jitter: 1.0,
            jitter_seed: 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn burst(&self) -> f64 {
        // ~2 ms of credit, bounded. Keeps the bucket from handing out 8 ms lumps
        // when goodput is flat (the v1 burst tell under constant-rate fingerprinting).
        let b = self.rate_bps * BURST_WINDOW_S;
        if b.is_finite() {
            b.clamp(1_024.0, 16_384.0)
        } else {
            1_024.0
        }
    }

    /// Per-iteration cap inside [`gate`](DegradationPacer::gate): at most ~2 ms of
    /// bytes per sleep cycle, even if the bucket holds more.
    fn max_gate_slice(&self) -> f64 {
        let slice = self.rate_bps * MAX_GATE_SLICE_S;
        if slice.is_finite() {
            slice.clamp(512.0, 8_192.0)
        } else {
            512.0
        }
    }

    /// Refill by elapsed·rate (lazy), then try to take `need`. Returns `None` if
    /// granted, or `Some(wait)` if the caller must sleep. Large requests are sliced
    /// across several iterations via [`max_gate_slice`](Self::max_gate_slice).
    fn refill_and_take(&mut self, need: f64, now: Instant) -> Option<Duration> {
        let dt = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        let burst = self.burst();
        self.tokens = (self.tokens + dt * self.rate_bps).min(burst);
        self.last_refill = now;
        let need = need.min(self.max_gate_slice()).min(burst);
        if self.tokens >= need {
            self.tokens -= need;
            None
        } else {
            let deficit = need - self.tokens;
            let secs = deficit / self.rate_bps.max(1.0);
            let secs = if secs.is_finite() { secs.min(5.0) } else { 0.0 };
            Some(Duration::from_secs_f64(secs))
        }
    }

    /// Cheap deterministic LCG noise in [-0.05, 0.05] for the jitter random-walk.
    fn jitter_noise(&mut self) -> f64 {
        self.jitter_seed = self
            .jitter_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let u = (self.jitter_seed >> 40) as f64 / (1u64 << 24) as f64; // [0,1)
        (u - 0.5) * 0.10
    }

    fn recompute(&mut self, cfg: &PacerConfig, sample: PathSample, now: Instant) {
        let dt = now
            .saturating_duration_since(self.last_recompute)
            .as_secs_f64();
        if dt <= 0.0 {
            return;
        }
        self.last_recompute = now;

        // cwnd/rtt = the path's deliverable rate — gate-independent and already
        // degradation-aware (cwnd shrinks on loss, rtt grows on delay).
        if sample.cwnd > 0 {
            let rtt_s = sample.rtt.as_secs_f64().max(1e-6);
            let bdp_rate = sample.cwnd as f64 / rtt_s;
            if bdp_rate.is_finite() && bdp_rate > 0.0 {
                self.goodput_ewma =
                    cfg.ewma_alpha * bdp_rate + (1.0 - cfg.ewma_alpha) * self.goodput_ewma;
            }
        }

        if cfg.jitter {
            let noise = self.jitter_noise();
            self.jitter = (self.jitter * 0.9 + noise + 0.1).clamp(0.85, 1.15);
        } else {
            self.jitter = 1.0;
        }

        let r = target_rate_bps(self.goodput_ewma, cfg) * self.jitter;
        let target = if r.is_finite() {
            r.clamp(cfg.min_rate_bps, cfg.max_rate_bps)
        } else {
            cfg.min_rate_bps
        };
        // Smooth rate transitions (v2): avoid step jumps when goodput is flat.
        self.rate_bps = cfg.ewma_alpha * target + (1.0 - cfg.ewma_alpha) * self.rate_bps;
        self.rate_bps = self.rate_bps.clamp(cfg.min_rate_bps, cfg.max_rate_bps);
    }
}

/// The pacer: a send-rate governor driven by QUIC path feedback. The only `.await`
/// is [`gate`](Self::gate), which sleeps **outside** the lock so it can never
/// deadlock the send mutex.
pub struct DegradationPacer {
    config: PacerConfig,
    inner: Mutex<Inner>,
}

impl DegradationPacer {
    pub fn new(config: PacerConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            inner: Mutex::new(Inner::new(&config, now)),
        }
    }

    /// A no-op pacer (mirrors [`crate::volume_guard::VolumeGuard::disabled`]).
    pub fn disabled() -> Self {
        Self::new(PacerConfig {
            enabled: false,
            ..Default::default()
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// The pacer's config — so a TCP carrier can build a [`TcpAppRttProbe`] with the
    /// same reference rate and EWMA smoothing.
    pub fn config(&self) -> PacerConfig {
        self.config
    }

    /// Sampler period (how often [`observe_path`](Self::observe_path) is called).
    pub fn sample_interval(&self) -> Duration {
        self.config.recompute_interval
    }

    /// Block until the covert-byte budget allows ~`bytes`. Returns immediately when
    /// disabled. Large frames are sliced across several short sleeps (v2). Sleeps
    /// OUTSIDE the lock (caller must NOT hold the session mutex — gate before framing).
    pub async fn gate(&self, bytes: usize) {
        if !self.config.enabled {
            return;
        }
        let mut remaining = bytes as f64;
        while remaining > 0.0 {
            let wait = {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let take = remaining.min(inner.max_gate_slice());
                match inner.refill_and_take(take, Instant::now()) {
                    None => {
                        remaining -= take;
                        None
                    }
                    Some(d) => Some(d),
                }
            };
            match wait {
                None if remaining <= 0.0 => return,
                None => {}
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }

    /// Sampler tick: fold a live QUIC path sample (`cwnd/rtt`) into the rate.
    pub fn observe_path(&self, sample: PathSample) {
        if !self.config.enabled {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.recompute(&self.config, sample, Instant::now());
    }

    /// Current pacing target (bytes/sec) — for telemetry/tests.
    pub fn current_rate_bps(&self) -> f64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rate_bps
    }

    /// Current goodput estimate (bytes/sec) — for telemetry.
    pub fn current_goodput_bps(&self) -> f64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .goodput_ewma
    }

    /// True when pinned to the rate floor (visible collapse symptom).
    pub fn is_at_floor(&self) -> bool {
        self.current_rate_bps() <= self.config.min_rate_bps * 1.05
    }
}

// ---------------------------------------------------------------------------
// App-RTT probe — a `PathStatsSource` for TCP carriers (no userspace cwnd/rtt).
// ---------------------------------------------------------------------------

/// First byte of a [`FrameFlags::PING`](crate::proto::FrameFlags) payload: a
/// *request* asks the peer to echo the carried 8-byte originator timestamp.
const PING_REQUEST_TAG: u8 = 0x01;
/// First byte of a PING payload that is a *reply* — the peer echoing back the
/// originator's timestamp so the originator can compute RTT in its own clock.
const PING_REPLY_TAG: u8 = 0x02;
/// tag (1) + big-endian u64 micros (8).
pub const PING_MSG_LEN: usize = 9;

/// A decoded `FrameFlags::PING` payload. The same flag carries both directions of
/// the app-RTT handshake; the tag disambiguates, and anything unrecognized (the
/// legacy `b"pong"`, or an old peer) is [`Legacy`](PingMsg::Legacy) — never sampled
/// and never re-replied, so old and new binaries can't form a ping/pong loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingMsg {
    /// Peer asks us to echo this timestamp.
    Request([u8; 8]),
    /// Peer echoed back a timestamp we originated (value is in *our* clock).
    Reply([u8; 8]),
    /// Unrecognized — no RTT sample, do not re-reply.
    Legacy,
}

/// Classify a received PING payload. Pure.
pub fn parse_ping(payload: &[u8]) -> PingMsg {
    if payload.len() >= PING_MSG_LEN {
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&payload[1..9]);
        match payload[0] {
            PING_REQUEST_TAG => return PingMsg::Request(ts),
            PING_REPLY_TAG => return PingMsg::Reply(ts),
            _ => {}
        }
    }
    PingMsg::Legacy
}

/// Build a PING *request* payload carrying `ts_micros`.
pub fn build_ping_request(ts_micros: u64) -> [u8; PING_MSG_LEN] {
    let mut b = [0u8; PING_MSG_LEN];
    b[0] = PING_REQUEST_TAG;
    b[1..9].copy_from_slice(&ts_micros.to_be_bytes());
    b
}

/// Build a PING *reply* echoing the originator's 8-byte timestamp.
pub fn build_ping_reply(ts: [u8; 8]) -> [u8; PING_MSG_LEN] {
    let mut b = [0u8; PING_MSG_LEN];
    b[0] = PING_REPLY_TAG;
    b[1..9].copy_from_slice(&ts);
    b
}

/// Base period between originated app-RTT pings (jittered ±30% to avoid a
/// trivially constant probe cadence; this is not a traffic-analysis proof).
const PROBE_PING_INTERVAL: Duration = Duration::from_millis(400);
/// Below this measured peer throughput (B/s) the delivered-rate is treated as
/// "idle" and capacity falls back to the reference rate, so a healthy path with
/// light return traffic is not starved to the floor (only a *stall* floors it).
const PROBE_DELIVERED_ACTIVE_FLOOR: f64 = 2_000.0;
/// RTT inflation alone can attenuate `g` to at most this fraction; a full collapse
/// is left to the reply-absence heuristic.
const PROBE_RTT_HEALTH_FLOOR: f64 = 0.10;

struct ProbeInner {
    rtt_ewma_s: f64,
    rtt_min_s: f64,
    has_rtt: bool,
    delivered_ewma: f64,
    bytes_since_mark: u64,
    last_mark: Instant,
    last_reply: Instant,
    jitter_seed: u64,
}

/// An app-level RTT + delivered-rate probe for **TCP carriers**. Implements
/// [`PathStatsSource`] from three signals, all independent of this side's own
/// pacer gating (so it cannot death-spiral):
///   1. **app-RTT** — timestamped `FrameFlags::PING`/reply round-trips;
///   2. **delivered-rate** — the rate the *peer's* DATA wire-bytes arrive;
///   3. **reply absence** — if replies stop, `g` is driven to the floor regardless
///      of (1)/(2); this is a health signal, not censor attribution.
///
/// `g = capacity · rtt_health · stall_health`, where `capacity` is the measured
/// delivered-rate when the peer is actively sending, else the reference rate. The
/// returned [`PathSample`] sets `cwnd = g·rtt`, so the pacer's `cwnd/rtt` recovers
/// exactly `g`.
pub struct TcpAppRttProbe {
    start: Instant,
    reference_rate_bps: f64,
    ewma_alpha: f64,
    inner: Mutex<ProbeInner>,
}

impl TcpAppRttProbe {
    pub fn new(reference_rate_bps: f64, ewma_alpha: f64) -> Self {
        let now = Instant::now();
        Self {
            start: now,
            reference_rate_bps: reference_rate_bps.max(1.0),
            ewma_alpha: ewma_alpha.clamp(0.01, 1.0),
            inner: Mutex::new(ProbeInner {
                rtt_ewma_s: 0.05,
                rtt_min_s: 0.05,
                has_rtt: false,
                delivered_ewma: 0.0,
                bytes_since_mark: 0,
                last_mark: now,
                last_reply: now,
                jitter_seed: 0xDEAD_BEEF_1234_5678,
            }),
        }
    }

    fn now_micros(&self) -> u64 {
        Instant::now()
            .saturating_duration_since(self.start)
            .as_micros() as u64
    }

    /// The next originated PING payload, stamped with the current time.
    pub fn next_ping(&self) -> [u8; PING_MSG_LEN] {
        build_ping_request(self.now_micros())
    }

    /// Jittered delay until the next originated ping (±30% of the base period).
    pub fn ping_interval(&self) -> Duration {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.jitter_seed = inner
            .jitter_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let u = (inner.jitter_seed >> 40) as f64 / (1u64 << 24) as f64; // [0,1)
        PROBE_PING_INTERVAL.mul_f64(0.7 + 0.6 * u) // [0.7, 1.3)·base
    }

    /// Fold a received reply (our echoed timestamp) into the RTT estimate and reset
    /// the stall clock. `ts` is in *our* clock, so a peer clock offset is irrelevant.
    pub fn on_reply(&self, ts: [u8; 8]) {
        let now_us = self.now_micros();
        let sent = u64::from_be_bytes(ts);
        let rtt_s = now_us.saturating_sub(sent) as f64 / 1e6;
        if !rtt_s.is_finite() {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.last_reply = Instant::now();
        if !inner.has_rtt {
            inner.rtt_ewma_s = rtt_s.max(1e-6);
            inner.rtt_min_s = inner.rtt_ewma_s;
            inner.has_rtt = true;
        } else {
            inner.rtt_ewma_s = self.ewma_alpha * rtt_s + (1.0 - self.ewma_alpha) * inner.rtt_ewma_s;
            if inner.rtt_ewma_s < inner.rtt_min_s {
                inner.rtt_min_s = inner.rtt_ewma_s.max(1e-6);
            }
        }
    }

    /// Count `wire` bytes the peer delivered (a DATA frame) toward the rate estimate.
    pub fn on_peer_data(&self, wire: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.bytes_since_mark = inner.bytes_since_mark.saturating_add(wire);
    }
}

impl PathStatsSource for TcpAppRttProbe {
    fn sample(&self) -> PathSample {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // (1) delivered-rate EWMA from the peer's DATA bytes since the last sample.
        let dt = now.saturating_duration_since(inner.last_mark).as_secs_f64();
        if dt > 0.0 {
            let inst = inner.bytes_since_mark as f64 / dt;
            inner.delivered_ewma =
                self.ewma_alpha * inst + (1.0 - self.ewma_alpha) * inner.delivered_ewma;
            inner.bytes_since_mark = 0;
            inner.last_mark = now;
        }

        // (2) capacity: the measured delivered-rate when the peer is actively
        // sending, else the reference rate (do not starve a light-return path).
        let capacity = if inner.delivered_ewma > PROBE_DELIVERED_ACTIVE_FLOOR {
            inner.delivered_ewma
        } else {
            self.reference_rate_bps
        };

        // (3) rtt-health: nominal RTT ⇒ 1.0; inflation attenuates, floored.
        let rtt_health = if inner.has_rtt && inner.rtt_ewma_s > 0.0 {
            (inner.rtt_min_s / inner.rtt_ewma_s).clamp(PROBE_RTT_HEALTH_FLOOR, 1.0)
        } else {
            1.0
        };

        // (4) stall-health: replies flowing ⇒ 1.0; ramps to 0 across the
        // observation window. Reply absence is deliberately fail-slow for rate
        // control, but it does not distinguish censorship from other failures.
        let stall_health = if inner.has_rtt {
            let gap = now
                .saturating_duration_since(inner.last_reply)
                .as_secs_f64();
            let lo = 2.0 * PROBE_PING_INTERVAL.as_secs_f64();
            let hi = 5.0 * PROBE_PING_INTERVAL.as_secs_f64();
            if gap <= lo {
                1.0
            } else if gap >= hi {
                0.0
            } else {
                1.0 - (gap - lo) / (hi - lo)
            }
        } else {
            1.0
        };

        let g = (capacity * rtt_health * stall_health).max(0.0);
        let rtt = Duration::from_secs_f64(inner.rtt_ewma_s.max(1e-3));
        // cwnd = g·rtt so the pacer recovers cwnd/rtt = g.
        let cwnd = (g * rtt.as_secs_f64()).max(1.0) as u64;
        PathSample { rtt, cwnd }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PacerConfig {
        PacerConfig {
            enabled: true,
            jitter: false,
            ..Default::default()
        }
    }

    #[test]
    fn rate_follows_sqrt_law() {
        let c = cfg();
        let at_r0 = target_rate_bps(c.reference_rate_bps, &c);
        assert!((at_r0 - c.k_frac * c.reference_rate_bps).abs() < 1.0);
        // 4× goodput ⇒ 2× rate (sub-linear √ regime above R0).
        let at_4 = target_rate_bps(4.0 * c.reference_rate_bps, &c);
        assert!((at_4 / at_r0 - 2.0).abs() < 0.01, "4x goodput -> 2x rate");
        // Below R0 it tracks linearly (a small path is not starved).
        let half = target_rate_bps(0.5 * c.reference_rate_bps, &c);
        let expect = (c.k_frac * 0.5 * c.reference_rate_bps).max(c.min_rate_bps);
        assert!((half - expect).abs() < 1.0, "linear below R0");
    }

    #[test]
    fn rate_tracks_goodput_down_to_the_floor() {
        let c = cfg();
        let healthy = target_rate_bps(8.0 * c.reference_rate_bps, &c);
        let degraded = target_rate_bps(2.0 * c.reference_rate_bps, &c);
        assert!(degraded < healthy, "lower goodput ⇒ lower rate");
        let collapsed = target_rate_bps(1.0, &c);
        assert!((collapsed - c.min_rate_bps).abs() < 1.0);
        assert!(collapsed >= c.min_rate_bps);
    }

    #[test]
    fn disabled_gate_is_instant_and_no_op() {
        let p = DegradationPacer::disabled();
        assert!(!p.is_enabled());
        p.observe_path(PathSample {
            rtt: Duration::from_millis(10),
            cwnd: 1_000_000,
        });
        assert!(!p.is_at_floor() || p.current_rate_bps() > 0.0);
    }

    #[tokio::test(start_paused = true)]
    async fn gate_paces_to_the_target_rate() {
        let p = DegradationPacer::new(cfg());
        let rate = p.current_rate_bps();
        assert!(rate > 0.0);
        let start = Instant::now();
        let chunk = 1_400usize;
        for _ in 0..40 {
            p.gate(chunk).await;
        }
        let elapsed = start.elapsed().as_secs_f64();
        let bytes = (40 * chunk) as f64;
        let min_time = (bytes - p.inner.lock().unwrap().burst()) / rate;
        assert!(
            elapsed + 1e-6 >= min_time,
            "paced: {elapsed}s >= {min_time}s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gate_slices_large_frames_instead_of_one_burst() {
        let p = DegradationPacer::new(cfg());
        let rate = p.current_rate_bps();
        let slice = (rate * MAX_GATE_SLICE_S).clamp(512.0, 8_192.0);
        let big = (slice * 4.0) as usize;
        let start = Instant::now();
        p.gate(big).await;
        let elapsed = start.elapsed().as_secs_f64();
        // v1 would often finish in one tick (~0 s paused clock); v2 needs ≥2 slices.
        let min_slices = 3.0;
        let min_time = (min_slices - 1.0) * MAX_GATE_SLICE_S * 0.9;
        assert!(
            elapsed + 1e-6 >= min_time,
            "large gate spread over slices: {elapsed}s >= {min_time}s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rate_transitions_are_ewma_smoothed() {
        let p = DegradationPacer::new(cfg());
        let fat = PathSample {
            rtt: Duration::from_millis(20),
            cwnd: 4_000_000,
        };
        for _ in 0..8 {
            tokio::time::advance(Duration::from_millis(100)).await;
            p.observe_path(fat);
        }
        let hi = p.current_rate_bps();
        let thin = PathSample {
            rtt: Duration::from_millis(40),
            cwnd: 500_000,
        };
        tokio::time::advance(Duration::from_millis(100)).await;
        p.observe_path(thin);
        let after_one = p.current_rate_bps();
        // One tick does not snap to the new target — EWMA smooths the step.
        assert!(
            after_one > hi * 0.5,
            "rate did not snap down in one tick: {after_one} vs {hi}"
        );
        for _ in 0..16 {
            tokio::time::advance(Duration::from_millis(100)).await;
            p.observe_path(thin);
        }
        assert!(
            p.current_rate_bps() < after_one,
            "rate eventually tracks lower goodput"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn quic_cwnd_rtt_drives_the_rate_and_backs_off() {
        // Goodput = cwnd/rtt, independent of app bytes (no death-spiral possible).
        let p = DegradationPacer::new(cfg());
        let fat = PathSample {
            rtt: Duration::from_millis(20),
            cwnd: 4_000_000, // 4 MB / 20 ms = 200 MB/s
        };
        for _ in 0..8 {
            tokio::time::advance(Duration::from_millis(100)).await;
            p.observe_path(fat);
        }
        let hi = p.current_goodput_bps();
        assert!(
            hi > p.config.reference_rate_bps * 4.0,
            "cwnd/rtt raised goodput: {hi}"
        );
        // Degradation: cwnd halved + rtt doubled ⇒ ¼ the deliverable rate ⇒ back off.
        let thin = PathSample {
            rtt: Duration::from_millis(40),
            cwnd: 2_000_000,
        };
        for _ in 0..16 {
            tokio::time::advance(Duration::from_millis(100)).await;
            p.observe_path(thin);
        }
        assert!(
            p.current_goodput_bps() < hi,
            "degraded cwnd/rtt lowered goodput"
        );
    }

    /// The PING/reply payload protocol round-trips and is legacy-safe (so an old
    /// `b"pong"` peer yields no sample and cannot trigger a re-reply loop).
    #[test]
    fn ping_protocol_parses_and_is_legacy_safe() {
        let req = build_ping_request(0x0102_0304_0506_0708);
        assert_eq!(
            parse_ping(&req),
            PingMsg::Request(0x0102_0304_0506_0708u64.to_be_bytes())
        );
        let ts = 0x1122_3344_5566_7788u64.to_be_bytes();
        assert_eq!(parse_ping(&build_ping_reply(ts)), PingMsg::Reply(ts));
        assert_eq!(parse_ping(b"pong"), PingMsg::Legacy); // legacy 4-byte echo
        assert_eq!(parse_ping(b""), PingMsg::Legacy);
        assert_eq!(parse_ping(&[0x09u8; 9]), PingMsg::Legacy); // unknown tag
    }

    // g as the pacer would see it from a probe sample.
    fn probe_goodput(p: &TcpAppRttProbe) -> f64 {
        let s = p.sample();
        s.cwnd as f64 / s.rtt.as_secs_f64()
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_probe_goodput_tracks_the_peer_delivered_rate() {
        let p = TcpAppRttProbe::new(REFERENCE_RATE_BPS, 0.5);
        // Establish a healthy RTT (10 ms) so the health factors stay ~1.0.
        let PingMsg::Request(ts) = parse_ping(&p.next_ping()) else {
            panic!()
        };
        tokio::time::advance(Duration::from_millis(10)).await;
        p.on_reply(ts);

        // Heavy downlink: 200 KB / 100 ms tick = 2 MB/s.
        let mut g_hi = 0.0;
        for _ in 0..8 {
            p.on_peer_data(200_000);
            tokio::time::advance(Duration::from_millis(100)).await;
            g_hi = probe_goodput(&p);
        }
        assert!(
            g_hi > 4.0 * REFERENCE_RATE_BPS,
            "heavy downlink raised g: {g_hi}"
        );

        // Throttle the downlink (still above the active floor, replies kept alive):
        // 30 KB / 100 ms tick = 300 KB/s ⇒ g must follow it DOWN.
        let mut g_lo = g_hi;
        for _ in 0..8 {
            p.on_peer_data(30_000);
            let PingMsg::Request(ts) = parse_ping(&p.next_ping()) else {
                panic!()
            };
            tokio::time::advance(Duration::from_millis(10)).await;
            p.on_reply(ts);
            tokio::time::advance(Duration::from_millis(90)).await;
            g_lo = probe_goodput(&p);
        }
        assert!(g_lo < g_hi, "throttled downlink lowered g: {g_lo} < {g_hi}");
        assert!(
            g_lo > REFERENCE_RATE_BPS,
            "300 KB/s downlink still above reference: {g_lo}"
        );

        // Lift the throttle ⇒ g recovers.
        let mut g_re = g_lo;
        for _ in 0..8 {
            p.on_peer_data(200_000);
            tokio::time::advance(Duration::from_millis(100)).await;
            g_re = probe_goodput(&p);
        }
        assert!(g_re > g_lo, "downlink recovery raised g: {g_re} > {g_lo}");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_probe_reply_stall_floors_goodput_then_recovers() {
        let p = TcpAppRttProbe::new(REFERENCE_RATE_BPS, 0.5);
        // Healthy: steady delivered + replies flowing.
        for _ in 0..4 {
            p.on_peer_data(50_000);
            let PingMsg::Request(ts) = parse_ping(&p.next_ping()) else {
                panic!()
            };
            tokio::time::advance(Duration::from_millis(10)).await;
            p.on_reply(ts);
            tokio::time::advance(Duration::from_millis(90)).await;
        }
        let healthy = probe_goodput(&p);
        assert!(
            healthy > REFERENCE_RATE_BPS,
            "healthy g above reference: {healthy}"
        );

        // Silent freeze: replies STOP. Advance past the stall window (5·400 ms = 2 s).
        tokio::time::advance(Duration::from_millis(2_500)).await;
        let frozen = probe_goodput(&p);
        assert!(
            frozen < healthy * 0.2,
            "stall collapsed g toward floor: {frozen} << {healthy}"
        );

        // A fresh reply resets the stall clock ⇒ g recovers.
        let PingMsg::Request(ts) = parse_ping(&p.next_ping()) else {
            panic!()
        };
        tokio::time::advance(Duration::from_millis(10)).await;
        p.on_reply(ts);
        p.on_peer_data(50_000);
        tokio::time::advance(Duration::from_millis(90)).await;
        let recovered = probe_goodput(&p);
        assert!(
            recovered > frozen,
            "reply reset the stall: {recovered} > {frozen}"
        );
    }
}
