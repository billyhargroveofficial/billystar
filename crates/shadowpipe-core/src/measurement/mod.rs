//! Versioned, closed-schema session measurement records.
//!
//! This deliberately closed schema has no address, hostname, arbitrary label,
//! free-form tag, or error-message field. Endpoints and paths are represented by
//! run-local integer references. That removes common accidental leak surfaces,
//! but does **not** make a trace anonymous or export-safe: exact event timing and
//! byte counts remain correlatable traffic-shape data, and callers can misuse
//! the opaque-ID constructor. IDs must come from randomness or a keyed,
//! domain-separated pseudonym, never endpoint/key/config bytes. Raw traces need
//! access control, bounded retention, and aggregation/quantization before
//! publication.
//!
//! Durations are integer microseconds from a monotonic clock.  Wall time appears
//! only once in [`RunMetadata`] for correlation and must never drive ordering.

pub mod causal;
mod runtime;
mod stats;

pub use runtime::{FinishError, MeasurementRecorder, RecordError, RecorderInitError};
pub use stats::{
    conservative_success_lcb, wilson_lower_bound, wilson_lower_bound_95, ConfidenceError,
    MomentError, OnlineMoments, Z_95_TWO_SIDED,
};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

/// The only schema revision this module emits and validates.
pub const MEASUREMENT_SCHEMA_VERSION: u16 = 1;

/// A public, opaque 128-bit pseudonym serialized as 32 lowercase hex digits.
///
/// This type prevents arbitrary strings from entering telemetry.  It is not a
/// hashing primitive: construct it from randomness or a keyed, domain-separated
/// digest.  All-zero IDs are rejected because they usually indicate an
/// uninitialized caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicId([u8; Self::BYTE_LEN]);

impl PublicId {
    /// Binary width of an identifier.
    pub const BYTE_LEN: usize = 16;
    /// Canonical encoded width of an identifier.
    pub const HEX_LEN: usize = Self::BYTE_LEN * 2;

    /// Validate and construct an ID from caller-supplied opaque bytes.
    ///
    /// This checks representation only; it cannot detect an embedded IP address,
    /// key fragment, or other identifier. Exporting callers must supply random
    /// bytes or a keyed, domain-separated pseudonym.
    pub fn from_bytes(bytes: [u8; Self::BYTE_LEN]) -> Result<Self, PublicIdError> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(PublicIdError::AllZero)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Parse the canonical fixed-width hexadecimal representation.
    pub fn from_hex(encoded: &str) -> Result<Self, PublicIdError> {
        if encoded.len() != Self::HEX_LEN {
            return Err(PublicIdError::InvalidLength {
                actual: encoded.len(),
            });
        }
        if encoded.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(PublicIdError::InvalidHex);
        }

        let mut bytes = [0_u8; Self::BYTE_LEN];
        hex::decode_to_slice(encoded, &mut bytes).map_err(|_| PublicIdError::InvalidHex)?;
        Self::from_bytes(bytes)
    }

    /// Raw pseudonym bytes (never endpoint/address bytes).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }
}

impl fmt::Display for PublicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl Serialize for PublicId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

struct PublicIdVisitor;

impl Visitor<'_> for PublicIdVisitor {
    type Value = PublicId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a non-zero {}-character hexadecimal public ID",
            PublicId::HEX_LEN
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        PublicId::from_hex(value).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PublicIdVisitor)
    }
}

/// Invalid public pseudonym.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicIdError {
    /// Encoded IDs are exactly 32 hexadecimal characters.
    InvalidLength { actual: usize },
    /// At least one character was not hexadecimal.
    InvalidHex,
    /// The all-zero sentinel is never a valid ID.
    AllZero,
}

impl fmt::Display for PublicIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual } => write!(
                f,
                "public ID has length {actual}; expected {} hexadecimal characters",
                PublicId::HEX_LEN
            ),
            Self::InvalidHex => f.write_str("public ID contains non-hexadecimal characters"),
            Self::AllZero => f.write_str("public ID must not be all zero"),
        }
    }
}

impl Error for PublicIdError {}

/// Numeric software version, intentionally excluding arbitrary build strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

/// Role of the process that produced the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Client,
    Server,
    Observer,
}

/// Coarse execution environment without identifying OS/host details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEnvironment {
    BareMetal,
    VirtualMachine,
    Container,
    ContinuousIntegration,
}

/// Reproducibility metadata that cannot carry endpoints, credentials, or logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetadata {
    /// Unique random/keyed-pseudonymous ID for this run.
    pub run_id: PublicId,
    /// Optional public experiment-series pseudonym.
    pub experiment_id: Option<PublicId>,
    /// Optional public pseudonym of the exact built artifact.
    pub artifact_id: Option<PublicId>,
    /// Wall time for controlled correlation; event ordering never uses it.
    ///
    /// Millisecond precision is sensitive and must be bucketed before an export
    /// intended to be aggregate-only.
    pub started_unix_ms: u64,
    pub software_version: SoftwareVersion,
    pub role: NodeRole,
    pub environment: ExecutionEnvironment,
}

/// The strongest environment in which the recorded claim was exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScope {
    Unit,
    Loopback,
    VirtualMachine,
    ControlledNetwork,
    PublicInternet,
    TargetNetwork,
}

/// Epistemic result of the run, distinct from a connection close reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    Pending,
    Supported,
    Refuted,
    Inconclusive,
    Invalid,
}

/// Scope and outcome travel together so exported traces cannot lose qualifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAssessment {
    pub scope: EvidenceScope,
    pub outcome: EvidenceOutcome,
}

/// Closed set of transports; no user-controlled carrier name is serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Tcp,
    TlsChrome,
    Http2,
    Quic,
    Reality,
}

/// Sanitized result of one dial attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialOutcome {
    Connected,
    TimedOut,
    Refused,
    Unreachable,
    AuthenticationRejected,
    ProtocolError,
    Cancelled,
}

/// Lifecycle transition or observation for a run-local path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    Candidate,
    Selected,
    Migrated,
    Degraded,
    Recovered,
    Retired,
}

/// Integer-only path snapshot; optional counters distinguish unavailable data
/// from a measured zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathMetrics {
    pub rtt_us: Option<u64>,
    pub congestion_window_bytes: Option<u64>,
    /// Lost packets per million sent packets, in `[0, 1_000_000]`.
    pub loss_ppm: Option<u32>,
    pub delivered_bytes_per_second: Option<u64>,
}

impl PathMetrics {
    #[must_use]
    const fn is_empty(self) -> bool {
        self.rtt_us.is_none()
            && self.congestion_window_bytes.is_none()
            && self.loss_ppm.is_none()
            && self.delivered_bytes_per_second.is_none()
    }
}

/// Byte direction relative to the collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Transmit,
    Receive,
}

/// Whether a stall began or progress resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StallState {
    Detected,
    Recovered,
}

/// Sanitized terminal connection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseOutcome {
    Clean,
    PeerClosed,
    TimedOut,
    TransportError,
    ProtocolError,
    AuthenticationError,
    Cancelled,
}

/// Measurement payload.  Serde's internal `kind` tag gives stable, readable
/// JSON while preserving a closed enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventKind {
    /// One attempt to a run-local endpoint index (never an address).
    Dial {
        endpoint_ref: u32,
        transport: TransportKind,
        attempt: u32,
        duration_us: u64,
        outcome: DialOutcome,
    },
    /// Path lifecycle/metrics for run-local endpoint and path indexes.
    Path {
        path_ref: u32,
        endpoint_ref: u32,
        state: PathState,
        metrics: Option<PathMetrics>,
    },
    /// Delta counters over a non-zero observation interval.
    Transfer {
        path_ref: u32,
        direction: Direction,
        payload_bytes: u64,
        wire_bytes: u64,
        interval_us: u64,
    },
    /// A progress gap crossing a declared threshold, or its recovery.
    Stall {
        path_ref: u32,
        direction: Direction,
        state: StallState,
        gap_us: u64,
        threshold_us: u64,
        /// Cumulative payload progress at the event boundary.
        progress_bytes: u64,
    },
    /// Terminal event with aggregate payload counts.
    Close {
        outcome: CloseOutcome,
        transmitted_payload_bytes: u64,
        received_payload_bytes: u64,
    },
}

/// One event ordered by an explicit sequence and monotonic elapsed time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementEvent {
    /// Must be strictly increasing within a run.  Gaps are allowed so filtered
    /// exports can preserve original ordering and reveal omitted observations.
    pub sequence: u64,
    /// Microseconds since the run's monotonic origin; may equal the prior event.
    pub elapsed_us: u64,
    pub event: EventKind,
}

/// One self-describing, versioned trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementRun {
    pub schema_version: u16,
    pub metadata: RunMetadata,
    pub evidence: EvidenceAssessment,
    pub events: Vec<MeasurementEvent>,
}

impl MeasurementRun {
    /// Construct a trace using the current schema revision.
    #[must_use]
    pub fn new(
        metadata: RunMetadata,
        evidence: EvidenceAssessment,
        events: Vec<MeasurementEvent>,
    ) -> Self {
        Self {
            schema_version: MEASUREMENT_SCHEMA_VERSION,
            metadata,
            evidence,
            events,
        }
    }

    /// Validate schema revision, event order, monotonic time, and payload bounds.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != MEASUREMENT_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: MEASUREMENT_SCHEMA_VERSION,
            });
        }

        let mut previous_sequence = None;
        let mut previous_elapsed_us = None;
        let mut close_index = None;
        let mut connected_endpoints = HashSet::new();
        let mut paths = HashMap::new();
        // Retain the progress counter at detection so a producer cannot erase
        // an active stall by emitting a nominal `Recovered` event without any
        // intervening payload progress.
        let mut active_stalls = HashMap::new();
        let mut observed_transmit_payload = 0_u128;
        let mut observed_receive_payload = 0_u128;
        let mut maximum_transmit_progress = 0_u64;
        let mut maximum_receive_progress = 0_u64;

        for (index, measurement) in self.events.iter().enumerate() {
            if let Some(previous) = previous_sequence {
                if measurement.sequence <= previous {
                    return Err(ValidationError::NonIncreasingSequence {
                        index,
                        previous,
                        current: measurement.sequence,
                    });
                }
            }
            if let Some(previous) = previous_elapsed_us {
                if measurement.elapsed_us < previous {
                    return Err(ValidationError::DecreasingElapsedTime {
                        index,
                        previous,
                        current: measurement.elapsed_us,
                    });
                }
            }
            if let Some(closed_at) = close_index {
                return Err(ValidationError::EventAfterClose { index, closed_at });
            }

            Self::validate_event(index, &measurement.event)?;
            match &measurement.event {
                EventKind::Dial {
                    endpoint_ref,
                    outcome: DialOutcome::Connected,
                    ..
                } => {
                    connected_endpoints.insert(*endpoint_ref);
                }
                EventKind::Dial { .. } => {}
                EventKind::Path {
                    path_ref,
                    endpoint_ref,
                    state,
                    ..
                } => {
                    if !connected_endpoints.contains(endpoint_ref) {
                        return Err(ValidationError::UnknownEndpointRef {
                            index,
                            endpoint_ref: *endpoint_ref,
                        });
                    }
                    if paths.get(path_ref).copied().unwrap_or(false) {
                        return Err(ValidationError::EventForRetiredPath {
                            index,
                            path_ref: *path_ref,
                        });
                    }
                    paths.insert(*path_ref, matches!(state, PathState::Retired));
                }
                EventKind::Transfer {
                    path_ref,
                    direction,
                    payload_bytes,
                    ..
                } => {
                    Self::validate_live_path(index, *path_ref, &paths)?;
                    let total = match direction {
                        Direction::Transmit => &mut observed_transmit_payload,
                        Direction::Receive => &mut observed_receive_payload,
                    };
                    *total = total.checked_add(u128::from(*payload_bytes)).ok_or(
                        ValidationError::ObservedPayloadOverflow {
                            index,
                            direction: *direction,
                        },
                    )?;
                }
                EventKind::Stall {
                    path_ref,
                    direction,
                    state,
                    progress_bytes,
                    ..
                } => {
                    Self::validate_live_path(index, *path_ref, &paths)?;
                    let maximum_progress = match direction {
                        Direction::Transmit => &mut maximum_transmit_progress,
                        Direction::Receive => &mut maximum_receive_progress,
                    };
                    *maximum_progress = (*maximum_progress).max(*progress_bytes);
                    let key = (*path_ref, *direction);
                    match state {
                        StallState::Detected => {
                            if active_stalls.insert(key, *progress_bytes).is_some() {
                                return Err(ValidationError::DuplicateStallDetection {
                                    index,
                                    path_ref: *path_ref,
                                    direction: *direction,
                                });
                            }
                        }
                        StallState::Recovered => {
                            let Some(detected_progress_bytes) = active_stalls.remove(&key) else {
                                return Err(ValidationError::StallRecoveryWithoutDetection {
                                    index,
                                    path_ref: *path_ref,
                                    direction: *direction,
                                });
                            };
                            if *progress_bytes <= detected_progress_bytes {
                                return Err(ValidationError::StallRecoveryWithoutProgress {
                                    index,
                                    path_ref: *path_ref,
                                    direction: *direction,
                                    detected_progress_bytes,
                                    recovered_progress_bytes: *progress_bytes,
                                });
                            }
                        }
                    }
                }
                EventKind::Close {
                    transmitted_payload_bytes,
                    received_payload_bytes,
                    ..
                } => {
                    if u128::from(*transmitted_payload_bytes) < observed_transmit_payload
                        || u128::from(*received_payload_bytes) < observed_receive_payload
                    {
                        return Err(ValidationError::CloseTotalsBelowObserved {
                            index,
                            observed_transmit_payload,
                            observed_receive_payload,
                            close_transmit_payload: *transmitted_payload_bytes,
                            close_receive_payload: *received_payload_bytes,
                        });
                    }
                    if *transmitted_payload_bytes < maximum_transmit_progress
                        || *received_payload_bytes < maximum_receive_progress
                    {
                        return Err(ValidationError::CloseTotalsBelowStallProgress {
                            index,
                            maximum_transmit_progress,
                            maximum_receive_progress,
                            close_transmit_payload: *transmitted_payload_bytes,
                            close_receive_payload: *received_payload_bytes,
                        });
                    }
                    close_index = Some(index);
                }
            }
            previous_sequence = Some(measurement.sequence);
            previous_elapsed_us = Some(measurement.elapsed_us);
        }

        if self.evidence.outcome != EvidenceOutcome::Pending {
            if self.events.len() < 2 {
                return Err(ValidationError::InsufficientEvidenceEvents {
                    outcome: self.evidence.outcome,
                    observed: self.events.len(),
                });
            }
            if close_index.is_none() {
                return Err(ValidationError::MissingTerminalClose {
                    outcome: self.evidence.outcome,
                });
            }
        }

        Ok(())
    }

    fn validate_live_path(
        index: usize,
        path_ref: u32,
        paths: &HashMap<u32, bool>,
    ) -> Result<(), ValidationError> {
        match paths.get(&path_ref) {
            None => Err(ValidationError::UnknownPathRef { index, path_ref }),
            Some(true) => Err(ValidationError::EventForRetiredPath { index, path_ref }),
            Some(false) => Ok(()),
        }
    }

    fn validate_event(index: usize, event: &EventKind) -> Result<(), ValidationError> {
        match event {
            EventKind::Dial { attempt: 0, .. } => Err(ValidationError::ZeroDialAttempt { index }),
            EventKind::Path {
                metrics: Some(metrics),
                ..
            } if metrics.is_empty() => Err(ValidationError::EmptyPathMetrics { index }),
            EventKind::Path {
                metrics:
                    Some(PathMetrics {
                        loss_ppm: Some(loss_ppm),
                        ..
                    }),
                ..
            } if *loss_ppm > 1_000_000 => Err(ValidationError::LossOutOfRange {
                index,
                loss_ppm: *loss_ppm,
            }),
            EventKind::Transfer { interval_us: 0, .. } => {
                Err(ValidationError::ZeroTransferInterval { index })
            }
            EventKind::Transfer {
                payload_bytes: 0,
                wire_bytes: 0,
                ..
            } => Err(ValidationError::EmptyTransfer { index }),
            EventKind::Transfer {
                payload_bytes,
                wire_bytes,
                ..
            } if wire_bytes < payload_bytes => Err(ValidationError::WireBytesBelowPayload {
                index,
                payload_bytes: *payload_bytes,
                wire_bytes: *wire_bytes,
            }),
            EventKind::Stall {
                threshold_us: 0, ..
            } => Err(ValidationError::ZeroStallThreshold { index }),
            EventKind::Stall {
                gap_us,
                threshold_us,
                ..
            } if gap_us < threshold_us => Err(ValidationError::StallBelowThreshold {
                index,
                gap_us: *gap_us,
                threshold_us: *threshold_us,
            }),
            _ => Ok(()),
        }
    }
}

/// A measurement trace whose full semantic validation ran during construction
/// or deserialization.
///
/// Use this at trust boundaries where accepting a syntactically valid but
/// semantically invalid [`MeasurementRun`] would be unsafe. The inner value is
/// immutable through this wrapper; callers must explicitly consume it before
/// they can alter fields and thereby invalidate the proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ValidatedMeasurementRun(MeasurementRun);

impl ValidatedMeasurementRun {
    pub fn new(run: MeasurementRun) -> Result<Self, ValidationError> {
        run.validate()?;
        Ok(Self(run))
    }

    #[must_use]
    pub const fn as_run(&self) -> &MeasurementRun {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> MeasurementRun {
        self.0
    }
}

impl TryFrom<MeasurementRun> for ValidatedMeasurementRun {
    type Error = ValidationError;

    fn try_from(run: MeasurementRun) -> Result<Self, Self::Error> {
        Self::new(run)
    }
}

impl std::ops::Deref for ValidatedMeasurementRun {
    type Target = MeasurementRun;

    fn deref(&self) -> &Self::Target {
        self.as_run()
    }
}

impl<'de> Deserialize<'de> for ValidatedMeasurementRun {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let run = MeasurementRun::deserialize(deserializer)?;
        Self::new(run).map_err(de::Error::custom)
    }
}

/// Structural or semantic failure in a deserialized measurement trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedSchemaVersion {
        found: u16,
        supported: u16,
    },
    NonIncreasingSequence {
        index: usize,
        previous: u64,
        current: u64,
    },
    DecreasingElapsedTime {
        index: usize,
        previous: u64,
        current: u64,
    },
    EventAfterClose {
        index: usize,
        closed_at: usize,
    },
    ZeroDialAttempt {
        index: usize,
    },
    EmptyPathMetrics {
        index: usize,
    },
    LossOutOfRange {
        index: usize,
        loss_ppm: u32,
    },
    ZeroTransferInterval {
        index: usize,
    },
    EmptyTransfer {
        index: usize,
    },
    ZeroStallThreshold {
        index: usize,
    },
    StallBelowThreshold {
        index: usize,
        gap_us: u64,
        threshold_us: u64,
    },
    WireBytesBelowPayload {
        index: usize,
        payload_bytes: u64,
        wire_bytes: u64,
    },
    UnknownEndpointRef {
        index: usize,
        endpoint_ref: u32,
    },
    UnknownPathRef {
        index: usize,
        path_ref: u32,
    },
    EventForRetiredPath {
        index: usize,
        path_ref: u32,
    },
    DuplicateStallDetection {
        index: usize,
        path_ref: u32,
        direction: Direction,
    },
    StallRecoveryWithoutDetection {
        index: usize,
        path_ref: u32,
        direction: Direction,
    },
    StallRecoveryWithoutProgress {
        index: usize,
        path_ref: u32,
        direction: Direction,
        detected_progress_bytes: u64,
        recovered_progress_bytes: u64,
    },
    ObservedPayloadOverflow {
        index: usize,
        direction: Direction,
    },
    CloseTotalsBelowObserved {
        index: usize,
        observed_transmit_payload: u128,
        observed_receive_payload: u128,
        close_transmit_payload: u64,
        close_receive_payload: u64,
    },
    CloseTotalsBelowStallProgress {
        index: usize,
        maximum_transmit_progress: u64,
        maximum_receive_progress: u64,
        close_transmit_payload: u64,
        close_receive_payload: u64,
    },
    InsufficientEvidenceEvents {
        outcome: EvidenceOutcome,
        observed: usize,
    },
    MissingTerminalClose {
        outcome: EvidenceOutcome,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                f,
                "unsupported measurement schema version {found}; supported version is {supported}"
            ),
            Self::NonIncreasingSequence {
                index,
                previous,
                current,
            } => write!(
                f,
                "event {index} sequence {current} is not greater than prior sequence {previous}"
            ),
            Self::DecreasingElapsedTime {
                index,
                previous,
                current,
            } => write!(
                f,
                "event {index} elapsed time {current}us precedes prior time {previous}us"
            ),
            Self::EventAfterClose { index, closed_at } => write!(
                f,
                "event {index} appears after terminal close event {closed_at}"
            ),
            Self::ZeroDialAttempt { index } => {
                write!(f, "dial event {index} uses reserved attempt number zero")
            }
            Self::EmptyPathMetrics { index } => {
                write!(f, "path event {index} contains an empty metrics object")
            }
            Self::LossOutOfRange { index, loss_ppm } => write!(
                f,
                "path event {index} loss {loss_ppm} ppm exceeds 1,000,000"
            ),
            Self::ZeroTransferInterval { index } => {
                write!(f, "transfer event {index} has a zero-length interval")
            }
            Self::EmptyTransfer { index } => {
                write!(f, "transfer event {index} reports no payload or wire bytes")
            }
            Self::ZeroStallThreshold { index } => {
                write!(f, "stall event {index} has a zero threshold")
            }
            Self::StallBelowThreshold {
                index,
                gap_us,
                threshold_us,
            } => write!(
                f,
                "stall event {index} gap {gap_us}us is below threshold {threshold_us}us"
            ),
            Self::WireBytesBelowPayload {
                index,
                payload_bytes,
                wire_bytes,
            } => write!(
                f,
                "transfer event {index} reports {payload_bytes} payload bytes but only {wire_bytes} wire bytes"
            ),
            Self::UnknownEndpointRef {
                index,
                endpoint_ref,
            } => write!(f, "event {index} references unknown endpoint {endpoint_ref}"),
            Self::UnknownPathRef { index, path_ref } => {
                write!(f, "event {index} references unknown path {path_ref}")
            }
            Self::EventForRetiredPath { index, path_ref } => {
                write!(f, "event {index} references retired path {path_ref}")
            }
            Self::DuplicateStallDetection {
                index,
                path_ref,
                direction,
            } => write!(
                f,
                "event {index} repeats an active {direction:?} stall on path {path_ref}"
            ),
            Self::StallRecoveryWithoutDetection {
                index,
                path_ref,
                direction,
            } => write!(
                f,
                "event {index} recovers a {direction:?} stall that was not active on path {path_ref}"
            ),
            Self::StallRecoveryWithoutProgress {
                index,
                path_ref,
                direction,
                detected_progress_bytes,
                recovered_progress_bytes,
            } => write!(
                f,
                "event {index} recovers a {direction:?} stall on path {path_ref} without progress ({recovered_progress_bytes} <= {detected_progress_bytes})"
            ),
            Self::ObservedPayloadOverflow { index, direction } => write!(
                f,
                "event {index} overflows the observed {direction:?} payload accumulator"
            ),
            Self::CloseTotalsBelowObserved {
                index,
                observed_transmit_payload,
                observed_receive_payload,
                close_transmit_payload,
                close_receive_payload,
            } => write!(
                f,
                "close event {index} totals tx={close_transmit_payload}/rx={close_receive_payload} are below observed tx={observed_transmit_payload}/rx={observed_receive_payload}"
            ),
            Self::CloseTotalsBelowStallProgress {
                index,
                maximum_transmit_progress,
                maximum_receive_progress,
                close_transmit_payload,
                close_receive_payload,
            } => write!(
                f,
                "close event {index} totals tx={close_transmit_payload}/rx={close_receive_payload} are below declared stall progress tx={maximum_transmit_progress}/rx={maximum_receive_progress}"
            ),
            Self::InsufficientEvidenceEvents { outcome, observed } => write!(
                f,
                "{outcome:?} evidence needs at least one observation plus close; found {observed} event(s)"
            ),
            Self::MissingTerminalClose { outcome } => {
                write!(f, "{outcome:?} evidence is missing a terminal close event")
            }
        }
    }
}

impl Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_id(seed: u8) -> PublicId {
        PublicId::from_bytes([seed; PublicId::BYTE_LEN]).expect("non-zero test ID")
    }

    fn metadata() -> RunMetadata {
        RunMetadata {
            run_id: public_id(1),
            experiment_id: Some(public_id(2)),
            artifact_id: Some(public_id(3)),
            started_unix_ms: 1_800_000_000_000,
            software_version: SoftwareVersion {
                major: 1,
                minor: 4,
                patch: 2,
            },
            role: NodeRole::Client,
            environment: ExecutionEnvironment::VirtualMachine,
        }
    }

    fn evidence() -> EvidenceAssessment {
        EvidenceAssessment {
            scope: EvidenceScope::VirtualMachine,
            outcome: EvidenceOutcome::Supported,
        }
    }

    fn all_event_kinds() -> Vec<MeasurementEvent> {
        vec![
            MeasurementEvent {
                sequence: 10,
                elapsed_us: 0,
                event: EventKind::Dial {
                    endpoint_ref: 0,
                    transport: TransportKind::Quic,
                    attempt: 1,
                    duration_us: 14_000,
                    outcome: DialOutcome::Connected,
                },
            },
            MeasurementEvent {
                sequence: 20,
                elapsed_us: 14_000,
                event: EventKind::Path {
                    path_ref: 0,
                    endpoint_ref: 0,
                    state: PathState::Selected,
                    metrics: Some(PathMetrics {
                        rtt_us: Some(31_000),
                        congestion_window_bytes: Some(65_536),
                        loss_ppm: Some(1_250),
                        delivered_bytes_per_second: Some(8_000_000),
                    }),
                },
            },
            MeasurementEvent {
                sequence: 30,
                elapsed_us: 20_000,
                event: EventKind::Transfer {
                    path_ref: 0,
                    direction: Direction::Receive,
                    payload_bytes: 32_768,
                    wire_bytes: 33_024,
                    interval_us: 6_000,
                },
            },
            MeasurementEvent {
                sequence: 40,
                elapsed_us: 8_020_000,
                event: EventKind::Stall {
                    path_ref: 0,
                    direction: Direction::Receive,
                    state: StallState::Detected,
                    gap_us: 8_000_000,
                    threshold_us: 8_000_000,
                    progress_bytes: 32_768,
                },
            },
            MeasurementEvent {
                sequence: 50,
                elapsed_us: 8_030_000,
                event: EventKind::Close {
                    outcome: CloseOutcome::TimedOut,
                    transmitted_payload_bytes: 1_024,
                    received_payload_bytes: 32_768,
                },
            },
        ]
    }

    fn valid_run() -> MeasurementRun {
        MeasurementRun::new(metadata(), evidence(), all_event_kinds())
    }

    #[test]
    fn complete_schema_json_roundtrip_is_stable_and_valid() {
        let run = valid_run();
        run.validate().expect("fixture is valid");

        let json = serde_json::to_string_pretty(&run).expect("serialize schema");
        let decoded: MeasurementRun = serde_json::from_str(&json).expect("deserialize schema");

        assert_eq!(decoded, run);
        assert!(json.contains("\"schema_version\": 1"));
        for kind in ["dial", "path", "transfer", "stall", "close"] {
            assert!(json.contains(&format!("\"kind\": \"{kind}\"")));
        }
        assert!(!json.contains("server_ip"));
        assert!(!json.contains("hostname"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn validated_wrapper_enforces_semantics_at_deserialization() {
        let valid = valid_run();
        let wrapped = ValidatedMeasurementRun::new(valid.clone()).expect("valid fixture");
        let json = serde_json::to_string(&wrapped).expect("serialize wrapper");
        let decoded: ValidatedMeasurementRun =
            serde_json::from_str(&json).expect("validated deserialize");
        assert_eq!(decoded.as_run(), &valid);

        let mut invalid = valid;
        invalid.schema_version = MEASUREMENT_SCHEMA_VERSION + 1;
        let invalid_json = serde_json::to_string(&invalid).expect("serialize invalid fixture");
        assert!(serde_json::from_str::<ValidatedMeasurementRun>(&invalid_json).is_err());
    }

    #[test]
    fn unknown_sensitive_fields_are_rejected_not_silently_ignored() {
        let mut value = serde_json::to_value(valid_run()).expect("serialize fixture");
        value["metadata"]["server_ip"] = serde_json::json!("203.0.113.9");
        assert!(serde_json::from_value::<MeasurementRun>(value).is_err());

        let mut value = serde_json::to_value(valid_run()).expect("serialize fixture");
        value["events"][0]["raw_error"] = serde_json::json!("token=do-not-export");
        assert!(serde_json::from_value::<MeasurementRun>(value).is_err());

        let mut value = serde_json::to_value(valid_run()).expect("serialize fixture");
        value["events"][0]["event"]["endpoint_ip"] = serde_json::json!("203.0.113.9");
        assert!(serde_json::from_value::<MeasurementRun>(value).is_err());
    }

    #[test]
    fn public_ids_have_canonical_checked_serde() {
        let id = public_id(0xab);
        let json = serde_json::to_string(&id).expect("serialize ID");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(16)));
        assert_eq!(
            serde_json::from_str::<PublicId>(&json).expect("deserialize ID"),
            id
        );
        assert_eq!(
            PublicId::from_hex("00"),
            Err(PublicIdError::InvalidLength { actual: 2 })
        );
        assert_eq!(
            PublicId::from_hex(&"gg".repeat(16)),
            Err(PublicIdError::InvalidHex)
        );
        assert_eq!(
            PublicId::from_hex(&"AB".repeat(16)),
            Err(PublicIdError::InvalidHex)
        );
        assert_eq!(
            PublicId::from_bytes([0; PublicId::BYTE_LEN]),
            Err(PublicIdError::AllZero)
        );
        assert!(serde_json::from_str::<PublicId>(&format!("\"{}\"", "00".repeat(16))).is_err());
    }

    #[test]
    fn schema_version_is_checked() {
        let mut run = valid_run();
        run.schema_version = MEASUREMENT_SCHEMA_VERSION + 1;
        assert_eq!(
            run.validate(),
            Err(ValidationError::UnsupportedSchemaVersion {
                found: MEASUREMENT_SCHEMA_VERSION + 1,
                supported: MEASUREMENT_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn sequence_must_be_strictly_increasing_but_may_have_gaps() {
        let mut run = valid_run();
        run.events[1].sequence = run.events[0].sequence;
        assert_eq!(
            run.validate(),
            Err(ValidationError::NonIncreasingSequence {
                index: 1,
                previous: 10,
                current: 10,
            })
        );

        run.events[1].sequence = 9;
        assert_eq!(
            run.validate(),
            Err(ValidationError::NonIncreasingSequence {
                index: 1,
                previous: 10,
                current: 9,
            })
        );
    }

    #[test]
    fn monotonic_time_may_tie_but_never_move_backwards() {
        let mut run = valid_run();
        run.events[1].elapsed_us = run.events[0].elapsed_us;
        run.validate()
            .expect("equal monotonic timestamps are valid");

        run.events[1].elapsed_us = 1;
        run.events[2].elapsed_us = 0;
        assert_eq!(
            run.validate(),
            Err(ValidationError::DecreasingElapsedTime {
                index: 2,
                previous: 1,
                current: 0,
            })
        );
    }

    #[test]
    fn no_event_may_follow_close() {
        let mut run = valid_run();
        let trailing = MeasurementEvent {
            sequence: 60,
            elapsed_us: 8_030_000,
            event: EventKind::Path {
                path_ref: 0,
                endpoint_ref: 0,
                state: PathState::Retired,
                metrics: None,
            },
        };
        run.events.push(trailing);
        assert_eq!(
            run.validate(),
            Err(ValidationError::EventAfterClose {
                index: 5,
                closed_at: 4,
            })
        );
    }

    #[test]
    fn event_payload_bounds_are_validated() {
        let invalid_events = [
            (
                EventKind::Dial {
                    endpoint_ref: 0,
                    transport: TransportKind::Tcp,
                    attempt: 0,
                    duration_us: 0,
                    outcome: DialOutcome::Connected,
                },
                ValidationError::ZeroDialAttempt { index: 0 },
            ),
            (
                EventKind::Path {
                    path_ref: 0,
                    endpoint_ref: 0,
                    state: PathState::Candidate,
                    metrics: Some(PathMetrics {
                        rtt_us: None,
                        congestion_window_bytes: None,
                        loss_ppm: None,
                        delivered_bytes_per_second: None,
                    }),
                },
                ValidationError::EmptyPathMetrics { index: 0 },
            ),
            (
                EventKind::Path {
                    path_ref: 0,
                    endpoint_ref: 0,
                    state: PathState::Degraded,
                    metrics: Some(PathMetrics {
                        rtt_us: None,
                        congestion_window_bytes: None,
                        loss_ppm: Some(1_000_001),
                        delivered_bytes_per_second: None,
                    }),
                },
                ValidationError::LossOutOfRange {
                    index: 0,
                    loss_ppm: 1_000_001,
                },
            ),
            (
                EventKind::Transfer {
                    path_ref: 0,
                    direction: Direction::Transmit,
                    payload_bytes: 1,
                    wire_bytes: 1,
                    interval_us: 0,
                },
                ValidationError::ZeroTransferInterval { index: 0 },
            ),
            (
                EventKind::Transfer {
                    path_ref: 0,
                    direction: Direction::Transmit,
                    payload_bytes: 0,
                    wire_bytes: 0,
                    interval_us: 1,
                },
                ValidationError::EmptyTransfer { index: 0 },
            ),
            (
                EventKind::Transfer {
                    path_ref: 0,
                    direction: Direction::Transmit,
                    payload_bytes: 2,
                    wire_bytes: 1,
                    interval_us: 1,
                },
                ValidationError::WireBytesBelowPayload {
                    index: 0,
                    payload_bytes: 2,
                    wire_bytes: 1,
                },
            ),
            (
                EventKind::Stall {
                    path_ref: 0,
                    direction: Direction::Receive,
                    state: StallState::Detected,
                    gap_us: 1,
                    threshold_us: 0,
                    progress_bytes: 0,
                },
                ValidationError::ZeroStallThreshold { index: 0 },
            ),
            (
                EventKind::Stall {
                    path_ref: 0,
                    direction: Direction::Receive,
                    state: StallState::Detected,
                    gap_us: 99,
                    threshold_us: 100,
                    progress_bytes: 0,
                },
                ValidationError::StallBelowThreshold {
                    index: 0,
                    gap_us: 99,
                    threshold_us: 100,
                },
            ),
        ];

        for (event, expected) in invalid_events {
            let run = MeasurementRun::new(
                metadata(),
                evidence(),
                vec![MeasurementEvent {
                    sequence: 1,
                    elapsed_us: 0,
                    event,
                }],
            );
            assert_eq!(run.validate(), Err(expected));
        }
    }

    #[test]
    fn evidence_requires_live_references_and_a_terminal_close() {
        let mut run = valid_run();
        if let EventKind::Path { endpoint_ref, .. } = &mut run.events[1].event {
            *endpoint_ref = 99;
        }
        assert_eq!(
            run.validate(),
            Err(ValidationError::UnknownEndpointRef {
                index: 1,
                endpoint_ref: 99,
            })
        );

        let mut run = valid_run();
        run.events.remove(1);
        assert_eq!(
            run.validate(),
            Err(ValidationError::UnknownPathRef {
                index: 1,
                path_ref: 0,
            })
        );

        let mut run = valid_run();
        run.events.pop();
        assert_eq!(
            run.validate(),
            Err(ValidationError::MissingTerminalClose {
                outcome: EvidenceOutcome::Supported,
            })
        );

        let empty_supported = MeasurementRun::new(metadata(), evidence(), Vec::new());
        assert_eq!(
            empty_supported.validate(),
            Err(ValidationError::InsufficientEvidenceEvents {
                outcome: EvidenceOutcome::Supported,
                observed: 0,
            })
        );
    }

    #[test]
    fn stall_lifecycle_and_close_aggregates_are_checked() {
        let mut run = valid_run();
        run.events.insert(
            4,
            MeasurementEvent {
                sequence: 45,
                elapsed_us: 8_025_000,
                event: EventKind::Stall {
                    path_ref: 0,
                    direction: Direction::Receive,
                    state: StallState::Detected,
                    gap_us: 8_000_000,
                    threshold_us: 8_000_000,
                    progress_bytes: 32_768,
                },
            },
        );
        assert_eq!(
            run.validate(),
            Err(ValidationError::DuplicateStallDetection {
                index: 4,
                path_ref: 0,
                direction: Direction::Receive,
            })
        );

        let mut run = valid_run();
        if let EventKind::Close {
            received_payload_bytes,
            ..
        } = &mut run.events[4].event
        {
            *received_payload_bytes = 1;
        }
        assert_eq!(
            run.validate(),
            Err(ValidationError::CloseTotalsBelowObserved {
                index: 4,
                observed_transmit_payload: 0,
                observed_receive_payload: 32_768,
                close_transmit_payload: 1_024,
                close_receive_payload: 1,
            })
        );

        let mut run = valid_run();
        run.events.insert(
            4,
            MeasurementEvent {
                sequence: 45,
                elapsed_us: 8_025_000,
                event: EventKind::Stall {
                    path_ref: 0,
                    direction: Direction::Receive,
                    state: StallState::Recovered,
                    gap_us: 8_000_000,
                    threshold_us: 8_000_000,
                    // Merely relabelling the same cumulative progress as a
                    // recovery must not clear an active stall.
                    progress_bytes: 32_768,
                },
            },
        );
        assert_eq!(
            run.validate(),
            Err(ValidationError::StallRecoveryWithoutProgress {
                index: 4,
                path_ref: 0,
                direction: Direction::Receive,
                detected_progress_bytes: 32_768,
                recovered_progress_bytes: 32_768,
            })
        );

        let mut run = valid_run();
        run.events.insert(
            4,
            MeasurementEvent {
                sequence: 45,
                elapsed_us: 8_025_000,
                event: EventKind::Stall {
                    path_ref: 0,
                    direction: Direction::Receive,
                    state: StallState::Recovered,
                    gap_us: 8_000_000,
                    threshold_us: 8_000_000,
                    progress_bytes: 32_769,
                },
            },
        );
        assert_eq!(
            run.validate(),
            Err(ValidationError::CloseTotalsBelowStallProgress {
                index: 5,
                maximum_transmit_progress: 0,
                maximum_receive_progress: 32_769,
                close_transmit_payload: 1_024,
                close_receive_payload: 32_768,
            })
        );
    }
}
