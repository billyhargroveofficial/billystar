//! Bounded, monotonic collection of closed-schema measurement events.
//!
//! The recorder owns sequence numbers and elapsed timestamps so callers cannot
//! accidentally create ambiguous ordering. Rejected observations are counted,
//! and any rejection makes [`MeasurementRecorder::finish`] fail closed instead
//! of exporting a trace that appears complete.

use super::{
    EventKind, EvidenceAssessment, MeasurementEvent, MeasurementRun, RunMetadata, ValidationError,
};
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

/// Construction failure for a measurement recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecorderInitError {
    /// A zero-event recorder could never accept an observation.
    ZeroCapacity,
}

impl fmt::Display for RecorderInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => f.write_str("measurement recorder capacity must be non-zero"),
        }
    }
}

impl Error for RecorderInitError {}

/// Failure to record one observation.
///
/// Every returned error means that the observation was not appended and the
/// dropped-event counter was incremented, unless that counter was already
/// exhausted. Once an error occurs, [`MeasurementRecorder::finish`] will not
/// produce an apparently complete run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// The configured in-memory event bound has been reached.
    CapacityExceeded { max_events: usize },
    /// A terminal close was already accepted.
    Closed,
    /// No sequence number remains after `u64::MAX`.
    SequenceOverflow,
    /// Elapsed microseconds could not be represented by the schema.
    ElapsedTimeOverflow,
    /// The supplied elapsed time preceded the last accepted event.
    ClockRegressed { previous_us: u64, current_us: u64 },
    /// The event violates the closed measurement schema.
    InvalidEvent(ValidationError),
    /// Even the dropped-event counter could no longer be incremented.
    DroppedCountOverflow,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded { max_events } => {
                write!(
                    f,
                    "measurement recorder reached its {max_events}-event capacity"
                )
            }
            Self::Closed => f.write_str("measurement recorder is already closed"),
            Self::SequenceOverflow => {
                f.write_str("measurement recorder sequence number overflowed")
            }
            Self::ElapsedTimeOverflow => {
                f.write_str("measurement elapsed time exceeds the schema's u64 microseconds")
            }
            Self::ClockRegressed {
                previous_us,
                current_us,
            } => write!(
                f,
                "measurement clock regressed from {previous_us}us to {current_us}us"
            ),
            Self::InvalidEvent(error) => write!(f, "invalid measurement event: {error}"),
            Self::DroppedCountOverflow => {
                f.write_str("measurement dropped-event counter overflowed")
            }
        }
    }
}

impl Error for RecordError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEvent(error) => Some(error),
            _ => None,
        }
    }
}

/// Failure to finalize a recorded run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishError {
    /// At least one attempted observation was rejected.
    DroppedEvents { count: u64 },
    /// Defensive whole-run validation rejected the assembled trace.
    Validation(ValidationError),
}

impl fmt::Display for FinishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DroppedEvents { count } => write!(
                f,
                "measurement run is incomplete because {count} event(s) were dropped"
            ),
            Self::Validation(error) => write!(f, "measurement run validation failed: {error}"),
        }
    }
}

impl Error for FinishError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Validation(error) => Some(error),
            Self::DroppedEvents { .. } => None,
        }
    }
}

/// Bounded recorder whose ordering and timestamps come from one monotonic clock.
#[derive(Debug)]
pub struct MeasurementRecorder {
    origin: Instant,
    metadata: RunMetadata,
    evidence: EvidenceAssessment,
    max_events: usize,
    events: Vec<MeasurementEvent>,
    last_sequence: u64,
    last_elapsed_us: Option<u64>,
    dropped_events: u64,
    closed: bool,
}

impl MeasurementRecorder {
    /// Start a run at a fresh monotonic origin with an explicit event bound.
    pub fn new(
        metadata: RunMetadata,
        evidence: EvidenceAssessment,
        max_events: usize,
    ) -> Result<Self, RecorderInitError> {
        if max_events == 0 {
            return Err(RecorderInitError::ZeroCapacity);
        }

        Ok(Self {
            origin: Instant::now(),
            metadata,
            evidence,
            max_events,
            events: Vec::new(),
            last_sequence: 0,
            last_elapsed_us: None,
            dropped_events: 0,
            closed: false,
        })
    }

    /// Append one event using elapsed time from the recorder's monotonic origin.
    pub fn push(&mut self, event: EventKind) -> Result<(), RecordError> {
        self.push_elapsed(event, self.origin.elapsed())
    }

    /// Number of accepted events retained in memory.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether no event has been accepted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Configured maximum number of retained events.
    #[must_use]
    pub const fn max_events(&self) -> usize {
        self.max_events
    }

    /// Capacity remaining before the next observation must be rejected.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.max_events - self.events.len()
    }

    /// Number of observations rejected since construction.
    ///
    /// Any non-zero result guarantees that [`Self::finish`] returns
    /// [`FinishError::DroppedEvents`].
    #[must_use]
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Whether a terminal [`EventKind::Close`] has been accepted.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Assemble and validate a complete schema object.
    ///
    /// This consumes the recorder. A run with rejected observations is never
    /// returned because doing so would erase evidence that the trace is
    /// incomplete.
    pub fn finish(self) -> Result<MeasurementRun, FinishError> {
        if self.dropped_events != 0 {
            return Err(FinishError::DroppedEvents {
                count: self.dropped_events,
            });
        }

        let run = MeasurementRun::new(self.metadata, self.evidence, self.events);
        run.validate().map_err(FinishError::Validation)?;
        Ok(run)
    }

    fn push_elapsed(&mut self, event: EventKind, elapsed: Duration) -> Result<(), RecordError> {
        if self.closed {
            return Err(self.reject(RecordError::Closed));
        }
        if self.events.len() >= self.max_events {
            return Err(self.reject(RecordError::CapacityExceeded {
                max_events: self.max_events,
            }));
        }

        if let Err(error) = MeasurementRun::validate_event(self.events.len(), &event) {
            return Err(self.reject(RecordError::InvalidEvent(error)));
        }

        let sequence = match self.last_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => return Err(self.reject(RecordError::SequenceOverflow)),
        };
        let elapsed_us = match u64::try_from(elapsed.as_micros()) {
            Ok(elapsed_us) => elapsed_us,
            Err(_) => return Err(self.reject(RecordError::ElapsedTimeOverflow)),
        };
        if let Some(previous_us) = self.last_elapsed_us {
            if elapsed_us < previous_us {
                return Err(self.reject(RecordError::ClockRegressed {
                    previous_us,
                    current_us: elapsed_us,
                }));
            }
        }

        let terminal = matches!(event, EventKind::Close { .. });
        self.events.push(MeasurementEvent {
            sequence,
            elapsed_us,
            event,
        });
        self.last_sequence = sequence;
        self.last_elapsed_us = Some(elapsed_us);
        self.closed = terminal;
        Ok(())
    }

    fn reject(&mut self, error: RecordError) -> RecordError {
        match self.dropped_events.checked_add(1) {
            Some(count) => {
                self.dropped_events = count;
                error
            }
            None => RecordError::DroppedCountOverflow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurement::{
        CloseOutcome, DialOutcome, Direction, EvidenceOutcome, EvidenceScope, ExecutionEnvironment,
        NodeRole, PathMetrics, PathState, PublicId, SoftwareVersion, StallState, TransportKind,
    };

    fn metadata() -> RunMetadata {
        RunMetadata {
            run_id: PublicId::from_bytes([7; PublicId::BYTE_LEN]).expect("non-zero public ID"),
            experiment_id: None,
            artifact_id: None,
            started_unix_ms: 1_800_000_000_000,
            software_version: SoftwareVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            role: NodeRole::Client,
            environment: ExecutionEnvironment::VirtualMachine,
        }
    }

    const fn evidence() -> EvidenceAssessment {
        EvidenceAssessment {
            scope: EvidenceScope::VirtualMachine,
            outcome: EvidenceOutcome::Supported,
        }
    }

    fn dial() -> EventKind {
        EventKind::Dial {
            endpoint_ref: 0,
            transport: TransportKind::Quic,
            attempt: 1,
            duration_us: 1_000,
            outcome: DialOutcome::Connected,
        }
    }

    fn transfer() -> EventKind {
        EventKind::Transfer {
            path_ref: 0,
            direction: Direction::Receive,
            payload_bytes: 4_096,
            wire_bytes: 4_192,
            interval_us: 2_000,
        }
    }

    fn selected_path() -> EventKind {
        EventKind::Path {
            path_ref: 0,
            endpoint_ref: 0,
            state: PathState::Selected,
            metrics: None,
        }
    }

    fn close() -> EventKind {
        EventKind::Close {
            outcome: CloseOutcome::Clean,
            transmitted_payload_bytes: 512,
            received_payload_bytes: 4_096,
        }
    }

    fn recorder(max_events: usize) -> MeasurementRecorder {
        MeasurementRecorder::new(metadata(), evidence(), max_events).expect("valid recorder")
    }

    #[test]
    fn rejects_zero_capacity() {
        assert_eq!(
            MeasurementRecorder::new(metadata(), evidence(), 0).unwrap_err(),
            RecorderInitError::ZeroCapacity
        );
    }

    #[test]
    fn owns_contiguous_sequence_and_monotonic_elapsed_time() {
        let mut recorder = recorder(4);
        recorder
            .push_elapsed(dial(), Duration::from_micros(11))
            .unwrap();
        recorder
            .push_elapsed(selected_path(), Duration::from_micros(11))
            .unwrap();
        recorder
            .push_elapsed(transfer(), Duration::from_micros(11))
            .unwrap();
        recorder
            .push_elapsed(close(), Duration::from_micros(19))
            .unwrap();

        assert_eq!(recorder.len(), 4);
        assert_eq!(recorder.remaining_capacity(), 0);
        assert!(recorder.is_closed());
        assert_eq!(recorder.dropped_events(), 0);

        let run = recorder.finish().unwrap();
        assert_eq!(
            run.events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            run.events
                .iter()
                .map(|event| event.elapsed_us)
                .collect::<Vec<_>>(),
            vec![11, 11, 11, 19]
        );
        run.validate().unwrap();
    }

    #[test]
    fn public_push_uses_instant_origin() {
        let mut recorder = recorder(4);
        recorder.push(dial()).unwrap();
        recorder.push(selected_path()).unwrap();
        recorder.push(transfer()).unwrap();
        recorder.push(close()).unwrap();
        let run = recorder.finish().unwrap();
        assert!(run.events[1].elapsed_us >= run.events[0].elapsed_us);
    }

    #[test]
    fn close_is_terminal_and_rejection_poison_finishes() {
        let mut recorder = recorder(2);
        recorder.push(close()).unwrap();
        assert_eq!(recorder.push(dial()), Err(RecordError::Closed));
        assert_eq!(recorder.len(), 1);
        assert_eq!(recorder.dropped_events(), 1);
        assert_eq!(
            recorder.finish(),
            Err(FinishError::DroppedEvents { count: 1 })
        );
    }

    #[test]
    fn capacity_is_a_hard_bound_and_rejection_is_visible() {
        let mut recorder = recorder(1);
        recorder.push(dial()).unwrap();
        assert_eq!(
            recorder.push(transfer()),
            Err(RecordError::CapacityExceeded { max_events: 1 })
        );
        assert_eq!(recorder.len(), 1);
        assert_eq!(recorder.remaining_capacity(), 0);
        assert_eq!(recorder.dropped_events(), 1);
    }

    #[test]
    fn rejects_invalid_event_before_assigning_a_sequence() {
        let mut recorder = recorder(2);
        let invalid = EventKind::Dial {
            endpoint_ref: 0,
            transport: TransportKind::Tcp,
            attempt: 0,
            duration_us: 0,
            outcome: DialOutcome::Cancelled,
        };

        assert_eq!(
            recorder.push_elapsed(invalid, Duration::ZERO),
            Err(RecordError::InvalidEvent(
                ValidationError::ZeroDialAttempt { index: 0 }
            ))
        );
        recorder
            .push_elapsed(dial(), Duration::from_micros(1))
            .unwrap();
        assert_eq!(recorder.events[0].sequence, 1);
        assert_eq!(recorder.dropped_events(), 1);
    }

    #[test]
    fn delegates_all_single_event_semantics_to_schema_validation() {
        let invalid_events = [
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
            EventKind::Transfer {
                path_ref: 0,
                direction: Direction::Transmit,
                payload_bytes: 1,
                wire_bytes: 1,
                interval_us: 0,
            },
            EventKind::Transfer {
                path_ref: 0,
                direction: Direction::Transmit,
                payload_bytes: 0,
                wire_bytes: 0,
                interval_us: 1,
            },
            EventKind::Stall {
                path_ref: 0,
                direction: Direction::Receive,
                state: StallState::Detected,
                gap_us: 1,
                threshold_us: 0,
                progress_bytes: 0,
            },
            EventKind::Stall {
                path_ref: 0,
                direction: Direction::Receive,
                state: StallState::Recovered,
                gap_us: 9,
                threshold_us: 10,
                progress_bytes: 1,
            },
        ];

        for event in invalid_events {
            let mut recorder = recorder(1);
            assert!(matches!(
                recorder.push_elapsed(event, Duration::ZERO),
                Err(RecordError::InvalidEvent(_))
            ));
            assert!(recorder.is_empty());
            assert_eq!(recorder.dropped_events(), 1);
        }
    }

    #[test]
    fn rejects_elapsed_and_sequence_overflow_without_mutating_events() {
        let mut elapsed = recorder(1);
        assert_eq!(
            elapsed.push_elapsed(dial(), Duration::from_secs(u64::MAX)),
            Err(RecordError::ElapsedTimeOverflow)
        );
        assert!(elapsed.is_empty());

        let mut sequence = recorder(1);
        sequence.last_sequence = u64::MAX;
        assert_eq!(
            sequence.push_elapsed(dial(), Duration::ZERO),
            Err(RecordError::SequenceOverflow)
        );
        assert!(sequence.is_empty());
    }

    #[test]
    fn rejects_regressing_elapsed_time() {
        let mut recorder = recorder(2);
        recorder
            .push_elapsed(dial(), Duration::from_micros(20))
            .unwrap();
        assert_eq!(
            recorder.push_elapsed(transfer(), Duration::from_micros(19)),
            Err(RecordError::ClockRegressed {
                previous_us: 20,
                current_us: 19,
            })
        );
        assert_eq!(recorder.len(), 1);
        assert_eq!(recorder.dropped_events(), 1);
    }

    #[test]
    fn dropped_counter_overflow_is_explicit_and_still_fail_closed() {
        let mut recorder = recorder(1);
        recorder.dropped_events = u64::MAX;
        assert_eq!(
            recorder.push_elapsed(
                EventKind::Transfer {
                    path_ref: 0,
                    direction: Direction::Transmit,
                    payload_bytes: 0,
                    wire_bytes: 0,
                    interval_us: 1,
                },
                Duration::ZERO,
            ),
            Err(RecordError::DroppedCountOverflow)
        );
        assert_eq!(
            recorder.finish(),
            Err(FinishError::DroppedEvents { count: u64::MAX })
        );
    }

    #[test]
    fn unfinished_but_lossless_run_remains_valid() {
        let mut recorder = MeasurementRecorder::new(
            metadata(),
            EvidenceAssessment {
                scope: EvidenceScope::VirtualMachine,
                outcome: EvidenceOutcome::Pending,
            },
            1,
        )
        .unwrap();
        recorder.push(dial()).unwrap();
        let run = recorder.finish().unwrap();
        assert_eq!(run.events.len(), 1);
        assert!(!matches!(run.events[0].event, EventKind::Close { .. }));
        run.validate().unwrap();
    }
}
