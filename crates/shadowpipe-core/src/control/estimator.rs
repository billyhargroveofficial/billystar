//! Conservative, carrier-local health estimation from independent probe windows.
//!
//! The estimator is deliberately a pure state machine: it performs no I/O,
//! owns no carrier or route handle, and cannot activate a recommendation.  A
//! caller supplies exactly one bounded [`ObservationKind::VolumeProbe`] result
//! for each independently scheduled, strictly ordered window.  Rejected input
//! is transactional and leaves both the estimate and its sequence unchanged.
//!
//! The Wilson and Student-t intervals are fixed-look summaries over declared
//! independent windows. Repeatedly inspecting them is not an anytime-valid
//! confidence sequence, and comparing many carriers needs a separately
//! preregistered multiplicity policy. The selector therefore remains advisory.

use crate::carrier::api::{
    CarrierHealthSnapshot, CarrierHealthState, CarrierId, CarrierObservation, EstimateBounds,
    EvidenceSummary, ObservationKind,
};
use crate::measurement::causal::student_t_critical_95;
use crate::measurement::{wilson_lower_bound_95, MomentError, OnlineMoments};
use std::error::Error;
use std::fmt;

use super::DEFAULT_MIN_REPRESENTATIVE_WORKLOAD_BYTES;

/// Default upper bound for one representative workload probe (64 MiB).
pub const DEFAULT_MAX_PROBE_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Default upper bound for one representative workload probe (120 seconds).
pub const DEFAULT_MAX_PROBE_ELAPSED_MS: u64 = 120_000;

/// Policy for one carrier-local estimator.
#[derive(Clone, Debug, PartialEq)]
pub struct HealthEstimatorConfig {
    /// Minimum received payload required before a probe may report success.
    pub min_successful_probe_bytes: u64,
    /// Hard ingestion bound for received payload in any one window.
    pub max_probe_payload_bytes: u64,
    /// Hard ingestion bound for elapsed time in any one window.
    pub max_probe_elapsed_ms: u64,
    /// Evidence required before health may leave `Unknown`.
    pub min_classification_windows: u32,
    /// Wilson lower bound required for `Healthy`.
    pub healthy_reachability_lower_bound: f64,
    /// Conservative successful-probe goodput bound required for `Healthy`.
    pub healthy_goodput_lower_bound_bytes_per_second: f64,
    /// Wilson upper bound at or below which a path is `Unreachable`.
    pub unreachable_reachability_upper_bound: f64,
}

impl Default for HealthEstimatorConfig {
    fn default() -> Self {
        Self {
            min_successful_probe_bytes: DEFAULT_MIN_REPRESENTATIVE_WORKLOAD_BYTES,
            max_probe_payload_bytes: DEFAULT_MAX_PROBE_PAYLOAD_BYTES,
            max_probe_elapsed_ms: DEFAULT_MAX_PROBE_ELAPSED_MS,
            min_classification_windows: 3,
            healthy_reachability_lower_bound: 0.40,
            healthy_goodput_lower_bound_bytes_per_second: 7.0 * 1024.0,
            unreachable_reachability_upper_bound: 0.20,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthEstimatorConfigError {
    ZeroMinimumPayload,
    PayloadBoundsInverted,
    ZeroMaximumElapsed,
    ZeroClassificationWindows,
    ProbeRateNumeratorOverflow,
    InvalidHealthyReachabilityBound,
    InvalidUnreachableReachabilityBound,
    OverlappingReachabilityRules,
    InvalidHealthyGoodputBound,
    HealthyGoodputExceedsProbeMaximum,
}

impl fmt::Display for HealthEstimatorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroMinimumPayload => "minimum successful probe payload must be non-zero",
            Self::PayloadBoundsInverted => {
                "maximum probe payload must cover the minimum successful payload"
            }
            Self::ZeroMaximumElapsed => "maximum probe elapsed time must be non-zero",
            Self::ZeroClassificationWindows => "minimum classification windows must be non-zero",
            Self::ProbeRateNumeratorOverflow => {
                "maximum probe payload cannot be converted to bytes per second"
            }
            Self::InvalidHealthyReachabilityBound => {
                "healthy reachability lower bound must be finite and in (0, 1]"
            }
            Self::InvalidUnreachableReachabilityBound => {
                "unreachable reachability upper bound must be finite and in [0, 1)"
            }
            Self::OverlappingReachabilityRules => {
                "unreachable upper bound must be below the healthy lower bound"
            }
            Self::InvalidHealthyGoodputBound => {
                "healthy goodput lower bound must be finite and greater than zero"
            }
            Self::HealthyGoodputExceedsProbeMaximum => {
                "healthy goodput lower bound exceeds the bounded probe maximum"
            }
        };
        f.write_str(message)
    }
}

impl Error for HealthEstimatorConfigError {}

impl HealthEstimatorConfig {
    pub fn validate(&self) -> Result<(), HealthEstimatorConfigError> {
        if self.min_successful_probe_bytes == 0 {
            return Err(HealthEstimatorConfigError::ZeroMinimumPayload);
        }
        if self.max_probe_payload_bytes < self.min_successful_probe_bytes {
            return Err(HealthEstimatorConfigError::PayloadBoundsInverted);
        }
        if self.max_probe_elapsed_ms == 0 {
            return Err(HealthEstimatorConfigError::ZeroMaximumElapsed);
        }
        if self.min_classification_windows == 0 {
            return Err(HealthEstimatorConfigError::ZeroClassificationWindows);
        }

        let maximum_goodput =
            self.max_probe_payload_bytes
                .checked_mul(1_000)
                .ok_or(HealthEstimatorConfigError::ProbeRateNumeratorOverflow)? as f64;
        if !(self.healthy_reachability_lower_bound.is_finite()
            && 0.0 < self.healthy_reachability_lower_bound
            && self.healthy_reachability_lower_bound <= 1.0)
        {
            return Err(HealthEstimatorConfigError::InvalidHealthyReachabilityBound);
        }
        if !self.unreachable_reachability_upper_bound.is_finite()
            || !(0.0..1.0).contains(&self.unreachable_reachability_upper_bound)
        {
            return Err(HealthEstimatorConfigError::InvalidUnreachableReachabilityBound);
        }
        if self.unreachable_reachability_upper_bound >= self.healthy_reachability_lower_bound {
            return Err(HealthEstimatorConfigError::OverlappingReachabilityRules);
        }
        if !self
            .healthy_goodput_lower_bound_bytes_per_second
            .is_finite()
            || self.healthy_goodput_lower_bound_bytes_per_second <= 0.0
        {
            return Err(HealthEstimatorConfigError::InvalidHealthyGoodputBound);
        }
        if self.healthy_goodput_lower_bound_bytes_per_second > maximum_goodput {
            return Err(HealthEstimatorConfigError::HealthyGoodputExceedsProbeMaximum);
        }
        Ok(())
    }

    fn maximum_goodput_bytes_per_second(&self) -> f64 {
        // `validate` proves this product is representable.  Every accepted
        // observation is at or below this payload and has elapsed_ms >= 1.
        self.max_probe_payload_bytes as f64 * 1_000.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthEstimatorInitError {
    EmptyCarrierId,
    InvalidConfig(HealthEstimatorConfigError),
}

impl fmt::Display for HealthEstimatorInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCarrierId => f.write_str("health estimator carrier ID must not be empty"),
            Self::InvalidConfig(error) => write!(f, "invalid health estimator config: {error}"),
        }
    }
}

impl Error for HealthEstimatorInitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EmptyCarrierId => None,
            Self::InvalidConfig(error) => Some(error),
        }
    }
}

/// One independent scheduling window and its sole representative probe result.
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeWindowObservation {
    pub window_index: u64,
    pub carrier_observation: CarrierObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeIngestError {
    NotAccepting { state: CarrierHealthState },
    CarrierIdMismatch,
    UnsupportedObservationKind,
    DuplicateWindow { window_index: u64 },
    RegressingWindow { previous: u64, observed: u64 },
    DuplicateObservationTime { unix_ms: u64 },
    RegressingObservationTime { previous: u64, observed: u64 },
    ZeroElapsed,
    ElapsedExceedsBound,
    PayloadExceedsBound,
    SuccessfulPayloadBelowFloor,
    EvidenceCounterOverflow,
    SequenceOverflow,
    RateArithmeticOverflow,
    Statistics(MomentError),
}

impl fmt::Display for ProbeIngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NotAccepting { .. } => "health estimator is not accepting observations",
            Self::CarrierIdMismatch => "observation carrier ID does not match estimator",
            Self::UnsupportedObservationKind => {
                "health estimator accepts only representative volume probes"
            }
            Self::DuplicateWindow { .. } => "probe window index is duplicated",
            Self::RegressingWindow { .. } => "probe window index regressed",
            Self::DuplicateObservationTime { .. } => "probe observation time is duplicated",
            Self::RegressingObservationTime { .. } => "probe observation time regressed",
            Self::ZeroElapsed => "probe elapsed time must be non-zero",
            Self::ElapsedExceedsBound => "probe elapsed time exceeds configured bound",
            Self::PayloadExceedsBound => "probe payload exceeds configured bound",
            Self::SuccessfulPayloadBelowFloor => {
                "successful probe did not meet the configured workload floor"
            }
            Self::EvidenceCounterOverflow => "health evidence counter overflowed",
            Self::SequenceOverflow => "health snapshot sequence overflowed",
            Self::RateArithmeticOverflow => "probe goodput arithmetic overflowed",
            Self::Statistics(_) => "probe goodput statistics rejected the sample",
        };
        f.write_str(message)
    }
}

impl Error for ProbeIngestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Statistics(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthTransitionError {
    MustBeginClosing,
    AlreadyClosed,
    SequenceOverflow,
}

impl fmt::Display for HealthTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MustBeginClosing => "health estimator must enter closing before closed",
            Self::AlreadyClosed => "health estimator is already closed",
            Self::SequenceOverflow => "health snapshot sequence overflowed",
        };
        f.write_str(message)
    }
}

impl Error for HealthTransitionError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Open,
    Closing,
    Closed,
}

/// Deterministic per-carrier accumulator for independent volume probes.
#[derive(Clone, Debug)]
pub struct CarrierHealthEstimator {
    carrier_id: CarrierId,
    config: HealthEstimatorConfig,
    lifecycle: Lifecycle,
    sequence: u64,
    probe_count: u32,
    successful_probes: u32,
    last_window_index: Option<u64>,
    last_observation_unix_ms: Option<u64>,
    last_successful_probe_unix_ms: Option<u64>,
    minimum_successful_probe_bytes: Option<u64>,
    largest_successful_probe_bytes: u64,
    goodput: OnlineMoments,
    minimum_successful_goodput_bytes_per_second: Option<f64>,
    maximum_successful_goodput_bytes_per_second: Option<f64>,
}

impl CarrierHealthEstimator {
    pub fn new(
        carrier_id: impl Into<CarrierId>,
        config: HealthEstimatorConfig,
    ) -> Result<Self, HealthEstimatorInitError> {
        let carrier_id = carrier_id.into();
        if carrier_id.is_empty() {
            return Err(HealthEstimatorInitError::EmptyCarrierId);
        }
        config
            .validate()
            .map_err(HealthEstimatorInitError::InvalidConfig)?;

        Ok(Self {
            carrier_id,
            config,
            lifecycle: Lifecycle::Open,
            sequence: 0,
            probe_count: 0,
            successful_probes: 0,
            last_window_index: None,
            last_observation_unix_ms: None,
            last_successful_probe_unix_ms: None,
            minimum_successful_probe_bytes: None,
            largest_successful_probe_bytes: 0,
            goodput: OnlineMoments::new(),
            minimum_successful_goodput_bytes_per_second: None,
            maximum_successful_goodput_bytes_per_second: None,
        })
    }

    pub fn carrier_id(&self) -> &CarrierId {
        &self.carrier_id
    }

    pub fn config(&self) -> &HealthEstimatorConfig {
        &self.config
    }

    /// Largest successful representative payload retained for diagnostics.
    ///
    /// The current [`EvidenceSummary`] schema exports the stricter *minimum*
    /// successful workload.  This accessor preserves the requested largest
    /// payload without weakening that fail-closed serialized evidence.
    pub fn largest_successful_probe_bytes(&self) -> u64 {
        self.largest_successful_probe_bytes
    }

    /// Ingest exactly one volume-probe result for a strictly newer window.
    pub fn observe(&mut self, observation: ProbeWindowObservation) -> Result<(), ProbeIngestError> {
        let lifecycle_state = match self.lifecycle {
            Lifecycle::Open => None,
            Lifecycle::Closing => Some(CarrierHealthState::Closing),
            Lifecycle::Closed => Some(CarrierHealthState::Closed),
        };
        if let Some(state) = lifecycle_state {
            return Err(ProbeIngestError::NotAccepting { state });
        }
        if observation.carrier_observation.carrier_id != self.carrier_id {
            return Err(ProbeIngestError::CarrierIdMismatch);
        }

        let (succeeded, bytes_received, elapsed_ms) =
            match observation.carrier_observation.observation {
                ObservationKind::VolumeProbe {
                    succeeded,
                    bytes_received,
                    elapsed_ms,
                } => (succeeded, bytes_received, elapsed_ms),
                _ => return Err(ProbeIngestError::UnsupportedObservationKind),
            };

        if let Some(previous) = self.last_window_index {
            if observation.window_index == previous {
                return Err(ProbeIngestError::DuplicateWindow {
                    window_index: observation.window_index,
                });
            }
            if observation.window_index < previous {
                return Err(ProbeIngestError::RegressingWindow {
                    previous,
                    observed: observation.window_index,
                });
            }
        }

        let observed_at = observation.carrier_observation.observed_at_unix_ms;
        if let Some(previous) = self.last_observation_unix_ms {
            if observed_at == previous {
                return Err(ProbeIngestError::DuplicateObservationTime {
                    unix_ms: observed_at,
                });
            }
            if observed_at < previous {
                return Err(ProbeIngestError::RegressingObservationTime {
                    previous,
                    observed: observed_at,
                });
            }
        }
        if elapsed_ms == 0 {
            return Err(ProbeIngestError::ZeroElapsed);
        }
        if elapsed_ms > self.config.max_probe_elapsed_ms {
            return Err(ProbeIngestError::ElapsedExceedsBound);
        }
        if bytes_received > self.config.max_probe_payload_bytes {
            return Err(ProbeIngestError::PayloadExceedsBound);
        }
        if succeeded && bytes_received < self.config.min_successful_probe_bytes {
            return Err(ProbeIngestError::SuccessfulPayloadBelowFloor);
        }

        let next_probe_count = self
            .probe_count
            .checked_add(1)
            .ok_or(ProbeIngestError::EvidenceCounterOverflow)?;
        let next_successful_probes = if succeeded {
            self.successful_probes
                .checked_add(1)
                .ok_or(ProbeIngestError::EvidenceCounterOverflow)?
        } else {
            self.successful_probes
        };
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ProbeIngestError::SequenceOverflow)?;

        // Prepare all fallible statistic updates before committing any state.
        let mut next_goodput = self.goodput;
        let mut next_minimum_goodput = self.minimum_successful_goodput_bytes_per_second;
        let mut next_maximum_goodput = self.maximum_successful_goodput_bytes_per_second;
        let mut next_minimum_payload = self.minimum_successful_probe_bytes;
        let mut next_largest_payload = self.largest_successful_probe_bytes;
        let mut next_last_successful_probe_unix_ms = self.last_successful_probe_unix_ms;
        if succeeded {
            let numerator = bytes_received
                .checked_mul(1_000)
                .ok_or(ProbeIngestError::RateArithmeticOverflow)?;
            let goodput_bytes_per_second = numerator as f64 / elapsed_ms as f64;
            if !goodput_bytes_per_second.is_finite() {
                return Err(ProbeIngestError::RateArithmeticOverflow);
            }
            next_goodput
                .push(goodput_bytes_per_second)
                .map_err(ProbeIngestError::Statistics)?;
            next_minimum_goodput = Some(
                next_minimum_goodput
                    .map(|prior| prior.min(goodput_bytes_per_second))
                    .unwrap_or(goodput_bytes_per_second),
            );
            next_maximum_goodput = Some(
                next_maximum_goodput
                    .map(|prior| prior.max(goodput_bytes_per_second))
                    .unwrap_or(goodput_bytes_per_second),
            );
            next_minimum_payload = Some(
                next_minimum_payload
                    .map(|prior| prior.min(bytes_received))
                    .unwrap_or(bytes_received),
            );
            next_largest_payload = next_largest_payload.max(bytes_received);
            next_last_successful_probe_unix_ms = Some(observed_at);
        }

        self.probe_count = next_probe_count;
        self.successful_probes = next_successful_probes;
        self.sequence = next_sequence;
        self.last_window_index = Some(observation.window_index);
        self.last_observation_unix_ms = Some(observed_at);
        self.last_successful_probe_unix_ms = next_last_successful_probe_unix_ms;
        self.goodput = next_goodput;
        self.minimum_successful_goodput_bytes_per_second = next_minimum_goodput;
        self.maximum_successful_goodput_bytes_per_second = next_maximum_goodput;
        self.minimum_successful_probe_bytes = next_minimum_payload;
        self.largest_successful_probe_bytes = next_largest_payload;
        Ok(())
    }

    /// Enter `Closing`.  Repeating the transition is an idempotent no-op.
    pub fn begin_closing(&mut self) -> Result<bool, HealthTransitionError> {
        match self.lifecycle {
            Lifecycle::Open => {
                let next_sequence = self
                    .sequence
                    .checked_add(1)
                    .ok_or(HealthTransitionError::SequenceOverflow)?;
                self.sequence = next_sequence;
                self.lifecycle = Lifecycle::Closing;
                Ok(true)
            }
            Lifecycle::Closing => Ok(false),
            Lifecycle::Closed => Err(HealthTransitionError::AlreadyClosed),
        }
    }

    /// Complete the explicit `Open -> Closing -> Closed` lifecycle.
    /// Repeating `Closed -> Closed` is an idempotent no-op.
    pub fn mark_closed(&mut self) -> Result<bool, HealthTransitionError> {
        match self.lifecycle {
            Lifecycle::Open => Err(HealthTransitionError::MustBeginClosing),
            Lifecycle::Closing => {
                let next_sequence = self
                    .sequence
                    .checked_add(1)
                    .ok_or(HealthTransitionError::SequenceOverflow)?;
                self.sequence = next_sequence;
                self.lifecycle = Lifecycle::Closed;
                Ok(true)
            }
            Lifecycle::Closed => Ok(false),
        }
    }

    /// Produce an immutable estimate.  Snapshotting itself never advances the
    /// deterministic sequence.
    pub fn snapshot(&self) -> CarrierHealthSnapshot {
        let reachability = self.reachability_bounds();
        let goodput_bytes_per_second = self.goodput_bounds();
        let state = self.classify(reachability, goodput_bytes_per_second);

        CarrierHealthSnapshot {
            carrier_id: self.carrier_id.clone(),
            sequence: self.sequence,
            state,
            reachability,
            goodput_bytes_per_second,
            evidence: EvidenceSummary {
                probe_count: self.probe_count,
                successful_probes: self.successful_probes,
                independent_windows: self.probe_count,
                successful_independent_windows: self.successful_probes,
                minimum_successful_workload_bytes: self.minimum_successful_probe_bytes.unwrap_or(0),
                last_observation_unix_ms: self.last_observation_unix_ms,
                last_successful_probe_unix_ms: self.last_successful_probe_unix_ms,
            },
            // This estimator accepts only numeric volume results.  Correlated
            // failure-domain evidence belongs to a separate typed detector.
            active_failure_domains: Vec::new(),
        }
    }

    fn reachability_bounds(&self) -> EstimateBounds {
        if self.probe_count == 0 {
            return EstimateBounds::new(0.0, 0.0, 1.0);
        }

        let trials = u64::from(self.probe_count);
        let successes = u64::from(self.successful_probes);
        let failures = trials - successes;
        // Errors are unreachable because the estimator preserves successes <=
        // trials and the helper owns its valid fixed z-score.  Fail-closed
        // fallbacks still make snapshotting total if that contract changes.
        let lower = wilson_lower_bound_95(successes, trials)
            .ok()
            .flatten()
            .unwrap_or(0.0);
        let failure_lower = wilson_lower_bound_95(failures, trials)
            .ok()
            .flatten()
            .unwrap_or(0.0);
        let point = successes as f64 / trials as f64;
        let upper = (1.0 - failure_lower).clamp(point, 1.0);
        EstimateBounds::new(lower.min(point), point, upper)
    }

    fn goodput_bounds(&self) -> EstimateBounds {
        let maximum_possible = self.config.maximum_goodput_bytes_per_second();
        let Some(point) = self.goodput.mean() else {
            return EstimateBounds::new(0.0, 0.0, maximum_possible);
        };

        let point = point.clamp(0.0, maximum_possible);
        if self.goodput.count() == 1 {
            return EstimateBounds::new(0.0, point, maximum_possible);
        }

        let standard_error = self.goodput.standard_error().unwrap_or(f64::INFINITY);
        let critical = student_t_critical_95(self.goodput.count() - 1);
        let margin = critical * standard_error;
        if !margin.is_finite() {
            return EstimateBounds::new(0.0, point, maximum_possible);
        }

        let observed_minimum = self
            .minimum_successful_goodput_bytes_per_second
            .unwrap_or(0.0);
        let observed_maximum = self
            .maximum_successful_goodput_bytes_per_second
            .unwrap_or(maximum_possible);
        let lower = (point - margin).max(0.0).min(observed_minimum).min(point);
        let upper = (point + margin)
            .max(observed_maximum)
            .max(point)
            .min(maximum_possible);
        EstimateBounds::new(lower, point, upper)
    }

    fn classify(
        &self,
        reachability: EstimateBounds,
        goodput: EstimateBounds,
    ) -> CarrierHealthState {
        match self.lifecycle {
            Lifecycle::Closing => return CarrierHealthState::Closing,
            Lifecycle::Closed => return CarrierHealthState::Closed,
            Lifecycle::Open => {}
        }
        if self.probe_count < self.config.min_classification_windows {
            return CarrierHealthState::Unknown;
        }
        if self.successful_probes == 0
            || reachability.upper <= self.config.unreachable_reachability_upper_bound
        {
            return CarrierHealthState::Unreachable;
        }
        if reachability.lower >= self.config.healthy_reachability_lower_bound
            && goodput.lower >= self.config.healthy_goodput_lower_bound_bytes_per_second
        {
            CarrierHealthState::Healthy
        } else {
            CarrierHealthState::Degraded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: u64 = DEFAULT_MIN_REPRESENTATIVE_WORKLOAD_BYTES;

    fn estimator() -> CarrierHealthEstimator {
        CarrierHealthEstimator::new("carrier-a", HealthEstimatorConfig::default())
            .expect("valid defaults")
    }

    fn probe(
        window_index: u64,
        observed_at_unix_ms: u64,
        succeeded: bool,
        bytes_received: u64,
        elapsed_ms: u64,
    ) -> ProbeWindowObservation {
        ProbeWindowObservation {
            window_index,
            carrier_observation: CarrierObservation {
                carrier_id: CarrierId::from("carrier-a"),
                observed_at_unix_ms,
                observation: ObservationKind::VolumeProbe {
                    succeeded,
                    bytes_received,
                    elapsed_ms,
                },
            },
        }
    }

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= 1.0e-12,
            "actual={actual}, expected={expected}"
        );
    }

    #[test]
    fn defaults_validate_and_empty_carrier_id_is_rejected() {
        HealthEstimatorConfig::default()
            .validate()
            .expect("valid defaults");
        assert!(matches!(
            CarrierHealthEstimator::new("", HealthEstimatorConfig::default()),
            Err(HealthEstimatorInitError::EmptyCarrierId)
        ));
    }

    #[test]
    fn config_rejects_nonfinite_inverted_and_overflowing_bounds() {
        let config = HealthEstimatorConfig {
            healthy_reachability_lower_bound: f64::NAN,
            ..HealthEstimatorConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(HealthEstimatorConfigError::InvalidHealthyReachabilityBound)
        );

        let config = HealthEstimatorConfig {
            unreachable_reachability_upper_bound: f64::INFINITY,
            ..HealthEstimatorConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(HealthEstimatorConfigError::InvalidUnreachableReachabilityBound)
        );

        let config = HealthEstimatorConfig {
            healthy_goodput_lower_bound_bytes_per_second: f64::NEG_INFINITY,
            ..HealthEstimatorConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(HealthEstimatorConfigError::InvalidHealthyGoodputBound)
        );

        let config = HealthEstimatorConfig {
            healthy_goodput_lower_bound_bytes_per_second: 0.0,
            ..HealthEstimatorConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(HealthEstimatorConfigError::InvalidHealthyGoodputBound)
        );

        let config = HealthEstimatorConfig {
            max_probe_payload_bytes: DEFAULT_MIN_REPRESENTATIVE_WORKLOAD_BYTES - 1,
            ..HealthEstimatorConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(HealthEstimatorConfigError::PayloadBoundsInverted)
        );

        let config = HealthEstimatorConfig {
            max_probe_payload_bytes: u64::MAX,
            ..HealthEstimatorConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(HealthEstimatorConfigError::ProbeRateNumeratorOverflow)
        );
    }

    #[test]
    fn ordered_successes_produce_wilson_bounds_and_complete_evidence() {
        let mut estimator = estimator();
        for window in 1..=3 {
            estimator
                .observe(probe(window, 1_000 + window, true, 2 * FLOOR, 1_000))
                .expect("ordered probe");
        }

        let snapshot = estimator.snapshot();
        let expected_lower = wilson_lower_bound_95(3, 3)
            .expect("valid counts")
            .expect("non-empty");
        assert_close(snapshot.reachability.lower, expected_lower);
        assert_close(snapshot.reachability.point, 1.0);
        assert_close(snapshot.reachability.upper, 1.0);
        assert_eq!(snapshot.sequence, 3);
        assert_eq!(snapshot.state, CarrierHealthState::Healthy);
        assert_eq!(snapshot.evidence.probe_count, 3);
        assert_eq!(snapshot.evidence.successful_probes, 3);
        assert_eq!(snapshot.evidence.independent_windows, 3);
        assert_eq!(snapshot.evidence.successful_independent_windows, 3);
        assert_eq!(
            snapshot.evidence.minimum_successful_workload_bytes,
            2 * FLOOR
        );
        assert_eq!(snapshot.evidence.last_observation_unix_ms, Some(1_003));
        assert_eq!(snapshot.evidence.last_successful_probe_unix_ms, Some(1_003));
        assert_eq!(estimator.largest_successful_probe_bytes(), 2 * FLOOR);
        assert!(snapshot.active_failure_domains.is_empty());
    }

    #[test]
    fn duplicate_or_regressing_windows_are_transactionally_rejected() {
        let mut estimator = estimator();
        estimator
            .observe(probe(7, 7_000, true, FLOOR, 1_000))
            .expect("first probe");
        let before = estimator.snapshot();

        assert!(matches!(
            estimator.observe(probe(7, 7_001, true, FLOOR, 1_000)),
            Err(ProbeIngestError::DuplicateWindow { window_index: 7 })
        ));
        assert_eq!(estimator.snapshot(), before);
        assert!(matches!(
            estimator.observe(probe(6, 7_002, true, FLOOR, 1_000)),
            Err(ProbeIngestError::RegressingWindow {
                previous: 7,
                observed: 6
            })
        ));
        assert_eq!(estimator.snapshot(), before);
    }

    #[test]
    fn duplicate_or_regressing_times_are_transactionally_rejected() {
        let mut estimator = estimator();
        estimator
            .observe(probe(1, 5_000, true, FLOOR, 1_000))
            .expect("first probe");
        let before = estimator.snapshot();

        assert!(matches!(
            estimator.observe(probe(2, 5_000, true, FLOOR, 1_000)),
            Err(ProbeIngestError::DuplicateObservationTime { unix_ms: 5_000 })
        ));
        assert_eq!(estimator.snapshot(), before);
        assert!(matches!(
            estimator.observe(probe(2, 4_999, true, FLOOR, 1_000)),
            Err(ProbeIngestError::RegressingObservationTime {
                previous: 5_000,
                observed: 4_999
            })
        ));
        assert_eq!(estimator.snapshot(), before);
    }

    #[test]
    fn elapsed_payload_and_success_floor_are_hard_bounds() {
        let mut estimator = estimator();
        assert_eq!(
            estimator.observe(probe(1, 1, true, FLOOR, 0)),
            Err(ProbeIngestError::ZeroElapsed)
        );
        assert_eq!(
            estimator.observe(probe(1, 1, true, FLOOR, DEFAULT_MAX_PROBE_ELAPSED_MS + 1)),
            Err(ProbeIngestError::ElapsedExceedsBound)
        );
        assert_eq!(
            estimator.observe(probe(
                1,
                1,
                true,
                DEFAULT_MAX_PROBE_PAYLOAD_BYTES + 1,
                1_000
            )),
            Err(ProbeIngestError::PayloadExceedsBound)
        );
        assert_eq!(
            estimator.observe(probe(1, 1, true, FLOOR - 1, 1_000)),
            Err(ProbeIngestError::SuccessfulPayloadBelowFloor)
        );
        assert_eq!(estimator.snapshot().sequence, 0);
    }

    #[test]
    fn failed_partial_probe_is_reachability_evidence_not_goodput() {
        let mut estimator = estimator();
        estimator
            .observe(probe(1, 1, false, FLOOR - 1, 1_000))
            .expect("bounded failure");
        let snapshot = estimator.snapshot();
        assert_eq!(snapshot.evidence.probe_count, 1);
        assert_eq!(snapshot.evidence.successful_probes, 0);
        assert_eq!(snapshot.evidence.minimum_successful_workload_bytes, 0);
        assert_eq!(snapshot.evidence.last_successful_probe_unix_ms, None);
        assert_eq!(estimator.largest_successful_probe_bytes(), 0);
        assert_eq!(snapshot.goodput_bytes_per_second.lower, 0.0);
        assert_eq!(snapshot.goodput_bytes_per_second.point, 0.0);
        assert_eq!(snapshot.state, CarrierHealthState::Unknown);
    }

    #[test]
    fn fresh_failure_does_not_refresh_last_successful_probe() {
        let mut estimator = estimator();
        estimator
            .observe(probe(1, 1_000, true, 2 * FLOOR, 1_000))
            .expect("successful probe");
        estimator
            .observe(probe(2, 2_000, false, FLOOR / 2, 1_000))
            .expect("failed probe");

        let snapshot = estimator.snapshot();
        assert_eq!(snapshot.evidence.last_observation_unix_ms, Some(2_000));
        assert_eq!(snapshot.evidence.last_successful_probe_unix_ms, Some(1_000));
        assert_eq!(
            snapshot.evidence.minimum_successful_workload_bytes,
            2 * FLOOR
        );
        assert_eq!(estimator.largest_successful_probe_bytes(), 2 * FLOOR);
    }

    #[test]
    fn mismatched_and_non_volume_observations_are_rejected() {
        let mut estimator = estimator();
        let mut mismatched = probe(1, 1, true, FLOOR, 1_000);
        mismatched.carrier_observation.carrier_id = CarrierId::from("carrier-b");
        assert_eq!(
            estimator.observe(mismatched),
            Err(ProbeIngestError::CarrierIdMismatch)
        );

        let dial = ProbeWindowObservation {
            window_index: 1,
            carrier_observation: CarrierObservation {
                carrier_id: CarrierId::from("carrier-a"),
                observed_at_unix_ms: 1,
                observation: ObservationKind::Dial {
                    succeeded: true,
                    latency_ms: Some(5),
                },
            },
        };
        assert_eq!(
            estimator.observe(dial),
            Err(ProbeIngestError::UnsupportedObservationKind)
        );
        assert_eq!(estimator.snapshot().sequence, 0);
    }

    #[test]
    fn one_goodput_sample_has_a_zero_lower_bound() {
        let mut estimator = estimator();
        estimator
            .observe(probe(1, 1, true, FLOOR, 1_000))
            .expect("probe");
        let bounds = estimator.snapshot().goodput_bytes_per_second;
        assert_eq!(bounds.lower, 0.0);
        assert_eq!(bounds.point, FLOOR as f64);
        assert_eq!(
            bounds.upper,
            estimator.config().maximum_goodput_bytes_per_second()
        );
    }

    #[test]
    fn repeated_equal_goodput_has_tight_welford_bounds() {
        let mut estimator = estimator();
        for window in 1..=3 {
            estimator
                .observe(probe(window, window, true, FLOOR, 1_000))
                .expect("probe");
        }
        let bounds = estimator.snapshot().goodput_bytes_per_second;
        assert_eq!(
            bounds,
            EstimateBounds::new(FLOOR as f64, FLOOR as f64, FLOOR as f64)
        );
    }

    #[test]
    fn varying_goodput_interval_contains_observed_extremes() {
        let mut estimator = estimator();
        for (window, bytes) in [(1, FLOOR), (2, 2 * FLOOR), (3, 4 * FLOOR)] {
            estimator
                .observe(probe(window, window, true, bytes, 1_000))
                .expect("probe");
        }
        let bounds = estimator.snapshot().goodput_bytes_per_second;
        assert!(bounds.lower <= FLOOR as f64);
        assert!(bounds.upper >= (4 * FLOOR) as f64);
        assert_close(bounds.point, (7 * FLOOR) as f64 / 3.0);
        assert!(bounds.is_non_negative());
    }

    #[test]
    fn health_states_follow_closed_nonoverlapping_rules() {
        let mut healthy = estimator();
        for window in 1..=2 {
            healthy
                .observe(probe(window, window, true, FLOOR, 1_000))
                .expect("probe");
        }
        assert_eq!(healthy.snapshot().state, CarrierHealthState::Unknown);
        healthy
            .observe(probe(3, 3, true, FLOOR, 1_000))
            .expect("probe");
        assert_eq!(healthy.snapshot().state, CarrierHealthState::Healthy);

        let mut unreachable = estimator();
        for window in 1..=3 {
            unreachable
                .observe(probe(window, window, false, 0, 1_000))
                .expect("probe");
        }
        assert_eq!(
            unreachable.snapshot().state,
            CarrierHealthState::Unreachable
        );

        let mut degraded = estimator();
        degraded
            .observe(probe(1, 1, true, FLOOR, 1_000))
            .expect("probe");
        degraded
            .observe(probe(2, 2, false, 0, 1_000))
            .expect("probe");
        degraded
            .observe(probe(3, 3, false, 0, 1_000))
            .expect("probe");
        assert_eq!(degraded.snapshot().state, CarrierHealthState::Degraded);
    }

    #[test]
    fn lifecycle_overrides_evidence_and_rejects_late_observations() {
        let mut health = estimator();
        assert_eq!(health.begin_closing(), Ok(true));
        assert_eq!(health.snapshot().state, CarrierHealthState::Closing);
        assert_eq!(health.snapshot().sequence, 1);
        assert_eq!(health.begin_closing(), Ok(false));
        assert!(matches!(
            health.observe(probe(1, 1, true, FLOOR, 1_000)),
            Err(ProbeIngestError::NotAccepting {
                state: CarrierHealthState::Closing
            })
        ));
        assert_eq!(health.mark_closed(), Ok(true));
        assert_eq!(health.snapshot().state, CarrierHealthState::Closed);
        assert_eq!(health.snapshot().sequence, 2);
        assert_eq!(health.mark_closed(), Ok(false));
        assert_eq!(
            health.begin_closing(),
            Err(HealthTransitionError::AlreadyClosed)
        );

        let mut direct_close = estimator();
        assert_eq!(
            direct_close.mark_closed(),
            Err(HealthTransitionError::MustBeginClosing)
        );
        assert_eq!(direct_close.snapshot().sequence, 0);
    }

    #[test]
    fn sequence_and_evidence_overflow_fail_without_mutation() {
        let mut sequence_overflow = estimator();
        sequence_overflow.sequence = u64::MAX;
        assert_eq!(
            sequence_overflow.observe(probe(1, 1, true, FLOOR, 1_000)),
            Err(ProbeIngestError::SequenceOverflow)
        );
        assert_eq!(sequence_overflow.sequence, u64::MAX);
        assert_eq!(sequence_overflow.probe_count, 0);

        let mut evidence_overflow = estimator();
        evidence_overflow.probe_count = u32::MAX;
        assert_eq!(
            evidence_overflow.observe(probe(1, 1, false, 0, 1_000)),
            Err(ProbeIngestError::EvidenceCounterOverflow)
        );
        assert_eq!(evidence_overflow.sequence, 0);
        assert_eq!(evidence_overflow.last_window_index, None);
    }

    #[test]
    fn snapshotting_is_deterministic_and_does_not_advance_sequence() {
        let mut estimator = estimator();
        estimator
            .observe(probe(10, 10, true, FLOOR, 1_000))
            .expect("probe");
        let first = estimator.snapshot();
        let second = estimator.snapshot();
        assert_eq!(first, second);
        assert_eq!(first.sequence, 1);
    }
}
