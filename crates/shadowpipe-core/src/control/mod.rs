//! Read-only, uncertainty-aware carrier selection.
//!
//! This module is deliberately **shadow mode only**.  It accepts immutable
//! snapshots and returns an auditable `WouldSelect` verdict.  It has no carrier
//! handle, route handle, callback, or activation method, so evaluating a report
//! cannot mutate routes or move live traffic.

pub mod estimator;

use crate::carrier::api::{
    AccessRegime, CarrierCapabilities, CarrierHealthSnapshot, CarrierHealthState, CarrierId,
    CarrierTopology, FailureDomain,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// Default floor for a probe that represents an application's real workload.
///
/// One MiB is a configurable measurement-quality default.  It is not a claim
/// that a censor has a byte threshold, nor should callers infer one from it.
pub const DEFAULT_MIN_REPRESENTATIVE_WORKLOAD_BYTES: u64 = 1024 * 1024;

const REACHABILITY_LCB_TOLERANCE: f64 = 1e-9;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGate {
    pub min_probe_count: u32,
    pub min_successful_probes: u32,
    pub min_independent_windows: u32,
    pub min_representative_workload_bytes: u64,
    pub max_observation_age_ms: u64,
    pub min_reachability_lower_bound: f64,
    pub min_goodput_lower_bound_bytes_per_second: f64,
}

impl Default for EvidenceGate {
    fn default() -> Self {
        Self {
            min_probe_count: 3,
            min_successful_probes: 2,
            min_independent_windows: 2,
            min_representative_workload_bytes: DEFAULT_MIN_REPRESENTATIVE_WORKLOAD_BYTES,
            max_observation_age_ms: 5 * 60 * 1_000,
            min_reachability_lower_bound: 0.25,
            min_goodput_lower_bound_bytes_per_second: 7.0 * 1024.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorPolicy {
    pub evidence: EvidenceGate,
    /// Half-saturation constant for goodput normalization.  At this lower-bound
    /// goodput, the normalized goodput term is exactly 0.5.
    pub goodput_scale_bytes_per_second: f64,
}

impl Default for SelectorPolicy {
    fn default() -> Self {
        Self {
            evidence: EvidenceGate::default(),
            goodput_scale_bytes_per_second: 256.0 * 1024.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectorPolicyError {
    ZeroMinimumProbeCount,
    ZeroMinimumSuccessfulProbes,
    ZeroMinimumIndependentWindows,
    ZeroMinimumRepresentativeWorkloadBytes,
    ProbeSuccessesExceedProbes,
    WindowsExceedProbes,
    InvalidReachabilityFloor,
    InvalidGoodputFloor,
    InvalidGoodputScale,
}

impl fmt::Display for SelectorPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroMinimumProbeCount => "minimum probe count must be greater than zero",
            Self::ZeroMinimumSuccessfulProbes => {
                "minimum successful probes must be greater than zero"
            }
            Self::ZeroMinimumIndependentWindows => {
                "minimum independent windows must be greater than zero"
            }
            Self::ZeroMinimumRepresentativeWorkloadBytes => {
                "minimum representative workload bytes must be greater than zero"
            }
            Self::ProbeSuccessesExceedProbes => {
                "minimum successful probes exceeds minimum probe count"
            }
            Self::WindowsExceedProbes => "minimum independent windows exceeds minimum probe count",
            Self::InvalidReachabilityFloor => {
                "reachability lower-bound floor must be finite and in (0, 1]"
            }
            Self::InvalidGoodputFloor => {
                "goodput lower-bound floor must be finite and greater than zero"
            }
            Self::InvalidGoodputScale => "goodput scale must be finite and greater than zero",
        };
        f.write_str(message)
    }
}

impl Error for SelectorPolicyError {}

impl SelectorPolicy {
    pub fn validate(&self) -> Result<(), SelectorPolicyError> {
        if self.evidence.min_probe_count == 0 {
            return Err(SelectorPolicyError::ZeroMinimumProbeCount);
        }
        if self.evidence.min_successful_probes == 0 {
            return Err(SelectorPolicyError::ZeroMinimumSuccessfulProbes);
        }
        if self.evidence.min_independent_windows == 0 {
            return Err(SelectorPolicyError::ZeroMinimumIndependentWindows);
        }
        if self.evidence.min_representative_workload_bytes == 0 {
            return Err(SelectorPolicyError::ZeroMinimumRepresentativeWorkloadBytes);
        }
        if self.evidence.min_successful_probes > self.evidence.min_probe_count {
            return Err(SelectorPolicyError::ProbeSuccessesExceedProbes);
        }
        if self.evidence.min_independent_windows > self.evidence.min_probe_count {
            return Err(SelectorPolicyError::WindowsExceedProbes);
        }
        if !self.evidence.min_reachability_lower_bound.is_finite()
            || self.evidence.min_reachability_lower_bound <= 0.0
            || self.evidence.min_reachability_lower_bound > 1.0
        {
            return Err(SelectorPolicyError::InvalidReachabilityFloor);
        }
        if !self
            .evidence
            .min_goodput_lower_bound_bytes_per_second
            .is_finite()
            || self.evidence.min_goodput_lower_bound_bytes_per_second <= 0.0
        {
            return Err(SelectorPolicyError::InvalidGoodputFloor);
        }
        if !self.goodput_scale_bytes_per_second.is_finite()
            || self.goodput_scale_bytes_per_second <= 0.0
        {
            return Err(SelectorPolicyError::InvalidGoodputScale);
        }
        Ok(())
    }
}

/// Fail-closed topology constraint.  `OneOf(Vec::new())` allows nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum TopologyConstraint {
    Any,
    OneOf { topologies: Vec<CarrierTopology> },
}

impl TopologyConstraint {
    fn allows(&self, topology: CarrierTopology) -> bool {
        match self {
            Self::Any => true,
            Self::OneOf { topologies } => topologies.contains(&topology),
        }
    }
}

/// Immutable conditions under which candidates are evaluated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionRequirements {
    pub access_regime: AccessRegime,
    pub topology: TopologyConstraint,
    /// Avoid statically shared or currently active correlated failure domains.
    pub excluded_failure_domains: Vec<FailureDomain>,
    pub now_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierCandidate {
    pub capabilities: CarrierCapabilities,
    pub health: CarrierHealthSnapshot,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RejectionReason {
    EmptyCarrierId,
    DuplicateCarrierId {
        carrier_id: CarrierId,
    },
    CarrierIdMismatch {
        capabilities_id: CarrierId,
        health_id: CarrierId,
    },
    UnsupportedAccessRegime {
        required: AccessRegime,
    },
    TopologyNotAllowed {
        observed: CarrierTopology,
    },
    ExcludedFailureDomain {
        domain: FailureDomain,
    },
    HealthStateNotSelectable {
        state: CarrierHealthState,
    },
    ZeroMaxParallelStreams,
    InvalidReachabilityBounds,
    InvalidGoodputBounds,
    InvalidEvidenceCounters,
    InsufficientProbes {
        observed: u32,
        required: u32,
    },
    InsufficientSuccessfulProbes {
        observed: u32,
        required: u32,
    },
    InsufficientIndependentWindows {
        observed: u32,
        required: u32,
    },
    RepresentativeWorkloadTooSmall {
        observed_bytes: u64,
        required_bytes: u64,
    },
    NoDatedObservation,
    NoDatedSuccessfulObservation,
    ObservationFromFuture {
        observed_at_unix_ms: u64,
        now_unix_ms: u64,
    },
    StaleObservation {
        age_ms: u64,
        max_age_ms: u64,
    },
    SuccessfulObservationFromFuture {
        observed_at_unix_ms: u64,
        now_unix_ms: u64,
    },
    StaleSuccessfulObservation {
        age_ms: u64,
        max_age_ms: u64,
    },
    ReportedReachabilityLowerBoundExceedsEmpirical {
        reported: f64,
        empirical: f64,
    },
    ConservativeReachabilityLowerBoundBelowFloor {
        observed: f64,
        required: f64,
    },
    GoodputLowerBoundBelowFloor {
        observed_bytes_per_second: f64,
        required_bytes_per_second: f64,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum CandidateAssessment {
    Eligible {
        carrier_id: CarrierId,
        conservative_score: f64,
        reachability_lower_bound: f64,
        goodput_lower_bound_bytes_per_second: f64,
    },
    Rejected {
        carrier_id: CarrierId,
        reasons: Vec<RejectionReason>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCandidate {
    pub carrier_id: CarrierId,
    pub conservative_score: f64,
    pub reachability_lower_bound: f64,
    pub goodput_lower_bound_bytes_per_second: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoCandidateCause {
    NoCarriersProvided,
    AllCarriersRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoCandidateVerdict {
    pub cause: NoCandidateCause,
    pub evaluated_candidates: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ShadowVerdict {
    WouldSelect { candidate: ShadowCandidate },
    NoCandidate { detail: NoCandidateVerdict },
}

/// The only supported mode.  It is serialized into every report so downstream
/// tooling cannot mistake an advisory verdict for an applied route transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorMode {
    Shadow,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowSelectionReport {
    pub mode: SelectorMode,
    pub verdict: ShadowVerdict,
    pub assessments: Vec<CandidateAssessment>,
}

/// Pure shadow selector.  It owns only policy and cannot access carrier or route
/// mutation surfaces.
#[derive(Clone, Debug, Default)]
pub struct ShadowSelector {
    policy: SelectorPolicy,
}

impl ShadowSelector {
    pub fn new(policy: SelectorPolicy) -> Result<Self, SelectorPolicyError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn policy(&self) -> &SelectorPolicy {
        &self.policy
    }

    /// Evaluate snapshots without dialing, closing, activating, or mutating.
    pub fn evaluate(
        &self,
        requirements: &SelectionRequirements,
        candidates: &[CarrierCandidate],
    ) -> ShadowSelectionReport {
        let mut assessments = Vec::with_capacity(candidates.len());
        let mut best: Option<ShadowCandidate> = None;
        let carrier_id_counts = candidates
            .iter()
            .fold(BTreeMap::new(), |mut counts, candidate| {
                *counts
                    .entry(candidate.capabilities.carrier_id.clone())
                    .or_insert(0_usize) += 1;
                counts
            });

        for candidate in candidates {
            let duplicate_carrier_id = carrier_id_counts
                .get(&candidate.capabilities.carrier_id)
                .copied()
                .unwrap_or_default()
                > 1;
            let reasons = self.rejection_reasons(requirements, candidate, duplicate_carrier_id);
            let carrier_id = candidate.capabilities.carrier_id.clone();

            if reasons.is_empty() {
                let Some(reachability_lower_bound) =
                    conservative_reachability_lcb(&candidate.health)
                else {
                    // Defensive totality: future validation changes must not
                    // turn malformed evidence into a selector panic.
                    assessments.push(CandidateAssessment::Rejected {
                        carrier_id,
                        reasons: vec![RejectionReason::InvalidEvidenceCounters],
                    });
                    continue;
                };
                let goodput_lower_bound_bytes_per_second =
                    candidate.health.goodput_bytes_per_second.lower;
                let conservative_score = conservative_score(
                    reachability_lower_bound,
                    goodput_lower_bound_bytes_per_second,
                    self.policy.goodput_scale_bytes_per_second,
                );
                let eligible = ShadowCandidate {
                    carrier_id: carrier_id.clone(),
                    conservative_score,
                    reachability_lower_bound,
                    goodput_lower_bound_bytes_per_second,
                };

                if best
                    .as_ref()
                    .map(|incumbent| better_candidate(&eligible, incumbent))
                    .unwrap_or(true)
                {
                    best = Some(eligible);
                }

                assessments.push(CandidateAssessment::Eligible {
                    carrier_id,
                    conservative_score,
                    reachability_lower_bound,
                    goodput_lower_bound_bytes_per_second,
                });
            } else {
                assessments.push(CandidateAssessment::Rejected {
                    carrier_id,
                    reasons,
                });
            }
        }

        let verdict = match best {
            Some(candidate) => ShadowVerdict::WouldSelect { candidate },
            None => ShadowVerdict::NoCandidate {
                detail: NoCandidateVerdict {
                    cause: if candidates.is_empty() {
                        NoCandidateCause::NoCarriersProvided
                    } else {
                        NoCandidateCause::AllCarriersRejected
                    },
                    evaluated_candidates: candidates.len(),
                },
            },
        };

        ShadowSelectionReport {
            mode: SelectorMode::Shadow,
            verdict,
            assessments,
        }
    }

    fn rejection_reasons(
        &self,
        requirements: &SelectionRequirements,
        candidate: &CarrierCandidate,
        duplicate_carrier_id: bool,
    ) -> Vec<RejectionReason> {
        let mut reasons = Vec::new();
        let capabilities = &candidate.capabilities;
        let health = &candidate.health;
        let gate = &self.policy.evidence;

        if capabilities.carrier_id.is_empty() {
            reasons.push(RejectionReason::EmptyCarrierId);
        }
        if duplicate_carrier_id {
            reasons.push(RejectionReason::DuplicateCarrierId {
                carrier_id: capabilities.carrier_id.clone(),
            });
        }
        if capabilities.carrier_id != health.carrier_id {
            reasons.push(RejectionReason::CarrierIdMismatch {
                capabilities_id: capabilities.carrier_id.clone(),
                health_id: health.carrier_id.clone(),
            });
        }
        if !capabilities.supports_access_regime(requirements.access_regime) {
            reasons.push(RejectionReason::UnsupportedAccessRegime {
                required: requirements.access_regime,
            });
        }
        if !requirements.topology.allows(capabilities.topology) {
            reasons.push(RejectionReason::TopologyNotAllowed {
                observed: capabilities.topology,
            });
        }

        for domain in capabilities
            .failure_domains
            .iter()
            .chain(health.active_failure_domains.iter())
        {
            if requirements.excluded_failure_domains.contains(domain)
                && !reasons.iter().any(|reason| {
                    matches!(
                        reason,
                        RejectionReason::ExcludedFailureDomain { domain: prior }
                            if prior == domain
                    )
                })
            {
                reasons.push(RejectionReason::ExcludedFailureDomain {
                    domain: domain.clone(),
                });
            }
        }

        if !matches!(
            health.state,
            CarrierHealthState::Healthy | CarrierHealthState::Degraded
        ) {
            reasons.push(RejectionReason::HealthStateNotSelectable {
                state: health.state,
            });
        }
        if capabilities.max_parallel_streams == Some(0) {
            reasons.push(RejectionReason::ZeroMaxParallelStreams);
        }

        let reachability_valid = health.reachability.is_probability();
        if !reachability_valid {
            reasons.push(RejectionReason::InvalidReachabilityBounds);
        }
        let goodput_valid = health.goodput_bytes_per_second.is_non_negative();
        if !goodput_valid {
            reasons.push(RejectionReason::InvalidGoodputBounds);
        }

        let evidence_counters_valid = health.evidence.successful_probes
            <= health.evidence.probe_count
            && health.evidence.independent_windows <= health.evidence.probe_count
            && health.evidence.successful_independent_windows
                <= health.evidence.independent_windows
            && health.evidence.successful_independent_windows <= health.evidence.successful_probes
            && match health.evidence.successful_probes {
                0 => {
                    health.evidence.successful_independent_windows == 0
                        && health.evidence.minimum_successful_workload_bytes == 0
                        && health.evidence.last_successful_probe_unix_ms.is_none()
                }
                _ => {
                    health.evidence.successful_independent_windows > 0
                        && health.evidence.minimum_successful_workload_bytes > 0
                        && health.evidence.last_successful_probe_unix_ms.is_some()
                        && health.evidence.last_successful_probe_unix_ms
                            <= health.evidence.last_observation_unix_ms
                }
            };
        if !evidence_counters_valid {
            reasons.push(RejectionReason::InvalidEvidenceCounters);
        }
        if health.evidence.probe_count < gate.min_probe_count {
            reasons.push(RejectionReason::InsufficientProbes {
                observed: health.evidence.probe_count,
                required: gate.min_probe_count,
            });
        }
        if health.evidence.successful_probes < gate.min_successful_probes {
            reasons.push(RejectionReason::InsufficientSuccessfulProbes {
                observed: health.evidence.successful_probes,
                required: gate.min_successful_probes,
            });
        }
        if health.evidence.independent_windows < gate.min_independent_windows {
            reasons.push(RejectionReason::InsufficientIndependentWindows {
                observed: health.evidence.independent_windows,
                required: gate.min_independent_windows,
            });
        }
        if health.evidence.minimum_successful_workload_bytes
            < gate.min_representative_workload_bytes
        {
            reasons.push(RejectionReason::RepresentativeWorkloadTooSmall {
                observed_bytes: health.evidence.minimum_successful_workload_bytes,
                required_bytes: gate.min_representative_workload_bytes,
            });
        }

        match health.evidence.last_observation_unix_ms {
            None => reasons.push(RejectionReason::NoDatedObservation),
            Some(observed_at) if observed_at > requirements.now_unix_ms => {
                reasons.push(RejectionReason::ObservationFromFuture {
                    observed_at_unix_ms: observed_at,
                    now_unix_ms: requirements.now_unix_ms,
                });
            }
            Some(observed_at) => {
                let age_ms = requirements.now_unix_ms - observed_at;
                if age_ms > gate.max_observation_age_ms {
                    reasons.push(RejectionReason::StaleObservation {
                        age_ms,
                        max_age_ms: gate.max_observation_age_ms,
                    });
                }
            }
        }

        if health.evidence.successful_probes > 0 {
            match health.evidence.last_successful_probe_unix_ms {
                None => reasons.push(RejectionReason::NoDatedSuccessfulObservation),
                Some(observed_at) if observed_at > requirements.now_unix_ms => {
                    reasons.push(RejectionReason::SuccessfulObservationFromFuture {
                        observed_at_unix_ms: observed_at,
                        now_unix_ms: requirements.now_unix_ms,
                    });
                }
                Some(observed_at) => {
                    let age_ms = requirements.now_unix_ms - observed_at;
                    if age_ms > gate.max_observation_age_ms {
                        reasons.push(RejectionReason::StaleSuccessfulObservation {
                            age_ms,
                            max_age_ms: gate.max_observation_age_ms,
                        });
                    }
                }
            }
        }

        if reachability_valid
            && evidence_counters_valid
            && health.evidence.probe_count > 0
            && health.evidence.independent_windows > 0
        {
            if let Some(empirical) = empirical_reachability_lcb(health) {
                if health.reachability.lower - empirical > REACHABILITY_LCB_TOLERANCE {
                    reasons.push(
                        RejectionReason::ReportedReachabilityLowerBoundExceedsEmpirical {
                            reported: health.reachability.lower,
                            empirical,
                        },
                    );
                }
                let conservative = health.reachability.lower.min(empirical);
                if conservative < gate.min_reachability_lower_bound {
                    reasons.push(
                        RejectionReason::ConservativeReachabilityLowerBoundBelowFloor {
                            observed: conservative,
                            required: gate.min_reachability_lower_bound,
                        },
                    );
                }
            } else if !reasons
                .iter()
                .any(|reason| matches!(reason, RejectionReason::InvalidEvidenceCounters))
            {
                reasons.push(RejectionReason::InvalidEvidenceCounters);
            }
        }
        if goodput_valid
            && health.goodput_bytes_per_second.lower < gate.min_goodput_lower_bound_bytes_per_second
        {
            reasons.push(RejectionReason::GoodputLowerBoundBelowFloor {
                observed_bytes_per_second: health.goodput_bytes_per_second.lower,
                required_bytes_per_second: gate.min_goodput_lower_bound_bytes_per_second,
            });
        }

        reasons
    }
}

/// Two-sided 95% Wilson score interval's lower endpoint.
///
/// Wilson is well behaved for small samples and all-success/all-failure data,
/// unlike the symmetric Wald interval. Invalid or empty evidence has no bound.
fn wilson_95_lower_bound(successes: u32, trials: u32) -> Option<f64> {
    if trials == 0 || successes > trials {
        return None;
    }

    const Z: f64 = 1.959_963_984_540_054;
    let n = f64::from(trials);
    let p = f64::from(successes) / n;
    let z_squared = Z * Z;
    let center = p + z_squared / (2.0 * n);
    let radius = Z * ((p * (1.0 - p) + z_squared / (4.0 * n)) / n).sqrt();
    let lower = (center - radius) / (1.0 + z_squared / n);
    Some(lower.clamp(0.0, 1.0))
}

/// Fail closed to the weaker of per-probe and independent-window evidence.
fn empirical_reachability_lcb(health: &CarrierHealthSnapshot) -> Option<f64> {
    let probe_lcb = wilson_95_lower_bound(
        health.evidence.successful_probes,
        health.evidence.probe_count,
    )?;
    let window_lcb = wilson_95_lower_bound(
        health.evidence.successful_independent_windows,
        health.evidence.independent_windows,
    )?;
    Some(probe_lcb.min(window_lcb))
}

/// Never override a producer's more conservative valid interval with a
/// stronger count-only estimate. The selector admits and scores the weakest of
/// the reported, per-probe, and independent-window lower bounds.
fn conservative_reachability_lcb(health: &CarrierHealthSnapshot) -> Option<f64> {
    empirical_reachability_lcb(health).map(|empirical| health.reachability.lower.min(empirical))
}

/// Bounded, monotone score computed exclusively from lower confidence bounds.
///
/// `g/(g+s)` supplies a unitless, saturating goodput term without allowing a
/// huge but uncertain point estimate to dominate reachability evidence.
fn conservative_score(
    reachability_lcb: f64,
    goodput_lcb_bytes_per_second: f64,
    scale_bytes_per_second: f64,
) -> f64 {
    let normalized_goodput = if goodput_lcb_bytes_per_second >= scale_bytes_per_second {
        1.0 / (1.0 + scale_bytes_per_second / goodput_lcb_bytes_per_second)
    } else {
        let ratio = goodput_lcb_bytes_per_second / scale_bytes_per_second;
        ratio / (1.0 + ratio)
    };
    reachability_lcb * normalized_goodput
}

fn better_candidate(candidate: &ShadowCandidate, incumbent: &ShadowCandidate) -> bool {
    candidate
        .conservative_score
        .total_cmp(&incumbent.conservative_score)
        .then_with(|| {
            candidate
                .reachability_lower_bound
                .total_cmp(&incumbent.reachability_lower_bound)
        })
        .then_with(|| {
            candidate
                .goodput_lower_bound_bytes_per_second
                .total_cmp(&incumbent.goodput_lower_bound_bytes_per_second)
        })
        .then_with(|| incumbent.carrier_id.cmp(&candidate.carrier_id))
        .is_gt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier::api::{
        CarrierFeature, EstimateBounds, EvidenceSummary, FailureDomainScope,
    };

    const NOW: u64 = 1_000_000;

    fn requirements(regime: AccessRegime, topology: TopologyConstraint) -> SelectionRequirements {
        SelectionRequirements {
            access_regime: regime,
            topology,
            excluded_failure_domains: Vec::new(),
            now_unix_ms: NOW,
        }
    }

    fn candidate(
        id: &str,
        topology: CarrierTopology,
        regimes: Vec<AccessRegime>,
        reachability: EstimateBounds,
        goodput: EstimateBounds,
    ) -> CarrierCandidate {
        let carrier_id = CarrierId::from(id);
        CarrierCandidate {
            capabilities: CarrierCapabilities {
                carrier_id: carrier_id.clone(),
                topology,
                access_regimes: regimes,
                features: vec![CarrierFeature::CoverPathProbe],
                failure_domains: Vec::new(),
                max_parallel_streams: Some(4),
            },
            health: CarrierHealthSnapshot {
                carrier_id,
                sequence: 7,
                state: CarrierHealthState::Healthy,
                reachability,
                goodput_bytes_per_second: goodput,
                evidence: EvidenceSummary {
                    probe_count: 1_000,
                    successful_probes: 990,
                    independent_windows: 100,
                    successful_independent_windows: 99,
                    minimum_successful_workload_bytes: 2 * 1024 * 1024,
                    last_observation_unix_ms: Some(NOW - 1_000),
                    last_successful_probe_unix_ms: Some(NOW - 1_000),
                },
                active_failure_domains: Vec::new(),
            },
        }
    }

    fn selected_id(report: &ShadowSelectionReport) -> Option<&CarrierId> {
        match &report.verdict {
            ShadowVerdict::WouldSelect { candidate } => Some(&candidate.carrier_id),
            ShadowVerdict::NoCandidate { .. } => None,
        }
    }

    #[test]
    fn lower_bounds_beat_optimistic_point_estimates() {
        let mut optimistic_but_uncertain = candidate(
            "a-uncertain",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.35, 0.99, 1.0),
            EstimateBounds::new(300_000.0, 50_000_000.0, 90_000_000.0),
        );
        optimistic_but_uncertain.health.evidence.probe_count = 40;
        optimistic_but_uncertain.health.evidence.successful_probes = 30;
        optimistic_but_uncertain.health.evidence.independent_windows = 10;
        optimistic_but_uncertain
            .health
            .evidence
            .successful_independent_windows = 7;

        let mut narrower = candidate(
            "b-narrow",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.80, 0.84, 0.88),
            EstimateBounds::new(100_000.0, 110_000.0, 120_000.0),
        );
        narrower.health.evidence.probe_count = 1_000;
        narrower.health.evidence.successful_probes = 900;
        narrower.health.evidence.independent_windows = 100;
        narrower.health.evidence.successful_independent_windows = 90;

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[optimistic_but_uncertain, narrower],
        );

        assert_eq!(selected_id(&report).unwrap().as_str(), "b-narrow");
        assert_eq!(report.mode, SelectorMode::Shadow);
    }

    #[test]
    fn access_regime_and_topology_are_both_required() {
        let direct = candidate(
            "direct",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.9, 0.95, 1.0),
            EstimateBounds::new(2_000_000.0, 3_000_000.0, 4_000_000.0),
        );
        let relay = candidate(
            "allowlisted-relay",
            CarrierTopology::DomesticCloudRelay,
            vec![
                AccessRegime::OpenInternet,
                AccessRegime::DestinationIpAndNameAllowlist,
            ],
            EstimateBounds::new(0.7, 0.8, 0.9),
            EstimateBounds::new(100_000.0, 150_000.0, 200_000.0),
        );
        let req = requirements(
            AccessRegime::DestinationIpAndNameAllowlist,
            TopologyConstraint::OneOf {
                topologies: vec![CarrierTopology::DomesticCloudRelay],
            },
        );

        let report = ShadowSelector::default().evaluate(&req, &[direct, relay]);

        assert_eq!(selected_id(&report).unwrap().as_str(), "allowlisted-relay");
        assert!(matches!(
            &report.assessments[0],
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.iter().any(|r| matches!(r, RejectionReason::UnsupportedAccessRegime { .. }))
                    && reasons.iter().any(|r| matches!(r, RejectionReason::TopologyNotAllowed { .. }))
        ));
    }

    #[test]
    fn evidence_gate_rejects_non_representative_workloads() {
        let mut too_small = candidate(
            "small-probe",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.9, 0.95, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        too_small.health.evidence.minimum_successful_workload_bytes =
            DEFAULT_MIN_REPRESENTATIVE_WORKLOAD_BYTES - 1;

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[too_small],
        );

        assert!(matches!(
            report.verdict,
            ShadowVerdict::NoCandidate {
                detail: NoCandidateVerdict {
                    cause: NoCandidateCause::AllCarriersRejected,
                    evaluated_candidates: 1
                }
            }
        ));
        assert!(matches!(
            &report.assessments[0],
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.iter().any(|r| matches!(r, RejectionReason::RepresentativeWorkloadTooSmall { .. }))
        ));
    }

    #[test]
    fn empty_input_has_an_explicit_no_candidate_verdict() {
        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[],
        );

        assert_eq!(report.assessments, Vec::new());
        assert!(matches!(
            report.verdict,
            ShadowVerdict::NoCandidate {
                detail: NoCandidateVerdict {
                    cause: NoCandidateCause::NoCarriersProvided,
                    evaluated_candidates: 0
                }
            }
        ));
    }

    #[test]
    fn malformed_and_stale_telemetry_fails_closed() {
        let mut bad = candidate(
            "bad",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(f64::NAN, 0.9, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        bad.health.evidence.last_observation_unix_ms = Some(0);

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[bad],
        );

        assert!(matches!(
            &report.assessments[0],
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.iter().any(|r| matches!(r, RejectionReason::InvalidReachabilityBounds))
                    && reasons.iter().any(|r| matches!(r, RejectionReason::StaleObservation { .. }))
        ));
    }

    #[test]
    fn fresh_failure_cannot_refresh_stale_success_evidence() {
        let policy = SelectorPolicy::default();
        let mut stale_success = candidate(
            "stale-success",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.8, 0.9, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        stale_success.health.evidence.last_observation_unix_ms = Some(NOW - 1_000);
        stale_success.health.evidence.last_successful_probe_unix_ms =
            Some(NOW - policy.evidence.max_observation_age_ms - 1);

        let report = ShadowSelector::new(policy).unwrap().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[stale_success],
        );

        assert!(matches!(report.verdict, ShadowVerdict::NoCandidate { .. }));
        assert!(matches!(
            &report.assessments[0],
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    RejectionReason::StaleSuccessfulObservation {
                        age_ms,
                        max_age_ms,
                    } if *age_ms == *max_age_ms + 1
                ))
        ));
    }

    #[test]
    fn overclaimed_reported_lcb_is_rejected_against_empirical_wilson_bound() {
        let mut overclaimed = candidate(
            "overclaimed",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.95, 0.98, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        overclaimed.health.evidence.probe_count = 20;
        overclaimed.health.evidence.successful_probes = 18;
        overclaimed.health.evidence.independent_windows = 5;
        overclaimed.health.evidence.successful_independent_windows = 5;

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[overclaimed],
        );

        assert!(matches!(
            &report.assessments[0],
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    RejectionReason::ReportedReachabilityLowerBoundExceedsEmpirical {
                        reported,
                        empirical,
                    } if *reported == 0.95 && *empirical < *reported
                ))
        ));
    }

    #[test]
    fn selector_scores_with_weakest_reported_or_empirical_bound() {
        let mut measured = candidate(
            "measured",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.30, 0.90, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        measured.health.evidence.probe_count = 40;
        measured.health.evidence.successful_probes = 30;
        measured.health.evidence.independent_windows = 10;
        measured.health.evidence.successful_independent_windows = 7;
        let empirical = empirical_reachability_lcb(&measured.health).unwrap();
        assert!(empirical > measured.health.reachability.lower);

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[measured],
        );

        match report.verdict {
            ShadowVerdict::WouldSelect { candidate } => {
                assert!((candidate.reachability_lower_bound - 0.30).abs() < 1e-12);
            }
            ShadowVerdict::NoCandidate { detail } => panic!("unexpected rejection: {detail:?}"),
        }
    }

    #[test]
    fn conservative_reported_bound_below_policy_floor_is_not_overridden() {
        let mut measured = candidate(
            "reported-caution",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.20, 0.90, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        measured.health.evidence.probe_count = 40;
        measured.health.evidence.successful_probes = 30;
        measured.health.evidence.independent_windows = 10;
        measured.health.evidence.successful_independent_windows = 7;
        assert!(empirical_reachability_lcb(&measured.health).unwrap() > 0.20);

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[measured],
        );

        assert!(matches!(report.verdict, ShadowVerdict::NoCandidate { .. }));
        assert!(matches!(
            &report.assessments[0],
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    RejectionReason::ConservativeReachabilityLowerBoundBelowFloor {
                        observed,
                        required,
                    } if *observed == 0.20 && *required == 0.25
                ))
        ));
    }

    #[test]
    fn excluded_failure_domain_blocks_correlated_candidate() {
        let domain = FailureDomain::new(FailureDomainScope::Provider, "shared-provider");
        let mut shared = candidate(
            "shared",
            CarrierTopology::CloudEdge,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.9, 0.95, 1.0),
            EstimateBounds::new(500_000.0, 600_000.0, 700_000.0),
        );
        shared.capabilities.failure_domains.push(domain.clone());
        let independent = candidate(
            "independent",
            CarrierTopology::CloudEdge,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.7, 0.8, 0.9),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        let mut req = requirements(AccessRegime::OpenInternet, TopologyConstraint::Any);
        req.excluded_failure_domains.push(domain);

        let report = ShadowSelector::default().evaluate(&req, &[shared, independent]);

        assert_eq!(selected_id(&report).unwrap().as_str(), "independent");
    }

    #[test]
    fn exact_ties_are_deterministic_by_carrier_id() {
        let z = candidate(
            "z-carrier",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.8, 0.9, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        let a = CarrierCandidate {
            capabilities: CarrierCapabilities {
                carrier_id: CarrierId::from("a-carrier"),
                ..z.capabilities.clone()
            },
            health: CarrierHealthSnapshot {
                carrier_id: CarrierId::from("a-carrier"),
                ..z.health.clone()
            },
        };

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[z, a],
        );

        assert_eq!(selected_id(&report).unwrap().as_str(), "a-carrier");
    }

    #[test]
    fn duplicate_carrier_ids_are_all_rejected() {
        let first = candidate(
            "duplicate",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.8, 0.9, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        let second = first.clone();

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[first, second],
        );

        assert!(matches!(report.verdict, ShadowVerdict::NoCandidate { .. }));
        assert!(report.assessments.iter().all(|assessment| matches!(
            assessment,
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.iter().any(|reason| matches!(reason, RejectionReason::DuplicateCarrierId { .. }))
        )));
    }

    #[test]
    fn zero_max_parallel_streams_is_rejected() {
        let mut invalid = candidate(
            "zero-streams",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.8, 0.9, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        );
        invalid.capabilities.max_parallel_streams = Some(0);

        let report = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &[invalid],
        );

        assert!(matches!(
            &report.assessments[0],
            CandidateAssessment::Rejected { reasons, .. }
                if reasons.contains(&RejectionReason::ZeroMaxParallelStreams)
        ));
    }

    #[test]
    fn evaluation_cannot_mutate_inputs_or_routes() {
        let candidates = vec![candidate(
            "read-only",
            CarrierTopology::Direct,
            vec![AccessRegime::OpenInternet],
            EstimateBounds::new(0.8, 0.9, 1.0),
            EstimateBounds::new(100_000.0, 120_000.0, 140_000.0),
        )];
        let before = candidates.clone();
        let route_generation = 42_u64;

        let _ = ShadowSelector::default().evaluate(
            &requirements(AccessRegime::OpenInternet, TopologyConstraint::Any),
            &candidates,
        );

        assert_eq!(candidates, before);
        assert_eq!(route_generation, 42);
    }

    #[test]
    fn invalid_policy_is_rejected_before_evaluation() {
        let policy = SelectorPolicy {
            goodput_scale_bytes_per_second: 0.0,
            ..SelectorPolicy::default()
        };
        assert!(matches!(
            ShadowSelector::new(policy),
            Err(SelectorPolicyError::InvalidGoodputScale)
        ));
    }

    #[test]
    fn zero_minimum_evidence_requirements_are_rejected() {
        fn assert_rejected(
            mutate: impl FnOnce(&mut SelectorPolicy),
            expected: SelectorPolicyError,
        ) {
            let mut policy = SelectorPolicy::default();
            mutate(&mut policy);
            assert_eq!(policy.validate(), Err(expected));
        }

        assert_rejected(
            |policy| policy.evidence.min_probe_count = 0,
            SelectorPolicyError::ZeroMinimumProbeCount,
        );
        assert_rejected(
            |policy| policy.evidence.min_successful_probes = 0,
            SelectorPolicyError::ZeroMinimumSuccessfulProbes,
        );
        assert_rejected(
            |policy| policy.evidence.min_independent_windows = 0,
            SelectorPolicyError::ZeroMinimumIndependentWindows,
        );
        assert_rejected(
            |policy| policy.evidence.min_representative_workload_bytes = 0,
            SelectorPolicyError::ZeroMinimumRepresentativeWorkloadBytes,
        );
        assert_rejected(
            |policy| policy.evidence.min_reachability_lower_bound = 0.0,
            SelectorPolicyError::InvalidReachabilityFloor,
        );
        assert_rejected(
            |policy| policy.evidence.min_goodput_lower_bound_bytes_per_second = 0.0,
            SelectorPolicyError::InvalidGoodputFloor,
        );
    }

    #[test]
    fn serde_rejects_unknown_policy_fields() {
        let mut value = serde_json::to_value(SelectorPolicy::default()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unreviewed_override".into(), serde_json::json!(true));

        assert!(serde_json::from_value::<SelectorPolicy>(value).is_err());
    }

    #[test]
    fn wilson_bounds_cover_edge_cases() {
        assert_eq!(wilson_95_lower_bound(0, 10), Some(0.0));
        let all_success = wilson_95_lower_bound(10, 10).unwrap();
        assert!(all_success > 0.72 && all_success < 0.73);
        assert_eq!(wilson_95_lower_bound(0, 0), None);
        assert_eq!(wilson_95_lower_bound(11, 10), None);
    }
}
