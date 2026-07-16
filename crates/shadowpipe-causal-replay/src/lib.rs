//! Offline replay from closed-schema raw measurements into an advisory verdict.
//!
//! The crate deliberately has no networking, carrier lifecycle, route, DNS, or
//! service-control API. Every health estimate is derived from versioned
//! [`MeasurementRun`] values; the input cannot provide a trusted health score.

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use shadowpipe_core::carrier::api::{
    CarrierCapabilities, CarrierHealthSnapshot, CarrierHealthState, EstimateBounds,
    EvidenceSummary, FailureDomain,
};
use shadowpipe_core::control::{
    CarrierCandidate, SelectionRequirements, SelectorPolicy, ShadowSelectionReport, ShadowSelector,
};
use shadowpipe_core::measurement::causal::student_t_critical_95;
use shadowpipe_core::measurement::{
    wilson_lower_bound_95, CloseOutcome, DialOutcome, Direction, EventKind, EvidenceOutcome,
    EvidenceScope, MeasurementRun, NodeRole, OnlineMoments, PublicId, StallState,
    MEASUREMENT_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

/// The replay-envelope revision. Embedded measurement traces are versioned
/// independently by `MEASUREMENT_SCHEMA_VERSION`.
pub const REPLAY_SCHEMA_VERSION: u16 = 2;

/// A complete, clock-free replay request.
///
/// `requirements.now_unix_ms` is explicit so replay never reads the host clock.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayScenario {
    pub replay_schema_version: u16,
    /// Caller-attested cohort IDs expected on every embedded trace. They make
    /// accidental cross-experiment/artifact mixing fail closed; they do not
    /// authenticate provenance without a separately signed manifest.
    pub expected_experiment_id: PublicId,
    pub expected_artifact_id: PublicId,
    #[serde(default)]
    pub policy: SelectorPolicy,
    pub requirements: SelectionRequirements,
    pub probe_direction: Direction,
    pub minimum_evidence_scope: EvidenceScope,
    pub carriers: Vec<ReplayCarrier>,
}

/// Static carrier facts plus the traces from which health must be derived.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCarrier {
    pub capabilities: CarrierCapabilities,
    #[serde(default)]
    pub active_failure_domains: Vec<FailureDomain>,
    /// Exact positive window references declared by the experiment schedule.
    /// Replay requires one trace for every entry and rejects undeclared traces.
    pub expected_window_refs: Vec<u32>,
    pub runs: Vec<ReplayRun>,
}

/// The integer window reference is supplied by the preregistered experiment.
/// It avoids inventing independence from nearby wall-clock timestamps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRun {
    pub window_ref: u32,
    pub trace: MeasurementRun,
}

/// An auditable output: derived candidates, per-run use/exclusion, then the
/// existing shadow selector's recommendation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplayReport {
    pub replay_schema_version: u16,
    pub measurement_schema_version: u16,
    pub experiment_id: PublicId,
    pub artifact_id: PublicId,
    pub validated_runs: u64,
    pub used_runs: u64,
    pub excluded_runs: u64,
    pub carriers: Vec<DerivedCarrierReport>,
    pub selection: ShadowSelectionReport,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DerivedCarrierReport {
    pub candidate: CarrierCandidate,
    pub runs: Vec<RunAssessment>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RunAssessment {
    pub run_id: PublicId,
    pub window_ref: u32,
    #[serde(flatten)]
    pub disposition: RunDisposition,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum RunDisposition {
    Used {
        successful: bool,
        terminal_outcome: CloseOutcome,
        payload_bytes: u64,
        elapsed_us: u64,
        goodput_bytes_per_second: Option<f64>,
        unresolved_stall: bool,
    },
    Excluded {
        reason: ExclusionReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    PendingEvidence,
    InconclusiveEvidence,
    EvidenceScopeBelowMinimum,
    MissingTerminalClose,
}

/// Validate and replay a scenario without dialing or mutating anything.
pub fn replay(mut scenario: ReplayScenario) -> Result<ReplayReport> {
    if scenario.replay_schema_version != REPLAY_SCHEMA_VERSION {
        bail!(
            "unsupported replay schema version {}; supported version is {}",
            scenario.replay_schema_version,
            REPLAY_SCHEMA_VERSION
        );
    }

    let selector =
        ShadowSelector::new(scenario.policy.clone()).context("invalid selector policy")?;

    // Canonicalize every set-like input that is retained in the report. This
    // makes report bytes independent of irrelevant JSON array ordering while
    // leaving event order (which is semantic) untouched.
    scenario.requirements.excluded_failure_domains.sort();
    scenario.requirements.excluded_failure_domains.dedup();
    if let shadowpipe_core::control::TopologyConstraint::OneOf { topologies } =
        &mut scenario.requirements.topology
    {
        topologies.sort();
        topologies.dedup();
    }
    scenario.carriers.sort_by(|left, right| {
        left.capabilities
            .carrier_id
            .cmp(&right.capabilities.carrier_id)
    });
    for carrier in &mut scenario.carriers {
        carrier.capabilities.access_regimes.sort();
        carrier.capabilities.access_regimes.dedup();
        carrier.capabilities.features.sort();
        carrier.capabilities.features.dedup();
        carrier.capabilities.failure_domains.sort();
        carrier.capabilities.failure_domains.dedup();
        carrier.active_failure_domains.sort();
        carrier.active_failure_domains.dedup();
        carrier.expected_window_refs.sort_unstable();
        carrier.runs.sort_by(|left, right| {
            left.window_ref
                .cmp(&right.window_ref)
                .then_with(|| left.trace.metadata.run_id.cmp(&right.trace.metadata.run_id))
        });
    }

    let mut carrier_ids = BTreeSet::new();
    let mut run_ids = BTreeSet::new();
    let mut shared_window_cohort: Option<BTreeSet<u32>> = None;
    let mut validated_runs = 0_u64;
    for carrier in &scenario.carriers {
        let carrier_id = carrier.capabilities.carrier_id.clone();
        if !carrier_ids.insert(carrier_id.clone()) {
            bail!("duplicate carrier ID {carrier_id}");
        }
        let expected_window_refs: BTreeSet<_> =
            carrier.expected_window_refs.iter().copied().collect();
        if expected_window_refs.len() != carrier.expected_window_refs.len()
            || expected_window_refs.contains(&0)
        {
            bail!("expected_window_refs must be unique and positive for carrier {carrier_id}");
        }
        if let Some(shared) = &shared_window_cohort {
            if shared != &expected_window_refs {
                bail!(
                    "all carriers must share one expected_window_refs cohort; carrier {carrier_id} differs"
                );
            }
        } else {
            shared_window_cohort = Some(expected_window_refs.clone());
        }
        let mut window_refs = BTreeSet::new();
        for run in &carrier.runs {
            if run.window_ref == 0 {
                bail!("window_ref must be positive for carrier {carrier_id}");
            }
            if !window_refs.insert(run.window_ref) {
                bail!(
                    "duplicate independent window_ref {} for carrier {carrier_id}",
                    run.window_ref
                );
            }
            run.trace.validate().with_context(|| {
                format!(
                    "invalid measurement run {} for carrier {}",
                    run.trace.metadata.run_id, carrier_id
                )
            })?;
            if run.trace.metadata.role != NodeRole::Client {
                bail!(
                    "measurement run {} for carrier {} is not a client probe",
                    run.trace.metadata.run_id,
                    carrier_id
                );
            }
            if run.trace.metadata.experiment_id != Some(scenario.expected_experiment_id) {
                bail!(
                    "measurement run {} for carrier {} does not match expected_experiment_id {}",
                    run.trace.metadata.run_id,
                    carrier_id,
                    scenario.expected_experiment_id
                );
            }
            if run.trace.metadata.artifact_id != Some(scenario.expected_artifact_id) {
                bail!(
                    "measurement run {} for carrier {} does not match expected_artifact_id {}",
                    run.trace.metadata.run_id,
                    carrier_id,
                    scenario.expected_artifact_id
                );
            }
            if !run_ids.insert(run.trace.metadata.run_id) {
                bail!("duplicate measurement run ID {}", run.trace.metadata.run_id);
            }
            validated_runs = validated_runs
                .checked_add(1)
                .context("validated run counter overflow")?;
        }
        if window_refs != expected_window_refs {
            bail!(
                "actual window_ref coverage does not match expected_window_refs for carrier {carrier_id}"
            );
        }
    }

    let mut derived = Vec::with_capacity(scenario.carriers.len());
    let mut used_runs = 0_u64;
    let mut excluded_runs = 0_u64;
    for carrier in scenario.carriers {
        let report = derive_carrier(
            carrier,
            &scenario.policy,
            scenario.probe_direction,
            scenario.minimum_evidence_scope,
        )?;
        for run in &report.runs {
            match &run.disposition {
                RunDisposition::Used { .. } => {
                    used_runs = used_runs
                        .checked_add(1)
                        .context("used run counter overflow")?
                }
                RunDisposition::Excluded { .. } => {
                    excluded_runs = excluded_runs
                        .checked_add(1)
                        .context("excluded run counter overflow")?
                }
            }
        }
        derived.push(report);
    }

    let candidates: Vec<_> = derived
        .iter()
        .map(|report| report.candidate.clone())
        .collect();
    let selection = selector.evaluate(&scenario.requirements, &candidates);

    Ok(ReplayReport {
        replay_schema_version: REPLAY_SCHEMA_VERSION,
        measurement_schema_version: MEASUREMENT_SCHEMA_VERSION,
        experiment_id: scenario.expected_experiment_id,
        artifact_id: scenario.expected_artifact_id,
        validated_runs,
        used_runs,
        excluded_runs,
        carriers: derived,
        selection,
    })
}

fn derive_carrier(
    carrier: ReplayCarrier,
    policy: &SelectorPolicy,
    direction: Direction,
    minimum_scope: EvidenceScope,
) -> Result<DerivedCarrierReport> {
    let mut assessments = Vec::with_capacity(carrier.runs.len());
    let mut successes = 0_u64;
    let mut trials = 0_u64;
    let mut observed_windows = BTreeSet::new();
    let mut successful_windows = BTreeSet::new();
    let mut minimum_successful_workload_bytes: Option<u64> = None;
    let mut last_observation_unix_ms = None;
    let mut last_successful_probe_unix_ms = None;
    let mut goodput = OnlineMoments::new();
    let mut excluded = 0_u64;

    for run in carrier.runs {
        let run_id = run.trace.metadata.run_id;
        let disposition = classify_run(
            &run.trace,
            direction,
            minimum_scope,
            policy.evidence.min_representative_workload_bytes,
        )?;

        if let RunDisposition::Used {
            successful,
            payload_bytes,
            elapsed_us,
            goodput_bytes_per_second,
            ..
        } = &disposition
        {
            trials = trials.checked_add(1).context("probe counter overflow")?;
            observed_windows.insert(run.window_ref);
            let elapsed_ms = elapsed_us / 1_000 + u64::from(elapsed_us % 1_000 != 0);
            let observed_at = run
                .trace
                .metadata
                .started_unix_ms
                .checked_add(elapsed_ms)
                .context("measurement observation timestamp overflow")?;
            last_observation_unix_ms = Some(
                last_observation_unix_ms
                    .map(|prior: u64| prior.max(observed_at))
                    .unwrap_or(observed_at),
            );

            if *successful {
                successes = successes
                    .checked_add(1)
                    .context("success counter overflow")?;
                successful_windows.insert(run.window_ref);
                last_successful_probe_unix_ms = Some(
                    last_successful_probe_unix_ms
                        .map(|prior: u64| prior.max(observed_at))
                        .unwrap_or(observed_at),
                );
                minimum_successful_workload_bytes = Some(
                    minimum_successful_workload_bytes
                        .map(|prior| prior.min(*payload_bytes))
                        .unwrap_or(*payload_bytes),
                );
                if let Some(sample) = goodput_bytes_per_second {
                    goodput
                        .push(*sample)
                        .context("invalid derived goodput sample")?;
                }
            }
        } else {
            excluded = excluded
                .checked_add(1)
                .context("excluded carrier run counter overflow")?;
        }

        assessments.push(RunAssessment {
            run_id,
            window_ref: run.window_ref,
            disposition,
        });
    }

    let probe_count = u32::try_from(trials).context("probe count exceeds u32")?;
    let successful_probes = u32::try_from(successes).context("success count exceeds u32")?;
    let independent_windows =
        u32::try_from(observed_windows.len()).context("window count exceeds u32")?;
    let successful_independent_windows =
        u32::try_from(successful_windows.len()).context("successful window count exceeds u32")?;
    let health = CarrierHealthSnapshot {
        carrier_id: carrier.capabilities.carrier_id.clone(),
        sequence: trials,
        state: health_state(
            successes,
            trials,
            observed_windows.len(),
            successful_windows.len(),
            excluded,
            policy,
        ),
        reachability: reachability_bounds(successes, trials)?,
        goodput_bytes_per_second: goodput_bounds(&goodput),
        evidence: EvidenceSummary {
            probe_count,
            successful_probes,
            independent_windows,
            successful_independent_windows,
            minimum_successful_workload_bytes: minimum_successful_workload_bytes.unwrap_or(0),
            last_observation_unix_ms,
            last_successful_probe_unix_ms,
        },
        active_failure_domains: carrier.active_failure_domains,
    };

    Ok(DerivedCarrierReport {
        candidate: CarrierCandidate {
            capabilities: carrier.capabilities,
            health,
        },
        runs: assessments,
    })
}

fn classify_run(
    run: &MeasurementRun,
    direction: Direction,
    minimum_scope: EvidenceScope,
    minimum_payload_bytes: u64,
) -> Result<RunDisposition> {
    match run.evidence.outcome {
        EvidenceOutcome::Invalid => {
            bail!("measurement run {} is marked invalid", run.metadata.run_id)
        }
        EvidenceOutcome::Pending => {
            return Ok(RunDisposition::Excluded {
                reason: ExclusionReason::PendingEvidence,
            })
        }
        EvidenceOutcome::Inconclusive => {
            return Ok(RunDisposition::Excluded {
                reason: ExclusionReason::InconclusiveEvidence,
            })
        }
        EvidenceOutcome::Supported | EvidenceOutcome::Refuted => {}
    }

    if scope_rank(run.evidence.scope) < scope_rank(minimum_scope) {
        return Ok(RunDisposition::Excluded {
            reason: ExclusionReason::EvidenceScopeBelowMinimum,
        });
    }

    let Some(last) = run.events.last() else {
        return Ok(RunDisposition::Excluded {
            reason: ExclusionReason::MissingTerminalClose,
        });
    };
    let EventKind::Close { outcome, .. } = &last.event else {
        return Ok(RunDisposition::Excluded {
            reason: ExclusionReason::MissingTerminalClose,
        });
    };

    // Close aggregates are useful consistency ceilings, but are not workload
    // proof: the schema intentionally allows a close total to exceed the
    // retained Transfer deltas (for filtered exports). Admission therefore
    // uses only direction-matched payload actually present in Transfer events.
    // This makes omitted observations conservative and prevents a forged clean
    // close from manufacturing a representative-workload success.
    let payload_bytes = observed_payload_bytes(run, direction)?;
    let unresolved_stall = has_unresolved_stall(run, direction);
    let successful = *outcome == CloseOutcome::Clean
        && payload_bytes >= minimum_payload_bytes
        && has_connected_dial(run)
        && !unresolved_stall;
    let goodput_bytes_per_second = (successful && last.elapsed_us > 0)
        .then(|| payload_bytes as f64 * 1_000_000.0 / last.elapsed_us as f64);

    Ok(RunDisposition::Used {
        successful,
        terminal_outcome: *outcome,
        payload_bytes,
        elapsed_us: last.elapsed_us,
        goodput_bytes_per_second,
        unresolved_stall,
    })
}

fn observed_payload_bytes(run: &MeasurementRun, direction: Direction) -> Result<u64> {
    run.events.iter().try_fold(0_u64, |total, measurement| {
        let EventKind::Transfer {
            direction: observed_direction,
            payload_bytes,
            ..
        } = &measurement.event
        else {
            return Ok(total);
        };
        if *observed_direction != direction {
            return Ok(total);
        }
        total
            .checked_add(*payload_bytes)
            .context("observed direction payload exceeds u64")
    })
}

fn has_connected_dial(run: &MeasurementRun) -> bool {
    run.events.iter().any(|measurement| {
        matches!(
            &measurement.event,
            EventKind::Dial {
                outcome: DialOutcome::Connected,
                ..
            }
        )
    })
}

fn has_unresolved_stall(run: &MeasurementRun, direction: Direction) -> bool {
    let mut stalled_paths = BTreeSet::new();
    for measurement in &run.events {
        if let EventKind::Stall {
            path_ref,
            direction: observed_direction,
            state,
            ..
        } = &measurement.event
        {
            if *observed_direction != direction {
                continue;
            }
            match state {
                StallState::Detected => {
                    stalled_paths.insert(*path_ref);
                }
                StallState::Recovered => {
                    stalled_paths.remove(path_ref);
                }
            }
        }
    }
    !stalled_paths.is_empty()
}

fn reachability_bounds(successes: u64, trials: u64) -> Result<EstimateBounds> {
    if trials == 0 {
        return Ok(EstimateBounds::new(0.0, 0.0, 0.0));
    }
    let lower = wilson_lower_bound_95(successes, trials)?
        .context("Wilson lower bound missing for nonzero trials")?;
    let failure_lower = wilson_lower_bound_95(trials - successes, trials)?
        .context("Wilson failure bound missing for nonzero trials")?;
    Ok(EstimateBounds::new(
        lower,
        successes as f64 / trials as f64,
        1.0 - failure_lower,
    ))
}

fn goodput_bounds(moments: &OnlineMoments) -> EstimateBounds {
    let Some(point) = moments.mean() else {
        return EstimateBounds::new(0.0, 0.0, 0.0);
    };
    let Some(standard_error) = moments.standard_error() else {
        // One sample is deliberately not allowed to produce a positive lower
        // bound; the default evidence gate also requires multiple successes.
        return EstimateBounds::new(0.0, point, point);
    };
    let critical = student_t_critical_95(moments.count() - 1);
    let margin = critical * standard_error;
    if !margin.is_finite() {
        return EstimateBounds::new(0.0, point, point);
    }
    EstimateBounds::new((point - margin).max(0.0), point, point + margin)
}

fn health_state(
    successes: u64,
    trials: u64,
    independent_windows: usize,
    successful_independent_windows: usize,
    excluded_runs: u64,
    policy: &SelectorPolicy,
) -> CarrierHealthState {
    if excluded_runs > 0 || trials == 0 {
        CarrierHealthState::Unknown
    } else if successes == 0 && trials >= u64::from(policy.evidence.min_probe_count) {
        CarrierHealthState::Unreachable
    } else if trials < u64::from(policy.evidence.min_probe_count)
        || successes < u64::from(policy.evidence.min_successful_probes)
        || independent_windows < policy.evidence.min_independent_windows as usize
        || successful_independent_windows == 0
    {
        CarrierHealthState::Unknown
    } else if successes == trials {
        CarrierHealthState::Healthy
    } else {
        CarrierHealthState::Degraded
    }
}

const fn scope_rank(scope: EvidenceScope) -> u8 {
    match scope {
        EvidenceScope::Unit => 0,
        EvidenceScope::Loopback => 1,
        EvidenceScope::VirtualMachine => 2,
        EvidenceScope::ControlledNetwork => 3,
        EvidenceScope::PublicInternet => 4,
        EvidenceScope::TargetNetwork => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowpipe_core::carrier::api::{
        AccessRegime, CarrierFeature, CarrierId, CarrierTopology, FailureDomainScope,
    };
    use shadowpipe_core::control::{ShadowVerdict, TopologyConstraint};
    use shadowpipe_core::measurement::{
        DialOutcome, EvidenceAssessment, ExecutionEnvironment, MeasurementEvent, NodeRole,
        PathState, RunMetadata, SoftwareVersion, TransportKind,
    };

    const NOW: u64 = 1_800_000_100_000;

    fn public_id(seed: u8) -> PublicId {
        PublicId::from_bytes([seed; PublicId::BYTE_LEN]).expect("nonzero test ID")
    }

    fn trace(seed: u8, window_start: u64, outcome: CloseOutcome, bytes: u64) -> MeasurementRun {
        MeasurementRun::new(
            RunMetadata {
                run_id: public_id(seed),
                experiment_id: Some(public_id(200)),
                artifact_id: Some(public_id(201)),
                started_unix_ms: window_start,
                software_version: SoftwareVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                role: NodeRole::Client,
                environment: ExecutionEnvironment::VirtualMachine,
            },
            EvidenceAssessment {
                scope: EvidenceScope::VirtualMachine,
                outcome: EvidenceOutcome::Supported,
            },
            vec![
                MeasurementEvent {
                    sequence: 1,
                    elapsed_us: 10_000,
                    event: EventKind::Dial {
                        endpoint_ref: 0,
                        transport: TransportKind::Tcp,
                        attempt: 1,
                        duration_us: 10_000,
                        outcome: DialOutcome::Connected,
                    },
                },
                MeasurementEvent {
                    sequence: 2,
                    elapsed_us: 20_000,
                    event: EventKind::Path {
                        path_ref: 0,
                        endpoint_ref: 0,
                        state: PathState::Selected,
                        metrics: None,
                    },
                },
                MeasurementEvent {
                    sequence: 3,
                    elapsed_us: 900_000,
                    event: EventKind::Transfer {
                        path_ref: 0,
                        direction: Direction::Receive,
                        payload_bytes: bytes,
                        wire_bytes: bytes,
                        interval_us: 880_000,
                    },
                },
                MeasurementEvent {
                    sequence: 4,
                    elapsed_us: 1_000_000,
                    event: EventKind::Close {
                        outcome,
                        transmitted_payload_bytes: 1_024,
                        received_payload_bytes: bytes,
                    },
                },
            ],
        )
    }

    fn carrier(id: &str, seeds: &[u8], bytes: u64) -> ReplayCarrier {
        ReplayCarrier {
            capabilities: CarrierCapabilities {
                carrier_id: CarrierId::from(id),
                topology: CarrierTopology::Direct,
                access_regimes: vec![AccessRegime::UnknownRestricted],
                features: vec![CarrierFeature::CoverPathProbe],
                failure_domains: Vec::new(),
                max_parallel_streams: Some(4),
            },
            active_failure_domains: Vec::new(),
            expected_window_refs: (1..=seeds.len() as u32).collect(),
            runs: seeds
                .iter()
                .enumerate()
                .map(|(index, seed)| ReplayRun {
                    window_ref: index as u32 + 1,
                    trace: trace(
                        *seed,
                        NOW - 5_000 + index as u64,
                        CloseOutcome::Clean,
                        bytes,
                    ),
                })
                .collect(),
        }
    }

    fn scenario(carriers: Vec<ReplayCarrier>) -> ReplayScenario {
        ReplayScenario {
            replay_schema_version: REPLAY_SCHEMA_VERSION,
            expected_experiment_id: public_id(200),
            expected_artifact_id: public_id(201),
            policy: SelectorPolicy::default(),
            requirements: SelectionRequirements {
                access_regime: AccessRegime::UnknownRestricted,
                topology: TopologyConstraint::Any,
                excluded_failure_domains: Vec::new(),
                now_unix_ms: NOW,
            },
            probe_direction: Direction::Receive,
            minimum_evidence_scope: EvidenceScope::VirtualMachine,
            carriers,
        }
    }

    #[test]
    fn health_is_derived_from_counts_and_volume_not_supplied_by_caller() {
        let mut candidate = carrier("derived", &[1, 2, 3], 2 * 1024 * 1024);
        candidate.runs[2]
            .trace
            .events
            .last_mut()
            .expect("terminal close")
            .event = EventKind::Close {
            outcome: CloseOutcome::TimedOut,
            transmitted_payload_bytes: 1_024,
            received_payload_bytes: 2 * 1024 * 1024,
        };

        let report = replay(scenario(vec![candidate])).expect("replay");
        let health = &report.carriers[0].candidate.health;
        assert_eq!(health.evidence.probe_count, 3);
        assert_eq!(health.evidence.successful_probes, 2);
        assert_eq!(health.evidence.independent_windows, 3);
        assert_eq!(health.evidence.successful_independent_windows, 2);
        assert_eq!(
            health.evidence.minimum_successful_workload_bytes,
            2 * 1024 * 1024
        );
        assert_eq!(health.state, CarrierHealthState::Degraded);
        assert_eq!(health.reachability.point, 2.0 / 3.0);
        assert_eq!(
            health.reachability.lower,
            wilson_lower_bound_95(2, 3).unwrap().unwrap()
        );
    }

    #[test]
    fn output_is_identical_after_candidate_and_run_permutation() {
        let mut original = scenario(vec![
            carrier("z-slower", &[10, 11, 12], 2 * 1024 * 1024),
            carrier("a-faster", &[20, 21, 22], 4 * 1024 * 1024),
        ]);
        for item in &mut original.carriers {
            item.capabilities
                .access_regimes
                .push(AccessRegime::OpenInternet);
            item.capabilities
                .features
                .push(CarrierFeature::NativeMultiplexing);
            item.capabilities.failure_domains = vec![
                FailureDomain::new(FailureDomainScope::Provider, "provider-b"),
                FailureDomain::new(FailureDomainScope::Protocol, "protocol-a"),
            ];
            item.active_failure_domains = vec![
                FailureDomain::new(FailureDomainScope::Region, "region-b"),
                FailureDomain::new(FailureDomainScope::Endpoint, "endpoint-a"),
            ];
        }
        let mut permuted = original.clone();
        permuted.carriers.reverse();
        for item in &mut permuted.carriers {
            item.runs.reverse();
            item.expected_window_refs.reverse();
            item.capabilities.access_regimes.reverse();
            item.capabilities.features.reverse();
            item.capabilities.failure_domains.reverse();
            item.active_failure_domains.reverse();
        }

        let left = serde_json::to_vec(&replay(original).unwrap()).unwrap();
        let right = serde_json::to_vec(&replay(permuted).unwrap()).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn unsupported_measurement_schema_is_rejected() {
        let mut candidate = carrier("bad-schema", &[30], 2 * 1024 * 1024);
        candidate.runs[0].trace.schema_version = MEASUREMENT_SCHEMA_VERSION + 1;
        let error = replay(scenario(vec![candidate])).unwrap_err().to_string();
        assert!(error.contains("invalid measurement run"));
    }

    #[test]
    fn duplicate_or_zero_independent_windows_are_rejected() {
        let mut duplicate = carrier("duplicate-window", &[31, 32], 2 * 1024 * 1024);
        duplicate.runs[1].window_ref = duplicate.runs[0].window_ref;
        let error = replay(scenario(vec![duplicate])).unwrap_err().to_string();
        assert!(error.contains("duplicate independent window_ref"));

        let mut zero = carrier("zero-window", &[33], 2 * 1024 * 1024);
        zero.runs[0].window_ref = 0;
        let error = replay(scenario(vec![zero])).unwrap_err().to_string();
        assert!(error.contains("window_ref must be positive"));
    }

    #[test]
    fn schedule_coverage_is_exact() {
        let mut omitted = carrier("omitted-window", &[34, 35], 2 * 1024 * 1024);
        omitted.expected_window_refs.push(3);
        let error = replay(scenario(vec![omitted])).unwrap_err().to_string();
        assert!(error.contains("actual window_ref coverage"));
    }

    #[test]
    fn every_trace_must_match_expected_experiment_and_artifact_ids() {
        let mut wrong_experiment = carrier("wrong-experiment", &[51], 2 * 1024 * 1024);
        wrong_experiment.runs[0].trace.metadata.experiment_id = Some(public_id(202));
        let error = replay(scenario(vec![wrong_experiment]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match expected_experiment_id"));

        let mut missing_artifact = carrier("missing-artifact", &[52], 2 * 1024 * 1024);
        missing_artifact.runs[0].trace.metadata.artifact_id = None;
        let error = replay(scenario(vec![missing_artifact]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match expected_artifact_id"));
    }

    #[test]
    fn every_carrier_must_share_the_same_window_cohort() {
        let first = carrier("first", &[53, 54], 2 * 1024 * 1024);
        let mut different = carrier("different", &[55, 56], 2 * 1024 * 1024);
        different.expected_window_refs = vec![1, 3];
        different.runs[1].window_ref = 3;

        let error = replay(scenario(vec![first, different]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("share one expected_window_refs cohort"));
    }

    #[test]
    fn report_echoes_the_validated_cohort_ids() {
        let report = replay(scenario(vec![carrier(
            "cohort",
            &[57, 58, 59],
            2 * 1024 * 1024,
        )]))
        .expect("valid replay");
        assert_eq!(report.experiment_id, public_id(200));
        assert_eq!(report.artifact_id, public_id(201));
    }

    #[test]
    fn excluded_run_makes_candidate_state_unknown() {
        let mut candidate = carrier("incomplete", &[36, 37, 38], 2 * 1024 * 1024);
        candidate.runs[2].trace.evidence.outcome = EvidenceOutcome::Pending;

        let report = replay(scenario(vec![candidate])).expect("replay");
        assert_eq!(
            report.carriers[0].candidate.health.state,
            CarrierHealthState::Unknown
        );
        assert!(matches!(
            report.selection.verdict,
            ShadowVerdict::NoCandidate { .. }
        ));
    }

    #[test]
    fn clean_close_cannot_hide_failed_dial() {
        let mut candidate = carrier("failed-dial", &[39, 43, 44], 2 * 1024 * 1024);
        for run in &mut candidate.runs {
            if let EventKind::Dial { outcome, .. } = &mut run.trace.events[0].event {
                *outcome = DialOutcome::TimedOut;
            }
            // Keep the failed trace structurally valid: a failed dial cannot
            // have a selected path or observed transfer.
            run.trace.events.retain(|measurement| {
                matches!(
                    measurement.event,
                    EventKind::Dial { .. } | EventKind::Close { .. }
                )
            });
        }

        let report = replay(scenario(vec![candidate])).expect("replay");
        let health = &report.carriers[0].candidate.health;
        assert_eq!(health.evidence.successful_probes, 0);
        assert_eq!(health.state, CarrierHealthState::Unreachable);
        assert!(matches!(
            report.selection.verdict,
            ShadowVerdict::NoCandidate { .. }
        ));
    }

    #[test]
    fn clean_close_aggregate_cannot_manufacture_unobserved_workload() {
        let mut candidate = carrier("aggregate-only", &[46, 47, 48], 2 * 1024 * 1024);
        for run in &mut candidate.runs {
            run.trace
                .events
                .retain(|measurement| !matches!(measurement.event, EventKind::Transfer { .. }));
        }

        // The close still claims 2 MiB and the trace remains structurally
        // valid, but replay must use the conservative observed Transfer sum.
        let report = replay(scenario(vec![candidate])).expect("replay");
        let health = &report.carriers[0].candidate.health;
        assert_eq!(health.evidence.probe_count, 3);
        assert_eq!(health.evidence.successful_probes, 0);
        assert_eq!(health.evidence.minimum_successful_workload_bytes, 0);
        assert_eq!(health.state, CarrierHealthState::Unreachable);
        assert!(matches!(
            report.selection.verdict,
            ShadowVerdict::NoCandidate { .. }
        ));
    }

    #[test]
    fn one_success_is_unknown_not_healthy() {
        let report =
            replay(scenario(vec![carrier("one-probe", &[45], 2 * 1024 * 1024)])).expect("replay");
        assert_eq!(
            report.carriers[0].candidate.health.state,
            CarrierHealthState::Unknown
        );
    }

    #[test]
    fn unresolved_stall_fails_but_recovered_stall_succeeds() {
        let mut candidate = carrier("stall-state", &[40, 41, 42], 2 * 1024 * 1024);
        for (index, run) in candidate.runs.iter_mut().enumerate() {
            run.trace.events.insert(
                2,
                MeasurementEvent {
                    sequence: 3,
                    elapsed_us: 100_000,
                    event: EventKind::Stall {
                        path_ref: 0,
                        direction: Direction::Receive,
                        state: StallState::Detected,
                        gap_us: 100_000,
                        threshold_us: 100_000,
                        progress_bytes: 0,
                    },
                },
            );
            run.trace.events[3].sequence = 4;
            run.trace
                .events
                .last_mut()
                .expect("terminal close")
                .sequence = 6;
            if index != 2 {
                run.trace.events.insert(
                    4,
                    MeasurementEvent {
                        sequence: 5,
                        elapsed_us: 950_000,
                        event: EventKind::Stall {
                            path_ref: 0,
                            direction: Direction::Receive,
                            state: StallState::Recovered,
                            gap_us: 100_000,
                            threshold_us: 100_000,
                            progress_bytes: 2 * 1024 * 1024,
                        },
                    },
                );
            }
        }

        let report = replay(scenario(vec![candidate])).expect("valid replay");
        assert_eq!(
            report.carriers[0]
                .candidate
                .health
                .evidence
                .successful_probes,
            2
        );
    }

    #[test]
    fn insufficient_evidence_never_selects_a_carrier() {
        let report = replay(scenario(vec![carrier("untested", &[50], 2 * 1024 * 1024)])).unwrap();
        assert!(matches!(
            report.selection.verdict,
            ShadowVerdict::NoCandidate { .. }
        ));
    }
}
