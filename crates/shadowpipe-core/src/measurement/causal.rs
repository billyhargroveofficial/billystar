//! Fail-closed primitives for preregistered causal network experiments.
//!
//! This module deliberately does not collect traffic, open sockets, or infer
//! causality from observational telemetry.  It only analyzes numeric outcomes
//! from two controlled designs:
//!
//! 1. paired, randomized AB/BA crossover blocks, summarized as one
//!    difference-in-differences (DiD) value per independent block; and
//! 2. trigger-budget scaling trials used to distinguish a shared budget from a
//!    per-flow budget when every stall event is observed.
//!
//! A Student-t interval is meaningful only under its declared assumptions.  A
//! caller must explicitly attest those assumptions; this module cannot verify
//! randomization, independence, carryover, or residual shape from the numbers
//! alone.  Equivalence is intentionally fail-closed: a point estimate inside a
//! band is insufficient unless the entire two-sided 95% interval is strictly
//! inside the preregistered band and every design gate passes.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;

/// Order in which conditions A and B were exercised in a crossover block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossoverOrder {
    Ab,
    Ba,
}

/// Closed set of outcome transforms fixed before observations are inspected.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutcomeTransform {
    /// Analyze values on their original scale.
    Identity,
    /// Analyze `ln(value + offset)`.
    ///
    /// The offset may be zero but may never be negative or non-finite.  Raw
    /// outcome values remain required to be finite and strictly positive.
    LogPlusOffset { offset: f64 },
}

/// One independent paired crossover block.
///
/// A and B are the two randomized experimental conditions. `control_*` and
/// `candidate_*` must be measured within the same block and condition.  After
/// applying the preregistered transform, the block effect is
///
/// `(candidate_b - candidate_a) - (control_b - control_a)`.
///
/// The neutral names are intentional: the experiment manifest, not this data
/// structure, defines whether B is impairment, treatment, or another condition.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossoverBlock {
    pub block_id: u64,
    pub order: CrossoverOrder,
    pub control_a: f64,
    pub control_b: f64,
    pub candidate_a: f64,
    pub candidate_b: f64,
}

/// Assumptions required for the ordinary Student-t interval over block DiDs.
///
/// These booleans are caller declarations, not conclusions computed from the
/// sample.  Requiring each declaration prevents an automated consumer from
/// accidentally presenting an assumption-dependent interval as design-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossoverAssumptions {
    /// Blocks are mutually independent; dependence inside a block is expected.
    pub independent_blocks: bool,
    /// AB/BA order was randomized before outcomes were observed.
    pub randomized_order: bool,
    /// Washout/design makes carryover and period effects negligible for DiD.
    pub negligible_carryover: bool,
    /// The sampling distribution of the mean block DiD is approximately normal.
    pub approximately_normal_mean: bool,
}

/// Preregistered gates for a paired crossover equivalence analysis.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossoverPreregistration {
    pub transform: OutcomeTransform,
    /// Symmetric equivalence margin on the transformed DiD scale.
    pub equivalence_margin: f64,
    /// Required number of complete independent blocks; must be at least two.
    pub minimum_blocks: u32,
    /// Minimum fraction assigned to the less frequent order, in `(0, 0.5]`.
    pub minimum_order_fraction: f64,
    pub assumptions: CrossoverAssumptions,
}

/// Aggregate of complete per-block DiDs.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossoverEstimate {
    pub block_count: u64,
    pub ab_blocks: u64,
    pub ba_blocks: u64,
    pub mean_did: f64,
    pub sample_standard_deviation: f64,
    pub standard_error: f64,
    pub degrees_of_freedom: u64,
    pub student_t_critical_95: f64,
    pub ci95_lower: f64,
    pub ci95_upper: f64,
    pub observed_order_fraction: f64,
}

/// Fail-closed interpretation of a crossover estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossoverVerdict {
    /// All gates passed and the complete CI is strictly inside `+/- margin`.
    Equivalent,
    /// A CI is available, but fewer than the preregistered blocks were observed.
    InsufficientBlocks,
    /// The less frequent order did not reach the preregistered fraction.
    OrderImbalance,
    /// Design gates passed, but the complete CI was not inside the margin.
    Inconclusive,
}

/// Result of one validated crossover analysis.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossoverAnalysis {
    pub estimate: CrossoverEstimate,
    pub verdict: CrossoverVerdict,
}

/// One closed equivalence band for the trigger-budget scaling exponent.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquivalenceBand {
    pub lower: f64,
    pub upper: f64,
}

/// Assumptions required for an ordinary least-squares Student-t slope interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalingAssumptions {
    /// Trials are independent at the analysis unit declared by the manifest.
    pub independent_trials: bool,
    /// The conditional mean relation is linear on the log-log scale.
    pub log_linear_mean: bool,
    /// Log-scale residuals are homoskedastic and approximately normal.
    pub homoskedastic_normal_residuals: bool,
    /// Trigger budgets were fixed or randomized before stall outcomes were seen.
    pub preregistered_trigger_budgets: bool,
}

/// Preregistered gates for trigger-budget scaling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerScalingPreregistration {
    /// Minimum complete stall events required before a mechanism classification.
    /// Must be at least three because a slope CI has `n - 2` degrees of freedom.
    pub minimum_observed_events: u32,
    /// Exponent band identified in advance with a shared aggregate budget.
    pub shared_budget_band: EquivalenceBand,
    /// Exponent band identified in advance with an independent per-flow budget.
    pub per_flow_budget_band: EquivalenceBand,
    pub assumptions: ScalingAssumptions,
}

/// One trigger-budget exposure and its optional stall event.
///
/// `bytes_observed` is the complete exposure horizon. `None` for
/// `bytes_until_stall` means the trial is right-censored at that horizon, not
/// that an infinite no-freeze threshold was observed.  If a stall was observed,
/// its byte count must not exceed the exposure horizon.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerBudgetObservation {
    pub observation_id: u64,
    pub trigger_budget_k: f64,
    pub bytes_observed: f64,
    pub bytes_until_stall: Option<f64>,
}

/// Mechanism classification from a complete log-log slope interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerBudgetClassification {
    SharedBudget,
    PerFlowBudget,
    Ambiguous,
}

/// OLS fit of `ln(bytes_until_stall) = beta0 + alpha * ln(K)`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerScalingFit {
    pub observation_count: u64,
    pub distinct_trigger_budgets: u64,
    pub beta0: f64,
    pub alpha: f64,
    pub residual_standard_deviation: f64,
    pub alpha_standard_error: f64,
    pub degrees_of_freedom: u64,
    pub student_t_critical_95: f64,
    pub alpha_ci95_lower: f64,
    pub alpha_ci95_upper: f64,
    pub minimum_events_met: bool,
    pub classification: TriggerBudgetClassification,
}

/// Fail-closed result of a trigger-budget analysis.
///
/// The mixed-censoring variant intentionally contains no OLS coefficients.  A
/// censored-regression or survival model must be separately preregistered; simply
/// deleting censored trials would bias the slope toward early stalls.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum TriggerScalingAnalysis {
    /// Every trial completed its exposure horizon without an observed stall.
    NoFreezeObserved {
        observation_count: u64,
        minimum_trigger_budget_k: f64,
        maximum_trigger_budget_k: f64,
        minimum_censor_bytes: f64,
        total_censor_bytes: f64,
    },
    /// At least one, but not all, observations were right-censored; OLS refused.
    MixedRightCensoring {
        observation_count: u64,
        observed_event_count: u64,
        right_censored_count: u64,
    },
    /// All available events were observed, but fewer than three cannot form a
    /// Student-t slope interval with positive residual degrees of freedom.
    InsufficientObservedEvents {
        observation_count: u64,
        required_for_fit: u64,
    },
    /// Every event was observed and an assumption-gated OLS fit was computed.
    Fitted { fit: TriggerScalingFit },
}

/// Closed labels for invalid numeric fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericField {
    BlockId,
    ControlA,
    ControlB,
    CandidateA,
    CandidateB,
    TransformOffset,
    EquivalenceMargin,
    MinimumBlocks,
    MinimumOrderFraction,
    ObservationId,
    TriggerBudgetK,
    BytesObserved,
    BytesUntilStall,
    MinimumObservedEvents,
    SharedBandLower,
    SharedBandUpper,
    PerFlowBandLower,
    PerFlowBandUpper,
}

impl fmt::Display for NumericField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::BlockId => "block_id",
            Self::ControlA => "control_a",
            Self::ControlB => "control_b",
            Self::CandidateA => "candidate_a",
            Self::CandidateB => "candidate_b",
            Self::TransformOffset => "transform_offset",
            Self::EquivalenceMargin => "equivalence_margin",
            Self::MinimumBlocks => "minimum_blocks",
            Self::MinimumOrderFraction => "minimum_order_fraction",
            Self::ObservationId => "observation_id",
            Self::TriggerBudgetK => "trigger_budget_k",
            Self::BytesObserved => "bytes_observed",
            Self::BytesUntilStall => "bytes_until_stall",
            Self::MinimumObservedEvents => "minimum_observed_events",
            Self::SharedBandLower => "shared_budget_band.lower",
            Self::SharedBandUpper => "shared_budget_band.upper",
            Self::PerFlowBandLower => "per_flow_budget_band.lower",
            Self::PerFlowBandUpper => "per_flow_budget_band.upper",
        };
        f.write_str(name)
    }
}

/// Validation or numerical failure. Invalid input never produces a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalError {
    EmptyInput,
    DuplicateBlockId(u64),
    DuplicateObservationId(u64),
    InvalidNumericField {
        field: NumericField,
        record_id: Option<u64>,
    },
    StallBeyondObservationHorizon(u64),
    CrossoverAssumptionNotDeclared,
    ScalingAssumptionNotDeclared,
    OverlappingClassificationBands,
    DegenerateTriggerBudgets,
    NumericalOverflow,
}

impl fmt::Display for CausalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("causal analysis requires at least one observation"),
            Self::DuplicateBlockId(id) => write!(f, "duplicate crossover block ID {id}"),
            Self::DuplicateObservationId(id) => {
                write!(f, "duplicate trigger observation ID {id}")
            }
            Self::InvalidNumericField { field, record_id } => match record_id {
                Some(id) => write!(f, "invalid numeric field {field} in record {id}"),
                None => write!(f, "invalid numeric field {field}"),
            },
            Self::StallBeyondObservationHorizon(id) => write!(
                f,
                "bytes_until_stall exceeds bytes_observed in observation {id}"
            ),
            Self::CrossoverAssumptionNotDeclared => {
                f.write_str("all crossover Student-t assumptions must be explicitly declared")
            }
            Self::ScalingAssumptionNotDeclared => {
                f.write_str("all scaling OLS Student-t assumptions must be explicitly declared")
            }
            Self::OverlappingClassificationBands => {
                f.write_str("shared and per-flow exponent bands must be strictly disjoint")
            }
            Self::DegenerateTriggerBudgets => {
                f.write_str("at least two distinct positive trigger budgets are required")
            }
            Self::NumericalOverflow => {
                f.write_str("finite inputs produced a non-finite analysis result")
            }
        }
    }
}

impl Error for CausalError {}

/// Analyze complete paired crossover blocks under preregistered gates.
pub fn analyze_crossover(
    preregistration: CrossoverPreregistration,
    blocks: &[CrossoverBlock],
) -> Result<CrossoverAnalysis, CausalError> {
    validate_crossover_preregistration(preregistration)?;
    if blocks.is_empty() {
        return Err(CausalError::EmptyInput);
    }

    // Block order is not part of either estimand. Canonicalizing by the stable
    // ID makes floating-point accumulation and serialized results reproducible
    // across irrelevant input permutations.
    let mut ordered_blocks: Vec<_> = blocks.iter().collect();
    ordered_blocks.sort_by_key(|block| block.block_id);
    let mut ids = HashSet::with_capacity(blocks.len());
    let mut moments = Moments::default();
    let mut ab_blocks = 0_u64;
    let mut ba_blocks = 0_u64;

    for block in ordered_blocks {
        if block.block_id == 0 {
            return Err(invalid(NumericField::BlockId, Some(block.block_id)));
        }
        if !ids.insert(block.block_id) {
            return Err(CausalError::DuplicateBlockId(block.block_id));
        }

        let did = crossover_block_did(preregistration.transform, block)?;
        moments.push(did)?;

        match block.order {
            CrossoverOrder::Ab => ab_blocks = checked_increment(ab_blocks)?,
            CrossoverOrder::Ba => ba_blocks = checked_increment(ba_blocks)?,
        }
    }

    let block_count = moments.count;
    if block_count < 2 {
        return Err(invalid(NumericField::MinimumBlocks, None));
    }
    let degrees_of_freedom = block_count - 1;
    let sample_variance = moments.m2 / degrees_of_freedom as f64;
    let sample_standard_deviation = sample_variance.max(0.0).sqrt();
    let standard_error = sample_standard_deviation / (block_count as f64).sqrt();
    let student_t_critical_95 = student_t_critical_95(degrees_of_freedom);
    let half_width = student_t_critical_95 * standard_error;
    let ci95_lower = moments.mean - half_width;
    let ci95_upper = moments.mean + half_width;
    let observed_order_fraction = ab_blocks.min(ba_blocks) as f64 / block_count as f64;
    ensure_finite(&[
        sample_standard_deviation,
        standard_error,
        student_t_critical_95,
        ci95_lower,
        ci95_upper,
        observed_order_fraction,
    ])?;

    let estimate = CrossoverEstimate {
        block_count,
        ab_blocks,
        ba_blocks,
        mean_did: moments.mean,
        sample_standard_deviation,
        standard_error,
        degrees_of_freedom,
        student_t_critical_95,
        ci95_lower,
        ci95_upper,
        observed_order_fraction,
    };

    let verdict = if block_count < u64::from(preregistration.minimum_blocks) {
        CrossoverVerdict::InsufficientBlocks
    } else if observed_order_fraction < preregistration.minimum_order_fraction {
        CrossoverVerdict::OrderImbalance
    } else if ci95_lower > -preregistration.equivalence_margin
        && ci95_upper < preregistration.equivalence_margin
    {
        CrossoverVerdict::Equivalent
    } else {
        CrossoverVerdict::Inconclusive
    };

    Ok(CrossoverAnalysis { estimate, verdict })
}

/// Validate and compute the transformed DiD for one complete crossover block.
///
/// This audit primitive exposes the exact block-level statistic aggregated by
/// [`analyze_crossover`]. Duplicate IDs are necessarily a collection-level
/// property and are therefore checked only by the aggregate analysis.
pub fn crossover_block_did(
    transform_kind: OutcomeTransform,
    block: &CrossoverBlock,
) -> Result<f64, CausalError> {
    validate_transform(transform_kind)?;
    if block.block_id == 0 {
        return Err(invalid(NumericField::BlockId, Some(block.block_id)));
    }
    validate_positive(block.control_a, NumericField::ControlA, block.block_id)?;
    validate_positive(block.control_b, NumericField::ControlB, block.block_id)?;
    validate_positive(block.candidate_a, NumericField::CandidateA, block.block_id)?;
    validate_positive(block.candidate_b, NumericField::CandidateB, block.block_id)?;

    let control_a = transform(block.control_a, transform_kind)?;
    let control_b = transform(block.control_b, transform_kind)?;
    let candidate_a = transform(block.candidate_a, transform_kind)?;
    let candidate_b = transform(block.candidate_b, transform_kind)?;
    let did = (candidate_b - candidate_a) - (control_b - control_a);
    if did.is_finite() {
        Ok(did)
    } else {
        Err(CausalError::NumericalOverflow)
    }
}

/// Analyze trigger-budget scaling without silently discarding censored trials.
pub fn analyze_trigger_scaling(
    preregistration: TriggerScalingPreregistration,
    observations: &[TriggerBudgetObservation],
) -> Result<TriggerScalingAnalysis, CausalError> {
    validate_scaling_preregistration(preregistration)?;
    if observations.is_empty() {
        return Err(CausalError::EmptyInput);
    }

    // Trial array order is non-semantic; stabilize validation, aggregation, and
    // OLS roundoff by consuming observations in ID order.
    let mut ordered_observations: Vec<_> = observations.iter().collect();
    ordered_observations.sort_by_key(|observation| observation.observation_id);
    let mut ids = HashSet::with_capacity(observations.len());
    let mut event_count = 0_u64;
    let mut censored_count = 0_u64;
    let mut minimum_k = f64::INFINITY;
    let mut maximum_k = f64::NEG_INFINITY;
    let mut minimum_censor_bytes = f64::INFINITY;
    let mut total_censor_bytes = 0.0_f64;

    for observation in &ordered_observations {
        validate_trigger_observation(observation, &mut ids)?;
        minimum_k = minimum_k.min(observation.trigger_budget_k);
        maximum_k = maximum_k.max(observation.trigger_budget_k);
        match observation.bytes_until_stall {
            Some(_) => event_count = checked_increment(event_count)?,
            None => {
                censored_count = checked_increment(censored_count)?;
                minimum_censor_bytes = minimum_censor_bytes.min(observation.bytes_observed);
                total_censor_bytes += observation.bytes_observed;
                if !total_censor_bytes.is_finite() {
                    return Err(CausalError::NumericalOverflow);
                }
            }
        }
    }

    let observation_count = usize_to_u64(ordered_observations.len())?;
    if event_count == 0 {
        ensure_finite(&[
            minimum_k,
            maximum_k,
            minimum_censor_bytes,
            total_censor_bytes,
        ])?;
        return Ok(TriggerScalingAnalysis::NoFreezeObserved {
            observation_count,
            minimum_trigger_budget_k: minimum_k,
            maximum_trigger_budget_k: maximum_k,
            minimum_censor_bytes,
            total_censor_bytes,
        });
    }
    if censored_count != 0 {
        return Ok(TriggerScalingAnalysis::MixedRightCensoring {
            observation_count,
            observed_event_count: event_count,
            right_censored_count: censored_count,
        });
    }
    if observation_count < 3 {
        return Ok(TriggerScalingAnalysis::InsufficientObservedEvents {
            observation_count,
            required_for_fit: 3,
        });
    }

    if !all_scaling_assumptions_declared(preregistration.assumptions) {
        return Err(CausalError::ScalingAssumptionNotDeclared);
    }

    let fit = fit_complete_trigger_scaling(preregistration, &ordered_observations)?;
    Ok(TriggerScalingAnalysis::Fitted { fit })
}

fn validate_crossover_preregistration(
    preregistration: CrossoverPreregistration,
) -> Result<(), CausalError> {
    validate_transform(preregistration.transform)?;
    if !preregistration.equivalence_margin.is_finite() || preregistration.equivalence_margin <= 0.0
    {
        return Err(invalid(NumericField::EquivalenceMargin, None));
    }
    if preregistration.minimum_blocks < 2 {
        return Err(invalid(NumericField::MinimumBlocks, None));
    }
    if !preregistration.minimum_order_fraction.is_finite()
        || preregistration.minimum_order_fraction <= 0.0
        || preregistration.minimum_order_fraction > 0.5
    {
        return Err(invalid(NumericField::MinimumOrderFraction, None));
    }
    if !all_crossover_assumptions_declared(preregistration.assumptions) {
        return Err(CausalError::CrossoverAssumptionNotDeclared);
    }
    Ok(())
}

fn validate_transform(transform: OutcomeTransform) -> Result<(), CausalError> {
    match transform {
        OutcomeTransform::Identity => {}
        OutcomeTransform::LogPlusOffset { offset } => {
            if !offset.is_finite() || offset < 0.0 {
                return Err(invalid(NumericField::TransformOffset, None));
            }
        }
    }
    Ok(())
}

fn validate_scaling_preregistration(
    preregistration: TriggerScalingPreregistration,
) -> Result<(), CausalError> {
    if preregistration.minimum_observed_events < 3 {
        return Err(invalid(NumericField::MinimumObservedEvents, None));
    }
    validate_band(
        preregistration.shared_budget_band,
        NumericField::SharedBandLower,
        NumericField::SharedBandUpper,
    )?;
    validate_band(
        preregistration.per_flow_budget_band,
        NumericField::PerFlowBandLower,
        NumericField::PerFlowBandUpper,
    )?;

    let shared = preregistration.shared_budget_band;
    let per_flow = preregistration.per_flow_budget_band;
    if !(shared.upper < per_flow.lower || per_flow.upper < shared.lower) {
        return Err(CausalError::OverlappingClassificationBands);
    }
    Ok(())
}

fn validate_band(
    band: EquivalenceBand,
    lower_field: NumericField,
    upper_field: NumericField,
) -> Result<(), CausalError> {
    if !band.lower.is_finite() {
        return Err(invalid(lower_field, None));
    }
    if !band.upper.is_finite() {
        return Err(invalid(upper_field, None));
    }
    if band.lower >= band.upper {
        return Err(invalid(upper_field, None));
    }
    Ok(())
}

fn validate_trigger_observation(
    observation: &TriggerBudgetObservation,
    ids: &mut HashSet<u64>,
) -> Result<(), CausalError> {
    if observation.observation_id == 0 {
        return Err(invalid(
            NumericField::ObservationId,
            Some(observation.observation_id),
        ));
    }
    if !ids.insert(observation.observation_id) {
        return Err(CausalError::DuplicateObservationId(
            observation.observation_id,
        ));
    }
    validate_positive(
        observation.trigger_budget_k,
        NumericField::TriggerBudgetK,
        observation.observation_id,
    )?;
    validate_positive(
        observation.bytes_observed,
        NumericField::BytesObserved,
        observation.observation_id,
    )?;
    if let Some(stall) = observation.bytes_until_stall {
        validate_positive(
            stall,
            NumericField::BytesUntilStall,
            observation.observation_id,
        )?;
        if stall > observation.bytes_observed {
            return Err(CausalError::StallBeyondObservationHorizon(
                observation.observation_id,
            ));
        }
    }
    Ok(())
}

fn fit_complete_trigger_scaling(
    preregistration: TriggerScalingPreregistration,
    observations: &[&TriggerBudgetObservation],
) -> Result<TriggerScalingFit, CausalError> {
    let mut x_mean = 0.0;
    let mut y_mean = 0.0;
    let mut count = 0_u64;
    let mut distinct_k_bits = HashSet::with_capacity(observations.len());

    for observation in observations {
        let x = observation.trigger_budget_k.ln();
        let y = observation
            .bytes_until_stall
            .ok_or(CausalError::NumericalOverflow)?
            .ln();
        ensure_finite(&[x, y])?;
        count = checked_increment(count)?;
        let n = count as f64;
        x_mean += (x - x_mean) / n;
        y_mean += (y - y_mean) / n;
        ensure_finite(&[x_mean, y_mean])?;
        distinct_k_bits.insert(observation.trigger_budget_k.to_bits());
    }

    if distinct_k_bits.len() < 2 {
        return Err(CausalError::DegenerateTriggerBudgets);
    }

    let mut sxx = 0.0;
    let mut sxy = 0.0;
    for observation in observations {
        let x_delta = observation.trigger_budget_k.ln() - x_mean;
        let y_delta = observation
            .bytes_until_stall
            .ok_or(CausalError::NumericalOverflow)?
            .ln()
            - y_mean;
        sxx += x_delta * x_delta;
        sxy += x_delta * y_delta;
    }
    if !sxx.is_finite() || !sxy.is_finite() || sxx <= 0.0 {
        return Err(CausalError::DegenerateTriggerBudgets);
    }

    let alpha = sxy / sxx;
    let beta0 = y_mean - alpha * x_mean;
    ensure_finite(&[alpha, beta0])?;

    let mut residual_sum_squares = 0.0;
    for observation in observations {
        let x = observation.trigger_budget_k.ln();
        let y = observation
            .bytes_until_stall
            .ok_or(CausalError::NumericalOverflow)?
            .ln();
        let residual = y - (beta0 + alpha * x);
        residual_sum_squares += residual * residual;
        if !residual_sum_squares.is_finite() {
            return Err(CausalError::NumericalOverflow);
        }
    }

    let degrees_of_freedom = count - 2;
    let residual_variance = residual_sum_squares / degrees_of_freedom as f64;
    let residual_standard_deviation = residual_variance.max(0.0).sqrt();
    let alpha_standard_error = (residual_variance.max(0.0) / sxx).sqrt();
    let student_t_critical_95 = student_t_critical_95(degrees_of_freedom);
    let half_width = student_t_critical_95 * alpha_standard_error;
    let alpha_ci95_lower = alpha - half_width;
    let alpha_ci95_upper = alpha + half_width;
    ensure_finite(&[
        residual_standard_deviation,
        alpha_standard_error,
        student_t_critical_95,
        alpha_ci95_lower,
        alpha_ci95_upper,
    ])?;

    let minimum_events_met = count >= u64::from(preregistration.minimum_observed_events);
    let classification = if !minimum_events_met {
        TriggerBudgetClassification::Ambiguous
    } else if interval_strictly_inside(
        alpha_ci95_lower,
        alpha_ci95_upper,
        preregistration.shared_budget_band,
    ) {
        TriggerBudgetClassification::SharedBudget
    } else if interval_strictly_inside(
        alpha_ci95_lower,
        alpha_ci95_upper,
        preregistration.per_flow_budget_band,
    ) {
        TriggerBudgetClassification::PerFlowBudget
    } else {
        TriggerBudgetClassification::Ambiguous
    };

    Ok(TriggerScalingFit {
        observation_count: count,
        distinct_trigger_budgets: usize_to_u64(distinct_k_bits.len())?,
        beta0,
        alpha,
        residual_standard_deviation,
        alpha_standard_error,
        degrees_of_freedom,
        student_t_critical_95,
        alpha_ci95_lower,
        alpha_ci95_upper,
        minimum_events_met,
        classification,
    })
}

fn transform(value: f64, transform: OutcomeTransform) -> Result<f64, CausalError> {
    match transform {
        OutcomeTransform::Identity => Ok(value),
        OutcomeTransform::LogPlusOffset { offset } => {
            let shifted = value + offset;
            if !shifted.is_finite() || shifted <= 0.0 {
                return Err(CausalError::NumericalOverflow);
            }
            let transformed = shifted.ln();
            if transformed.is_finite() {
                Ok(transformed)
            } else {
                Err(CausalError::NumericalOverflow)
            }
        }
    }
}

fn interval_strictly_inside(lower: f64, upper: f64, band: EquivalenceBand) -> bool {
    lower > band.lower && upper < band.upper
}

fn all_crossover_assumptions_declared(assumptions: CrossoverAssumptions) -> bool {
    assumptions.independent_blocks
        && assumptions.randomized_order
        && assumptions.negligible_carryover
        && assumptions.approximately_normal_mean
}

fn all_scaling_assumptions_declared(assumptions: ScalingAssumptions) -> bool {
    assumptions.independent_trials
        && assumptions.log_linear_mean
        && assumptions.homoskedastic_normal_residuals
        && assumptions.preregistered_trigger_budgets
}

fn validate_positive(value: f64, field: NumericField, id: u64) -> Result<(), CausalError> {
    if value.is_finite() && value > 0.0 {
        Ok(())
    } else {
        Err(invalid(field, Some(id)))
    }
}

fn invalid(field: NumericField, record_id: Option<u64>) -> CausalError {
    CausalError::InvalidNumericField { field, record_id }
}

fn checked_increment(value: u64) -> Result<u64, CausalError> {
    value.checked_add(1).ok_or(CausalError::NumericalOverflow)
}

fn usize_to_u64(value: usize) -> Result<u64, CausalError> {
    u64::try_from(value).map_err(|_| CausalError::NumericalOverflow)
}

fn ensure_finite(values: &[f64]) -> Result<(), CausalError> {
    if values.iter().all(|value| value.is_finite()) {
        Ok(())
    } else {
        Err(CausalError::NumericalOverflow)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Moments {
    count: u64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn push(&mut self, value: f64) -> Result<(), CausalError> {
        if !value.is_finite() {
            return Err(CausalError::NumericalOverflow);
        }
        let next_count = checked_increment(self.count)?;
        let delta = value - self.mean;
        let next_mean = self.mean + delta / next_count as f64;
        let next_m2 = self.m2 + delta * (value - next_mean);
        if !next_mean.is_finite() || !next_m2.is_finite() || next_m2 < 0.0 {
            return Err(CausalError::NumericalOverflow);
        }
        self.count = next_count;
        self.mean = next_mean;
        self.m2 = next_m2;
        Ok(())
    }
}

/// Two-sided 95% Student-t critical value.
///
/// Values through 30 df are tabulated. Above 30 df, the first three terms of
/// the standard inverse-t asymptotic expansion around `z(0.975)` are used.  At
/// 31 df the approximation differs from the tabulated quantile by less than
/// `2e-5`, with error decreasing as df grows. Zero degrees of freedom has no
/// finite critical value and therefore returns positive infinity, which makes
/// downstream confidence bounds fail closed.
#[must_use]
pub fn student_t_critical_95(degrees_of_freedom: u64) -> f64 {
    const TABLE: [f64; 30] = [
        12.706_204_736_4,
        4.302_652_729_75,
        3.182_446_305_28,
        2.776_445_105_2,
        2.570_581_835_64,
        2.446_911_848_79,
        2.364_624_251_01,
        2.306_004_135_2,
        2.262_157_162_8,
        2.228_138_851_96,
        2.200_985_160_08,
        2.178_812_829_66,
        2.160_368_656_46,
        2.144_786_687_92,
        2.131_449_545_56,
        2.119_905_299_22,
        2.109_815_577_83,
        2.100_922_040_24,
        2.093_024_054_41,
        2.085_963_447_27,
        2.079_613_844_73,
        2.073_873_067_9,
        2.068_657_610_42,
        2.063_898_561_63,
        2.059_538_552_75,
        2.055_529_438_64,
        2.051_830_516_48,
        2.048_407_141_8,
        2.045_229_642_13,
        2.042_272_456_3,
    ];

    if degrees_of_freedom == 0 {
        return f64::INFINITY;
    }
    if degrees_of_freedom <= TABLE.len() as u64 {
        return TABLE[(degrees_of_freedom - 1) as usize];
    }

    const Z: f64 = 1.959_963_984_540_054;
    let nu = degrees_of_freedom as f64;
    let z2 = Z * Z;
    let z3 = z2 * Z;
    let z5 = z3 * z2;
    let z7 = z5 * z2;
    Z + (z3 + Z) / (4.0 * nu)
        + (5.0 * z5 + 16.0 * z3 + 3.0 * Z) / (96.0 * nu * nu)
        + (3.0 * z7 + 19.0 * z5 + 17.0 * z3 - 15.0 * Z) / (384.0 * nu * nu * nu)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1.0e-10;

    fn crossover_assumptions() -> CrossoverAssumptions {
        CrossoverAssumptions {
            independent_blocks: true,
            randomized_order: true,
            negligible_carryover: true,
            approximately_normal_mean: true,
        }
    }

    fn crossover_preregistration() -> CrossoverPreregistration {
        CrossoverPreregistration {
            transform: OutcomeTransform::Identity,
            equivalence_margin: 0.5,
            minimum_blocks: 4,
            minimum_order_fraction: 0.5,
            assumptions: crossover_assumptions(),
        }
    }

    fn block(id: u64, order: CrossoverOrder, did: f64) -> CrossoverBlock {
        CrossoverBlock {
            block_id: id,
            order,
            control_a: 100.0,
            control_b: 110.0,
            candidate_a: 200.0,
            candidate_b: 210.0 + did,
        }
    }

    fn scaling_assumptions() -> ScalingAssumptions {
        ScalingAssumptions {
            independent_trials: true,
            log_linear_mean: true,
            homoskedastic_normal_residuals: true,
            preregistered_trigger_budgets: true,
        }
    }

    fn scaling_preregistration() -> TriggerScalingPreregistration {
        TriggerScalingPreregistration {
            minimum_observed_events: 4,
            shared_budget_band: EquivalenceBand {
                lower: -0.2,
                upper: 0.2,
            },
            per_flow_budget_band: EquivalenceBand {
                lower: 0.8,
                upper: 1.2,
            },
            assumptions: scaling_assumptions(),
        }
    }

    fn event(id: u64, k: f64, bytes: f64) -> TriggerBudgetObservation {
        TriggerBudgetObservation {
            observation_id: id,
            trigger_budget_k: k,
            bytes_observed: bytes,
            bytes_until_stall: Some(bytes),
        }
    }

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= EPSILON,
            "actual={actual:.15}, expected={expected:.15}"
        );
    }

    #[test]
    fn balanced_crossover_computes_did_and_requires_full_ci_equivalence() {
        let blocks = [
            block(1, CrossoverOrder::Ab, -0.1),
            block(2, CrossoverOrder::Ba, 0.1),
            block(3, CrossoverOrder::Ab, -0.1),
            block(4, CrossoverOrder::Ba, 0.1),
        ];
        let result = analyze_crossover(crossover_preregistration(), &blocks).unwrap();

        assert_close(result.estimate.mean_did, 0.0);
        assert_eq!(result.estimate.ab_blocks, 2);
        assert_eq!(result.estimate.ba_blocks, 2);
        assert_close(result.estimate.observed_order_fraction, 0.5);
        assert!(result.estimate.ci95_lower > -0.5);
        assert!(result.estimate.ci95_upper < 0.5);
        assert_eq!(result.verdict, CrossoverVerdict::Equivalent);
    }

    #[test]
    fn nonsemantic_input_permutations_are_bit_deterministic() {
        let blocks = vec![
            block(7, CrossoverOrder::Ab, 0.031),
            block(2, CrossoverOrder::Ba, -0.047),
            block(9, CrossoverOrder::Ab, 0.113),
            block(4, CrossoverOrder::Ba, -0.029),
        ];
        let mut reversed_blocks = blocks.clone();
        reversed_blocks.reverse();
        assert_eq!(
            analyze_crossover(crossover_preregistration(), &blocks).unwrap(),
            analyze_crossover(crossover_preregistration(), &reversed_blocks).unwrap()
        );

        let observations = vec![
            event(7, 1.0, 101.0),
            event(2, 2.0, 213.0),
            event(9, 4.0, 397.0),
            event(4, 8.0, 823.0),
        ];
        let mut reversed_observations = observations.clone();
        reversed_observations.reverse();
        assert_eq!(
            analyze_trigger_scaling(scaling_preregistration(), &observations).unwrap(),
            analyze_trigger_scaling(scaling_preregistration(), &reversed_observations).unwrap()
        );
    }

    #[test]
    fn log_plus_offset_is_applied_before_each_block_did() {
        let preregistration = CrossoverPreregistration {
            transform: OutcomeTransform::LogPlusOffset { offset: 1.0 },
            equivalence_margin: 10.0,
            minimum_blocks: 2,
            minimum_order_fraction: 0.5,
            assumptions: crossover_assumptions(),
        };
        let blocks = [
            CrossoverBlock {
                block_id: 1,
                order: CrossoverOrder::Ab,
                control_a: 1.0,
                control_b: 3.0,
                candidate_a: 3.0,
                candidate_b: 15.0,
            },
            CrossoverBlock {
                block_id: 2,
                order: CrossoverOrder::Ba,
                control_a: 1.0,
                control_b: 3.0,
                candidate_a: 3.0,
                candidate_b: 15.0,
            },
        ];
        let result = analyze_crossover(preregistration, &blocks).unwrap();
        // ln(16/4) - ln(4/2) = ln(2).
        assert_close(result.estimate.mean_did, 2.0_f64.ln());
    }

    #[test]
    fn crossover_gates_minimum_blocks_then_order_balance() {
        let three = [
            block(1, CrossoverOrder::Ab, 0.0),
            block(2, CrossoverOrder::Ba, 0.0),
            block(3, CrossoverOrder::Ab, 0.0),
        ];
        assert_eq!(
            analyze_crossover(crossover_preregistration(), &three)
                .unwrap()
                .verdict,
            CrossoverVerdict::InsufficientBlocks
        );

        let unbalanced = [
            block(1, CrossoverOrder::Ab, 0.0),
            block(2, CrossoverOrder::Ab, 0.0),
            block(3, CrossoverOrder::Ab, 0.0),
            block(4, CrossoverOrder::Ba, 0.0),
        ];
        assert_eq!(
            analyze_crossover(crossover_preregistration(), &unbalanced)
                .unwrap()
                .verdict,
            CrossoverVerdict::OrderImbalance
        );
    }

    #[test]
    fn crossover_rejects_duplicate_nonpositive_and_nonfinite_values() {
        let duplicate = [
            block(1, CrossoverOrder::Ab, 0.0),
            block(1, CrossoverOrder::Ba, 0.0),
        ];
        assert_eq!(
            analyze_crossover(crossover_preregistration(), &duplicate),
            Err(CausalError::DuplicateBlockId(1))
        );

        let mut invalid = block(1, CrossoverOrder::Ab, 0.0);
        invalid.control_a = 0.0;
        assert!(matches!(
            analyze_crossover(
                crossover_preregistration(),
                &[invalid, block(2, CrossoverOrder::Ba, 0.0)]
            ),
            Err(CausalError::InvalidNumericField {
                field: NumericField::ControlA,
                ..
            })
        ));

        invalid.control_a = f64::NAN;
        assert!(matches!(
            analyze_crossover(
                crossover_preregistration(),
                &[invalid, block(2, CrossoverOrder::Ba, 0.0)]
            ),
            Err(CausalError::InvalidNumericField {
                field: NumericField::ControlA,
                ..
            })
        ));
    }

    #[test]
    fn undeclared_crossover_assumption_is_rejected() {
        let mut preregistration = crossover_preregistration();
        preregistration.assumptions.randomized_order = false;
        assert_eq!(
            analyze_crossover(
                preregistration,
                &[
                    block(1, CrossoverOrder::Ab, 0.0),
                    block(2, CrossoverOrder::Ba, 0.0),
                ]
            ),
            Err(CausalError::CrossoverAssumptionNotDeclared)
        );
    }

    #[test]
    fn all_right_censored_returns_no_freeze_observed_with_horizon() {
        let observations = [
            TriggerBudgetObservation {
                observation_id: 1,
                trigger_budget_k: 1.0,
                bytes_observed: 1_000.0,
                bytes_until_stall: None,
            },
            TriggerBudgetObservation {
                observation_id: 2,
                trigger_budget_k: 4.0,
                bytes_observed: 2_000.0,
                bytes_until_stall: None,
            },
        ];
        let result = analyze_trigger_scaling(scaling_preregistration(), &observations).unwrap();
        assert_eq!(
            result,
            TriggerScalingAnalysis::NoFreezeObserved {
                observation_count: 2,
                minimum_trigger_budget_k: 1.0,
                maximum_trigger_budget_k: 4.0,
                minimum_censor_bytes: 1_000.0,
                total_censor_bytes: 3_000.0,
            }
        );
    }

    #[test]
    fn mixed_right_censoring_is_flagged_without_ols_fit() {
        let observations = [
            event(1, 1.0, 1_000.0),
            TriggerBudgetObservation {
                observation_id: 2,
                trigger_budget_k: 2.0,
                bytes_observed: 2_000.0,
                bytes_until_stall: None,
            },
        ];
        assert_eq!(
            analyze_trigger_scaling(scaling_preregistration(), &observations).unwrap(),
            TriggerScalingAnalysis::MixedRightCensoring {
                observation_count: 2,
                observed_event_count: 1,
                right_censored_count: 1,
            }
        );
    }

    #[test]
    fn complete_per_flow_scaling_is_classified_only_by_full_alpha_ci() {
        let observations = [
            event(1, 1.0, 100.0),
            event(2, 2.0, 200.0),
            event(3, 4.0, 400.0),
            event(4, 8.0, 800.0),
        ];
        let TriggerScalingAnalysis::Fitted { fit } =
            analyze_trigger_scaling(scaling_preregistration(), &observations).unwrap()
        else {
            panic!("expected complete fit");
        };
        assert_close(fit.alpha, 1.0);
        assert!(fit.alpha_ci95_lower > 0.8);
        assert!(fit.alpha_ci95_upper < 1.2);
        assert!(fit.minimum_events_met);
        assert_eq!(
            fit.classification,
            TriggerBudgetClassification::PerFlowBudget
        );
    }

    #[test]
    fn complete_constant_threshold_is_classified_as_shared_budget() {
        let observations = [
            event(1, 1.0, 100.0),
            event(2, 2.0, 100.0),
            event(3, 4.0, 100.0),
            event(4, 8.0, 100.0),
        ];
        let TriggerScalingAnalysis::Fitted { fit } =
            analyze_trigger_scaling(scaling_preregistration(), &observations).unwrap()
        else {
            panic!("expected complete fit");
        };
        assert_close(fit.alpha, 0.0);
        assert_eq!(
            fit.classification,
            TriggerBudgetClassification::SharedBudget
        );
    }

    #[test]
    fn exponent_between_preregistered_bands_is_ambiguous() {
        let observations = [
            event(1, 1.0, 100.0),
            event(2, 4.0, 200.0),
            event(3, 16.0, 400.0),
            event(4, 64.0, 800.0),
        ];
        let TriggerScalingAnalysis::Fitted { fit } =
            analyze_trigger_scaling(scaling_preregistration(), &observations).unwrap()
        else {
            panic!("expected complete fit");
        };
        assert_close(fit.alpha, 0.5);
        assert_eq!(fit.classification, TriggerBudgetClassification::Ambiguous);
    }

    #[test]
    fn minimum_events_gate_keeps_precise_small_fit_ambiguous() {
        let mut preregistration = scaling_preregistration();
        preregistration.minimum_observed_events = 5;
        let observations = [
            event(1, 1.0, 100.0),
            event(2, 2.0, 200.0),
            event(3, 4.0, 400.0),
            event(4, 8.0, 800.0),
        ];
        let TriggerScalingAnalysis::Fitted { fit } =
            analyze_trigger_scaling(preregistration, &observations).unwrap()
        else {
            panic!("expected complete fit");
        };
        assert!(!fit.minimum_events_met);
        assert_eq!(fit.classification, TriggerBudgetClassification::Ambiguous);
    }

    #[test]
    fn scaling_rejects_duplicates_invalid_numbers_and_impossible_event_horizon() {
        let duplicate = [event(1, 1.0, 100.0), event(1, 2.0, 200.0)];
        assert_eq!(
            analyze_trigger_scaling(scaling_preregistration(), &duplicate),
            Err(CausalError::DuplicateObservationId(1))
        );

        let mut invalid = event(1, f64::INFINITY, 100.0);
        assert!(matches!(
            analyze_trigger_scaling(scaling_preregistration(), &[invalid]),
            Err(CausalError::InvalidNumericField {
                field: NumericField::TriggerBudgetK,
                ..
            })
        ));
        invalid.trigger_budget_k = 1.0;
        invalid.bytes_until_stall = Some(101.0);
        assert_eq!(
            analyze_trigger_scaling(scaling_preregistration(), &[invalid]),
            Err(CausalError::StallBeyondObservationHorizon(1))
        );
    }

    #[test]
    fn mixed_censoring_refusal_does_not_require_ols_assumptions() {
        let mut preregistration = scaling_preregistration();
        preregistration.assumptions.independent_trials = false;
        let observations = [
            event(1, 1.0, 100.0),
            TriggerBudgetObservation {
                observation_id: 2,
                trigger_budget_k: 2.0,
                bytes_observed: 200.0,
                bytes_until_stall: None,
            },
        ];
        assert!(matches!(
            analyze_trigger_scaling(preregistration, &observations),
            Ok(TriggerScalingAnalysis::MixedRightCensoring { .. })
        ));
    }

    #[test]
    fn complete_fit_requires_declared_ols_assumptions_and_distinct_k() {
        let observations = [
            event(1, 1.0, 100.0),
            event(2, 2.0, 200.0),
            event(3, 4.0, 400.0),
        ];
        let mut preregistration = scaling_preregistration();
        preregistration.assumptions.log_linear_mean = false;
        assert_eq!(
            analyze_trigger_scaling(preregistration, &observations),
            Err(CausalError::ScalingAssumptionNotDeclared)
        );

        let same_k = [
            event(1, 2.0, 100.0),
            event(2, 2.0, 110.0),
            event(3, 2.0, 120.0),
        ];
        assert_eq!(
            analyze_trigger_scaling(scaling_preregistration(), &same_k),
            Err(CausalError::DegenerateTriggerBudgets)
        );
    }

    #[test]
    fn overlapping_classification_bands_are_rejected() {
        let mut preregistration = scaling_preregistration();
        preregistration.per_flow_budget_band.lower = 0.1;
        assert_eq!(
            analyze_trigger_scaling(preregistration, &[event(1, 1.0, 100.0)]),
            Err(CausalError::OverlappingClassificationBands)
        );
    }

    #[test]
    fn t_critical_table_and_asymptotic_branch_match_reference_values() {
        assert_close(student_t_critical_95(1), 12.706_204_736_4);
        assert_close(student_t_critical_95(30), 2.042_272_456_3);
        assert!((student_t_critical_95(31) - 2.039_513_446).abs() < 2.0e-5);
        assert!((student_t_critical_95(1_000) - 1.962_339_081).abs() < 1.0e-8);
    }
}
