//! Small, dependency-free online statistics for measurement decisions.
//!
//! The accumulator uses Welford's recurrence, avoiding the catastrophic
//! cancellation of `E[x^2] - E[x]^2`.  [`OnlineMoments::merge`] uses the
//! pairwise/Chan form of the same recurrence, so independent workers can be
//! reduced without retaining raw samples.

use std::error::Error;
use std::fmt;

/// The standard-normal quantile used for a two-sided 95% Wilson interval.
///
/// Using this for only the lower endpoint is deliberately more conservative
/// than a one-sided 95% bound (whose quantile is approximately 1.64485).
pub const Z_95_TWO_SIDED: f64 = 1.959_963_984_540_054;

/// Failures possible while updating online moments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MomentError {
    /// NaN and infinities are not observations and would poison all later state.
    NonFiniteSample,
    /// The exact observation counter cannot be represented by `u64`.
    CountOverflow,
    /// Finite inputs produced a non-finite intermediate/result.
    NumericalOverflow,
}

impl fmt::Display for MomentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonFiniteSample => f.write_str("online-moments sample must be finite"),
            Self::CountOverflow => f.write_str("online-moments observation count overflowed"),
            Self::NumericalOverflow => {
                f.write_str("online-moments arithmetic overflowed floating-point range")
            }
        }
    }
}

impl Error for MomentError {}

/// Numerically stable online first and second central moments.
///
/// The internal `m2` is the sum of squared deviations from the current mean.
/// Keeping fields private preserves the recurrence invariants.  Invalid input
/// returns an error without changing the accumulator.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OnlineMoments {
    count: u64,
    mean: f64,
    m2: f64,
}

impl Default for OnlineMoments {
    fn default() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }
}

impl OnlineMoments {
    /// Construct an empty accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Number of accepted observations.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Whether no observations have been accepted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Arithmetic mean, or `None` when empty.
    #[must_use]
    pub fn mean(&self) -> Option<f64> {
        (self.count != 0).then_some(self.mean)
    }

    /// Population variance (`M2 / n`), or `None` when empty.
    #[must_use]
    pub fn population_variance(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.m2 / self.count as f64)
        }
    }

    /// Unbiased sample variance (`M2 / (n - 1)`), requiring two samples.
    #[must_use]
    pub fn sample_variance(&self) -> Option<f64> {
        if self.count < 2 {
            None
        } else {
            Some(self.m2 / (self.count - 1) as f64)
        }
    }

    /// Population standard deviation, or `None` when empty.
    #[must_use]
    pub fn population_stddev(&self) -> Option<f64> {
        self.population_variance().map(f64::sqrt)
    }

    /// Estimated standard error of the mean, requiring two samples.
    #[must_use]
    pub fn standard_error(&self) -> Option<f64> {
        self.sample_variance()
            .map(|variance| (variance / self.count as f64).sqrt())
    }

    /// Fold one finite sample into the accumulator using Welford's recurrence.
    ///
    /// On error, `self` is unchanged.
    pub fn push(&mut self, sample: f64) -> Result<(), MomentError> {
        if !sample.is_finite() {
            return Err(MomentError::NonFiniteSample);
        }

        let next_count = self
            .count
            .checked_add(1)
            .ok_or(MomentError::CountOverflow)?;
        if self.count == 0 {
            self.count = 1;
            self.mean = sample;
            self.m2 = 0.0;
            return Ok(());
        }

        let delta = sample - self.mean;
        let next_mean = self.mean + delta / next_count as f64;
        let delta_after = sample - next_mean;
        let next_m2 = self.m2 + delta * delta_after;
        if !next_mean.is_finite() || !next_m2.is_finite() || next_m2 < 0.0 {
            return Err(MomentError::NumericalOverflow);
        }

        self.count = next_count;
        self.mean = next_mean;
        self.m2 = next_m2;
        Ok(())
    }

    /// Merge another accumulator using the pairwise/Chan recurrence.
    ///
    /// This is useful for per-path or per-worker aggregation without exporting
    /// the underlying samples.  On error, `self` is unchanged.
    pub fn merge(&mut self, other: &Self) -> Result<(), MomentError> {
        if other.count == 0 {
            return Ok(());
        }
        if self.count == 0 {
            *self = *other;
            return Ok(());
        }

        let combined_count = self
            .count
            .checked_add(other.count)
            .ok_or(MomentError::CountOverflow)?;
        let left_count = self.count as f64;
        let right_count = other.count as f64;
        let combined_count_f64 = combined_count as f64;
        let delta = other.mean - self.mean;
        let combined_mean = self.mean + delta * (right_count / combined_count_f64);
        let correction = delta * delta * (left_count * right_count / combined_count_f64);
        let combined_m2 = self.m2 + other.m2 + correction;

        if !combined_mean.is_finite() || !combined_m2.is_finite() || combined_m2 < 0.0 {
            return Err(MomentError::NumericalOverflow);
        }

        self.count = combined_count;
        self.mean = combined_mean;
        self.m2 = combined_m2;
        Ok(())
    }

    /// Discard all observations.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

/// Invalid inputs to a binomial confidence bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceError {
    /// A binomial sample cannot contain more successes than trials.
    SuccessesExceedTrials,
    /// The normal quantile must be finite and strictly positive.
    InvalidZScore,
}

impl fmt::Display for ConfidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SuccessesExceedTrials => f.write_str("binomial successes cannot exceed trials"),
            Self::InvalidZScore => f.write_str("Wilson-bound z-score must be finite and positive"),
        }
    }
}

impl Error for ConfidenceError {}

/// Lower endpoint of the Wilson score interval for a binomial proportion.
///
/// `z_score` is the desired standard-normal quantile.  Unlike the fragile Wald
/// interval, Wilson remains meaningful near zero/one and for small samples.
/// `Ok(None)` means no trials, i.e. no evidence rather than zero reliability.
pub fn wilson_lower_bound(
    successes: u64,
    trials: u64,
    z_score: f64,
) -> Result<Option<f64>, ConfidenceError> {
    if successes > trials {
        return Err(ConfidenceError::SuccessesExceedTrials);
    }
    if !z_score.is_finite() || z_score <= 0.0 {
        return Err(ConfidenceError::InvalidZScore);
    }
    if trials == 0 {
        return Ok(None);
    }

    let n = trials as f64;
    let proportion = successes as f64 / n;
    let z_squared = z_score * z_score;
    if !z_squared.is_finite() {
        return Err(ConfidenceError::InvalidZScore);
    }

    let denominator = 1.0 + z_squared / n;
    let center = proportion + z_squared / (2.0 * n);
    let radicand = (proportion * (1.0 - proportion) + z_squared / (4.0 * n)) / n;
    let margin = z_score * radicand.max(0.0).sqrt();
    let lower = ((center - margin) / denominator).clamp(0.0, 1.0);
    Ok(Some(lower))
}

/// Wilson lower bound from a two-sided 95% interval.
///
/// This is a conservative default for admission/routing decisions because its
/// quantile is stricter than a one-sided 95% lower confidence bound.
pub fn wilson_lower_bound_95(successes: u64, trials: u64) -> Result<Option<f64>, ConfidenceError> {
    wilson_lower_bound(successes, trials, Z_95_TWO_SIDED)
}

/// Conservative reliability score for automatic decisions.
///
/// Returns zero until `minimum_trials` observations exist; afterwards returns
/// the conservative 95% Wilson lower endpoint.  Thus insufficient evidence can
/// never be mistaken for a perfect but untested path.
pub fn conservative_success_lcb(
    successes: u64,
    trials: u64,
    minimum_trials: u64,
) -> Result<f64, ConfidenceError> {
    if successes > trials {
        return Err(ConfidenceError::SuccessesExceedTrials);
    }
    if trials < minimum_trials || trials == 0 {
        return Ok(0.0);
    }

    match wilson_lower_bound_95(successes, trials)? {
        Some(bound) => Ok(bound),
        None => Ok(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1.0e-12;

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= EPSILON,
            "actual={actual:.16}, expected={expected:.16}"
        );
    }

    #[test]
    fn welford_matches_known_population_and_sample_moments() {
        let mut moments = OnlineMoments::new();
        for sample in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            moments.push(sample).expect("finite sample");
        }

        assert_eq!(moments.count(), 8);
        assert!(!moments.is_empty());
        assert_close(moments.mean().expect("non-empty"), 5.0);
        assert_close(moments.population_variance().expect("non-empty"), 4.0);
        assert_close(
            moments.sample_variance().expect("at least two samples"),
            32.0 / 7.0,
        );
        assert_close(moments.population_stddev().expect("non-empty"), 2.0);
        assert_close(
            moments.standard_error().expect("at least two samples"),
            (4.0_f64 / 7.0).sqrt(),
        );
    }

    #[test]
    fn pairwise_merge_matches_single_pass() {
        let samples = [1.0, 1.0e9, -3.0, 8.0, 13.0, 21.0];
        let mut all = OnlineMoments::new();
        let mut left = OnlineMoments::new();
        let mut right = OnlineMoments::new();

        for (index, sample) in samples.into_iter().enumerate() {
            all.push(sample).expect("finite sample");
            if index < 3 {
                left.push(sample).expect("finite sample");
            } else {
                right.push(sample).expect("finite sample");
            }
        }
        left.merge(&right).expect("finite merge");

        assert_eq!(left.count(), all.count());
        let mean_scale = all.mean().expect("non-empty").abs().max(1.0);
        assert!(
            (left.mean().expect("non-empty") - all.mean().expect("non-empty")).abs()
                <= mean_scale * 1.0e-15
        );
        let variance_scale = all.population_variance().expect("non-empty").max(1.0);
        assert!(
            (left.population_variance().expect("non-empty")
                - all.population_variance().expect("non-empty"))
            .abs()
                <= variance_scale * 1.0e-15
        );
    }

    #[test]
    fn invalid_sample_does_not_poison_state() {
        let mut moments = OnlineMoments::new();
        moments.push(7.0).expect("finite sample");
        let before = moments;

        assert_eq!(moments.push(f64::NAN), Err(MomentError::NonFiniteSample));
        assert_eq!(moments, before);
        assert_eq!(
            moments.push(f64::INFINITY),
            Err(MomentError::NonFiniteSample)
        );
        assert_eq!(moments, before);
    }

    #[test]
    fn arithmetic_overflow_does_not_mutate_state() {
        let mut moments = OnlineMoments::new();
        moments.push(f64::MAX).expect("finite first sample");
        let before = moments;

        assert_eq!(moments.push(-f64::MAX), Err(MomentError::NumericalOverflow));
        assert_eq!(moments, before);
    }

    #[test]
    fn empty_and_singleton_semantics_are_explicit() {
        let mut moments = OnlineMoments::new();
        assert_eq!(moments.mean(), None);
        assert_eq!(moments.population_variance(), None);
        assert_eq!(moments.sample_variance(), None);
        assert_eq!(moments.standard_error(), None);

        moments.push(42.0).expect("finite sample");
        assert_eq!(moments.population_variance(), Some(0.0));
        assert_eq!(moments.sample_variance(), None);
        moments.clear();
        assert_eq!(moments, OnlineMoments::new());
    }

    #[test]
    fn wilson_bound_matches_reference_values() {
        assert_close(
            wilson_lower_bound_95(50, 100)
                .expect("valid counts")
                .expect("non-empty"),
            0.403_831_530_365_995_6,
        );
        assert_close(
            wilson_lower_bound_95(10, 10)
                .expect("valid counts")
                .expect("non-empty"),
            0.722_467_200_137_110_7,
        );
        assert_close(
            wilson_lower_bound_95(0, 10)
                .expect("valid counts")
                .expect("non-empty"),
            0.0,
        );
        assert_eq!(
            wilson_lower_bound_95(0, 0).expect("valid empty counts"),
            None
        );
    }

    #[test]
    fn confidence_inputs_are_checked() {
        assert_eq!(
            wilson_lower_bound_95(2, 1),
            Err(ConfidenceError::SuccessesExceedTrials)
        );
        assert_eq!(
            wilson_lower_bound(0, 1, 0.0),
            Err(ConfidenceError::InvalidZScore)
        );
        assert_eq!(
            wilson_lower_bound(0, 1, f64::NAN),
            Err(ConfidenceError::InvalidZScore)
        );
    }

    #[test]
    fn conservative_lcb_gates_small_samples() {
        assert_eq!(
            conservative_success_lcb(4, 4, 5).expect("valid counts"),
            0.0
        );
        assert_close(
            conservative_success_lcb(5, 5, 5).expect("valid counts"),
            wilson_lower_bound_95(5, 5)
                .expect("valid counts")
                .expect("non-empty"),
        );
    }
}
