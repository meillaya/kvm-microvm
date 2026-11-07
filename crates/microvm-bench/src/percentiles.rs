//! Deterministic percentile and distribution statistics for benchmark samples.
//!
//! The harness reports distributions, never a single number. Every
//! benchmark condition (cold/warm) is summarised by its sample count, p50/p95/p99
//! (nearest-rank), and min/max. A condition with zero samples carries `null`
//! percentiles: the harness never fabricates or zero-fills a statistic.
//!
//! # Method: nearest-rank
//! For `N` sorted samples, the `p`-th percentile is the value at 1-based rank
//! `ceil(p/100 * N)`, clamped to `[1, N]`. This is the textbook nearest-rank
//! definition: it always returns an actually-observed sample, is monotonic in
//! `p`, and is fully deterministic for a fixed input. For `N = 100` this yields
//! ranks 50, 95, and 99 for p50/p95/p99 respectively.

use serde::{Deserialize, Serialize};

/// p50/p95/p99 of a sample set, computed with the nearest-rank method.
///
/// All three values are actual observed samples. `None` when the input is
/// empty (a blocked or skipped condition).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Percentiles {
    /// 50th percentile (median).
    pub p50: f64,
    /// 95th percentile.
    pub p95: f64,
    /// 99th percentile.
    pub p99: f64,
}

impl Percentiles {
    /// Compute p50/p95/p99 over `samples` using the nearest-rank method.
    ///
    /// Returns `None` when `samples` is empty. Samples are sorted ascending;
    /// the input slice is not mutated. Non-finite samples (NaN/infinity) are a
    /// programming error and are rejected via `debug_assert`: the harness only
    /// ever feeds measured, finite durations.
    pub fn compute(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        debug_assert!(
            samples.iter().all(|s| s.is_finite()),
            "percentile input must be finite"
        );
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Some(Self {
            p50: nearest_rank(&sorted, 50.0),
            p95: nearest_rank(&sorted, 95.0),
            p99: nearest_rank(&sorted, 99.0),
        })
    }
}

/// Nearest-rank percentile over an ascending-sorted, non-empty slice.
///
/// rank = ceil(p/100 * N), clamped to [1, N]; returns `sorted[rank-1]`.
fn nearest_rank(sorted: &[f64], p: f64) -> f64 {
    let n = sorted.len();
    debug_assert!(n > 0, "nearest_rank requires a non-empty slice");
    let rank = ((p / 100.0) * n as f64).ceil() as usize;
    let rank = rank.clamp(1, n);
    sorted[rank - 1]
}

/// A full distribution summary for one benchmark condition (cold or warm).
///
/// Serializes to the `cold`/`warm` object shape in
/// `schemas/evidence-benchmark.v1.json`: `samples`, `p50`, `p95`, `p99`,
/// `min_ms`, `max_ms`. When `samples == 0` every statistic is `None`
/// (serialized as `null`): a blocked or skipped condition is reported as
/// absent data, never as a measured zero.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Distribution {
    /// Number of successful samples collected for this condition.
    pub samples: usize,
    /// Number of sample attempts that failed and were discarded.
    /// Failed samples are recorded here and never counted in `samples` or
    /// the percentiles: a failure is visible, not silently dropped or zero-filled.
    #[serde(default)]
    pub failures: usize,
    /// 50th percentile in milliseconds, or `null` when `samples == 0`.
    pub p50: Option<f64>,
    /// 95th percentile in milliseconds, or `null` when `samples == 0`.
    pub p95: Option<f64>,
    /// 99th percentile in milliseconds, or `null` when `samples == 0`.
    pub p99: Option<f64>,
    /// Minimum observed sample in milliseconds, or `null` when `samples == 0`.
    pub min_ms: Option<f64>,
    /// Maximum observed sample in milliseconds, or `null` when `samples == 0`.
    pub max_ms: Option<f64>,
}

impl Distribution {
    /// An empty distribution: zero samples and all-`null` statistics. Used for
    /// a blocked or skipped condition.
    pub fn empty() -> Self {
        Self {
            samples: 0,
            failures: 0,
            p50: None,
            p95: None,
            p99: None,
            min_ms: None,
            max_ms: None,
        }
    }

    /// Summarise a set of millisecond samples with zero failures. Returns
    /// [`Distribution::empty`] when `samples` is empty.
    pub fn from_samples(samples: &[f64]) -> Self {
        Self::from_samples_with_failures(samples, 0)
    }

    /// Summarise a set of successful millisecond samples plus a count of failed
    /// attempts. Failures are recorded but excluded from every
    /// statistic. Returns a distribution with `samples == 0` (and the failure
    /// count preserved) when no successful samples were collected.
    pub fn from_samples_with_failures(samples: &[f64], failures: usize) -> Self {
        let pct = match Percentiles::compute(samples) {
            Some(p) => p,
            None => {
                return Self {
                    failures,
                    ..Self::empty()
                }
            }
        };
        let min_ms = samples.iter().copied().fold(f64::INFINITY, f64::min);
        let max_ms = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        Self {
            samples: samples.len(),
            failures,
            p50: Some(pct.p50),
            p95: Some(pct.p95),
            p99: Some(pct.p99),
            min_ms: Some(min_ms),
            max_ms: Some(max_ms),
        }
    }

    /// True when no samples were collected (blocked or skipped condition).
    pub fn is_empty(&self) -> bool {
        self.samples == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_none() {
        assert!(Percentiles::compute(&[]).is_none());
        assert_eq!(Distribution::from_samples(&[]), Distribution::empty());
        assert!(Distribution::empty().is_empty());
    }

    #[test]
    fn single_sample_is_every_percentile() {
        let p = Percentiles::compute(&[42.0]).unwrap();
        assert_eq!(p.p50, 42.0);
        assert_eq!(p.p95, 42.0);
        assert_eq!(p.p99, 42.0);
    }

    #[test]
    fn nearest_rank_on_1_to_100() {
        // Samples 1.0..=100.0: nearest-rank p50=50, p95=95, p99=99.
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let p = Percentiles::compute(&samples).unwrap();
        assert_eq!(p.p50, 50.0);
        assert_eq!(p.p95, 95.0);
        assert_eq!(p.p99, 99.0);
    }

    #[test]
    fn nearest_rank_is_monotonic_in_p() {
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let p = Percentiles::compute(&samples).unwrap();
        assert!(p.p50 <= p.p95);
        assert!(p.p95 <= p.p99);
    }

    #[test]
    fn compute_sorts_unordered_input() {
        // Percentiles must not depend on input order.
        let a = Percentiles::compute(&[5.0, 1.0, 3.0, 2.0, 4.0]).unwrap();
        let b = Percentiles::compute(&[1.0, 2.0, 3.0, 4.0, 5.0]).unwrap();
        assert_eq!(a, b);
        // N=5: p50 rank=ceil(2.5)=3 -> 3.0; p95 rank=ceil(4.75)=5 -> 5.0.
        assert_eq!(a.p50, 3.0);
        assert_eq!(a.p99, 5.0);
    }

    #[test]
    fn distribution_min_max_and_count() {
        let d = Distribution::from_samples(&[10.0, 20.0, 30.0]);
        assert_eq!(d.samples, 3);
        assert_eq!(d.min_ms, Some(10.0));
        assert_eq!(d.max_ms, Some(30.0));
        assert!(d.p50.is_some());
        assert!(!d.is_empty());
    }

    #[test]
    fn empty_distribution_serializes_nulls() {
        let json = serde_json::to_value(Distribution::empty()).unwrap();
        assert_eq!(json["samples"], serde_json::json!(0));
        assert_eq!(json["failures"], serde_json::json!(0));
        assert!(json["p50"].is_null());
        assert!(json["min_ms"].is_null());
        assert!(json["max_ms"].is_null());
    }

    #[test]
    fn failures_are_recorded_but_excluded_from_statistics() {
        let d = Distribution::from_samples_with_failures(&[10.0, 20.0, 30.0], 4);
        assert_eq!(d.samples, 3);
        assert_eq!(d.failures, 4);
        // Statistics reflect only the 3 successful samples.
        assert_eq!(d.min_ms, Some(10.0));
        assert_eq!(d.max_ms, Some(30.0));
    }

    #[test]
    fn all_failed_condition_has_zero_samples_but_records_failures() {
        let d = Distribution::from_samples_with_failures(&[], 100);
        assert_eq!(d.samples, 0);
        assert_eq!(d.failures, 100);
        assert!(d.p50.is_none());
        assert!(d.is_empty());
    }
}
