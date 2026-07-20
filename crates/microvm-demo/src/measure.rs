//! Cold first-call vs warm request measurement structure (plan todo 28,
//! requirement 4).
//!
//! [`ColdWarmMeasurement`] summarises the demo's two latency regimes:
//! - the **cold first call** — the one-time `spawn -> request` cost that includes
//!   booting to readiness and taking the snapshot;
//! - the **warm request distribution** — p50/p95/p99 over requests served by
//!   pre-restored pool VMs, computed with the microvm-bench harness's
//!   nearest-rank [`Distribution`].
//!
//! The measurement reuses the benchmark harness for statistics (requirement 6):
//! warm samples are summarised by [`Distribution::from_samples_with_failures`],
//! so failed warm attempts are recorded and excluded from the percentiles, never
//! zero-filled. There is **no** pass/fail gate here: the structure reports numbers
//! and counts, never a verdict.

use microvm_bench::Distribution;
use serde::{Deserialize, Serialize};

/// Cold first-call vs warm request measurement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ColdWarmMeasurement {
    /// Cold first-call latency in milliseconds (`spawn -> request`), or `None`
    /// when the cold start failed (e.g. the guest never became ready).
    pub cold_first_call_ms: Option<f64>,
    /// Warm request distribution (samples, failures, p50/p95/p99, min/max).
    pub warm: Distribution,
    /// Number of warm request attempts (successful + failed). Equals the demo's
    /// `samples` budget so every trial is accounted for.
    pub request_trials: usize,
    /// Number of VMs successfully pre-restored (warmed) into the pool.
    pub warmup_count: usize,
    /// Total restore attempts (warmup fills + on-demand restores + no-snapshot
    /// attempts).
    pub restore_trials: usize,
    /// Restore attempts that failed.
    pub restore_failures: usize,
}

impl ColdWarmMeasurement {
    /// Build a measurement from raw parts. Warm samples are summarised by the
    /// benchmark harness; `warm_failures` are recorded but excluded from the
    /// percentiles.
    pub fn new(
        cold_first_call_ms: Option<f64>,
        warm_samples: &[f64],
        warm_failures: usize,
        request_trials: usize,
        warmup_count: usize,
        restore_trials: usize,
        restore_failures: usize,
    ) -> Self {
        Self {
            cold_first_call_ms,
            warm: Distribution::from_samples_with_failures(warm_samples, warm_failures),
            request_trials,
            warmup_count,
            restore_trials,
            restore_failures,
        }
    }

    /// A blocked measurement: no cold call, zero warm samples, null percentiles.
    /// Nothing is fabricated.
    pub fn blocked() -> Self {
        Self {
            cold_first_call_ms: None,
            warm: Distribution::empty(),
            request_trials: 0,
            warmup_count: 0,
            restore_trials: 0,
            restore_failures: 0,
        }
    }

    /// Warm p50 in milliseconds, or `None` when no warm samples were collected.
    pub fn warm_p50(&self) -> Option<f64> {
        self.warm.p50
    }

    /// Warm p95 in milliseconds, or `None` when no warm samples were collected.
    pub fn warm_p95(&self) -> Option<f64> {
        self.warm.p95
    }

    /// Warm p99 in milliseconds, or `None` when no warm samples were collected.
    pub fn warm_p99(&self) -> Option<f64> {
        self.warm.p99
    }

    /// Number of successful warm requests.
    pub fn warm_request_count(&self) -> usize {
        self.warm.samples
    }

    /// True when every warm request trial is accounted for (success or failure).
    pub fn trials_reconcile(&self) -> bool {
        self.warm.samples + self.warm.failures == self.request_trials
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_measurement_is_empty_with_nulls() {
        let m = ColdWarmMeasurement::blocked();
        assert!(m.cold_first_call_ms.is_none());
        assert_eq!(m.warm_request_count(), 0);
        assert!(m.warm_p50().is_none());
        assert!(m.warm_p99().is_none());
        assert_eq!(m.warmup_count, 0);
        assert!(m.trials_reconcile());
    }

    #[test]
    fn warm_percentiles_come_from_the_harness() {
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let m = ColdWarmMeasurement::new(Some(50.0), &samples, 0, 100, 8, 8, 0);
        assert_eq!(m.cold_first_call_ms, Some(50.0));
        assert_eq!(m.warm_p50(), Some(50.0));
        assert_eq!(m.warm_p95(), Some(95.0));
        assert_eq!(m.warm_p99(), Some(99.0));
        assert_eq!(m.warm_request_count(), 100);
        assert!(m.trials_reconcile());
    }

    #[test]
    fn warm_failures_are_recorded_but_excluded() {
        let m = ColdWarmMeasurement::new(Some(10.0), &[1.0, 2.0, 3.0], 7, 10, 4, 4, 0);
        assert_eq!(m.warm_request_count(), 3);
        assert_eq!(m.warm.failures, 7);
        assert!(m.trials_reconcile());
        // Percentiles reflect only the 3 successful samples.
        assert_eq!(m.warm_p50(), Some(2.0));
    }

    #[test]
    fn all_failed_warm_has_zero_samples_but_records_failures() {
        let m = ColdWarmMeasurement::new(None, &[], 100, 100, 0, 100, 100);
        assert_eq!(m.warm_request_count(), 0);
        assert_eq!(m.warm.failures, 100);
        assert!(m.warm_p50().is_none());
        assert!(m.trials_reconcile());
    }

    #[test]
    fn trials_reconcile_detects_mismatch() {
        let mut m = ColdWarmMeasurement::new(Some(1.0), &[1.0, 2.0], 0, 5, 1, 1, 0);
        assert!(!m.trials_reconcile());
        m.request_trials = 2;
        assert!(m.trials_reconcile());
    }
}
