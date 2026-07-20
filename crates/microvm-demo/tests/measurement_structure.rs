//! Cold/warm measurement-structure tests (plan todo 28, requirement 4).
//!
//! The measurement reuses the microvm-bench harness for warm statistics and
//! reconciles every trial. It carries no pass/fail gate.

use microvm_demo::ColdWarmMeasurement;

#[test]
fn cold_first_call_and_warm_percentiles_are_reported() {
    let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
    let m = ColdWarmMeasurement::new(Some(42.5), &samples, 0, 100, 8, 8, 0);
    assert_eq!(m.cold_first_call_ms, Some(42.5));
    assert_eq!(m.warm_p50(), Some(50.0));
    assert_eq!(m.warm_p95(), Some(95.0));
    assert_eq!(m.warm_p99(), Some(99.0));
    assert_eq!(m.warmup_count, 8);
}

#[test]
fn warm_failures_recorded_but_excluded_from_percentiles() {
    let m = ColdWarmMeasurement::new(Some(10.0), &[5.0, 6.0, 7.0], 97, 100, 4, 4, 0);
    assert_eq!(m.warm_request_count(), 3);
    assert_eq!(m.warm.failures, 97);
    assert_eq!(m.warm_p50(), Some(6.0));
    assert!(m.trials_reconcile());
}

#[test]
fn no_warm_data_yields_null_percentiles_not_zeros() {
    let m = ColdWarmMeasurement::new(None, &[], 100, 100, 0, 100, 100);
    assert!(m.cold_first_call_ms.is_none());
    assert!(m.warm_p50().is_none());
    assert!(m.warm_p99().is_none());
    assert_eq!(m.warm_request_count(), 0);
    assert_eq!(m.warm.failures, 100);
    assert!(m.trials_reconcile());
}

#[test]
fn blocked_measurement_is_empty() {
    let m = ColdWarmMeasurement::blocked();
    assert!(m.cold_first_call_ms.is_none());
    assert_eq!(m.warm_request_count(), 0);
    assert_eq!(m.request_trials, 0);
    assert!(m.trials_reconcile());
}
