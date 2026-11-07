//! Deterministic percentile-calculation tests (the benchmark harness).
//!
//! Named QA scenario: `cargo test -p microvm-bench --test percentiles`.
//!
//! The harness reports distributions, never a single number. These tests pin the
//! nearest-rank method and the distribution summary so a fixed input always
//! yields a fixed p50/p95/p99: the statistical core is fully deterministic and
//! requires no `/dev/kvm` or Docker daemon.

use microvm_bench::percentiles::{Distribution, Percentiles};

#[test]
fn nearest_rank_is_deterministic_for_fixed_input() {
    let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
    let a = Percentiles::compute(&samples).unwrap();
    let b = Percentiles::compute(&samples).unwrap();
    assert_eq!(a, b, "same input must give same percentiles");
    assert_eq!(a.p50, 50.0);
    assert_eq!(a.p95, 95.0);
    assert_eq!(a.p99, 99.0);
}

#[test]
fn nearest_rank_matches_textbook_definition() {
    // For N samples, p-th percentile = sorted[ceil(p/100 * N) - 1].
    let samples = vec![15.0, 20.0, 35.0, 40.0, 50.0];
    let p = Percentiles::compute(&samples).unwrap();
    // N=5: p50 rank=ceil(2.5)=3 -> 35.0; p95 rank=ceil(4.75)=5 -> 50.0.
    assert_eq!(p.p50, 35.0);
    assert_eq!(p.p95, 50.0);
    assert_eq!(p.p99, 50.0);
}

#[test]
fn percentiles_are_order_independent() {
    let shuffled = vec![42.0, 7.0, 99.0, 1.0, 23.0, 55.0, 88.0, 3.0, 17.0, 64.0];
    let sorted = {
        let mut s = shuffled.clone();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        s
    };
    assert_eq!(
        Percentiles::compute(&shuffled).unwrap(),
        Percentiles::compute(&sorted).unwrap()
    );
}

#[test]
fn percentiles_are_monotonic_non_decreasing() {
    let samples: Vec<f64> = (0..1000).map(|i| (i as f64) * 0.37 % 250.0).collect();
    let p = Percentiles::compute(&samples).unwrap();
    assert!(p.p50 <= p.p95);
    assert!(p.p95 <= p99_or_equal(&p));
}

fn p99_or_equal(p: &Percentiles) -> f64 {
    p.p99
}

#[test]
fn empty_input_has_no_percentiles() {
    assert!(Percentiles::compute(&[]).is_none());
}

#[test]
fn distribution_summarises_count_min_max_and_percentiles() {
    let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
    let d = Distribution::from_samples(&samples);
    assert_eq!(d.samples, 100);
    assert_eq!(d.failures, 0);
    assert_eq!(d.min_ms, Some(1.0));
    assert_eq!(d.max_ms, Some(100.0));
    assert_eq!(d.p50, Some(50.0));
    assert_eq!(d.p95, Some(95.0));
    assert_eq!(d.p99, Some(99.0));
}

#[test]
fn distribution_failures_are_excluded_from_statistics() {
    // 3 good samples + 7 failures: statistics reflect only the 3 good ones.
    let d = Distribution::from_samples_with_failures(&[100.0, 200.0, 300.0], 7);
    assert_eq!(d.samples, 3);
    assert_eq!(d.failures, 7);
    assert_eq!(d.min_ms, Some(100.0));
    assert_eq!(d.max_ms, Some(300.0));
}

#[test]
fn all_failed_distribution_records_failures_with_null_stats() {
    let d = Distribution::from_samples_with_failures(&[], 100);
    assert_eq!(d.samples, 0);
    assert_eq!(d.failures, 100);
    assert!(d.is_empty());
    assert!(d.p50.is_none() && d.p95.is_none() && d.p99.is_none());
    assert!(d.min_ms.is_none() && d.max_ms.is_none());
}
