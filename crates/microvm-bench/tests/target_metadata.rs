//! Target-is-metadata (not-SLA) tests (plan todo 27, requirement 10).
//!
//! Named QA scenario: `cargo test -p microvm-bench --test target_metadata`.
//!
//! `<200 ms` is a reference target, never a pass/fail gate. The benchmark
//! artifact must carry `target_ms` as a number and must contain no `pass`
//! field at any nesting level; even when every sample exceeds the target.
//! Reviewers compare the recorded distribution against `target_ms`; the harness
//! never reduces that comparison to a boolean.

use microvm_artifacts::Digest;
use microvm_bench::config::{BenchmarkConfig, Conditions, RuntimeVersions, Workload};
use microvm_bench::marker::BenchMarker;
use microvm_bench::percentiles::Distribution;
use microvm_bench::result::{BenchmarkItem, BenchmarkResult, HostMetadata, Unit};
use microvm_bench::{PageCachePolicy, ScriptedLane};
use serde_json::Value;

fn host() -> HostMetadata {
    HostMetadata {
        cpu: "test-cpu".into(),
        kernel: "7.1.3-test".into(),
        kvm_api_version: 12,
        page_cache_state: PageCachePolicy::Mixed,
        memory_size_mib: 65536,
        vcpu_count: 16,
        cgroup_v2: true,
        nested: false,
    }
}

/// Recursively assert no object key named `pass` exists anywhere in the tree.
fn assert_no_pass_anywhere(value: &Value, path: &str) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                assert_ne!(k, "pass", "forbidden 'pass' field at {path}");
                assert_no_pass_anywhere(v, &format!("{path}.{k}"));
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                assert_no_pass_anywhere(v, &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn samples_exceeding_target_produce_no_pass_field() {
    // Every sample is far above the 200ms target; the artifact must still only
    // record the distribution + target metadata, with no pass/fail verdict.
    let w = Workload::new("snapshot-restore", Digest::from_bytes([3; 32])).unwrap();
    let config = BenchmarkConfig::new(w, 100, Conditions::default()).unwrap();
    let marker = BenchMarker::new(config);
    let cold: Vec<Result<f64, String>> = (0..100).map(|i| Ok(500.0 + i as f64)).collect();
    let warm: Vec<Result<f64, String>> = (0..100).map(|i| Ok(400.0 + i as f64)).collect();
    let lane = ScriptedLane::new("snapshot_restore", 200.0, cold, warm);
    let result = marker
        .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
        .await;

    let json: Value = serde_json::from_str(&result.to_json_pretty().unwrap()).unwrap();
    assert_no_pass_anywhere(&json, "$");

    let item = &json["benchmarks"][0];
    assert!(
        item["target_ms"].is_number(),
        "target_ms is metadata, present"
    );
    assert_eq!(item["target_ms"], Value::from(200.0));
    // The distribution is recorded honestly even though it misses the target.
    assert!(item["warm"]["p50"].as_f64().unwrap() > 200.0);
}

#[test]
fn target_metadata_present_on_blocked_item_too() {
    // Even a blocked item carries target_ms as metadata (never a gate).
    let item = BenchmarkItem::blocked("snapshot_restore", 200.0, Unit::Ms, "kvm_unavailable");
    let json = serde_json::to_value(&item).unwrap();
    assert_no_pass_anywhere(&json, "$");
    assert_eq!(json["target_ms"], Value::from(200.0));
    assert!(json.get("pass").is_none());
}

#[test]
fn full_result_tree_has_no_pass_at_any_depth() {
    let w = Workload::new("snapshot-restore", Digest::from_bytes([4; 32])).unwrap();
    let result = BenchmarkResult::new(
        host(),
        w,
        RuntimeVersions {
            firecracker: Some("1.16.1".into()),
            docker: None,
        },
        vec![
            BenchmarkItem::new(
                "snapshot_restore",
                200.0,
                Unit::Ms,
                Distribution::from_samples(&[150.0, 160.0]),
                Distribution::from_samples(&[14.0, 16.0]),
                None,
            ),
            BenchmarkItem::blocked("docker_start_cold", 800.0, Unit::Ms, "docker_missing"),
        ],
    );
    let json: Value = serde_json::from_str(&result.to_json_pretty().unwrap()).unwrap();
    assert_no_pass_anywhere(&json, "$");
}

#[test]
fn target_is_not_a_threshold_accessor() {
    // The item exposes target_ms purely as data; there is no method that turns
    // it into a pass boolean. This test documents the contract by asserting the
    // serialized shape: a number, alongside distributions, and nothing boolean
    // named like a verdict.
    let item = BenchmarkItem::new(
        "snapshot_restore",
        200.0,
        Unit::Ms,
        Distribution::from_samples(&[10.0]),
        Distribution::from_samples(&[5.0]),
        None,
    );
    let json = serde_json::to_value(&item).unwrap();
    assert!(json["target_ms"].is_number());
    for forbidden in ["pass", "passed", "ok", "meets_target", "sla_met"] {
        assert!(
            json.get(forbidden).is_none(),
            "no verdict field '{forbidden}' may exist"
        );
    }
}
