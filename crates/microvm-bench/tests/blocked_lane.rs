//! Blocked-lane handling tests (the benchmark harness, the contract).
//!
//! Named QA scenario: `cargo test -p microvm-bench --test blocked_lane`.
//!
//! An unavailable Docker/KVM/firecracker lane must be blocked with evidence:
//! a stable `blocked_reason`, zero samples, and null percentiles. Samples are
//! never fabricated, and a blocked privileged lane maps to exit code 77 (a
//! skip, not a failure and not a pass).

use microvm_artifacts::Digest;
use microvm_bench::config::{
    BenchmarkConfig, Conditions, PageCachePolicy, RuntimeVersions, Workload,
};
use microvm_bench::marker::BenchMarker;
use microvm_bench::result::HostMetadata;
use microvm_bench::{BenchExitCode, BlockedReason, ScriptedLane};
use serde_json::Value;

fn host() -> HostMetadata {
    HostMetadata {
        cpu: "test-cpu".into(),
        kernel: "7.1.3-test".into(),
        kvm_api_version: -1, // KVM inaccessible in this scenario
        page_cache_state: PageCachePolicy::Mixed,
        memory_size_mib: 65536,
        vcpu_count: 16,
        cgroup_v2: true,
        nested: false,
    }
}

fn config() -> BenchmarkConfig {
    let w = Workload::new("snapshot-restore", Digest::from_bytes([9; 32])).unwrap();
    BenchmarkConfig::new(w, 100, Conditions::default()).unwrap()
}

#[tokio::test]
async fn blocked_lane_records_reason_and_zero_samples() {
    let marker = BenchMarker::new(config());
    let lane = ScriptedLane::blocked(
        "snapshot_restore",
        200.0,
        BlockedReason::KvmUnavailable,
        "/dev/kvm not accessible",
    );
    let result = marker
        .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
        .await;

    assert!(result.has_blocked_lane());
    let item = &result.benchmarks[0];
    assert_eq!(item.blocked_reason.as_deref(), Some("kvm_unavailable"));
    // No fabricated samples.
    assert_eq!(item.cold.samples, 0);
    assert_eq!(item.warm.samples, 0);
    assert_eq!(item.cold.failures, 0);
    assert_eq!(item.warm.failures, 0);
    assert!(item.p50.is_none() && item.p95.is_none() && item.p99.is_none());
}

#[tokio::test]
async fn blocked_lane_never_invokes_sampling() {
    // A blocked lane is created with EMPTY sample queues. If the marker wrongly
    // attempted to sample it, run_sample would return an error and record a
    // failure. Zero failures + zero samples proves sampling was never attempted.
    let marker = BenchMarker::new(config());
    let lane = ScriptedLane::blocked(
        "docker_start_cold",
        800.0,
        BlockedReason::DockerMissing,
        "daemon down",
    );
    let result = marker
        .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
        .await;
    let item = &result.benchmarks[0];
    assert_eq!(item.cold.samples + item.cold.failures, 0);
    assert_eq!(item.warm.samples + item.warm.failures, 0);
}

#[tokio::test]
async fn mixed_blocked_and_completed_lanes() {
    let marker = BenchMarker::new(config());
    let blocked = ScriptedLane::blocked(
        "snapshot_restore",
        200.0,
        BlockedReason::FirecrackerMissing,
        "no firecracker binary",
    );
    let cold: Vec<Result<f64, String>> = (0..100).map(|i| Ok(900.0 + i as f64)).collect();
    let warm: Vec<Result<f64, String>> = (0..100).map(|i| Ok(800.0 + i as f64)).collect();
    let running = ScriptedLane::new("docker_start_cold", 800.0, cold, warm);

    let result = marker
        .run(
            host(),
            RuntimeVersions {
                firecracker: None,
                docker: Some("27.0.0".into()),
            },
            vec![Box::new(blocked), Box::new(running)],
        )
        .await;

    assert!(result.has_blocked_lane());
    let fc = result
        .benchmarks
        .iter()
        .find(|b| b.name == "snapshot_restore")
        .unwrap();
    let docker = result
        .benchmarks
        .iter()
        .find(|b| b.name == "docker_start_cold")
        .unwrap();
    assert_eq!(fc.blocked_reason.as_deref(), Some("firecracker_missing"));
    assert!(docker.blocked_reason.is_none());
    assert_eq!(docker.cold.samples, 100);
    assert_eq!(docker.warm.samples, 100);
}

#[tokio::test]
async fn blocked_result_serializes_with_reason_and_nulls() {
    let marker = BenchMarker::new(config());
    let lane = ScriptedLane::blocked(
        "snapshot_restore",
        200.0,
        BlockedReason::KvmUnavailable,
        "missing",
    );
    let result = marker
        .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
        .await;
    let json: Value = serde_json::from_str(&result.to_json_pretty().unwrap()).unwrap();
    let item = &json["benchmarks"][0];
    assert_eq!(item["blocked_reason"], Value::from("kvm_unavailable"));
    assert!(item["p50"].is_null());
    assert_eq!(item["cold"]["samples"], Value::from(0));
    assert_eq!(item["warm"]["samples"], Value::from(0));
    // host_metadata still records kvm_api_version = -1 (always present).
    assert_eq!(json["host_metadata"]["kvm_api_version"], Value::from(-1));
}

#[test]
fn blocked_privileged_lane_maps_to_exit_77() {
    // A blocked privileged lane is a skip (77), never a failure (1) or pass (0).
    assert_eq!(BenchExitCode::Blocked.code(), 77);
    assert_ne!(BenchExitCode::Blocked, BenchExitCode::Success);
    assert_ne!(BenchExitCode::Blocked, BenchExitCode::GeneralError);
}

#[test]
fn every_blocked_reason_has_a_stable_token() {
    for reason in BlockedReason::all() {
        let token = reason.as_str();
        assert!(!token.is_empty());
        assert!(
            token.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "token '{token}' must be stable snake_case"
        );
    }
}
