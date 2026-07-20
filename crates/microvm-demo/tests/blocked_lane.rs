//! Blocked-lane handling tests (plan todo 28).
//!
//! A blocked restorer (missing prerequisite) yields a blocked report: null cold
//! call, empty warm distribution, recorded reason, and no fabricated samples.
//! The blocked outcome is an execution skip, never a performance pass/fail.

use microvm_artifacts::Digest;
use microvm_bench::{BlockedReason, HostMetadata, PageCachePolicy};
use microvm_demo::{DemoConfig, DemoOutcome, DemoRunner, HttpFunction, Rootfs, ScriptedRestorer};

fn function() -> HttpFunction {
    let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
    HttpFunction::new("hello-http", rootfs).unwrap()
}

fn host() -> HostMetadata {
    HostMetadata {
        cpu: "test-cpu".into(),
        kernel: "7.1.3-test".into(),
        kvm_api_version: -1,
        page_cache_state: PageCachePolicy::Mixed,
        memory_size_mib: 65536,
        vcpu_count: 32,
        cgroup_v2: true,
        nested: false,
    }
}

#[tokio::test]
async fn blocked_kvm_yields_blocked_report_with_no_samples() {
    let mut restorer = ScriptedRestorer::blocked("s", BlockedReason::KvmUnavailable, "no /dev/kvm");
    let runner = DemoRunner::new(DemoConfig::new(function(), 100, 4).unwrap());
    let report = runner.run(host(), &mut restorer).await;

    assert!(report.is_blocked());
    assert_eq!(report.blocked_reason.as_deref(), Some("kvm_unavailable"));
    assert!(report.cold_first_call_ms.is_none());
    assert!(
        report.warm_p50_ms.is_none()
            && report.warm_p95_ms.is_none()
            && report.warm_p99_ms.is_none()
    );
    assert_eq!(report.warm.samples, 0);
    assert_eq!(report.warm.failures, 0);
    assert_eq!(report.request_trials, 0);
    assert_eq!(report.warmup_count, 0);
    assert!(report.cold_phases.is_none());
}

#[tokio::test]
async fn blocked_outcome_is_not_a_performance_verdict() {
    let mut restorer =
        ScriptedRestorer::blocked("s", BlockedReason::FirecrackerMissing, "no firecracker bin");
    let runner = DemoRunner::new(DemoConfig::new(function(), 100, 4).unwrap());
    let report = runner.run(host(), &mut restorer).await;

    assert_eq!(
        report.outcome(),
        DemoOutcome::Blocked {
            reason: BlockedReason::FirecrackerMissing,
            detail: "no firecracker bin".to_string(),
        }
    );
    assert!(report.outcome().is_blocked());
    assert!(!report.outcome().is_completed());
    // The serialized report carries no pass/fail gate.
    let json = serde_json::to_value(&report).unwrap();
    assert!(json.get("pass").is_none());
}

#[tokio::test]
async fn every_blocked_reason_token_is_stable() {
    for reason in BlockedReason::all() {
        let mut restorer = ScriptedRestorer::blocked("s", *reason, "detail");
        let runner = DemoRunner::new(DemoConfig::new(function(), 10, 2).unwrap());
        let report = runner.run(host(), &mut restorer).await;
        assert_eq!(report.blocked_reason.as_deref(), Some(reason.as_str()));
    }
}
