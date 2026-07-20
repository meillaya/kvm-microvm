//! Snapshot/restore protocol tests (plan todo 28, requirements 2 and 3).
//!
//! The snapshot is taken after service readiness; warm instances are restored
//! through the orchestrator. The full demo records spawn/socket/configured/
//! guest-ready/snapshot-ready/restore-ready/request timings, accounts for every
//! restore trial, and cleans up. When guest health never becomes ready, every
//! trial is recorded as a failure, no request is counted as warm, and cleanup
//! evidence is present.

use microvm_artifacts::Digest;
use microvm_bench::{HostMetadata, PageCachePolicy};
use microvm_demo::{
    DemoConfig, DemoPhase, DemoRunner, HttpFunction, Rootfs, ScriptedRestore, ScriptedRestorer,
    VmRestorer,
};

fn function() -> HttpFunction {
    let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
    HttpFunction::new("hello-http", rootfs).unwrap()
}

fn host() -> HostMetadata {
    HostMetadata {
        cpu: "test-cpu".into(),
        kernel: "7.1.3-test".into(),
        kvm_api_version: 12,
        page_cache_state: PageCachePolicy::Mixed,
        memory_size_mib: 65536,
        vcpu_count: 32,
        cgroup_v2: true,
        nested: false,
    }
}

#[tokio::test]
async fn snapshot_is_taken_after_service_readiness() {
    let mut restorer =
        ScriptedRestorer::ok("s", 2.0, 3.0, vec![Ok(ScriptedRestore::new(1.0, 1.0))]);
    let cs = restorer.cold_start(&function()).await.unwrap();
    let guest = cs.phases.get(DemoPhase::GuestReady).unwrap();
    let snap = cs.phases.get(DemoPhase::SnapshotReady).unwrap();
    let req = cs.phases.get(DemoPhase::Request).unwrap();
    assert!(guest < snap, "snapshot must follow guest readiness");
    assert!(snap < req, "first request follows the snapshot");
    assert!(!cs.phases.contains(DemoPhase::RestoreReady));
}

#[tokio::test]
async fn warm_restore_reaches_restore_ready_without_guest_boot() {
    let mut restorer =
        ScriptedRestorer::ok("s", 1.0, 1.0, vec![Ok(ScriptedRestore::new(1.0, 0.5))]);
    let cs = restorer.cold_start(&function()).await.unwrap();
    let vm = restorer.restore(&cs.snapshot).await.unwrap();
    assert!(vm.phases().contains(DemoPhase::RestoreReady));
    assert!(!vm.phases().contains(DemoPhase::GuestReady));
    assert!(!vm.phases().contains(DemoPhase::SnapshotReady));
    assert!(vm.restore_ready_ms().is_some());
}

#[tokio::test]
async fn demo_records_all_named_phase_durations() {
    let restores: Vec<Result<ScriptedRestore, String>> =
        (0..4).map(|_| Ok(ScriptedRestore::new(1.0, 1.0))).collect();
    let mut restorer = ScriptedRestorer::ok("s", 2.0, 3.0, restores);
    let runner = DemoRunner::new(DemoConfig::new(function(), 100, 4).unwrap());
    let report = runner.run(host(), &mut restorer).await;

    let phases = report.cold_phases.expect("cold phases recorded");
    // spawn/socket/configured/guest-ready/snapshot-ready/request from the cold
    // path, plus restore-ready from a representative warm restore.
    assert!(phases.socket_ready_ms.is_some());
    assert!(phases.configured_ms.is_some());
    assert!(phases.guest_ready_ms.is_some());
    assert!(phases.snapshot_ready_ms.is_some());
    assert!(phases.restore_ready_ms.is_some());
    assert!(phases.request_ms.is_some());
    // Snapshot readiness precedes the first request.
    assert!(phases.snapshot_ready_ms < phases.request_ms);
}

#[tokio::test]
async fn happy_path_accounts_for_every_restore_trial_and_cleans_up() {
    let restores: Vec<Result<ScriptedRestore, String>> = (0..8)
        .map(|i| Ok(ScriptedRestore::new(1.0, (i % 4 + 1) as f64)))
        .collect();
    let mut restorer = ScriptedRestorer::ok("s", 2.0, 3.0, restores);
    let runner = DemoRunner::new(DemoConfig::new(function(), 100, 8).unwrap());
    let report = runner.run(host(), &mut restorer).await;

    assert!(!report.is_blocked());
    assert!(report.cold_first_call_ms.is_some());
    // N=100 warm requests, all accounted for.
    assert_eq!(report.request_trials, 100);
    assert_eq!(
        report.warm.samples + report.warm.failures,
        report.request_trials
    );
    assert_eq!(report.warm.samples, 100);
    assert_eq!(report.warmup_count, 8);
    // Cleanup evidence present.
    assert_eq!(report.cleanup.released_vms, 8);
    assert!(report.cleanup.snapshot_discarded);
}

#[tokio::test]
async fn guest_never_ready_records_all_timeouts_no_warm_and_cleanup() {
    let mut restorer = ScriptedRestorer::guest_never_ready("s");
    let runner = DemoRunner::new(DemoConfig::new(function(), 100, 4).unwrap());
    let report = runner.run(host(), &mut restorer).await;

    // The demo ran (not a blocked prerequisite) but the guest never became ready.
    assert!(!report.is_blocked());
    assert!(report.cold_first_call_ms.is_none());
    assert!(report.cold_phases.is_none());
    // No request is counted as warm.
    assert_eq!(report.warm.samples, 0);
    assert!(report.warm_p50_ms.is_none());
    // Every timed-out trial is recorded.
    assert_eq!(report.request_trials, 100);
    assert_eq!(report.warm.failures, 100);
    assert_eq!(report.restore_trials, 100);
    assert_eq!(report.restore_failures, 100);
    assert_eq!(report.warmup_count, 0);
    // Cleanup evidence is present.
    assert_eq!(report.cleanup.released_vms, 0);
    assert!(!report.cleanup.snapshot_discarded);
}
