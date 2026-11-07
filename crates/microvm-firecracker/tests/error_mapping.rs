//! Deterministic error-mapping tests: process/API/readiness/integrity failures
//! are mapped into lifecycle states (`VmState::Failed`) with typed error codes,
//! audit events, and cleanup evidence.

mod common;

use common::PrereqMode;
use common::{Rig, RigOptions};
use microvm_errors::ErrorCode;
use microvm_errors::MicrovmError;
use microvm_firecracker::phase::Phase;
use microvm_firecracker::testing::{ApiCall, FailPoint, SpawnOutcome};
use microvm_lifecycle::policy::{AuditResult, Operation};
use microvm_lifecycle::{LifecycleService, VmState};

#[tokio::test]
async fn spawn_failure_maps_to_failed() {
    let rig = Rig::new(RigOptions {
        spawn_outcome: SpawnOutcome::Fail(MicrovmError::new(
            ErrorCode::ProcessSpawnError,
            "exec format error",
        )),
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ProcessSpawnError);
    assert_eq!(
        err.context.get("vm_state").map(String::as_str),
        Some("failed")
    );
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Failed));

    // No InstanceStart was ever issued.
    assert!(!rig.api.recorded(&ApiCall::StartInstance));

    // Audited as an error.
    let events = rig.audit.events();
    let start = events
        .iter()
        .find(|e| e.operation == Operation::Start)
        .unwrap();
    assert_eq!(start.result, AuditResult::Error);
}

#[tokio::test]
async fn api_config_failure_maps_to_failed_and_cleans_up() {
    let rig = Rig::new(RigOptions {
        api_failure: Some(FailPoint::BootSource),
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::TransportError);
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Failed));

    // machine-config was issued before the boot-source failure, but InstanceStart
    // was not.
    assert!(rig.api.recorded(&ApiCall::MachineConfig(
        microvm_firecracker::api::MachineConfig::new(2, 512)
    )));
    assert!(!rig.api.recorded(&ApiCall::StartInstance));

    // Cleanup ran (a process had been spawned and stashed).
    assert!(
        !rig.cleanup.recorded().is_empty(),
        "expected cleanup actions"
    );
}

#[tokio::test]
async fn instance_start_failure_maps_to_failed() {
    let rig = Rig::new(RigOptions {
        api_failure: Some(FailPoint::StartInstance),
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::TransportError);
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Failed));

    // Configuration succeeded; guest-ready never recorded.
    let phases = rig.backend.phases(&rig.vm_id).unwrap();
    assert!(phases.configured().is_some());
    assert!(phases.get(Phase::GuestReady).is_none());
}

#[tokio::test]
async fn guest_not_ready_maps_to_failed_after_instance_start() {
    let rig = Rig::new(RigOptions {
        probe_ready: false,
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InternalError);
    assert_eq!(
        err.context.get("phase").map(String::as_str),
        Some("guest_ready")
    );
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Failed));

    // InstanceStart WAS issued; the guest simply never became ready.
    assert!(rig.api.recorded(&ApiCall::StartInstance));
    let phases = rig.backend.phases(&rig.vm_id).unwrap();
    assert!(phases.get(Phase::GuestReady).is_none());

    // Cleanup ran after the failed readiness gate.
    assert!(!rig.cleanup.recorded().is_empty());
}

#[tokio::test]
async fn malformed_rootfs_digest_mismatch_fails_before_instance_start() {
    // The plan's failure scenario: a malformed kernel/rootfs must not reach
    // InstanceStart, must end in Failed, and must produce an audit error.
    let rig = Rig::new(RigOptions {
        corrupt_rootfs: true,
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::DigestMismatch);
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Failed));

    // No child spawned, no API call issued at all.
    assert!(
        rig.launcher.spawned().is_empty(),
        "no child may be spawned on digest mismatch"
    );
    assert!(
        rig.api.calls().is_empty(),
        "no API call may be issued on digest mismatch"
    );
    assert!(!rig.api.recorded(&ApiCall::StartInstance));

    // Audited as an error.
    let events = rig.audit.events();
    let start = events
        .iter()
        .find(|e| e.operation == Operation::Start)
        .unwrap();
    assert_eq!(start.result, AuditResult::Error);
}

#[tokio::test]
async fn missing_boot_config_fails_before_spawn() {
    let rig = Rig::new(RigOptions {
        no_boot: true,
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // No child spawned.
    assert!(rig.launcher.spawned().is_empty());
    // State remains Created (config error, retryable once a boot config is set).
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Created));
}

#[tokio::test]
async fn prerequisite_failure_fails_before_child_creation() {
    let rig = Rig::new(RigOptions {
        prereq: PrereqMode::ScriptedFail,
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::CgroupUnavailable);
    assert_eq!(
        err.context.get("phase").map(String::as_str),
        Some("prerequisite")
    );

    // No child created, no API traffic.
    assert!(
        rig.launcher.spawned().is_empty(),
        "prereq must fail before spawn"
    );
    assert!(rig.api.calls().is_empty());
    // State remains Created (host problem, retryable).
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Created));
}

#[tokio::test]
async fn stop_from_created_is_an_invalid_transition() {
    let rig = Rig::healthy().await;
    let err = rig.backend.stop(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Created));
}

#[tokio::test]
async fn snapshot_on_created_vm_is_an_invalid_transition() {
    let rig = Rig::healthy().await;
    let err = LifecycleService::snapshot(&rig.backend, &rig.vm_id, &rig.owner)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[tokio::test]
async fn restore_missing_snapshot_is_not_found() {
    let rig = Rig::healthy().await;
    let snap = microvm_types::SnapshotId::new("snap-1").unwrap();
    let err = LifecycleService::restore(&rig.backend, &snap, &rig.owner)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);
}
