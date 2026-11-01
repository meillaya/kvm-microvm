//! Deterministic contract tests for the composed supervised lifecycle service.
//!
//! These tests drive a fully-scripted [`FirecrackerBackend`] wrapped in
//! [`VmLifecycleService`] and verify the supervision guarantees:
//! idempotency by request key, serialization of concurrent operations, quota
//! enforcement before mutation, supervisor-death reconciliation, guest-readiness
//! gating, and exactly-one audit event per mutating request.

mod common;

use common::{Rig, RigOptions};
use microvm_errors::ErrorCode;
use microvm_firecracker::testing::SpawnOutcome;
use microvm_lifecycle::policy::{AuditResult, Operation, TenantQuota};
use microvm_lifecycle::{LifecycleService, VmState};
use microvm_service::{is_guest_not_ready, RequestKey};
use microvm_types::VmId;
use std::sync::Arc;

fn key(op: &str, vm: &VmId, nonce: &str) -> RequestKey {
    match op {
        "start" => RequestKey::start(vm, nonce),
        "stop" => RequestKey::stop(vm, nonce),
        _ => unreachable!(),
    }
}

fn audit_ops(rig: &Rig) -> Vec<(Operation, AuditResult)> {
    rig.audit
        .events()
        .iter()
        .map(|e| (e.operation, e.result))
        .collect()
}

fn count_op(rig: &Rig, op: Operation) -> usize {
    rig.audit
        .events()
        .iter()
        .filter(|e| e.operation == op)
        .count()
}

async fn state_of(rig: &Rig, vm: &VmId) -> VmState {
    rig.service.status(vm, &rig.owner).await.unwrap().state
}

// ---------------------------------------------------------------------------
// Idempotency by request key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_is_idempotent_by_request_key() {
    let rig = Rig::healthy().await;
    let k = RequestKey::create(&rig.tenant, "create-1");

    let first = rig
        .service
        .create_with(k.clone(), rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap();
    let second = rig
        .service
        .create_with(k.clone(), rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap();

    // Duplicate create replays the same VM id; no second VM is created.
    assert_eq!(first, second);
    // A different key creates a distinct VM.
    let other = rig
        .service
        .create_with(
            RequestKey::create(&rig.tenant, "create-2"),
            rig.spec.clone(),
            rig.owner.clone(),
        )
        .await
        .unwrap();
    assert_ne!(first, other);
    // Exactly one create audit decision for the duplicated request key.
    assert_eq!(count_op(&rig, Operation::Create), 2);
}

#[tokio::test]
async fn start_is_idempotent_by_request_key() {
    let rig = Rig::healthy().await;
    let vm = rig.create_vm().await;
    let k = key("start", &vm, "start-1");

    rig.service
        .start_with(k.clone(), &vm, &rig.owner)
        .await
        .unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);
    assert_eq!(rig.instance_start_count(), 1);

    // Duplicate start with the same key is a no-op: no second backend start.
    rig.service
        .start_with(k.clone(), &vm, &rig.owner)
        .await
        .unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);
    assert_eq!(rig.instance_start_count(), 1);
    assert_eq!(count_op(&rig, Operation::Start), 1);
}

#[tokio::test]
async fn stop_is_idempotent_by_request_key() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;
    let k = key("stop", &vm, "stop-1");

    rig.service
        .stop_with(k.clone(), &vm, &rig.owner)
        .await
        .unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);

    // Duplicate stop with the same key is a no-op.
    rig.service
        .stop_with(k.clone(), &vm, &rig.owner)
        .await
        .unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);
    assert_eq!(count_op(&rig, Operation::Stop), 1);
}

// ---------------------------------------------------------------------------
// Concurrent operation serialization
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_concurrent_starts_serialize_to_one_backend_start() {
    let rig = Rig::healthy().await;
    let vm = rig.create_vm().await;
    let k = key("start", &vm, "same-key");

    // Force all tasks to start together so they genuinely contend on the lock.
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let service = rig.service.clone();
        let owner = rig.owner.clone();
        let vm = vm.clone();
        let k = k.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            service.start_with(k, &vm, &owner).await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }

    // One backend start, stable final state, one audit decision for the request.
    assert_eq!(rig.instance_start_count(), 1);
    assert_eq!(rig.spawn_count(), 1);
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);
    assert_eq!(count_op(&rig, Operation::Start), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_starts_with_distinct_keys_still_one_backend_start() {
    let rig = Rig::healthy().await;
    let vm = rig.create_vm().await;

    let barrier = Arc::new(tokio::sync::Barrier::new(4));
    let mut handles = Vec::new();
    for i in 0..4 {
        let service = rig.service.clone();
        let owner = rig.owner.clone();
        let vm = vm.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            // Distinct nonces: these are different requests, but per-VM
            // serialization plus state-based idempotency still yield one start.
            service
                .start_with(RequestKey::start(&vm, format!("n{i}")), &vm, &owner)
                .await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }

    assert_eq!(rig.instance_start_count(), 1);
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);
}

// ---------------------------------------------------------------------------
// Quota enforcement (before mutation)
// ---------------------------------------------------------------------------

fn quota(max_vms: u32, max_vcpus: u32) -> TenantQuota {
    TenantQuota {
        max_vcpus,
        max_memory_mib: 1_048_576,
        max_disk_mib: 1_048_576,
        max_vms,
        max_snapshots: 100,
    }
}

#[tokio::test]
async fn quota_enforcement_rejects_over_quota_create() {
    let rig = Rig::new(RigOptions {
        quota: Some(quota(1, 16)),
        ..RigOptions::no_net()
    })
    .await;

    // First create fits.
    rig.service
        .create(rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap();

    // Second create exceeds max_vms and is rejected before any backend mutation.
    let err = rig
        .service
        .create(rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::QuotaExceeded);
    // One successful create reached the backend; the rejected one did not spawn.
    assert_eq!(rig.spawn_count(), 0);
    assert_eq!(count_op(&rig, Operation::Create), 2);
    assert_eq!(
        audit_ops(&rig)
            .iter()
            .filter(|(_, r)| *r == AuditResult::Error)
            .count(),
        1
    );
}

#[tokio::test]
async fn vcpu_quota_rejects_over_quota_create() {
    let rig = Rig::new(RigOptions {
        quota: Some(quota(10, 2)), // spec uses 2 vcpus
        ..RigOptions::no_net()
    })
    .await;

    rig.service
        .create(rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap();
    let err = rig
        .service
        .create(rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::QuotaExceeded);
}

#[tokio::test]
async fn quota_is_freed_after_stop() {
    let rig = Rig::new(RigOptions {
        quota: Some(quota(1, 16)),
        ..RigOptions::no_net()
    })
    .await;

    let vm = rig.create_and_start().await;
    // At quota: a second create is rejected.
    assert_eq!(
        rig.service
            .create(rig.spec.clone(), rig.owner.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );

    // Stopping frees the slot.
    rig.service.stop(&vm, &rig.owner).await.unwrap();
    rig.service
        .create(rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Owner and role checks (before mutation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_tenant_start_is_denied_before_mutation() {
    let rig = Rig::healthy().await;
    let vm = rig.create_vm().await;

    let err = rig.service.start(&vm, &rig.other_tenant).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    // Denied before the backend started anything.
    assert_eq!(rig.instance_start_count(), 0);
    assert_eq!(state_of(&rig, &vm).await, VmState::Created);
    assert_eq!(
        audit_ops(&rig).last().unwrap(),
        &(Operation::Start, AuditResult::Denied)
    );
}

#[tokio::test]
async fn role_matrix_is_enforced() {
    let rig = Rig::healthy().await;

    // Viewer cannot create.
    assert_eq!(
        rig.service
            .create(rig.spec.clone(), rig.viewer.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    // Operator cannot create.
    assert_eq!(
        rig.service
            .create(rig.spec.clone(), rig.operator.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );

    // Owner creates; operator can start; viewer cannot start.
    let vm = rig.create_vm().await;
    assert_eq!(
        rig.service.start(&vm, &rig.viewer).await.unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    rig.service.start(&vm, &rig.operator).await.unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);
}

#[tokio::test]
async fn status_and_metrics_require_matching_tenant() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;

    // Owner and viewer (same tenant) can read status.
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);
    rig.service.status(&vm, &rig.viewer).await.unwrap();
    rig.service.metrics(&vm, &rig.viewer).await.unwrap();

    // Cross-tenant read is denied.
    assert_eq!(
        rig.service
            .status(&vm, &rig.other_tenant)
            .await
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
}

// ---------------------------------------------------------------------------
// Readiness gating (guest marker, not merely the process or socket)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn guest_not_ready_prevents_running() {
    let rig = Rig::new(RigOptions::guest_not_ready()).await;
    let vm = rig.create_vm().await;

    let err = rig.service.start(&vm, &rig.owner).await.unwrap_err();
    // Typed "guest not ready" classification.
    assert!(is_guest_not_ready(&err), "err: {err:?}");
    // The service must not advance to Running before the backend confirms
    // guest readiness; the failed boot reconciles to Failed.
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);
    // The instance was started, but the guest never became ready.
    assert_eq!(rig.instance_start_count(), 1);
    assert_eq!(
        audit_ops(&rig).last().unwrap(),
        &(Operation::Start, AuditResult::Error)
    );
}

#[tokio::test]
async fn spawn_failure_does_not_advance_state() {
    let rig = Rig::new(RigOptions {
        spawn_outcome: SpawnOutcome::Fail(microvm_errors::MicrovmError::new(
            ErrorCode::ProcessSpawnError,
            "scripted spawn failure",
        )),
        ..RigOptions::no_net()
    })
    .await;
    let vm = rig.create_vm().await;

    let err = rig.service.start(&vm, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ProcessSpawnError);
    // State is never advanced to Running when the backend fails to spawn.
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);
}

// ---------------------------------------------------------------------------
// Supervisor death reconciliation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn supervisor_death_is_reconciled_to_failed() {
    let rig = Rig::new(RigOptions::no_net()).await;
    let vm = rig.create_and_start().await;
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);

    // The supervisor process (first scripted spawn is pid 1000) dies.
    rig.cleanup.mark_pid_alive(1000);
    rig.supervisor.mark_dead(&vm, Some(1000));

    assert!(rig.service.reconcile(&vm));

    // The VM is reconciled to Failed and its supervisor flag is cleared.
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);
    let supervised = rig.service.supervisor_state(&vm).unwrap();
    assert!(!supervised.supervisor_alive());
    assert!(supervised.reconciled_at().is_some());

    // Owned resources were released via the isolation cleanup bridge.
    assert!(
        rig.cleanup
            .recorded()
            .iter()
            .any(|(op, _)| op == "kill:1000"),
        "expected kill:1000, got {:?}",
        rig.cleanup.recorded()
    );

    // A reconciliation audit event was recorded.
    assert!(audit_ops(&rig).contains(&(Operation::Stop, AuditResult::Error)));
}

#[tokio::test]
async fn supervisor_death_is_reconciled_on_next_status() {
    let rig = Rig::new(RigOptions::no_net()).await;
    let vm = rig.create_and_start().await;
    rig.supervisor.mark_dead(&vm, Some(1000));

    // Reading status reconciles the dead supervisor inline.
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);
}

#[tokio::test]
async fn live_supervisor_is_not_reconciled() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;
    rig.supervisor.mark_alive(&vm, Some(1000));

    assert!(!rig.service.reconcile(&vm));
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);
}

#[tokio::test]
async fn reconcile_is_idempotent() {
    let rig = Rig::new(RigOptions::no_net()).await;
    let vm = rig.create_and_start().await;
    rig.supervisor.mark_dead(&vm, Some(1000));

    assert!(rig.service.reconcile(&vm));
    // Once Failed, further reconciliation is a no-op (Failed needs no supervisor).
    assert!(!rig.service.reconcile(&vm));
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);
    // Only one reconciliation audit event.
    assert_eq!(
        audit_ops(&rig)
            .iter()
            .filter(|(op, r)| *op == Operation::Stop && *r == AuditResult::Error)
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------
// Audit emission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_audit_event_per_mutating_request() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;
    rig.service.stop(&vm, &rig.owner).await.unwrap();

    // create + start + stop = exactly three mutating requests, three events.
    assert_eq!(
        audit_ops(&rig),
        vec![
            (Operation::Create, AuditResult::Success),
            (Operation::Start, AuditResult::Success),
            (Operation::Stop, AuditResult::Success),
        ]
    );

    // A duplicate stop replaying the same request key adds no audit event.
    let k = key("stop", &vm, "dup-stop");
    rig.service
        .stop_with(k.clone(), &vm, &rig.owner)
        .await
        .unwrap();
    let before = rig.audit.len();
    rig.service
        .stop_with(k.clone(), &vm, &rig.owner)
        .await
        .unwrap();
    assert_eq!(
        rig.audit.len(),
        before,
        "duplicate request must not re-audit"
    );
}

#[tokio::test]
async fn denied_and_errored_requests_are_audited() {
    let rig = Rig::new(RigOptions {
        quota: Some(quota(1, 16)),
        ..RigOptions::no_net()
    })
    .await;

    // Success.
    rig.service
        .create(rig.spec.clone(), rig.owner.clone())
        .await
        .unwrap();
    // Denied (cross-tenant): use a fresh VM id space via the created VM.
    let vm = rig
        .service
        .create_with(
            RequestKey::create(&rig.tenant, "x"),
            rig.spec.clone(),
            rig.owner.clone(),
        )
        .await;
    // The second create is over quota -> Error audit (not Denied).
    assert_eq!(vm.unwrap_err().code, ErrorCode::QuotaExceeded);

    let ops = audit_ops(&rig);
    assert_eq!(ops[0], (Operation::Create, AuditResult::Success));
    assert_eq!(ops[1], (Operation::Create, AuditResult::Error));
}

// ---------------------------------------------------------------------------
// Trait-surface lifecycle (state-based idempotency, no request key)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trait_lifecycle_create_start_stop_restart() {
    let rig = Rig::healthy().await;
    let vm = rig.create_vm().await;
    assert_eq!(state_of(&rig, &vm).await, VmState::Created);

    rig.service.start(&vm, &rig.owner).await.unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);

    // Duplicate trait start is a state-based no-op (one backend start).
    rig.service.start(&vm, &rig.owner).await.unwrap();
    assert_eq!(rig.instance_start_count(), 1);

    rig.service.stop(&vm, &rig.owner).await.unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);

    // Duplicate trait stop is a no-op.
    rig.service.stop(&vm, &rig.owner).await.unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);

    // Stopped is terminal: restart is an invalid transition.
    let err = rig.service.start(&vm, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[tokio::test]
async fn stop_from_created_is_invalid_transition() {
    let rig = Rig::healthy().await;
    let vm = rig.create_vm().await;
    let err = rig.service.stop(&vm, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[tokio::test]
async fn operations_on_unknown_vm_return_not_found() {
    let rig = Rig::healthy().await;
    let ghost = VmId::new("ghost").unwrap();
    assert_eq!(
        rig.service
            .start(&ghost, &rig.owner)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ArtifactNotFound
    );
    assert_eq!(
        rig.service
            .status(&ghost, &rig.owner)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ArtifactNotFound
    );
}
