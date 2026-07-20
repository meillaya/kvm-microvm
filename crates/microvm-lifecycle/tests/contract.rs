//! Contract suite: a mock backend implementing [`LifecycleService`] must
//! pass all tests here, proving the trait is implementable and the state
//! machine is correctly integrated.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_lifecycle::{transition, LifecycleService, VmMetrics, VmState, VmStatus};
use microvm_metrics::VmMetricsRecord;
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, SnapshotId, TenantId, VmId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

struct VmRecord {
    state: VmState,
    spec: ResourceSpec,
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    owner: Principal,
}

struct MockBackend {
    vms: Mutex<HashMap<String, VmRecord>>,
    /// snapshot_id → source vm_id
    snapshots: Mutex<HashMap<String, String>>,
    next_id: AtomicU64,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            vms: Mutex::new(HashMap::new()),
            snapshots: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn alloc_id(&self, prefix: &str) -> String {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("{}-{:04}", prefix, n)
    }

    /// Transition a VM's state, returning an error if the transition is
    /// illegal.
    fn transition_vm(&self, vm_id: &str, to: VmState) -> Result<(), MicrovmError> {
        let mut vms = self.vms.lock().unwrap();
        let record = vms.get_mut(vm_id).ok_or_else(|| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "vm not found")
                .with_context("vm_id", vm_id)
        })?;
        let new_state = transition(record.state, to)?;
        record.state = new_state;
        Ok(())
    }
}

#[async_trait]
impl LifecycleService for MockBackend {
    async fn create(&self, spec: ResourceSpec, owner: Principal) -> Result<VmId, MicrovmError> {
        let raw_id = self.alloc_id("vm");
        let vm_id = VmId::new(&raw_id)
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.to_string()))?;
        let mut vms = self.vms.lock().unwrap();
        vms.insert(
            raw_id,
            VmRecord {
                state: VmState::Created,
                spec,
                created_at: Utc::now(),
                owner,
            },
        );
        Ok(vm_id)
    }

    async fn start(&self, vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        let key = vm_id.as_str().to_string();
        // Determine current state to pick the right transition path.
        let current = {
            let vms = self.vms.lock().unwrap();
            vms.get(&key)
                .ok_or_else(|| {
                    MicrovmError::new(ErrorCode::ArtifactNotFound, "vm not found")
                        .with_context("vm_id", key.as_str())
                })?
                .state
        };
        match current {
            VmState::Created => {
                self.transition_vm(&key, VmState::Configured)?;
                self.transition_vm(&key, VmState::Running)?;
            }
            VmState::Paused => {
                self.transition_vm(&key, VmState::Running)?;
            }
            _ => {
                // Attempt the transition anyway so the error is consistent.
                self.transition_vm(&key, VmState::Running)?;
            }
        }
        Ok(())
    }

    async fn stop(&self, vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        self.transition_vm(vm_id.as_str(), VmState::Stopped)
    }

    async fn snapshot(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError> {
        let key = vm_id.as_str().to_string();
        // Running|Paused → Snapshotting → Paused
        self.transition_vm(&key, VmState::Snapshotting)?;

        let raw_snap = self.alloc_id("snap");
        let snap_id = SnapshotId::new(&raw_snap)
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.to_string()))?;
        {
            let mut snaps = self.snapshots.lock().unwrap();
            snaps.insert(raw_snap, key.clone());
        }

        self.transition_vm(&key, VmState::Paused)?;
        Ok(snap_id)
    }

    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        _principal: &Principal,
    ) -> Result<VmId, MicrovmError> {
        let source_vm = {
            let snaps = self.snapshots.lock().unwrap();
            snaps.get(snapshot_id.as_str()).cloned().ok_or_else(|| {
                MicrovmError::new(ErrorCode::ArtifactNotFound, "snapshot not found")
                    .with_context("snapshot_id", snapshot_id.as_str())
            })?
        };

        // Clone the source VM's spec.
        let spec = {
            let vms = self.vms.lock().unwrap();
            vms.get(&source_vm)
                .ok_or_else(|| MicrovmError::new(ErrorCode::InternalError, "source vm missing"))?
                .spec
                .clone()
        };

        // Create a new VM in Restoring state, then transition to Running.
        let raw_id = self.alloc_id("vm");
        let vm_id = VmId::new(&raw_id)
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.to_string()))?;
        {
            let mut vms = self.vms.lock().unwrap();
            vms.insert(
                raw_id.clone(),
                VmRecord {
                    state: VmState::Restoring,
                    spec,
                    created_at: Utc::now(),
                    owner: Principal::new(TenantId::new("restore-tenant").unwrap(), Role::Operator),
                },
            );
        }
        self.transition_vm(&raw_id, VmState::Running)?;
        Ok(vm_id)
    }

    async fn status(&self, vm_id: &VmId, _principal: &Principal) -> Result<VmStatus, MicrovmError> {
        let vms = self.vms.lock().unwrap();
        let record = vms.get(vm_id.as_str()).ok_or_else(|| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "vm not found")
                .with_context("vm_id", vm_id.as_str())
        })?;
        Ok(VmStatus {
            vm_id: vm_id.clone(),
            state: record.state,
            created_at: record.created_at,
            resource_spec: record.spec.clone(),
        })
    }

    async fn metrics(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<VmMetrics, MicrovmError> {
        let vms = self.vms.lock().unwrap();
        let record = vms.get(vm_id.as_str()).ok_or_else(|| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "vm not found")
                .with_context("vm_id", vm_id.as_str())
        })?;
        Ok(VmMetrics {
            record: VmMetricsRecord::not_collected(
                vm_id.clone(),
                record.state.metrics_phase(),
                Utc::now(),
                0,
            ),
            vm_id: vm_id.clone(),
            state: record.state,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_principal() -> Principal {
    Principal::new(TenantId::new("tenant-test").unwrap(), Role::Operator)
}

fn test_spec() -> ResourceSpec {
    ResourceSpec::new(2, 512, 1024, NetworkPolicy::NatOnly).unwrap()
}

// ---------------------------------------------------------------------------
// Contract suite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_returns_valid_vm_id() {
    let backend = MockBackend::new();
    let vm_id = backend.create(test_spec(), test_principal()).await.unwrap();
    assert!(!vm_id.as_str().is_empty());
}

#[tokio::test]
async fn status_after_create_shows_created() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    let status = backend.status(&vm_id, &p).await.unwrap();
    assert_eq!(status.state, VmState::Created);
    assert_eq!(status.vm_id, vm_id);
}

#[tokio::test]
async fn start_transitions_to_running() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();
    let status = backend.status(&vm_id, &p).await.unwrap();
    assert_eq!(status.state, VmState::Running);
}

#[tokio::test]
async fn stop_from_running() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();
    backend.stop(&vm_id, &p).await.unwrap();
    let status = backend.status(&vm_id, &p).await.unwrap();
    assert_eq!(status.state, VmState::Stopped);
}

#[tokio::test]
async fn pause_and_resume() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();

    // Pause via snapshot (Running → Snapshotting → Paused).
    let _snap = backend.snapshot(&vm_id, &p).await.unwrap();
    let status = backend.status(&vm_id, &p).await.unwrap();
    assert_eq!(status.state, VmState::Paused);

    // Resume.
    backend.start(&vm_id, &p).await.unwrap();
    let status = backend.status(&vm_id, &p).await.unwrap();
    assert_eq!(status.state, VmState::Running);
}

#[tokio::test]
async fn snapshot_from_running_returns_snapshot_id() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();
    let snap_id = backend.snapshot(&vm_id, &p).await.unwrap();
    assert!(!snap_id.as_str().is_empty());
}

#[tokio::test]
async fn snapshot_from_created_returns_invalid_transition() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    let err = backend.snapshot(&vm_id, &p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[tokio::test]
async fn restore_creates_new_running_vm() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();
    let snap_id = backend.snapshot(&vm_id, &p).await.unwrap();

    let restored_id = backend.restore(&snap_id, &p).await.unwrap();
    assert_ne!(restored_id, vm_id);

    let status = backend.status(&restored_id, &p).await.unwrap();
    assert_eq!(status.state, VmState::Running);
}

#[tokio::test]
async fn restore_from_missing_snapshot_fails() {
    let backend = MockBackend::new();
    let p = test_principal();
    let snap_id = SnapshotId::new("snap-nonexistent").unwrap();
    let err = backend.restore(&snap_id, &p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);
}

#[tokio::test]
async fn status_for_missing_vm_fails() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = VmId::new("vm-ghost").unwrap();
    let err = backend.status(&vm_id, &p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);
}

#[tokio::test]
async fn metrics_returns_current_state() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();
    let m = backend.metrics(&vm_id, &p).await.unwrap();
    assert_eq!(m.vm_id, vm_id);
    assert_eq!(m.state, VmState::Running);
}

#[tokio::test]
async fn metrics_for_missing_vm_fails() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = VmId::new("vm-ghost").unwrap();
    let err = backend.metrics(&vm_id, &p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);
}

#[tokio::test]
async fn stop_from_created_is_illegal() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    let err = backend.stop(&vm_id, &p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[tokio::test]
async fn double_stop_is_illegal() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();
    backend.stop(&vm_id, &p).await.unwrap();
    let err = backend.stop(&vm_id, &p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[tokio::test]
async fn start_stopped_vm_is_illegal() {
    let backend = MockBackend::new();
    let p = test_principal();
    let vm_id = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm_id, &p).await.unwrap();
    backend.stop(&vm_id, &p).await.unwrap();
    let err = backend.start(&vm_id, &p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[tokio::test]
async fn status_preserves_resource_spec() {
    let backend = MockBackend::new();
    let p = test_principal();
    let spec = ResourceSpec::new(4, 2048, 4096, NetworkPolicy::None).unwrap();
    let vm_id = backend.create(spec.clone(), p.clone()).await.unwrap();
    let status = backend.status(&vm_id, &p).await.unwrap();
    assert_eq!(status.resource_spec, spec);
}

#[tokio::test]
async fn full_lifecycle_create_start_snapshot_restore_stop() {
    let backend = MockBackend::new();
    let p = test_principal();

    // Create → Running
    let vm1 = backend.create(test_spec(), p.clone()).await.unwrap();
    backend.start(&vm1, &p).await.unwrap();
    assert_eq!(
        backend.status(&vm1, &p).await.unwrap().state,
        VmState::Running
    );

    // Snapshot → Paused
    let snap = backend.snapshot(&vm1, &p).await.unwrap();
    assert_eq!(
        backend.status(&vm1, &p).await.unwrap().state,
        VmState::Paused
    );

    // Restore → new Running VM
    let vm2 = backend.restore(&snap, &p).await.unwrap();
    assert_eq!(
        backend.status(&vm2, &p).await.unwrap().state,
        VmState::Running
    );

    // Stop both
    backend.stop(&vm1, &p).await.unwrap();
    backend.stop(&vm2, &p).await.unwrap();
    assert_eq!(
        backend.status(&vm1, &p).await.unwrap().state,
        VmState::Stopped
    );
    assert_eq!(
        backend.status(&vm2, &p).await.unwrap().state,
        VmState::Stopped
    );
}
