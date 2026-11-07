//! In-memory lifecycle backend for deterministic tests and CLI exploration.
//!
//! [`SimBackend`] implements the same [`LifecycleService`] contract as the
//! Firecracker backend without touching KVM, cgroups, sockets, or the
//! filesystem. It is explicit: the daemon only selects it with
//! `backend = "sim"`, and it does not provide isolation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_lifecycle::{
    policy::{authorize, Operation},
    LifecycleService, VmMetrics, VmState, VmStatus,
};
use microvm_metrics::VmMetricsRecord;
use microvm_types::{Principal, ResourceSpec, SnapshotId, TenantId, VmId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A VM record held by the simulation backend.
#[derive(Clone, Debug)]
struct SimVm {
    vm_id: VmId,
    owner: TenantId,
    spec: ResourceSpec,
    state: VmState,
    created_at: DateTime<Utc>,
}

/// A snapshot record held by the simulation backend.
#[derive(Clone, Debug)]
struct SimSnapshot {
    owner: TenantId,
    spec: ResourceSpec,
}

/// An in-memory lifecycle service.
#[derive(Debug, Default)]
pub struct SimBackend {
    vms: Mutex<HashMap<VmId, SimVm>>,
    snapshots: Mutex<HashMap<SnapshotId, SimSnapshot>>,
    next_vm: AtomicU64,
    next_snapshot: AtomicU64,
}

impl SimBackend {
    /// Create an empty simulation backend.
    pub fn new() -> Self {
        Self::default()
    }

    fn new_vm_id(&self) -> Result<VmId, MicrovmError> {
        let n = self.next_vm.fetch_add(1, Ordering::SeqCst);
        VmId::new(format!("sim-{n}")).map_err(|e| {
            MicrovmError::new(
                ErrorCode::InvalidId,
                "generated simulation VM id failed validation",
            )
            .with_context("reason", e.reason)
        })
    }

    fn get_vm(&self, vm_id: &VmId) -> Result<SimVm, MicrovmError> {
        self.vms.lock().unwrap().get(vm_id).cloned().ok_or_else(|| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str())
        })
    }

    fn set_state(&self, vm_id: &VmId, state: VmState) {
        if let Some(vm) = self.vms.lock().unwrap().get_mut(vm_id) {
            vm.state = state;
        }
    }
}

#[async_trait]
impl LifecycleService for SimBackend {
    async fn create(&self, spec: ResourceSpec, owner: Principal) -> Result<VmId, MicrovmError> {
        authorize(&owner, owner.tenant_id(), Operation::Create)?;
        let vm_id = self.new_vm_id()?;
        self.vms.lock().unwrap().insert(
            vm_id.clone(),
            SimVm {
                vm_id: vm_id.clone(),
                owner: owner.tenant_id().clone(),
                spec,
                state: VmState::Created,
                created_at: Utc::now(),
            },
        );
        Ok(vm_id)
    }

    async fn start(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        let vm = self.get_vm(vm_id)?;
        authorize(principal, &vm.owner, Operation::Start)?;
        match vm.state {
            VmState::Running => Ok(()),
            VmState::Created | VmState::Configured | VmState::Paused => {
                self.set_state(vm_id, VmState::Running);
                Ok(())
            }
            other => Err(MicrovmError::new(
                ErrorCode::InvalidTransition,
                format!("cannot start VM in {other} state"),
            )
            .with_context("vm_id", vm_id.as_str())
            .with_context("state", other.as_str())),
        }
    }

    async fn stop(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        let vm = self.get_vm(vm_id)?;
        authorize(principal, &vm.owner, Operation::Stop)?;
        match vm.state {
            VmState::Stopped => Ok(()),
            VmState::Running | VmState::Paused => {
                self.set_state(vm_id, VmState::Stopped);
                Ok(())
            }
            other => Err(MicrovmError::new(
                ErrorCode::InvalidTransition,
                format!("cannot stop VM in {other} state"),
            )
            .with_context("vm_id", vm_id.as_str())
            .with_context("state", other.as_str())),
        }
    }

    async fn snapshot(
        &self,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError> {
        let vm = self.get_vm(vm_id)?;
        authorize(principal, &vm.owner, Operation::Snapshot)?;
        if !matches!(vm.state, VmState::Running | VmState::Paused) {
            return Err(MicrovmError::new(
                ErrorCode::InvalidTransition,
                format!("cannot snapshot VM in {} state", vm.state),
            )
            .with_context("vm_id", vm_id.as_str())
            .with_context("state", vm.state.as_str()));
        }
        let n = self.next_snapshot.fetch_add(1, Ordering::SeqCst);
        let snapshot_id = SnapshotId::new(format!("sim-snap-{n}")).map_err(|e| {
            MicrovmError::new(
                ErrorCode::InvalidId,
                "generated simulation snapshot id failed validation",
            )
            .with_context("reason", e.reason)
        })?;
        self.snapshots.lock().unwrap().insert(
            snapshot_id.clone(),
            SimSnapshot {
                owner: vm.owner,
                spec: vm.spec,
            },
        );
        Ok(snapshot_id)
    }

    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        principal: &Principal,
    ) -> Result<VmId, MicrovmError> {
        let snapshot = self
            .snapshots
            .lock()
            .unwrap()
            .get(snapshot_id)
            .cloned()
            .ok_or_else(|| {
                MicrovmError::new(ErrorCode::ArtifactNotFound, "no such snapshot")
                    .with_context("snapshot_id", snapshot_id.as_str())
            })?;
        authorize(principal, &snapshot.owner, Operation::Restore)?;
        let vm_id = self.new_vm_id()?;
        self.vms.lock().unwrap().insert(
            vm_id.clone(),
            SimVm {
                vm_id: vm_id.clone(),
                owner: snapshot.owner,
                spec: snapshot.spec,
                state: VmState::Running,
                created_at: Utc::now(),
            },
        );
        Ok(vm_id)
    }

    async fn status(&self, vm_id: &VmId, principal: &Principal) -> Result<VmStatus, MicrovmError> {
        let vm = self.get_vm(vm_id)?;
        authorize(principal, &vm.owner, Operation::Status)?;
        Ok(VmStatus {
            vm_id: vm.vm_id,
            state: vm.state,
            created_at: vm.created_at,
            resource_spec: vm.spec,
        })
    }

    async fn metrics(
        &self,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<VmMetrics, MicrovmError> {
        let vm = self.get_vm(vm_id)?;
        authorize(principal, &vm.owner, Operation::Metrics)?;
        Ok(VmMetrics {
            record: VmMetricsRecord::not_collected(
                vm.vm_id.clone(),
                vm.state.metrics_phase(),
                Utc::now(),
                0,
            ),
            vm_id: vm.vm_id,
            state: vm.state,
        })
    }

    async fn list(&self, principal: &Principal) -> Result<Vec<VmStatus>, MicrovmError> {
        let vms = self.vms.lock().unwrap();
        let mut statuses: Vec<VmStatus> = vms
            .values()
            .filter(|vm| authorize(principal, &vm.owner, Operation::Status).is_ok())
            .map(|vm| VmStatus {
                vm_id: vm.vm_id.clone(),
                state: vm.state,
                created_at: vm.created_at,
                resource_spec: vm.spec.clone(),
            })
            .collect();
        statuses.sort_by(|a, b| a.vm_id.as_str().cmp(b.vm_id.as_str()));
        Ok(statuses)
    }

    async fn delete(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        let vm = self.get_vm(vm_id)?;
        authorize(principal, &vm.owner, Operation::Delete)?;
        if !matches!(vm.state, VmState::Stopped | VmState::Failed) {
            return Err(MicrovmError::new(
                ErrorCode::InvalidTransition,
                format!("cannot delete VM in {} state", vm.state),
            )
            .with_context("vm_id", vm_id.as_str())
            .with_context("state", vm.state.as_str()));
        }
        self.vms.lock().unwrap().remove(vm_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_types::{NetworkPolicy, Role};

    fn owner() -> Principal {
        Principal::new(TenantId::new("local").unwrap(), Role::Owner)
    }

    fn spec() -> ResourceSpec {
        ResourceSpec::new(1, 128, 512, NetworkPolicy::None).unwrap()
    }

    #[tokio::test]
    async fn lifecycle_runs_in_memory() {
        let backend = SimBackend::new();
        let vm = backend.create(spec(), owner()).await.unwrap();
        backend.start(&vm, &owner()).await.unwrap();
        assert_eq!(
            backend.status(&vm, &owner()).await.unwrap().state,
            VmState::Running
        );
        let snap = backend.snapshot(&vm, &owner()).await.unwrap();
        backend.stop(&vm, &owner()).await.unwrap();
        let restored = backend.restore(&snap, &owner()).await.unwrap();
        assert_eq!(
            backend.status(&restored, &owner()).await.unwrap().state,
            VmState::Running
        );
        let list = backend.list(&owner()).await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn delete_requires_stopped_state() {
        let backend = SimBackend::new();
        let vm = backend.create(spec(), owner()).await.unwrap();
        backend.start(&vm, &owner()).await.unwrap();
        assert!(backend.delete(&vm, &owner()).await.is_err());
        backend.stop(&vm, &owner()).await.unwrap();
        backend.delete(&vm, &owner()).await.unwrap();
        assert!(backend.list(&owner()).await.unwrap().is_empty());
    }
}
