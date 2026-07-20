//! Supervisor health tracking and death reconciliation.
//!
//! The lifecycle service is the *supervisor* of record for every VM: it mirrors
//! the backend's lifecycle state and adds supervisor-health bookkeeping. Each
//! VM's authoritative, reconciled state lives in a [`SupervisorState`]. A
//! [`SupervisorProbe`] reports whether a VM's supervisor process is still
//! alive; when a VM that should be running has a dead supervisor, the service
//! reconciles it to [`VmState::Failed`] and releases its resources.

use chrono::{DateTime, Utc};
use microvm_lifecycle::VmState;
use microvm_types::{ResourceSpec, TenantId, VmId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Per-VM supervised state held by the lifecycle service.
///
/// This is the service's authoritative, reconciled view of a VM. It carries the
/// ownership and resource information needed for quota accounting and owner
/// checks, the reconciled lifecycle state, and supervisor-health bookkeeping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorState {
    vm_id: VmId,
    owner: TenantId,
    spec: ResourceSpec,
    created_at: DateTime<Utc>,
    state: VmState,
    supervisor_alive: bool,
    reconciled_at: Option<DateTime<Utc>>,
}

impl SupervisorState {
    /// Create a fresh supervised record in [`VmState::Created`].
    pub(crate) fn new(
        vm_id: VmId,
        owner: TenantId,
        spec: ResourceSpec,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            vm_id,
            owner,
            spec,
            created_at,
            state: VmState::Created,
            supervisor_alive: false,
            reconciled_at: None,
        }
    }

    /// The VM this record supervises.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }

    /// The tenant that owns the VM.
    pub fn owner(&self) -> &TenantId {
        &self.owner
    }

    /// The VM's resource allocation.
    pub fn spec(&self) -> &ResourceSpec {
        &self.spec
    }

    /// When the VM record was created.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// The reconciled lifecycle state.
    pub fn state(&self) -> VmState {
        self.state
    }

    /// Whether the supervisor process was alive at the last reconciliation.
    pub fn supervisor_alive(&self) -> bool {
        self.supervisor_alive
    }

    /// When a supervisor death was last reconciled, if ever.
    pub fn reconciled_at(&self) -> Option<DateTime<Utc>> {
        self.reconciled_at
    }

    /// Whether this state requires a live supervisor process.
    ///
    /// Only running/paused VMs depend on a live supervisor; a dead supervisor
    /// in any other state is not an anomaly.
    pub(crate) fn needs_live_supervisor(&self) -> bool {
        matches!(self.state, VmState::Running | VmState::Paused)
    }

    /// Whether this VM currently holds resources that count toward quota.
    ///
    /// Stopped and failed VMs have released their resources and no longer
    /// count.
    pub(crate) fn counts_toward_quota(&self) -> bool {
        !matches!(self.state, VmState::Stopped | VmState::Failed)
    }

    pub(crate) fn set_state(&mut self, state: VmState) {
        self.state = state;
    }

    pub(crate) fn set_supervisor_alive(&mut self, alive: bool) {
        self.supervisor_alive = alive;
    }

    pub(crate) fn set_reconciled_at(&mut self, at: Option<DateTime<Utc>>) {
        self.reconciled_at = at;
    }
}

/// A point-in-time health reading for a VM's supervisor process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupervisorHealth {
    /// Whether the supervisor process is currently alive.
    pub alive: bool,
    /// The supervisor process PID, if known.
    pub pid: Option<u32>,
}

impl SupervisorHealth {
    /// A healthy reading with an optional PID.
    pub fn alive(pid: Option<u32>) -> Self {
        Self { alive: true, pid }
    }

    /// A dead reading with the last-known PID.
    pub fn dead(pid: Option<u32>) -> Self {
        Self { alive: false, pid }
    }
}

/// Detects whether a VM's supervisor process is alive.
///
/// Production implementations wrap the runtime's process handle (for example,
/// the Firecracker launcher's PID liveness check). Tests use
/// [`ScriptedSupervisorProbe`] to flip a VM between alive and dead
/// deterministically.
pub trait SupervisorProbe: Send + Sync {
    /// Read the current supervisor health for a VM.
    fn health(&self, vm_id: &VmId) -> SupervisorHealth;
}

/// A scripted [`SupervisorProbe`] for deterministic tests.
///
/// VMs default to alive unless explicitly marked dead, so ordinary operations
/// do not spuriously reconcile.
#[derive(Debug)]
pub struct ScriptedSupervisorProbe {
    states: Mutex<HashMap<VmId, SupervisorHealth>>,
    default_alive: bool,
}

impl ScriptedSupervisorProbe {
    /// Create a probe whose unknown VMs default to alive.
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            default_alive: true,
        }
    }

    /// Create a probe whose unknown VMs default to dead.
    pub fn default_dead() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            default_alive: false,
        }
    }

    /// Mark a VM's supervisor as alive with an optional PID.
    pub fn mark_alive(&self, vm_id: &VmId, pid: Option<u32>) {
        self.states
            .lock()
            .unwrap()
            .insert(vm_id.clone(), SupervisorHealth::alive(pid));
    }

    /// Mark a VM's supervisor as dead with the last-known PID.
    pub fn mark_dead(&self, vm_id: &VmId, pid: Option<u32>) {
        self.states
            .lock()
            .unwrap()
            .insert(vm_id.clone(), SupervisorHealth::dead(pid));
    }
}

impl Default for ScriptedSupervisorProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl SupervisorProbe for ScriptedSupervisorProbe {
    fn health(&self, vm_id: &VmId) -> SupervisorHealth {
        self.states
            .lock()
            .unwrap()
            .get(vm_id)
            .copied()
            .unwrap_or(SupervisorHealth {
                alive: self.default_alive,
                pid: None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_types::NetworkPolicy;

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).unwrap()
    }

    fn spec() -> ResourceSpec {
        ResourceSpec::new(2, 512, 1024, NetworkPolicy::None).unwrap()
    }

    fn state_in(state: VmState) -> SupervisorState {
        let mut s = SupervisorState::new(vm("vm-1"), tenant("t1"), spec(), Utc::now());
        s.set_state(state);
        s
    }

    #[test]
    fn fresh_record_is_created_and_not_alive() {
        let s = SupervisorState::new(vm("vm-1"), tenant("t1"), spec(), Utc::now());
        assert_eq!(s.state(), VmState::Created);
        assert!(!s.supervisor_alive());
        assert_eq!(s.reconciled_at(), None);
    }

    #[test]
    fn only_running_and_paused_need_a_live_supervisor() {
        assert!(state_in(VmState::Running).needs_live_supervisor());
        assert!(state_in(VmState::Paused).needs_live_supervisor());
        for state in [
            VmState::Created,
            VmState::Configured,
            VmState::Stopped,
            VmState::Failed,
            VmState::Snapshotting,
            VmState::Restoring,
        ] {
            assert!(!state_in(state).needs_live_supervisor(), "{state:?}");
        }
    }

    #[test]
    fn stopped_and_failed_do_not_count_toward_quota() {
        assert!(state_in(VmState::Running).counts_toward_quota());
        assert!(state_in(VmState::Created).counts_toward_quota());
        assert!(!state_in(VmState::Stopped).counts_toward_quota());
        assert!(!state_in(VmState::Failed).counts_toward_quota());
    }

    #[test]
    fn supervisor_state_serde_roundtrip() {
        let mut s = state_in(VmState::Running);
        s.set_supervisor_alive(true);
        s.set_reconciled_at(Some(Utc::now()));
        let json = serde_json::to_string(&s).unwrap();
        let back: SupervisorState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn scripted_probe_defaults_to_alive() {
        let probe = ScriptedSupervisorProbe::new();
        assert!(probe.health(&vm("vm-x")).alive);
    }

    #[test]
    fn scripted_probe_mark_dead_and_alive() {
        let probe = ScriptedSupervisorProbe::new();
        let id = vm("vm-1");
        probe.mark_dead(&id, Some(1000));
        assert_eq!(probe.health(&id), SupervisorHealth::dead(Some(1000)));
        probe.mark_alive(&id, Some(1000));
        assert_eq!(probe.health(&id), SupervisorHealth::alive(Some(1000)));
    }

    #[test]
    fn scripted_probe_default_dead() {
        let probe = ScriptedSupervisorProbe::default_dead();
        assert!(!probe.health(&vm("vm-x")).alive);
    }

    #[test]
    fn probe_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ScriptedSupervisorProbe>();
        assert_send_sync::<Box<dyn SupervisorProbe>>();
    }
}
