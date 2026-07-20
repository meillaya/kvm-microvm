//! Composed supervised VM lifecycle service for the kvm-microvm-orchestrator
//! platform.
//!
//! [`VmLifecycleService`] is the transport-neutral service that composes the
//! platform's building blocks behind the
//! [`LifecycleService`](microvm_lifecycle::LifecycleService) contract:
//!
//! - **typed state + policy** ([`microvm_lifecycle`]) — the VM state machine,
//!   tenant authorization, quota enforcement, and structured audit events;
//! - **Firecracker backend** ([`microvm_firecracker`]) — the runtime that
//!   spawns, configures, starts, and stops the VM, gating `Running` on a
//!   guest-readiness probe rather than mere process/socket readiness;
//! - **isolation cleanup** ([`microvm_isolation`]) — idempotent teardown of
//!   cgroup/netns/socket/chroot resources during supervisor-death
//!   reconciliation.
//!
//! On top of the composed backend the service adds the *supervision* layer the
//! raw backend does not provide:
//!
//! - **Idempotency by request key** — duplicate create/start/stop requests
//!   carrying the same [`RequestKey`] are no-ops that replay the cached outcome
//!   (one backend mutation, one audit decision per request).
//! - **Per-VM serialization** — concurrent operations on the same VM are
//!   serialized on a per-VM lock so duplicate concurrent operations cannot both
//!   mutate the backend.
//! - **Owner + quota checks before mutation** — authorization and quota are
//!   verified before any backend call, so over-quota or cross-tenant requests
//!   are rejected without side effects.
//! - **Supervisor-death reconciliation** — a [`SupervisorProbe`] detects an
//!   unexpectedly-dead supervisor process; the VM is driven to `Failed`, an
//!   audit event is recorded, and its resources are released.
//! - **Audit** — every mutating request produces exactly one
//!   [`AuditEvent`](microvm_lifecycle::policy::AuditEvent).
//!
//! The service is the single audit source: construct the inner backend
//! *without* an audit log and attach the log here.
//!
//! # Determinism
//! All supervision logic (idempotency, serialization, quota, reconciliation,
//! audit) is exercised against a fully-scripted [`FirecrackerBackend`] in the
//! `tests/service_contract.rs` suite — no KVM, root, or real Firecracker binary
//! is required.

pub mod cleanup;
pub mod request;
pub mod supervisor;

pub use cleanup::{IsolationCleanup, ReconciliationCleanup};
pub use request::RequestKey;
pub use supervisor::{ScriptedSupervisorProbe, SupervisorHealth, SupervisorProbe, SupervisorState};

use async_trait::async_trait;
use chrono::Utc;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_firecracker::FirecrackerBackend;
use microvm_lifecycle::policy::{
    authorize, check_quota, AuditEvent, AuditLog, AuditResult, InMemoryAuditLog, Operation,
    ResourceType, TenantQuota, TenantUsage,
};
use microvm_lifecycle::{LifecycleService, VmMetrics, VmState, VmStatus};
use microvm_types::{Principal, ResourceSpec, Role, SnapshotId, TenantId, VmId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

use crate::request::{replay_create, replay_unit, StoredOutcome};

/// Default per-tenant quota applied when no override is configured.
pub const DEFAULT_QUOTA: TenantQuota = TenantQuota {
    max_vcpus: 64,
    max_memory_mib: 65_536,
    max_disk_mib: 1_048_576,
    max_vms: 64,
    max_snapshots: 256,
};

fn vm_scope(vm_id: &VmId) -> String {
    format!("vm:{}", vm_id.as_str())
}

fn create_scope(tenant: &TenantId) -> String {
    format!("create:{}", tenant.as_str())
}

fn not_found(vm_id: &VmId) -> MicrovmError {
    MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
        .with_context("vm_id", vm_id.as_str())
}

/// Map an operation outcome to an audit result: permission failures are
/// `Denied`, other failures are `Error`, success is `Success`.
fn audit_result<T>(outcome: &Result<T, MicrovmError>) -> AuditResult {
    match outcome {
        Ok(_) => AuditResult::Success,
        Err(e) if e.code == ErrorCode::PermissionDenied => AuditResult::Denied,
        Err(_) => AuditResult::Error,
    }
}

/// Whether a start failure indicates the guest never signalled readiness.
///
/// The composed Firecracker backend gates `Running` on a guest-readiness probe
/// (a guest marker / health service), not merely on process or socket
/// readiness. When the guest never becomes ready, the boot fails with
/// `phase=guest_ready` context; this classifier lets callers treat that case as
/// a typed "guest not ready" condition.
pub fn is_guest_not_ready(err: &MicrovmError) -> bool {
    err.context.get("phase").map(String::as_str) == Some("guest_ready")
}

/// The composed, supervised VM lifecycle service.
///
/// Construct via [`VmLifecycleService::builder`]. The inner backend (a
/// [`FirecrackerBackend`] in production) performs the actual VM operations; the
/// service wraps it with idempotency, per-VM serialization, owner/quota policy,
/// supervisor reconciliation, and audit.
pub struct VmLifecycleService {
    inner: Arc<dyn LifecycleService>,
    probe: Arc<dyn SupervisorProbe>,
    audit: Arc<dyn AuditLog>,
    cleanup: Option<Arc<dyn ReconciliationCleanup>>,
    vms: Mutex<HashMap<VmId, SupervisorState>>,
    completed: Mutex<HashMap<RequestKey, StoredOutcome>>,
    locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    quotas: Mutex<HashMap<TenantId, TenantQuota>>,
    default_quota: TenantQuota,
}

/// Builder for [`VmLifecycleService`].
#[derive(Default)]
pub struct ServiceBuilder {
    inner: Option<Arc<dyn LifecycleService>>,
    probe: Option<Arc<dyn SupervisorProbe>>,
    audit: Option<Arc<dyn AuditLog>>,
    cleanup: Option<Arc<dyn ReconciliationCleanup>>,
    default_quota: Option<TenantQuota>,
    quotas: HashMap<TenantId, TenantQuota>,
}

impl ServiceBuilder {
    /// Set the inner backend as a trait object.
    pub fn inner(mut self, inner: Arc<dyn LifecycleService>) -> Self {
        self.inner = Some(inner);
        self
    }

    /// Set the inner backend to a concrete [`FirecrackerBackend`].
    pub fn firecracker(mut self, backend: Arc<FirecrackerBackend>) -> Self {
        self.inner = Some(backend);
        self
    }

    /// Set the supervisor liveness probe.
    pub fn supervisor_probe(mut self, probe: Arc<dyn SupervisorProbe>) -> Self {
        self.probe = Some(probe);
        self
    }

    /// Attach the audit log (the service is the single audit source).
    pub fn audit_log(mut self, audit: Arc<dyn AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Attach the reconciliation cleanup (microvm-isolation bridge).
    pub fn cleanup(mut self, cleanup: Arc<dyn ReconciliationCleanup>) -> Self {
        self.cleanup = Some(cleanup);
        self
    }

    /// Override the default per-tenant quota.
    pub fn default_quota(mut self, quota: TenantQuota) -> Self {
        self.default_quota = Some(quota);
        self
    }

    /// Set a per-tenant quota override.
    pub fn tenant_quota(mut self, tenant: TenantId, quota: TenantQuota) -> Self {
        self.quotas.insert(tenant, quota);
        self
    }

    /// Build the service.
    ///
    /// # Panics
    /// Panics if no inner backend was set.
    pub fn build(self) -> VmLifecycleService {
        VmLifecycleService {
            inner: self.inner.expect("inner backend is required"),
            probe: self
                .probe
                .unwrap_or_else(|| Arc::new(ScriptedSupervisorProbe::new())),
            audit: self
                .audit
                .unwrap_or_else(|| Arc::new(InMemoryAuditLog::new())),
            cleanup: self.cleanup,
            vms: Mutex::new(HashMap::new()),
            completed: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            quotas: Mutex::new(self.quotas),
            default_quota: self.default_quota.unwrap_or(DEFAULT_QUOTA),
        }
    }
}

impl VmLifecycleService {
    /// Start building a service.
    pub fn builder() -> ServiceBuilder {
        ServiceBuilder::default()
    }

    /// The reconciled supervised state for a VM, if known.
    pub fn supervisor_state(&self, vm_id: &VmId) -> Option<SupervisorState> {
        self.vms.lock().unwrap().get(vm_id).cloned()
    }

    // -- locking ----------------------------------------------------------

    fn lock_for(&self, scope: &str) -> Arc<AsyncMutex<()>> {
        self.locks
            .lock()
            .unwrap()
            .entry(scope.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    // -- audit ------------------------------------------------------------

    fn record_audit(
        &self,
        principal: &Principal,
        resource_id: &str,
        operation: Operation,
        result: AuditResult,
    ) {
        self.audit.record(AuditEvent {
            timestamp: Utc::now(),
            tenant_id: principal.tenant_id().clone(),
            role: principal.role(),
            resource_type: ResourceType::Vm,
            resource_id: resource_id.to_string(),
            operation,
            result,
        });
    }

    fn cache(&self, key: &RequestKey, outcome: StoredOutcome) {
        self.completed.lock().unwrap().insert(key.clone(), outcome);
    }

    // -- registry views ---------------------------------------------------

    fn owner_of(&self, vm_id: &VmId) -> Result<TenantId, MicrovmError> {
        self.vms
            .lock()
            .unwrap()
            .get(vm_id)
            .map(|e| e.owner().clone())
            .ok_or_else(|| not_found(vm_id))
    }

    fn state_of(&self, vm_id: &VmId) -> Option<VmState> {
        self.vms.lock().unwrap().get(vm_id).map(|e| e.state())
    }

    fn set_state(&self, vm_id: &VmId, state: VmState, alive: bool) {
        if let Some(entry) = self.vms.lock().unwrap().get_mut(vm_id) {
            entry.set_state(state);
            entry.set_supervisor_alive(alive);
        }
    }

    // -- quota ------------------------------------------------------------

    fn quota_for(&self, tenant: &TenantId) -> TenantQuota {
        self.quotas
            .lock()
            .unwrap()
            .get(tenant)
            .copied()
            .unwrap_or(self.default_quota)
    }

    fn tenant_usage(&self, tenant: &TenantId) -> TenantUsage {
        let vms = self.vms.lock().unwrap();
        let mut usage = TenantUsage::default();
        for entry in vms.values() {
            if entry.owner() == tenant && entry.counts_toward_quota() {
                usage.vcpus_used = usage.vcpus_used.saturating_add(entry.spec().vcpu_count());
                usage.memory_mib_used = usage
                    .memory_mib_used
                    .saturating_add(entry.spec().memory_mib());
                usage.disk_mib_used = usage.disk_mib_used.saturating_add(entry.spec().disk_mib());
                usage.vm_count = usage.vm_count.saturating_add(1);
            }
        }
        usage
    }

    // -- reconciliation ---------------------------------------------------

    /// Reconcile a VM whose supervisor may have died.
    ///
    /// If the service believes the VM is running/paused but the
    /// [`SupervisorProbe`] reports the supervisor process is gone, the VM is
    /// driven to [`VmState::Failed`], its owned resources are released via the
    /// configured cleanup, and an audit event is recorded.
    ///
    /// Returns `true` if a supervisor death was reconciled.
    pub fn reconcile(&self, vm_id: &VmId) -> bool {
        let health = self.probe.health(vm_id);
        let owner = {
            let mut vms = self.vms.lock().unwrap();
            let Some(entry) = vms.get_mut(vm_id) else {
                return false;
            };
            if !entry.needs_live_supervisor() {
                entry.set_supervisor_alive(health.alive);
                return false;
            }
            if health.alive {
                entry.set_supervisor_alive(true);
                return false;
            }
            // Supervisor died unexpectedly: any -> Failed is always legal.
            entry.set_state(VmState::Failed);
            entry.set_supervisor_alive(false);
            entry.set_reconciled_at(Some(Utc::now()));
            entry.owner().clone()
        };

        // Release owned resources best-effort.
        if let Some(cleanup) = &self.cleanup {
            let _ = cleanup.cleanup_vm(vm_id, &owner, health.pid);
        }

        // The supervisor acts as owner of record for the reconciliation audit.
        let principal = Principal::new(owner, Role::Owner);
        self.record_audit(
            &principal,
            vm_id.as_str(),
            Operation::Stop,
            AuditResult::Error,
        );
        true
    }

    // -- keyed mutating operations ---------------------------------------

    /// Create a VM idempotently by request key.
    ///
    /// A duplicate request carrying the same key replays the cached outcome
    /// without creating a second VM.
    pub async fn create_with(
        &self,
        key: RequestKey,
        spec: ResourceSpec,
        owner: Principal,
    ) -> Result<VmId, MicrovmError> {
        self.do_create(spec, owner, Some(&key)).await
    }

    /// Start a VM idempotently by request key.
    pub async fn start_with(
        &self,
        key: RequestKey,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<(), MicrovmError> {
        self.do_start(vm_id, principal, Some(&key)).await
    }

    /// Stop a VM idempotently by request key.
    pub async fn stop_with(
        &self,
        key: RequestKey,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<(), MicrovmError> {
        self.do_stop(vm_id, principal, Some(&key)).await
    }

    // -- core logic (shared by keyed and trait surfaces) ------------------

    async fn do_create(
        &self,
        spec: ResourceSpec,
        owner: Principal,
        key: Option<&RequestKey>,
    ) -> Result<VmId, MicrovmError> {
        // Serialize creates per tenant so quota checks stay consistent.
        let lock = self.lock_for(&create_scope(owner.tenant_id()));
        let _guard = lock.lock().await;

        if let Some(key) = key {
            if let Some(outcome) = self.completed.lock().unwrap().get(key).cloned() {
                return replay_create(&outcome);
            }
        }

        // Authorization (role) before mutation.
        if let Err(e) = authorize(&owner, owner.tenant_id(), Operation::Create) {
            self.record_audit(&owner, "", Operation::Create, AuditResult::Denied);
            if let Some(key) = key {
                self.cache(key, StoredOutcome::Err(e.clone()));
            }
            return Err(e);
        }

        // Quota check before mutation.
        let quota = self.quota_for(owner.tenant_id());
        let usage = self.tenant_usage(owner.tenant_id());
        if let Err(e) = check_quota(&quota, &usage, &spec) {
            self.record_audit(&owner, "", Operation::Create, AuditResult::Error);
            if let Some(key) = key {
                self.cache(key, StoredOutcome::Err(e.clone()));
            }
            return Err(e);
        }

        let outcome = self.inner.create(spec.clone(), owner.clone()).await;
        match &outcome {
            Ok(vm_id) => {
                self.vms.lock().unwrap().insert(
                    vm_id.clone(),
                    SupervisorState::new(
                        vm_id.clone(),
                        owner.tenant_id().clone(),
                        spec,
                        Utc::now(),
                    ),
                );
                self.record_audit(
                    &owner,
                    vm_id.as_str(),
                    Operation::Create,
                    AuditResult::Success,
                );
                if let Some(key) = key {
                    self.cache(key, StoredOutcome::Created(vm_id.clone()));
                }
            }
            Err(e) => {
                self.record_audit(&owner, "", Operation::Create, audit_result(&outcome));
                if let Some(key) = key {
                    self.cache(key, StoredOutcome::Err(e.clone()));
                }
            }
        }
        outcome
    }

    async fn do_start(
        &self,
        vm_id: &VmId,
        principal: &Principal,
        key: Option<&RequestKey>,
    ) -> Result<(), MicrovmError> {
        // Serialize concurrent operations on this VM.
        let lock = self.lock_for(&vm_scope(vm_id));
        let _guard = lock.lock().await;

        // Reconcile a dead supervisor before mutating.
        self.reconcile(vm_id);

        if let Some(key) = key {
            if let Some(outcome) = self.completed.lock().unwrap().get(key).cloned() {
                return replay_unit(&outcome);
            }
        }

        // Owner + role check before mutation.
        let owner = self.owner_of(vm_id)?;
        if let Err(e) = authorize(principal, &owner, Operation::Start) {
            self.record_audit(
                principal,
                vm_id.as_str(),
                Operation::Start,
                AuditResult::Denied,
            );
            if let Some(key) = key {
                self.cache(key, StoredOutcome::Err(e.clone()));
            }
            return Err(e);
        }

        // State-based idempotency: starting a running VM is a no-op.
        if self.state_of(vm_id) == Some(VmState::Running) {
            self.record_audit(
                principal,
                vm_id.as_str(),
                Operation::Start,
                AuditResult::Success,
            );
            if let Some(key) = key {
                self.cache(key, StoredOutcome::Ok);
            }
            return Ok(());
        }

        let outcome = self.inner.start(vm_id, principal).await;
        match &outcome {
            Ok(()) => {
                self.set_state(vm_id, VmState::Running, true);
                self.record_audit(
                    principal,
                    vm_id.as_str(),
                    Operation::Start,
                    AuditResult::Success,
                );
                if let Some(key) = key {
                    self.cache(key, StoredOutcome::Ok);
                }
            }
            Err(e) => {
                // A failed boot drives the VM to Failed (mirrors the backend);
                // a pre-mutation rejection leaves the state untouched.
                if e.code != ErrorCode::PermissionDenied {
                    self.set_state(vm_id, VmState::Failed, false);
                }
                self.record_audit(
                    principal,
                    vm_id.as_str(),
                    Operation::Start,
                    audit_result(&outcome),
                );
                if let Some(key) = key {
                    self.cache(key, StoredOutcome::Err(e.clone()));
                }
            }
        }
        outcome
    }

    async fn do_stop(
        &self,
        vm_id: &VmId,
        principal: &Principal,
        key: Option<&RequestKey>,
    ) -> Result<(), MicrovmError> {
        let lock = self.lock_for(&vm_scope(vm_id));
        let _guard = lock.lock().await;

        self.reconcile(vm_id);

        if let Some(key) = key {
            if let Some(outcome) = self.completed.lock().unwrap().get(key).cloned() {
                return replay_unit(&outcome);
            }
        }

        let owner = self.owner_of(vm_id)?;
        if let Err(e) = authorize(principal, &owner, Operation::Stop) {
            self.record_audit(
                principal,
                vm_id.as_str(),
                Operation::Stop,
                AuditResult::Denied,
            );
            if let Some(key) = key {
                self.cache(key, StoredOutcome::Err(e.clone()));
            }
            return Err(e);
        }

        // State-based idempotency and transition validation.
        if let Err(e) = self.validate_stop(vm_id) {
            self.record_audit(
                principal,
                vm_id.as_str(),
                Operation::Stop,
                AuditResult::Error,
            );
            if let Some(key) = key {
                self.cache(key, StoredOutcome::Err(e.clone()));
            }
            return Err(e);
        }
        if self.state_of(vm_id) == Some(VmState::Stopped) {
            self.record_audit(
                principal,
                vm_id.as_str(),
                Operation::Stop,
                AuditResult::Success,
            );
            if let Some(key) = key {
                self.cache(key, StoredOutcome::Ok);
            }
            return Ok(());
        }

        let outcome = self.inner.stop(vm_id, principal).await;
        match &outcome {
            Ok(()) => {
                self.set_state(vm_id, VmState::Stopped, false);
                self.record_audit(
                    principal,
                    vm_id.as_str(),
                    Operation::Stop,
                    AuditResult::Success,
                );
                if let Some(key) = key {
                    self.cache(key, StoredOutcome::Ok);
                }
            }
            Err(e) => {
                self.record_audit(
                    principal,
                    vm_id.as_str(),
                    Operation::Stop,
                    audit_result(&outcome),
                );
                if let Some(key) = key {
                    self.cache(key, StoredOutcome::Err(e.clone()));
                }
            }
        }
        outcome
    }

    /// Validate that a stop is legal from the current reconciled state.
    ///
    /// Returns `Ok(())` for running/paused (stoppable) and stopped (idempotent
    /// no-op) states; an `InvalidTransition` error otherwise.
    fn validate_stop(&self, vm_id: &VmId) -> Result<(), MicrovmError> {
        match self.state_of(vm_id) {
            Some(VmState::Running) | Some(VmState::Paused) | Some(VmState::Stopped) => Ok(()),
            Some(other) => Err(MicrovmError::new(
                ErrorCode::InvalidTransition,
                format!("cannot stop VM in {} state", other),
            )
            .with_context("vm_id", vm_id.as_str())
            .with_context("state", other.as_str())),
            None => Err(not_found(vm_id)),
        }
    }
}

// ---------------------------------------------------------------------------
// LifecycleService implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl LifecycleService for VmLifecycleService {
    async fn create(&self, spec: ResourceSpec, owner: Principal) -> Result<VmId, MicrovmError> {
        // The trait surface carries no client nonce, so each call creates a VM;
        // request-key idempotency is the keyed API's responsibility. Quota and
        // authorization still apply.
        self.do_create(spec, owner, None).await
    }

    async fn start(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        // No request key: repeat starts are no-ops via state-based idempotency,
        // and a stop-then-start cycle correctly re-starts the VM.
        self.do_start(vm_id, principal, None).await
    }

    async fn stop(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        self.do_stop(vm_id, principal, None).await
    }

    async fn snapshot(
        &self,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError> {
        let owner = self.owner_of(vm_id)?;
        if let Err(e) = authorize(principal, &owner, Operation::Snapshot) {
            self.record_audit(
                principal,
                vm_id.as_str(),
                Operation::Snapshot,
                AuditResult::Denied,
            );
            return Err(e);
        }
        let outcome = self.inner.snapshot(vm_id, principal).await;
        self.record_audit(
            principal,
            vm_id.as_str(),
            Operation::Snapshot,
            audit_result(&outcome),
        );
        outcome
    }

    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        principal: &Principal,
    ) -> Result<VmId, MicrovmError> {
        // Restore is delegated to the backend (todo 22); the service audits the
        // attempt. Ownership is established by the backend on the new VM.
        let outcome = self.inner.restore(snapshot_id, principal).await;
        self.record_audit(
            principal,
            snapshot_id.as_str(),
            Operation::Restore,
            audit_result(&outcome),
        );
        outcome
    }

    async fn status(&self, vm_id: &VmId, principal: &Principal) -> Result<VmStatus, MicrovmError> {
        // Read-only, but reconcile under the per-VM lock so a dead supervisor is
        // reflected in the returned state.
        let lock = self.lock_for(&vm_scope(vm_id));
        let _guard = lock.lock().await;
        self.reconcile(vm_id);
        let entry = self
            .vms
            .lock()
            .unwrap()
            .get(vm_id)
            .cloned()
            .ok_or_else(|| not_found(vm_id))?;
        authorize(principal, entry.owner(), Operation::Status)?;
        Ok(VmStatus {
            vm_id: entry.vm_id().clone(),
            state: entry.state(),
            created_at: entry.created_at(),
            resource_spec: entry.spec().clone(),
        })
    }

    async fn metrics(
        &self,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<VmMetrics, MicrovmError> {
        let lock = self.lock_for(&vm_scope(vm_id));
        let _guard = lock.lock().await;
        self.reconcile(vm_id);
        let entry = self
            .vms
            .lock()
            .unwrap()
            .get(vm_id)
            .cloned()
            .ok_or_else(|| not_found(vm_id))?;
        authorize(principal, entry.owner(), Operation::Metrics)?;
        Ok(VmMetrics {
            vm_id: entry.vm_id().clone(),
            state: entry.state(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VmLifecycleService>();
    }

    #[test]
    fn default_quota_is_generous_but_bounded() {
        assert_eq!(DEFAULT_QUOTA.max_vms, 64);
        assert_eq!(DEFAULT_QUOTA.max_vcpus, 64);
    }

    #[test]
    fn lock_scopes_are_distinct_per_vm_and_tenant() {
        let a = vm_scope(&VmId::new("vm-a").unwrap());
        let b = vm_scope(&VmId::new("vm-b").unwrap());
        let c = create_scope(&TenantId::new("acme").unwrap());
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, "vm:vm-a");
        assert_eq!(c, "create:acme");
    }

    #[test]
    fn guest_not_ready_classifier_matches_phase_context() {
        let ready_err = MicrovmError::new(ErrorCode::InternalError, "guest not ready")
            .with_context("phase", "guest_ready");
        assert!(is_guest_not_ready(&ready_err));

        let other = MicrovmError::new(ErrorCode::InternalError, "socket timeout")
            .with_context("phase", "socket_ready");
        assert!(!is_guest_not_ready(&other));

        let no_ctx = MicrovmError::new(ErrorCode::InternalError, "boom");
        assert!(!is_guest_not_ready(&no_ctx));
    }

    #[test]
    fn audit_result_maps_permission_denied_to_denied() {
        let denied: Result<(), _> = Err(MicrovmError::new(ErrorCode::PermissionDenied, "no"));
        assert_eq!(audit_result(&denied), AuditResult::Denied);

        let errored: Result<(), _> = Err(MicrovmError::new(ErrorCode::InternalError, "x"));
        assert_eq!(audit_result(&errored), AuditResult::Error);

        let ok: Result<(), MicrovmError> = Ok(());
        assert_eq!(audit_result(&ok), AuditResult::Success);
    }
}
