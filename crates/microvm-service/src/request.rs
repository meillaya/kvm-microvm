//! Idempotency keys and stored outcomes for the supervised lifecycle service.
//!
//! A [`RequestKey`] names a single logical mutating request. Two requests that
//! carry the same key are treated as the *same* request: the first executes and
//! its outcome is cached; every later request with that key replays the cached
//! outcome without re-invoking the backend or emitting another audit event.
//! This is what makes duplicate create/start/stop operations no-ops.

use microvm_errors::MicrovmError;
use microvm_lifecycle::policy::Operation;
use microvm_types::{TenantId, VmId};
use serde::{Deserialize, Serialize};

use microvm_errors::ErrorCode;

/// A deduplication key for an idempotent mutating request.
///
/// The key is scoped to an [`Operation`] and a subject (the tenant for create,
/// the VM id for start/stop) plus a client-supplied `nonce`. The nonce lets a
/// client retry the *same* logical request safely while still allowing distinct
/// requests (different nonces) to proceed independently.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestKey {
    operation: Operation,
    subject: String,
    nonce: String,
}

impl RequestKey {
    /// Build a key for a create request scoped to a tenant.
    pub fn create(tenant: &TenantId, nonce: impl Into<String>) -> Self {
        Self {
            operation: Operation::Create,
            subject: tenant.as_str().to_string(),
            nonce: nonce.into(),
        }
    }

    /// Build a key for a start request scoped to a VM.
    pub fn start(vm_id: &VmId, nonce: impl Into<String>) -> Self {
        Self::for_vm(Operation::Start, vm_id, nonce)
    }

    /// Build a key for a stop request scoped to a VM.
    pub fn stop(vm_id: &VmId, nonce: impl Into<String>) -> Self {
        Self::for_vm(Operation::Stop, vm_id, nonce)
    }

    /// Build a key for an arbitrary VM-scoped operation.
    pub fn for_vm(operation: Operation, vm_id: &VmId, nonce: impl Into<String>) -> Self {
        Self {
            operation,
            subject: vm_id.as_str().to_string(),
            nonce: nonce.into(),
        }
    }

    /// The operation this key deduplicates.
    pub fn operation(&self) -> Operation {
        self.operation
    }

    /// The subject (tenant or VM id string) this key is scoped to.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The client-supplied idempotency nonce.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// A stable scope string identifying this request's lock domain.
    pub fn lock_scope(&self) -> String {
        format!(
            "{}:{}:{}",
            self.operation.as_str(),
            self.subject,
            self.nonce
        )
    }
}

/// The cached outcome of a completed idempotent request.
///
/// Stored in the service's idempotency map so a duplicate request can replay
/// the exact result of the original without touching the backend again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum StoredOutcome {
    /// A create succeeded and produced this VM id.
    Created(VmId),
    /// A start/stop succeeded.
    Ok,
    /// The request failed with this error.
    Err(MicrovmError),
}

/// Replay a cached outcome for a create-shaped request.
pub(crate) fn replay_create(outcome: &StoredOutcome) -> Result<VmId, MicrovmError> {
    match outcome {
        StoredOutcome::Created(vm_id) => Ok(vm_id.clone()),
        StoredOutcome::Err(e) => Err(e.clone()),
        StoredOutcome::Ok => Err(key_reuse_error()),
    }
}

/// Replay a cached outcome for a start/stop-shaped request.
pub(crate) fn replay_unit(outcome: &StoredOutcome) -> Result<(), MicrovmError> {
    match outcome {
        StoredOutcome::Ok => Ok(()),
        StoredOutcome::Err(e) => Err(e.clone()),
        StoredOutcome::Created(_) => Err(key_reuse_error()),
    }
}

fn key_reuse_error() -> MicrovmError {
    MicrovmError::new(
        ErrorCode::InternalError,
        "request key reused across operation kinds",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).unwrap()
    }

    #[test]
    fn create_key_scoped_to_tenant() {
        let key = RequestKey::create(&tenant("acme"), "nonce-1");
        assert_eq!(key.operation(), Operation::Create);
        assert_eq!(key.subject(), "acme");
        assert_eq!(key.nonce(), "nonce-1");
    }

    #[test]
    fn vm_keys_scoped_to_vm() {
        let start = RequestKey::start(&vm("vm-1"), "n");
        let stop = RequestKey::stop(&vm("vm-1"), "n");
        assert_eq!(start.subject(), "vm-1");
        assert_eq!(start.operation(), Operation::Start);
        assert_eq!(stop.operation(), Operation::Stop);
        assert_ne!(start, stop);
    }

    #[test]
    fn keys_with_different_nonces_are_distinct() {
        let a = RequestKey::start(&vm("vm-1"), "a");
        let b = RequestKey::start(&vm("vm-1"), "b");
        assert_ne!(a, b);
        assert_ne!(a.lock_scope(), b.lock_scope());
    }

    #[test]
    fn key_serde_roundtrip() {
        let key = RequestKey::start(&vm("vm-1"), "nonce");
        let json = serde_json::to_string(&key).unwrap();
        let back: RequestKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn replay_create_returns_vm_id() {
        let id = vm("vm-1");
        assert_eq!(
            replay_create(&StoredOutcome::Created(id.clone())).unwrap(),
            id
        );
    }

    #[test]
    fn replay_create_propagates_error() {
        let err = MicrovmError::new(ErrorCode::QuotaExceeded, "full");
        let got = replay_create(&StoredOutcome::Err(err.clone())).unwrap_err();
        assert_eq!(got, err);
    }

    #[test]
    fn replay_unit_ok_and_err() {
        assert!(replay_unit(&StoredOutcome::Ok).is_ok());
        let err = MicrovmError::new(ErrorCode::InternalError, "boom");
        assert_eq!(
            replay_unit(&StoredOutcome::Err(err.clone())).unwrap_err(),
            err
        );
    }

    #[test]
    fn replay_across_kinds_is_an_error() {
        assert!(replay_create(&StoredOutcome::Ok).is_err());
        assert!(replay_unit(&StoredOutcome::Created(vm("vm-1"))).is_err());
    }
}
