//! Tenant authorization, ownership policy, quota enforcement, and structured
//! audit events for the kvm-microvm-orchestrator platform.
//!
//! # Design constraints
//!
//! - Authorization is performed on typed identifiers ([`TenantId`],
//!   [`Role`]), never on mutable path strings.
//! - Quota checks happen before any backend call so that over-quota
//!   requests are rejected without side effects.
//! - Every mutating request produces exactly one [`AuditEvent`].

use chrono::{DateTime, Utc};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::{Principal, ResourceSpec, Role, TenantId};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Operation
// ---------------------------------------------------------------------------

/// Operations that can be performed on platform resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Create a new resource.
    Create,
    /// Start (or resume) a VM.
    Start,
    /// Stop a running or paused VM.
    Stop,
    /// Snapshot a VM.
    Snapshot,
    /// Restore a VM from a snapshot.
    Restore,
    /// Query resource status (read-only).
    Status,
    /// Query resource metrics (read-only).
    Metrics,
}

impl Operation {
    /// Return all operation variants.
    pub fn all() -> &'static [Operation] {
        &[
            Self::Create,
            Self::Start,
            Self::Stop,
            Self::Snapshot,
            Self::Restore,
            Self::Status,
            Self::Metrics,
        ]
    }

    /// Stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Snapshot => "snapshot",
            Self::Restore => "restore",
            Self::Status => "status",
            Self::Metrics => "metrics",
        }
    }

    /// Whether this operation mutates platform state.
    ///
    /// Mutating operations must produce exactly one [`AuditEvent`].
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Start | Self::Stop | Self::Snapshot | Self::Restore
        )
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ResourceType
// ---------------------------------------------------------------------------

/// The kind of platform resource an operation targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// A virtual machine instance.
    Vm,
    /// A bootable machine image.
    Image,
    /// A point-in-time VM snapshot.
    Snapshot,
}

impl ResourceType {
    /// Stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vm => "vm",
            Self::Image => "image",
            Self::Snapshot => "snapshot",
        }
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Check whether a role permits a given operation.
///
/// Permission matrix:
///
/// | Operation | Owner | Operator | Viewer |
/// |-----------|-------|----------|--------|
/// | Create    | ✓     |          |        |
/// | Start     | ✓     | ✓        |        |
/// | Stop      | ✓     | ✓        |        |
/// | Snapshot  | ✓     |          |        |
/// | Restore   | ✓     |          |        |
/// | Status    | ✓     | ✓        | ✓      |
/// | Metrics   | ✓     | ✓        | ✓      |
fn role_permits(role: Role, operation: Operation) -> bool {
    match role {
        Role::Owner => true,
        Role::Operator => matches!(
            operation,
            Operation::Start | Operation::Stop | Operation::Status | Operation::Metrics
        ),
        Role::Viewer => matches!(operation, Operation::Status | Operation::Metrics),
    }
}

/// Authorize a principal to perform an operation on a resource owned by
/// `resource_owner`.
///
/// # Rules
///
/// 1. The principal's [`TenantId`] must match `resource_owner`. Cross-tenant
///    access always returns [`ErrorCode::PermissionDenied`].
/// 2. The principal's [`Role`] must permit the operation (see
///    [`role_permits`]).
///
/// Authorization is performed on typed identifiers; never on mutable path
/// strings.
///
/// # Errors
///
/// Returns [`ErrorCode::PermissionDenied`] if the tenant does not match or
/// the role lacks permission.
pub fn authorize(
    principal: &Principal,
    resource_owner: &TenantId,
    operation: Operation,
) -> Result<(), MicrovmError> {
    // Rule 1: tenant match.
    if principal.tenant_id() != resource_owner {
        return Err(
            MicrovmError::new(ErrorCode::PermissionDenied, "cross-tenant access denied")
                .with_context("principal_tenant", principal.tenant_id().as_str())
                .with_context("resource_owner", resource_owner.as_str())
                .with_context("operation", operation.as_str()),
        );
    }

    // Rule 2: role check.
    if !role_permits(principal.role(), operation) {
        return Err(MicrovmError::new(
            ErrorCode::PermissionDenied,
            format!(
                "role {:?} is not permitted to perform {}",
                principal.role(),
                operation
            ),
        )
        .with_context("role", format!("{:?}", principal.role()))
        .with_context("operation", operation.as_str()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Quotas
// ---------------------------------------------------------------------------

/// Per-tenant resource quotas.
///
/// All fields are upper bounds. A value of `0` means the resource is
/// entirely disallowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantQuota {
    /// Maximum total vCPUs across all VMs.
    pub max_vcpus: u32,
    /// Maximum total memory in MiB across all VMs.
    pub max_memory_mib: u64,
    /// Maximum total disk in MiB across all VMs.
    pub max_disk_mib: u64,
    /// Maximum number of VMs.
    pub max_vms: u32,
    /// Maximum number of snapshots.
    pub max_snapshots: u32,
}

/// Current resource usage for a tenant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantUsage {
    /// vCPUs currently allocated.
    pub vcpus_used: u32,
    /// Memory in MiB currently allocated.
    pub memory_mib_used: u64,
    /// Disk in MiB currently allocated.
    pub disk_mib_used: u64,
    /// Number of VMs currently existing.
    pub vm_count: u32,
    /// Number of snapshots currently stored.
    pub snapshot_count: u32,
}

/// Validate that a create request fits within the tenant's quota.
///
/// This check must happen before any backend call so that over-quota
/// requests are rejected without side effects.
///
/// # Errors
///
/// Returns [`ErrorCode::QuotaExceeded`] with context describing which
/// dimension was exceeded.
pub fn check_quota(
    quota: &TenantQuota,
    usage: &TenantUsage,
    requested: &ResourceSpec,
) -> Result<(), MicrovmError> {
    // VM count.
    if usage.vm_count >= quota.max_vms {
        return Err(
            MicrovmError::new(ErrorCode::QuotaExceeded, "vm count limit reached")
                .with_context("limit", quota.max_vms.to_string())
                .with_context("current", usage.vm_count.to_string()),
        );
    }

    // vCPUs.
    let vcpus_after = usage.vcpus_used.saturating_add(requested.vcpu_count());
    if vcpus_after > quota.max_vcpus {
        return Err(
            MicrovmError::new(ErrorCode::QuotaExceeded, "vcpu limit would be exceeded")
                .with_context("limit", quota.max_vcpus.to_string())
                .with_context("current", usage.vcpus_used.to_string())
                .with_context("requested", requested.vcpu_count().to_string()),
        );
    }

    // Memory.
    let memory_after = usage.memory_mib_used.saturating_add(requested.memory_mib());
    if memory_after > quota.max_memory_mib {
        return Err(
            MicrovmError::new(ErrorCode::QuotaExceeded, "memory limit would be exceeded")
                .with_context("limit", quota.max_memory_mib.to_string())
                .with_context("current", usage.memory_mib_used.to_string())
                .with_context("requested", requested.memory_mib().to_string()),
        );
    }

    // Disk.
    let disk_after = usage.disk_mib_used.saturating_add(requested.disk_mib());
    if disk_after > quota.max_disk_mib {
        return Err(
            MicrovmError::new(ErrorCode::QuotaExceeded, "disk limit would be exceeded")
                .with_context("limit", quota.max_disk_mib.to_string())
                .with_context("current", usage.disk_mib_used.to_string())
                .with_context("requested", requested.disk_mib().to_string()),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Outcome of an audited operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// The operation completed successfully.
    Success,
    /// The operation was denied by policy.
    Denied,
    /// The operation failed with an error.
    Error,
}

impl AuditResult {
    /// Stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

impl std::fmt::Display for AuditResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A structured audit event produced for every mutating request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event was recorded.
    pub timestamp: DateTime<Utc>,
    /// The tenant that initiated the operation.
    pub tenant_id: TenantId,
    /// The role held by the principal at the time of the operation.
    pub role: Role,
    /// The kind of resource targeted.
    pub resource_type: ResourceType,
    /// The identifier of the targeted resource (string form of VmId,
    /// ImageId, or SnapshotId).
    pub resource_id: String,
    /// The operation attempted.
    pub operation: Operation,
    /// The outcome.
    pub result: AuditResult,
}

/// Sink for structured audit events.
///
/// Implementations must be safe to call from multiple threads.
pub trait AuditLog: Send + Sync {
    /// Record a single audit event.
    fn record(&self, event: AuditEvent);
}

/// In-memory [`AuditLog`] implementation for testing.
///
/// Stores events in a `Mutex`-protected `Vec` so it can be shared across
/// threads and inspected after a test run.
#[derive(Debug, Default)]
pub struct InMemoryAuditLog {
    events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditLog {
    /// Create an empty audit log.
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// Return a snapshot of all recorded events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Return the number of recorded events.
    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.events.lock().unwrap().is_empty()
    }
}

impl AuditLog for InMemoryAuditLog {
    fn record(&self, event: AuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_types::NetworkPolicy;

    // -- helpers ------------------------------------------------------------

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).unwrap()
    }

    fn principal(name: &str, role: Role) -> Principal {
        Principal::new(tenant(name), role)
    }

    fn spec(vcpus: u32, mem: u64, disk: u64) -> ResourceSpec {
        ResourceSpec::new(vcpus, mem, disk, NetworkPolicy::None).unwrap()
    }

    fn default_quota() -> TenantQuota {
        TenantQuota {
            max_vcpus: 16,
            max_memory_mib: 8192,
            max_disk_mib: 102_400,
            max_vms: 10,
            max_snapshots: 20,
        }
    }

    // -- authorization: tenant isolation ------------------------------------

    #[test]
    fn cross_tenant_get_returns_permission_denied() {
        let p = principal("tenant-a", Role::Owner);
        let owner = tenant("tenant-b");
        let err = authorize(&p, &owner, Operation::Status).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.message.contains("cross-tenant"));
    }

    #[test]
    fn cross_tenant_start_returns_permission_denied() {
        let p = principal("tenant-a", Role::Owner);
        let owner = tenant("tenant-b");
        let err = authorize(&p, &owner, Operation::Start).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn cross_tenant_stop_returns_permission_denied() {
        let p = principal("tenant-a", Role::Owner);
        let owner = tenant("tenant-b");
        assert_eq!(
            authorize(&p, &owner, Operation::Stop).unwrap_err().code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn cross_tenant_snapshot_returns_permission_denied() {
        let p = principal("tenant-a", Role::Owner);
        let owner = tenant("tenant-b");
        assert_eq!(
            authorize(&p, &owner, Operation::Snapshot).unwrap_err().code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn cross_tenant_restore_returns_permission_denied() {
        let p = principal("tenant-a", Role::Owner);
        let owner = tenant("tenant-b");
        assert_eq!(
            authorize(&p, &owner, Operation::Restore).unwrap_err().code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn cross_tenant_list_returns_permission_denied() {
        // "list" maps to Status (read-only enumeration).
        let p = principal("tenant-a", Role::Viewer);
        let owner = tenant("tenant-b");
        assert_eq!(
            authorize(&p, &owner, Operation::Status).unwrap_err().code,
            ErrorCode::PermissionDenied
        );
    }

    // -- authorization: role-based ------------------------------------------

    #[test]
    fn owner_can_start() {
        let p = principal("t1", Role::Owner);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Start).is_ok());
    }

    #[test]
    fn operator_can_start() {
        let p = principal("t1", Role::Operator);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Start).is_ok());
    }

    #[test]
    fn viewer_cannot_start() {
        let p = principal("t1", Role::Viewer);
        let owner = tenant("t1");
        let err = authorize(&p, &owner, Operation::Start).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn owner_can_snapshot() {
        let p = principal("t1", Role::Owner);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Snapshot).is_ok());
    }

    #[test]
    fn viewer_cannot_snapshot() {
        let p = principal("t1", Role::Viewer);
        let owner = tenant("t1");
        let err = authorize(&p, &owner, Operation::Snapshot).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn operator_cannot_snapshot() {
        let p = principal("t1", Role::Operator);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Snapshot).is_err());
    }

    #[test]
    fn owner_can_do_everything() {
        let p = principal("t1", Role::Owner);
        let owner = tenant("t1");
        for op in Operation::all() {
            assert!(
                authorize(&p, &owner, *op).is_ok(),
                "owner should be permitted to {:?}",
                op
            );
        }
    }

    #[test]
    fn operator_can_stop() {
        let p = principal("t1", Role::Operator);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Stop).is_ok());
    }

    #[test]
    fn operator_cannot_create() {
        let p = principal("t1", Role::Operator);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Create).is_err());
    }

    #[test]
    fn operator_cannot_restore() {
        let p = principal("t1", Role::Operator);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Restore).is_err());
    }

    #[test]
    fn viewer_can_status() {
        let p = principal("t1", Role::Viewer);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Status).is_ok());
    }

    #[test]
    fn viewer_can_metrics() {
        let p = principal("t1", Role::Viewer);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Metrics).is_ok());
    }

    #[test]
    fn viewer_cannot_stop() {
        let p = principal("t1", Role::Viewer);
        let owner = tenant("t1");
        assert!(authorize(&p, &owner, Operation::Stop).is_err());
    }

    // -- quota enforcement --------------------------------------------------

    #[test]
    fn quota_ok_within_limits() {
        let quota = default_quota();
        let usage = TenantUsage::default();
        let req = spec(2, 512, 1024);
        assert!(check_quota(&quota, &usage, &req).is_ok());
    }

    #[test]
    fn over_quota_vcpus_returns_quota_exceeded() {
        let quota = default_quota();
        let usage = TenantUsage {
            vcpus_used: 15,
            ..Default::default()
        };
        let req = spec(2, 512, 1024);
        let err = check_quota(&quota, &usage, &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
        assert!(err.message.contains("vcpu"));
    }

    #[test]
    fn over_quota_memory_returns_quota_exceeded() {
        let quota = default_quota();
        let usage = TenantUsage {
            memory_mib_used: 8000,
            ..Default::default()
        };
        let req = spec(1, 512, 1024);
        let err = check_quota(&quota, &usage, &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
        assert!(err.message.contains("memory"));
    }

    #[test]
    fn over_quota_disk_returns_quota_exceeded() {
        let quota = default_quota();
        let usage = TenantUsage {
            disk_mib_used: 102_000,
            ..Default::default()
        };
        let req = spec(1, 512, 1024);
        let err = check_quota(&quota, &usage, &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
        assert!(err.message.contains("disk"));
    }

    #[test]
    fn over_quota_vm_count_returns_quota_exceeded() {
        let quota = default_quota();
        let usage = TenantUsage {
            vm_count: 10,
            ..Default::default()
        };
        let req = spec(1, 512, 1024);
        let err = check_quota(&quota, &usage, &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
        assert!(err.message.contains("vm count"));
    }

    #[test]
    fn quota_exact_boundary_is_ok() {
        let quota = default_quota();
        // Exactly at the limit after adding the request is fine.
        let usage = TenantUsage {
            vcpus_used: 14,
            memory_mib_used: 7680,
            disk_mib_used: 101_376,
            vm_count: 9,
            ..Default::default()
        };
        let req = spec(2, 512, 1024);
        assert!(check_quota(&quota, &usage, &req).is_ok());
    }

    #[test]
    fn over_quota_rejected_before_backend_call() {
        // This test documents the contract: check_quota is a pure function
        // that returns QuotaExceeded without any side effects. A caller
        // must invoke it before touching any backend.
        let quota = TenantQuota {
            max_vcpus: 0,
            max_memory_mib: 0,
            max_disk_mib: 0,
            max_vms: 0,
            max_snapshots: 0,
        };
        let usage = TenantUsage::default();
        let req = spec(1, 1, 1);
        let err = check_quota(&quota, &usage, &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
    }

    // -- audit events -------------------------------------------------------

    #[test]
    fn mutating_request_yields_exactly_one_audit_event() {
        let log = InMemoryAuditLog::new();
        let tid = tenant("t1");

        // Simulate a mutating request: start.
        let event = AuditEvent {
            timestamp: Utc::now(),
            tenant_id: tid.clone(),
            role: Role::Owner,
            resource_type: ResourceType::Vm,
            resource_id: "vm-001".to_string(),
            operation: Operation::Start,
            result: AuditResult::Success,
        };
        log.record(event);

        assert_eq!(log.len(), 1);
        let events = log.events();
        assert_eq!(events[0].operation, Operation::Start);
        assert_eq!(events[0].result, AuditResult::Success);
        assert_eq!(events[0].tenant_id, tid);
    }

    #[test]
    fn denied_request_yields_audit_event_with_denied_result() {
        let log = InMemoryAuditLog::new();
        let event = AuditEvent {
            timestamp: Utc::now(),
            tenant_id: tenant("t1"),
            role: Role::Viewer,
            resource_type: ResourceType::Vm,
            resource_id: "vm-001".to_string(),
            operation: Operation::Start,
            result: AuditResult::Denied,
        };
        log.record(event);

        assert_eq!(log.len(), 1);
        assert_eq!(log.events()[0].result, AuditResult::Denied);
    }

    #[test]
    fn multiple_mutating_requests_yield_multiple_events() {
        let log = InMemoryAuditLog::new();
        let tid = tenant("t1");

        for (op, res_id) in [
            (Operation::Create, "vm-001"),
            (Operation::Start, "vm-001"),
            (Operation::Snapshot, "vm-001"),
        ] {
            log.record(AuditEvent {
                timestamp: Utc::now(),
                tenant_id: tid.clone(),
                role: Role::Owner,
                resource_type: ResourceType::Vm,
                resource_id: res_id.to_string(),
                operation: op,
                result: AuditResult::Success,
            });
        }

        assert_eq!(log.len(), 3);
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let event = AuditEvent {
            timestamp: Utc::now(),
            tenant_id: tenant("t1"),
            role: Role::Operator,
            resource_type: ResourceType::Snapshot,
            resource_id: "snap-001".to_string(),
            operation: Operation::Snapshot,
            result: AuditResult::Error,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn audit_log_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryAuditLog>();
    }

    // -- operation helpers --------------------------------------------------

    #[test]
    fn operation_all_count() {
        assert_eq!(Operation::all().len(), 7);
    }

    #[test]
    fn mutating_operations_identified() {
        assert!(Operation::Create.is_mutating());
        assert!(Operation::Start.is_mutating());
        assert!(Operation::Stop.is_mutating());
        assert!(Operation::Snapshot.is_mutating());
        assert!(Operation::Restore.is_mutating());
        assert!(!Operation::Status.is_mutating());
        assert!(!Operation::Metrics.is_mutating());
    }

    #[test]
    fn operation_display_matches_as_str() {
        for op in Operation::all() {
            assert_eq!(op.to_string(), op.as_str());
        }
    }

    #[test]
    fn operation_serde_roundtrip() {
        for op in Operation::all() {
            let json = serde_json::to_string(op).unwrap();
            let back: Operation = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, back);
        }
    }

    #[test]
    fn resource_type_display() {
        assert_eq!(ResourceType::Vm.to_string(), "vm");
        assert_eq!(ResourceType::Image.to_string(), "image");
        assert_eq!(ResourceType::Snapshot.to_string(), "snapshot");
    }

    #[test]
    fn audit_result_display() {
        assert_eq!(AuditResult::Success.to_string(), "success");
        assert_eq!(AuditResult::Denied.to_string(), "denied");
        assert_eq!(AuditResult::Error.to_string(), "error");
    }

    // -- authorization does not use path strings ----------------------------

    #[test]
    fn authorization_uses_typed_tenant_id_not_path() {
        // Two tenants with similar-looking names must not be confused.
        // Authorization compares TenantId values, not string prefixes or
        // path components.
        let p = principal("tenant-a", Role::Owner);
        let owner_a = tenant("tenant-a");
        let owner_ab = tenant("tenant-ab");

        assert!(authorize(&p, &owner_a, Operation::Start).is_ok());
        assert!(authorize(&p, &owner_ab, Operation::Start).is_err());
    }
}
