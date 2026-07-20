//! HTTP route matching and request dispatch for the REST API.
//!
//! Routes match the OpenAPI spec (todo 8):
//! - `POST /vms` — create a VM
//! - `GET /vms/{vm_id}` — get VM status
//! - `POST /vms/{vm_id}/start` — start a VM
//! - `POST /vms/{vm_id}/stop` — stop a VM
//! - `POST /vms/{vm_id}/snapshot` — snapshot a VM
//! - `GET /vms/{vm_id}/metrics` — get VM metrics
//! - `POST /snapshots/{snapshot_id}/restore` — restore from snapshot
//!
//! Business policy (state machine, quota, authorization) is delegated to the
//! [`LifecycleService`] backend. This module handles only transport concerns:
//! parsing, routing, serialization, and error mapping.

use microvm_errors::{ErrorCode, MicrovmError};
use microvm_lifecycle::LifecycleService;
use microvm_metrics::VmMetricsRecord;
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, SnapshotId, VmId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::{ErrorBody, HttpStatus};

// ---------------------------------------------------------------------------
// Request / Response types (OpenAPI schema mappings)
// ---------------------------------------------------------------------------

/// Request body for `POST /vms`.
#[derive(Clone, Debug, Deserialize)]
pub struct CreateVmRequest {
    /// Number of virtual CPUs (minimum 1).
    pub vcpu_count: u32,
    /// Memory allocation in MiB (minimum 1).
    pub memory_mib: u64,
    /// Disk allocation in MiB (minimum 1).
    pub disk_mib: u64,
    /// Network egress policy (defaults to `none`).
    #[serde(default)]
    pub network_policy: NetworkPolicy,
}

/// Response body for `POST /vms` (201).
#[derive(Clone, Debug, Serialize)]
pub struct CreateVmResponse {
    /// Assigned VM identifier.
    pub vm_id: String,
}

/// Response body for `GET /vms/{vm_id}` (200).
#[derive(Clone, Debug, Serialize)]
pub struct VmStatusResponse {
    /// VM identifier.
    pub vm_id: String,
    /// Current lifecycle state.
    pub state: String,
    /// RFC 3339 timestamp of VM creation.
    pub created_at: String,
    /// Resource allocation.
    pub resource_spec: ResourceSpecResponse,
}

/// Resource specification in API responses.
#[derive(Clone, Debug, Serialize)]
pub struct ResourceSpecResponse {
    /// Number of virtual CPUs.
    pub vcpu_count: u32,
    /// Memory in MiB.
    pub memory_mib: u64,
    /// Disk in MiB.
    pub disk_mib: u64,
    /// Network policy.
    pub network_policy: NetworkPolicy,
}

/// Response body for `GET /vms/{vm_id}/metrics` (200).
///
/// Carries the lifecycle state plus the full, availability-flagged
/// [`VmMetricsRecord`] (plan todo 23): host cgroup/TAP metrics, monotonic
/// boot/restore phases, and optional guest metrics. Missing sources are
/// flagged unavailable, never zero-filled.
#[derive(Clone, Debug, Serialize)]
pub struct VmMetricsResponse {
    /// VM identifier.
    pub vm_id: String,
    /// Current lifecycle state.
    pub state: String,
    /// The full measurement snapshot (stable schema
    /// `schemas/vm-metrics-record.v1.json`).
    pub record: VmMetricsRecord,
}

/// Response body for `POST /vms/{vm_id}/snapshot` (201).
#[derive(Clone, Debug, Serialize)]
pub struct SnapshotVmResponse {
    /// Identifier of the created snapshot.
    pub snapshot_id: String,
}

/// Response body for `POST /snapshots/{snapshot_id}/restore` (201).
#[derive(Clone, Debug, Serialize)]
pub struct RestoreVmResponse {
    /// Identifier of the newly restored VM.
    pub vm_id: String,
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

/// A parsed route from an HTTP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `POST /vms`
    CreateVm,
    /// `GET /vms/{vm_id}`
    GetVmStatus(String),
    /// `POST /vms/{vm_id}/start`
    StartVm(String),
    /// `POST /vms/{vm_id}/stop`
    StopVm(String),
    /// `POST /vms/{vm_id}/snapshot`
    SnapshotVm(String),
    /// `GET /vms/{vm_id}/metrics`
    GetVmMetrics(String),
    /// `POST /snapshots/{snapshot_id}/restore`
    RestoreSnapshot(String),
}

/// Match an HTTP method and path to a route.
///
/// Returns `None` if the method/path combination does not match any
/// defined route.
pub fn match_route(method: &str, path: &str) -> Option<Route> {
    // Strip trailing slash for consistency (except root).
    let path = if path.len() > 1 && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    };

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (method, segments.as_slice()) {
        ("POST", ["vms"]) => Some(Route::CreateVm),
        ("GET", ["vms", vm_id]) => Some(Route::GetVmStatus(vm_id.to_string())),
        ("POST", ["vms", vm_id, "start"]) => Some(Route::StartVm(vm_id.to_string())),
        ("POST", ["vms", vm_id, "stop"]) => Some(Route::StopVm(vm_id.to_string())),
        ("POST", ["vms", vm_id, "snapshot"]) => Some(Route::SnapshotVm(vm_id.to_string())),
        ("GET", ["vms", vm_id, "metrics"]) => Some(Route::GetVmMetrics(vm_id.to_string())),
        ("POST", ["snapshots", snap_id, "restore"]) => {
            Some(Route::RestoreSnapshot(snap_id.to_string()))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Response envelope
// ---------------------------------------------------------------------------

/// An HTTP response produced by the router.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: &'static str,
    /// JSON response body (empty for 204).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Create a 201 Created response with a JSON body.
    fn created(body: &impl Serialize) -> Self {
        Self {
            status: 201,
            reason: "Created",
            body: serde_json::to_vec(body).expect("serialization cannot fail"),
        }
    }

    /// Create a 200 OK response with a JSON body.
    fn ok(body: &impl Serialize) -> Self {
        Self {
            status: 200,
            reason: "OK",
            body: serde_json::to_vec(body).expect("serialization cannot fail"),
        }
    }

    /// Create a 204 No Content response.
    fn no_content() -> Self {
        Self {
            status: 204,
            reason: "No Content",
            body: Vec::new(),
        }
    }

    /// Create an error response from a status and body.
    fn error(status: HttpStatus, body: &ErrorBody) -> Self {
        Self {
            status: status.code(),
            reason: status.reason(),
            body: body.to_json_bytes(),
        }
    }

    /// Create a 404 Not Found response for unknown routes.
    fn route_not_found() -> Self {
        Self::error(HttpStatus::NotFound, &ErrorBody::not_found("unknown route"))
    }
}

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

/// Dispatch a matched route to the lifecycle service.
///
/// This is the core handler: it validates path parameters, deserializes
/// request bodies, calls the service, and maps results to HTTP responses.
/// Business policy is entirely delegated to the service.
pub async fn dispatch(
    route: &Route,
    body: &[u8],
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    match route {
        Route::CreateVm => handle_create_vm(body, principal, service).await,
        Route::GetVmStatus(vm_id) => handle_get_status(vm_id, principal, service).await,
        Route::StartVm(vm_id) => handle_start_vm(vm_id, principal, service).await,
        Route::StopVm(vm_id) => handle_stop_vm(vm_id, principal, service).await,
        Route::SnapshotVm(vm_id) => handle_snapshot_vm(vm_id, principal, service).await,
        Route::GetVmMetrics(vm_id) => handle_get_metrics(vm_id, principal, service).await,
        Route::RestoreSnapshot(snap_id) => handle_restore(snap_id, principal, service).await,
    }
}

/// Handle a request that matched no route.
pub fn handle_unknown_route() -> HttpResponse {
    HttpResponse::route_not_found()
}

// ---------------------------------------------------------------------------
// Individual handlers
// ---------------------------------------------------------------------------

async fn handle_create_vm(
    body: &[u8],
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    let req: CreateVmRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::error(
                HttpStatus::BadRequest,
                &ErrorBody::bad_request(format!("invalid request body: {}", e)),
            );
        }
    };

    let spec = match ResourceSpec::new(
        req.vcpu_count,
        req.memory_mib,
        req.disk_mib,
        req.network_policy,
    ) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::error(
                HttpStatus::BadRequest,
                &ErrorBody {
                    error_code: ErrorCode::InvalidResourceSpec.as_str().to_string(),
                    message: e.reason,
                    context: Default::default(),
                },
            );
        }
    };

    match service.create(spec, principal.clone()).await {
        Ok(vm_id) => HttpResponse::created(&CreateVmResponse {
            vm_id: vm_id.to_string(),
        }),
        Err(e) => service_error_response(&e),
    }
}

async fn handle_get_status(
    vm_id_raw: &str,
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    let vm_id = match parse_vm_id(vm_id_raw) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match service.status(&vm_id, principal).await {
        Ok(status) => HttpResponse::ok(&VmStatusResponse {
            vm_id: status.vm_id.to_string(),
            state: status.state.as_str().to_string(),
            created_at: status.created_at.to_rfc3339(),
            resource_spec: ResourceSpecResponse {
                vcpu_count: status.resource_spec.vcpu_count(),
                memory_mib: status.resource_spec.memory_mib(),
                disk_mib: status.resource_spec.disk_mib(),
                network_policy: status.resource_spec.network_policy(),
            },
        }),
        Err(e) => service_error_response(&e),
    }
}

async fn handle_start_vm(
    vm_id_raw: &str,
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    let vm_id = match parse_vm_id(vm_id_raw) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match service.start(&vm_id, principal).await {
        Ok(()) => HttpResponse::no_content(),
        Err(e) => service_error_response(&e),
    }
}

async fn handle_stop_vm(
    vm_id_raw: &str,
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    let vm_id = match parse_vm_id(vm_id_raw) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match service.stop(&vm_id, principal).await {
        Ok(()) => HttpResponse::no_content(),
        Err(e) => service_error_response(&e),
    }
}

async fn handle_snapshot_vm(
    vm_id_raw: &str,
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    let vm_id = match parse_vm_id(vm_id_raw) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match service.snapshot(&vm_id, principal).await {
        Ok(snap_id) => HttpResponse::created(&SnapshotVmResponse {
            snapshot_id: snap_id.to_string(),
        }),
        Err(e) => service_error_response(&e),
    }
}

async fn handle_get_metrics(
    vm_id_raw: &str,
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    let vm_id = match parse_vm_id(vm_id_raw) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match service.metrics(&vm_id, principal).await {
        Ok(metrics) => HttpResponse::ok(&VmMetricsResponse {
            vm_id: metrics.vm_id.to_string(),
            state: metrics.state.as_str().to_string(),
            record: metrics.record,
        }),
        Err(e) => service_error_response(&e),
    }
}

async fn handle_restore(
    snap_id_raw: &str,
    principal: &Principal,
    service: &Arc<dyn LifecycleService>,
) -> HttpResponse {
    let snap_id = match parse_snapshot_id(snap_id_raw) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match service.restore(&snap_id, principal).await {
        Ok(vm_id) => HttpResponse::created(&RestoreVmResponse {
            vm_id: vm_id.to_string(),
        }),
        Err(e) => service_error_response(&e),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse and validate a VM identifier from a path segment.
fn parse_vm_id(raw: &str) -> Result<VmId, HttpResponse> {
    VmId::new(raw).map_err(|e| {
        HttpResponse::error(
            HttpStatus::BadRequest,
            &ErrorBody::invalid_id(format!("invalid vm_id: {}", e.reason)),
        )
    })
}

/// Parse and validate a snapshot identifier from a path segment.
fn parse_snapshot_id(raw: &str) -> Result<SnapshotId, HttpResponse> {
    SnapshotId::new(raw).map_err(|e| {
        HttpResponse::error(
            HttpStatus::BadRequest,
            &ErrorBody::invalid_id(format!("invalid snapshot_id: {}", e.reason)),
        )
    })
}

/// Convert a service error to an HTTP error response.
fn service_error_response(err: &MicrovmError) -> HttpResponse {
    let status = crate::error::microvm_error_status(err);
    HttpResponse::error(status, &ErrorBody::from_microvm_error(err))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Route matching tests -----------------------------------------------

    #[test]
    fn match_create_vm() {
        assert_eq!(match_route("POST", "/vms"), Some(Route::CreateVm));
    }

    #[test]
    fn match_get_vm_status() {
        assert_eq!(
            match_route("GET", "/vms/vm-001"),
            Some(Route::GetVmStatus("vm-001".to_string()))
        );
    }

    #[test]
    fn match_start_vm() {
        assert_eq!(
            match_route("POST", "/vms/vm-001/start"),
            Some(Route::StartVm("vm-001".to_string()))
        );
    }

    #[test]
    fn match_stop_vm() {
        assert_eq!(
            match_route("POST", "/vms/vm-001/stop"),
            Some(Route::StopVm("vm-001".to_string()))
        );
    }

    #[test]
    fn match_snapshot_vm() {
        assert_eq!(
            match_route("POST", "/vms/vm-001/snapshot"),
            Some(Route::SnapshotVm("vm-001".to_string()))
        );
    }

    #[test]
    fn match_get_metrics() {
        assert_eq!(
            match_route("GET", "/vms/vm-001/metrics"),
            Some(Route::GetVmMetrics("vm-001".to_string()))
        );
    }

    #[test]
    fn match_restore_snapshot() {
        assert_eq!(
            match_route("POST", "/snapshots/snap-001/restore"),
            Some(Route::RestoreSnapshot("snap-001".to_string()))
        );
    }

    #[test]
    fn unknown_route_returns_none() {
        assert_eq!(match_route("GET", "/unknown"), None);
        assert_eq!(match_route("DELETE", "/vms/vm-001"), None);
        assert_eq!(match_route("POST", "/vms/vm-001/unknown"), None);
        assert_eq!(match_route("GET", "/"), None);
    }

    #[test]
    fn trailing_slash_is_stripped() {
        assert_eq!(match_route("POST", "/vms/"), Some(Route::CreateVm));
        assert_eq!(
            match_route("GET", "/vms/vm-001/"),
            Some(Route::GetVmStatus("vm-001".to_string()))
        );
    }

    #[test]
    fn wrong_method_returns_none() {
        assert_eq!(match_route("GET", "/vms"), None);
        assert_eq!(match_route("POST", "/vms/vm-001"), None);
        assert_eq!(match_route("GET", "/vms/vm-001/start"), None);
    }

    // -- ID validation tests ------------------------------------------------

    #[test]
    fn parse_vm_id_valid() {
        assert!(parse_vm_id("vm-001").is_ok());
        assert!(parse_vm_id("a").is_ok());
    }

    #[test]
    fn parse_vm_id_invalid() {
        assert!(parse_vm_id("").is_err());
        assert!(parse_vm_id("VM-001").is_err());
        assert!(parse_vm_id("vm/001").is_err());
    }

    #[test]
    fn parse_snapshot_id_valid() {
        assert!(parse_snapshot_id("snap-001").is_ok());
    }

    #[test]
    fn parse_snapshot_id_invalid() {
        assert!(parse_snapshot_id("").is_err());
        assert!(parse_snapshot_id("snap..bad").is_err());
    }

    // -- Request deserialization tests --------------------------------------

    #[test]
    fn create_vm_request_deserializes() {
        let json = r#"{"vcpu_count":2,"memory_mib":512,"disk_mib":1024}"#;
        let req: CreateVmRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.vcpu_count, 2);
        assert_eq!(req.memory_mib, 512);
        assert_eq!(req.disk_mib, 1024);
        assert_eq!(req.network_policy, NetworkPolicy::None);
    }

    #[test]
    fn create_vm_request_with_network_policy() {
        let json =
            r#"{"vcpu_count":4,"memory_mib":1024,"disk_mib":2048,"network_policy":"nat_only"}"#;
        let req: CreateVmRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.network_policy, NetworkPolicy::NatOnly);
    }

    #[test]
    fn create_vm_request_missing_field_fails() {
        let json = r#"{"vcpu_count":2,"memory_mib":512}"#;
        assert!(serde_json::from_str::<CreateVmRequest>(json).is_err());
    }

    // -- Response serialization tests ---------------------------------------

    #[test]
    fn create_vm_response_serializes() {
        let resp = CreateVmResponse {
            vm_id: "vm-001".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("vm-001"));
    }

    #[test]
    fn vm_status_response_serializes() {
        let resp = VmStatusResponse {
            vm_id: "vm-001".to_string(),
            state: "running".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            resource_spec: ResourceSpecResponse {
                vcpu_count: 2,
                memory_mib: 512,
                disk_mib: 1024,
                network_policy: NetworkPolicy::None,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("running"));
        assert!(json.contains("vcpu_count"));
    }

    // -- Error response tests -----------------------------------------------

    #[test]
    fn service_error_maps_to_correct_status() {
        let err = MicrovmError::new(ErrorCode::PermissionDenied, "denied");
        let resp = service_error_response(&err);
        assert_eq!(resp.status, 403);
    }

    #[test]
    fn not_found_error_maps_to_404() {
        let err = MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM");
        let resp = service_error_response(&err);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn conflict_error_maps_to_409() {
        let err = MicrovmError::new(ErrorCode::InvalidTransition, "bad transition");
        let resp = service_error_response(&err);
        assert_eq!(resp.status, 409);
    }
}
