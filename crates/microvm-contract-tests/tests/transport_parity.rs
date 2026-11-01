//! REST/gRPC transport parity, socket-hardening, and request-audit contract
//! tests (plan todo 18).
//!
//! Both transports are driven end-to-end over real Unix domain sockets and are
//! backed by the same [`VmLifecycleService`] instance, so the same request
//! reaches the same service result regardless of transport. These tests assert:
//!
//! - Operation parity: every lifecycle operation has one REST and one gRPC
//!   happy fixture, and the normalized results match.
//! - Error parity: every operation has an invalid/unauthorized fixture, and
//!   the stable `error_code` (plus the transport-specific status/code) matches
//!   across transports; the structured error body is byte-identical.
//! - Socket hardening: both sockets are mode `0660`; an insecure
//!   (world-writable) mode is rejected; neither transport binds any TCP endpoint.
//! - Audit: a denied request writes exactly one `Denied` audit event.
//!
//! Authorization is delegated entirely to the service; nothing here duplicates
//! or weakens it: the tests only assert that both adapters enforce it.

mod common;

use common::*;
use microvm_grpc::error::error_body_from_status;
use microvm_grpc::proto::v1::{
    CreateVmRequest, GetVmMetricsRequest, GetVmStatusRequest, NetworkPolicy as ProtoNetworkPolicy,
    StartVmRequest,
};
use microvm_grpc::GrpcServer;
use microvm_lifecycle::policy::{AuditResult, Operation};
use microvm_lifecycle::LifecycleService;
use microvm_rest::RestServer;
use microvm_types::{Principal, Role, TenantId};
use std::os::unix::fs::FileTypeExt;
use tonic::Code;

// ===========================================================================
// Operation parity: same request -> same service result on both transports
// ===========================================================================

#[tokio::test]
async fn happy_parity_every_operation_rest_eq_grpc() {
    let rig = Rig::new();
    let t = rig.spawn(rig.owner.clone(), "happy").await;
    let mut grpc = t.grpc().await;

    // CreateVm: deterministic id derived from the spec -> identical result.
    let rest = rest_create(&t.rest_sock, 2, 512, 1024).await;
    let grpc_r = grpc_create(&mut grpc, 2, 512, 1024).await;
    assert_eq!(rest, grpc_r, "create parity");
    assert_eq!(rest, OpResult::Created("vm-512mib".to_string()));

    // GetVmStatus (state == created): same view from both transports.
    let rest = rest_status(&t.rest_sock, "vm-512mib").await;
    let grpc_r = grpc_status(&mut grpc, "vm-512mib").await;
    assert_eq!(rest, grpc_r, "status(created) parity");
    assert!(
        matches!(rest, OpResult::Status { ref state, vcpu: 2, mem: 512, disk: 1024, .. } if state == "created")
    );

    // StartVm: REST starts; gRPC observes the idempotent no-op -> both Started.
    let rest = rest_start(&t.rest_sock, "vm-512mib").await;
    let grpc_r = grpc_start(&mut grpc, "vm-512mib").await;
    assert_eq!(rest, grpc_r, "start parity");
    assert_eq!(rest, OpResult::Started);

    // GetVmStatus (state == running) after start.
    let rest = rest_status(&t.rest_sock, "vm-512mib").await;
    let grpc_r = grpc_status(&mut grpc, "vm-512mib").await;
    assert_eq!(rest, grpc_r, "status(running) parity");
    assert!(matches!(rest, OpResult::Status { ref state, .. } if state == "running"));

    // SnapshotVm: deterministic snapshot id -> identical result.
    let rest = rest_snapshot(&t.rest_sock, "vm-512mib").await;
    let grpc_r = grpc_snapshot(&mut grpc, "vm-512mib").await;
    assert_eq!(rest, grpc_r, "snapshot parity");
    assert_eq!(rest, OpResult::Snapshotted("snap-vm-512mib".to_string()));

    // GetVmMetrics: same state from both transports.
    let rest = rest_metrics(&t.rest_sock, "vm-512mib").await;
    let grpc_r = grpc_metrics(&mut grpc, "vm-512mib").await;
    assert_eq!(rest, grpc_r, "metrics parity");
    assert_eq!(
        rest,
        OpResult::Metrics {
            vm_id: "vm-512mib".to_string(),
            state: "running".to_string()
        }
    );

    // RestoreVm: deterministic restored id -> identical result.
    let rest = rest_restore(&t.rest_sock, "snap-vm-512mib").await;
    let grpc_r = grpc_restore(&mut grpc, "snap-vm-512mib").await;
    assert_eq!(rest, grpc_r, "restore parity");
    assert_eq!(
        rest,
        OpResult::Restored("vm-restored-snap-vm-512mib".to_string())
    );

    // StopVm: REST stops; gRPC observes the idempotent no-op -> both Stopped.
    let rest = rest_stop(&t.rest_sock, "vm-512mib").await;
    let grpc_r = grpc_stop(&mut grpc, "vm-512mib").await;
    assert_eq!(rest, grpc_r, "stop parity");
    assert_eq!(rest, OpResult::Stopped);

    t.shutdown();
}

// ===========================================================================
// Metrics record (plan todo 23) is exposed via BOTH UDS transports
// ===========================================================================

/// The full, availability-flagged `VmMetricsRecord` must be reachable over both
/// the REST and gRPC Unix-socket APIs. REST returns it as structured JSON under
/// `record`; gRPC returns the same canonical JSON in `metrics_json`. The
/// deterministic parts of the record (identity, schema version, phase, and the
/// availability flags) must agree across transports.
#[tokio::test]
async fn metrics_record_schema_exposed_on_both_transports() {
    let rig = Rig::new();
    let t = rig.spawn(rig.owner.clone(), "metrics-schema").await;
    let mut grpc = t.grpc().await;

    // Create the VM so metrics has a subject.
    let created = rest_create(&t.rest_sock, 2, 512, 1024).await;
    assert_eq!(created, OpResult::Created("vm-512mib".to_string()));

    // -- REST: structured record under `record` ----------------------------
    let r = rest_call(&t.rest_sock, "GET", "/vms/vm-512mib/metrics", None).await;
    assert_eq!(r.status, 200);
    let rest_record = &r.body["record"];
    assert_eq!(rest_record["vm_id"], serde_json::json!("vm-512mib"));
    assert_eq!(rest_record["schema_version"], serde_json::json!(1));
    assert!(rest_record["phase"].is_string());
    assert!(rest_record["collected_at"].is_string());
    assert!(rest_record["monotonic_ns"].is_number());
    // The in-memory backend has no host collector: every source is flagged
    // unavailable (never zero-filled).
    for source in ["cgroup", "network", "guest"] {
        assert_eq!(rest_record[source]["available"], serde_json::json!(false));
        assert_eq!(
            rest_record[source]["reason"],
            serde_json::json!("no_backend")
        );
        assert!(rest_record[source].get("value").is_none());
    }

    // -- gRPC: canonical record JSON in `metrics_json` ---------------------
    let resp = grpc
        .get_vm_metrics(GetVmMetricsRequest {
            vm_id: "vm-512mib".to_string(),
        })
        .await
        .expect("grpc metrics");
    let grpc_record: serde_json::Value =
        serde_json::from_str(&resp.into_inner().metrics_json).expect("metrics_json is valid JSON");

    // -- Deterministic parity between the two transports -------------------
    for field in [
        "vm_id",
        "schema_version",
        "phase",
        "cgroup",
        "network",
        "guest",
        "errors",
    ] {
        assert_eq!(
            rest_record[field], grpc_record[field],
            "metrics field {field} must match across transports"
        );
    }

    t.shutdown();
}

// ===========================================================================
// Error parity: invalid / not-found fixtures agree across transports
// ===========================================================================

#[tokio::test]
async fn error_parity_invalid_input_and_not_found() {
    let rig = Rig::new();
    let t = rig.spawn(rig.owner.clone(), "errors").await;
    let mut grpc = t.grpc().await;

    // CreateVm with zero vCPUs -> invalid_resource_spec on both transports.
    let rest = rest_create(&t.rest_sock, 0, 512, 1024).await;
    let grpc_r = grpc_create(&mut grpc, 0, 512, 1024).await;
    assert_eq!(rest, grpc_r, "create invalid parity");
    assert_eq!(
        rest,
        OpResult::Error {
            code: "invalid_resource_spec".to_string()
        }
    );

    // Malformed vm_id (uppercase) -> invalid_id on start/stop/snapshot/status/metrics.
    for (name, rest_r, grpc_r) in [
        (
            "start",
            rest_start(&t.rest_sock, "BAD-ID").await,
            grpc_start(&mut grpc, "BAD-ID").await,
        ),
        (
            "stop",
            rest_stop(&t.rest_sock, "BAD-ID").await,
            grpc_stop(&mut grpc, "BAD-ID").await,
        ),
        (
            "snapshot",
            rest_snapshot(&t.rest_sock, "BAD-ID").await,
            grpc_snapshot(&mut grpc, "BAD-ID").await,
        ),
        (
            "status",
            rest_status(&t.rest_sock, "BAD-ID").await,
            grpc_status(&mut grpc, "BAD-ID").await,
        ),
        (
            "metrics",
            rest_metrics(&t.rest_sock, "BAD-ID").await,
            grpc_metrics(&mut grpc, "BAD-ID").await,
        ),
    ] {
        assert_eq!(rest_r, grpc_r, "{name} invalid-id parity");
        assert_eq!(
            rest_r,
            OpResult::Error {
                code: "invalid_id".to_string()
            },
            "{name} invalid-id code"
        );
    }

    // GetVmStatus for an unknown VM -> artifact_not_found on both transports.
    let rest = rest_status(&t.rest_sock, "missing-vm").await;
    let grpc_r = grpc_status(&mut grpc, "missing-vm").await;
    assert_eq!(rest, grpc_r, "status not-found parity");
    assert_eq!(
        rest,
        OpResult::Error {
            code: "artifact_not_found".to_string()
        }
    );

    // RestoreVm with a malformed snapshot id -> invalid_id on both transports.
    let rest = rest_restore(&t.rest_sock, "BAD..ID").await;
    let grpc_r = grpc_restore(&mut grpc, "BAD..ID").await;
    assert_eq!(rest, grpc_r, "restore invalid-id parity");
    assert_eq!(
        rest,
        OpResult::Error {
            code: "invalid_id".to_string()
        }
    );

    // RestoreVm of an unknown snapshot -> artifact_not_found on both transports.
    let rest = rest_restore(&t.rest_sock, "missing-snap").await;
    let grpc_r = grpc_restore(&mut grpc, "missing-snap").await;
    assert_eq!(rest, grpc_r, "restore not-found parity");
    assert_eq!(
        rest,
        OpResult::Error {
            code: "artifact_not_found".to_string()
        }
    );

    t.shutdown();
}

// ===========================================================================
// Transport-code mapping: REST HTTP status <-> gRPC code agree per error
// ===========================================================================

#[tokio::test]
async fn transport_status_and_code_mapping_agree() {
    let rig = Rig::new();

    // Owner transport for invalid/not-found errors.
    let owner_t = rig.spawn(rig.owner.clone(), "map-owner").await;
    let mut grpc = owner_t.grpc().await;

    // invalid_resource_spec -> REST 400 / gRPC InvalidArgument.
    let raw = rest_call_raw(
        &owner_t.rest_sock,
        "POST",
        "/vms",
        Some(r#"{"vcpu_count":0,"memory_mib":512,"disk_mib":1024}"#),
    )
    .await;
    assert_eq!(raw.status, 400);
    let err = grpc
        .create_vm(CreateVmRequest {
            vcpu_count: 0,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        error_body_from_status(&err).unwrap().error_code,
        "invalid_resource_spec"
    );

    // invalid_id -> REST 400 / gRPC InvalidArgument.
    let raw = rest_call_raw(&owner_t.rest_sock, "POST", "/vms/BAD-ID/start", Some("")).await;
    assert_eq!(raw.status, 400);
    let err = grpc
        .start_vm(StartVmRequest {
            vm_id: "BAD-ID".to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        error_body_from_status(&err).unwrap().error_code,
        "invalid_id"
    );

    // artifact_not_found -> REST 404 / gRPC NotFound.
    let raw = rest_call_raw(&owner_t.rest_sock, "GET", "/vms/missing-vm", None).await;
    assert_eq!(raw.status, 404);
    let err = grpc
        .get_vm_status(GetVmStatusRequest {
            vm_id: "missing-vm".to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(
        error_body_from_status(&err).unwrap().error_code,
        "artifact_not_found"
    );

    owner_t.shutdown();

    // Viewer transport for permission_denied -> REST 403 / gRPC PermissionDenied.
    let viewer_t = rig.spawn(rig.viewer.clone(), "map-viewer").await;
    let mut vgrpc = viewer_t.grpc().await;
    let raw = rest_call_raw(
        &viewer_t.rest_sock,
        "POST",
        "/vms",
        Some(r#"{"vcpu_count":2,"memory_mib":512,"disk_mib":1024}"#),
    )
    .await;
    assert_eq!(raw.status, 403);
    let err = vgrpc
        .create_vm(CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        error_body_from_status(&err).unwrap().error_code,
        "permission_denied"
    );
    viewer_t.shutdown();
}

// ===========================================================================
// Byte-identical structured error body across transports
// ===========================================================================

#[tokio::test]
async fn error_body_bytes_identical_rest_and_grpc() {
    let rig = Rig::new();
    let t = rig.spawn(rig.owner.clone(), "bytes").await;
    let mut grpc = t.grpc().await;

    // The same service error (unknown VM) must serialize to byte-identical
    // structured error bodies: REST HTTP body == gRPC status details.
    let raw = rest_call_raw(&t.rest_sock, "GET", "/vms/missing-vm", None).await;
    assert_eq!(raw.status, 404);

    let err = grpc
        .get_vm_status(GetVmStatusRequest {
            vm_id: "missing-vm".to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    assert_eq!(
        raw.body,
        err.details().to_vec(),
        "REST error body and gRPC status details must be byte-identical"
    );
    // Sanity: the shared body carries the stable code and context.
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "artifact_not_found");
    assert_eq!(body.context.get("vm_id").unwrap(), "missing-vm");

    t.shutdown();
}

// ===========================================================================
// Authorization parity + exactly-one-audit-event for denied requests
// ===========================================================================

/// Assert the audit log grew by exactly one `Denied` event for `op`.
fn assert_single_denied_event(rig: &Rig, before: usize, op: Operation) {
    assert_eq!(
        rig.audit_len(),
        before + 1,
        "a denied request must write exactly one audit event"
    );
    let event = rig.last_audit();
    assert_eq!(
        event.result,
        AuditResult::Denied,
        "denied request audits Denied"
    );
    assert_eq!(
        event.operation, op,
        "audit event records the attempted operation"
    );
}

#[tokio::test]
async fn denied_role_request_parity_and_single_audit_event() {
    let rig = Rig::new();

    // Set up a running VM as the owner.
    let owner_t = rig.spawn(rig.owner.clone(), "deny-owner").await;
    assert_eq!(
        rest_create(&owner_t.rest_sock, 2, 512, 1024).await,
        OpResult::Created("vm-512mib".to_string())
    );
    assert_eq!(
        rest_start(&owner_t.rest_sock, "vm-512mib").await,
        OpResult::Started
    );
    owner_t.shutdown();

    // The viewer (read-only role) is denied every mutating operation. Each
    // denied request must produce the same error on both transports and write
    // exactly one Denied audit event.
    let viewer_t = rig.spawn(rig.viewer.clone(), "deny-viewer").await;
    let mut grpc = viewer_t.grpc().await;

    // CreateVm (role lacks Create).
    let before = rig.audit_len();
    let rest = rest_create(&viewer_t.rest_sock, 2, 512, 1024).await;
    assert_eq!(
        rest,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_single_denied_event(&rig, before, Operation::Create);
    let before = rig.audit_len();
    let grpc_r = grpc_create(&mut grpc, 2, 512, 1024).await;
    assert_eq!(
        grpc_r,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_eq!(rest, grpc_r, "create denied parity");
    assert_single_denied_event(&rig, before, Operation::Create);

    // StartVm (role lacks Start).
    let before = rig.audit_len();
    let rest = rest_start(&viewer_t.rest_sock, "vm-512mib").await;
    assert_eq!(
        rest,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_single_denied_event(&rig, before, Operation::Start);
    let before = rig.audit_len();
    let grpc_r = grpc_start(&mut grpc, "vm-512mib").await;
    assert_eq!(
        grpc_r,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_eq!(rest, grpc_r, "start denied parity");
    assert_single_denied_event(&rig, before, Operation::Start);

    // StopVm (role lacks Stop).
    let before = rig.audit_len();
    let rest = rest_stop(&viewer_t.rest_sock, "vm-512mib").await;
    assert_eq!(
        rest,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_single_denied_event(&rig, before, Operation::Stop);
    let before = rig.audit_len();
    let grpc_r = grpc_stop(&mut grpc, "vm-512mib").await;
    assert_eq!(
        grpc_r,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_eq!(rest, grpc_r, "stop denied parity");
    assert_single_denied_event(&rig, before, Operation::Stop);

    // SnapshotVm (role lacks Snapshot).
    let before = rig.audit_len();
    let rest = rest_snapshot(&viewer_t.rest_sock, "vm-512mib").await;
    assert_eq!(
        rest,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_single_denied_event(&rig, before, Operation::Snapshot);
    let before = rig.audit_len();
    let grpc_r = grpc_snapshot(&mut grpc, "vm-512mib").await;
    assert_eq!(
        grpc_r,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_eq!(rest, grpc_r, "snapshot denied parity");
    assert_single_denied_event(&rig, before, Operation::Snapshot);

    viewer_t.shutdown();
}

#[tokio::test]
async fn denied_cross_tenant_request_parity_and_single_audit_event() {
    let rig = Rig::new();

    // Owner of `acme` creates and starts a VM.
    let owner_t = rig.spawn(rig.owner.clone(), "xtenant-owner").await;
    assert_eq!(
        rest_create(&owner_t.rest_sock, 2, 512, 1024).await,
        OpResult::Created("vm-512mib".to_string())
    );
    assert_eq!(
        rest_start(&owner_t.rest_sock, "vm-512mib").await,
        OpResult::Started
    );
    owner_t.shutdown();

    // An owner of a *different* tenant is denied access to acme's VM.
    let intruder = Principal::new(TenantId::new("globex").unwrap(), Role::Owner);
    let intruder_t = rig.spawn(intruder, "xtenant-intruder").await;
    let mut grpc = intruder_t.grpc().await;

    let before = rig.audit_len();
    let rest = rest_start(&intruder_t.rest_sock, "vm-512mib").await;
    assert_eq!(
        rest,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_single_denied_event(&rig, before, Operation::Start);

    let before = rig.audit_len();
    let grpc_r = grpc_start(&mut grpc, "vm-512mib").await;
    assert_eq!(
        grpc_r,
        OpResult::Error {
            code: "permission_denied".to_string()
        }
    );
    assert_eq!(rest, grpc_r, "cross-tenant start denied parity");
    assert_single_denied_event(&rig, before, Operation::Start);

    intruder_t.shutdown();
}

// ===========================================================================
// Socket hardening: mode 0660, insecure-mode rejection, no-TCP policy
// ===========================================================================

#[tokio::test]
async fn both_sockets_are_created_with_mode_0660() {
    use std::os::unix::fs::PermissionsExt;

    let rig = Rig::new();
    let t = rig.spawn(rig.owner.clone(), "mode").await;

    for sock in [&t.rest_sock, &t.grpc_sock] {
        let meta = std::fs::metadata(sock).unwrap();
        assert!(
            meta.file_type().is_socket(),
            "{} must be a socket",
            sock.display()
        );
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o660,
            "{} must be mode 0660",
            sock.display()
        );
    }

    t.shutdown();
}

#[test]
fn insecure_socket_mode_is_rejected_by_both_transports() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;

    // A socket left world-writable (an insecure mode) must fail the secure
    // validator (which expects 0660) on BOTH transports.
    for insecure_mode in [0o777u32, 0o666, 0o644] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = StdUnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(insecure_mode)).unwrap();

        let rest_cfg = microvm_rest::SocketConfig::with_path(&path).with_mode(0o660);
        assert!(
            RestServer::validate_socket(&path, &rest_cfg).is_err(),
            "REST must reject insecure mode {insecure_mode:04o}"
        );

        let grpc_cfg = microvm_grpc::SocketConfig::with_path(&path).with_mode(0o660);
        assert!(
            GrpcServer::validate_socket(&path, &grpc_cfg).is_err(),
            "gRPC must reject insecure mode {insecure_mode:04o}"
        );

        drop(listener);
    }
}

// --- No-TCP policy ---------------------------------------------------------

const REST_SOURCES: &[(&str, &str)] = &[
    ("rest/lib.rs", include_str!("../../microvm-rest/src/lib.rs")),
    (
        "rest/config.rs",
        include_str!("../../microvm-rest/src/config.rs"),
    ),
    (
        "rest/server.rs",
        include_str!("../../microvm-rest/src/server.rs"),
    ),
];

const GRPC_SOURCES: &[(&str, &str)] = &[
    ("grpc/lib.rs", include_str!("../../microvm-grpc/src/lib.rs")),
    (
        "grpc/config.rs",
        include_str!("../../microvm-grpc/src/config.rs"),
    ),
    (
        "grpc/server.rs",
        include_str!("../../microvm-grpc/src/server.rs"),
    ),
];

/// Mirror of the platform's canonical forbidden TCP patterns (todo 8), plus the
/// TCP listener/socket type names a Unix-only server must never reference.
const FORBIDDEN_TCP_PATTERNS: &[&str] = &[
    "0.0.0.0",
    "127.0.0.1",
    "tcp://",
    "[::]",
    "::1",
    "localhost:",
];
const FORBIDDEN_TCP_TYPES: &[&str] = &["TcpListener", "TcpSocket", "TcpStream", "to_socket_addrs"];

fn tcp_violations(content: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for line in content.lines() {
        for pattern in FORBIDDEN_TCP_PATTERNS
            .iter()
            .chain(FORBIDDEN_TCP_TYPES.iter())
        {
            if line.contains(pattern) {
                violations.push(format!("'{pattern}' in: {}", line.trim()));
            }
        }
    }
    violations
}

#[test]
fn neither_transport_binds_a_tcp_endpoint() {
    for (name, content) in REST_SOURCES.iter().chain(GRPC_SOURCES.iter()) {
        let violations = tcp_violations(content);
        assert!(
            violations.is_empty(),
            "forbidden TCP pattern in {name}:\n{}",
            violations.join("\n")
        );
    }

    // Both servers must bind a UnixListener (positive control).
    let rest_server = include_str!("../../microvm-rest/src/server.rs");
    let grpc_server = include_str!("../../microvm-grpc/src/server.rs");
    assert!(
        rest_server.contains("UnixListener"),
        "REST server must use UnixListener"
    );
    assert!(
        grpc_server.contains("UnixListener"),
        "gRPC server must use UnixListener"
    );
    assert!(
        grpc_server.contains("serve_with_incoming"),
        "gRPC server must serve over the Unix incoming stream"
    );
}

#[tokio::test]
async fn tcp_config_fails_to_reach_the_api() {
    // The API is reachable only via its Unix socket; a TCP connection to the
    // loopback (mirroring `grpcurl -plaintext 127.0.0.1:50051 ...`) must fail
    // because no orchestrator TCP listener exists.
    let rig = Rig::new();
    let t = rig.spawn(rig.owner.clone(), "tcp").await;

    // Positive control: the Unix socket serves the API.
    assert_eq!(
        rest_create(&t.rest_sock, 2, 512, 1024).await,
        OpResult::Created("vm-512mib".to_string())
    );

    // Negative control: TCP to the loopback control port does not reach it.
    let tcp = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::TcpStream::connect("127.0.0.1:50051"),
    )
    .await;
    assert!(
        !matches!(tcp, Ok(Ok(_))),
        "no TCP endpoint may exist for the orchestrator API"
    );

    t.shutdown();
}

// ===========================================================================
// Backend bound: the production service satisfies the transport backend
// ===========================================================================

#[test]
fn vm_lifecycle_service_satisfies_both_transport_backends() {
    // Compile-time proof that the composed production service can back both
    // adapters (they share the same `LifecycleService` contract).
    fn assert_backend<T: LifecycleService + 'static>() {}
    assert_backend::<microvm_service::VmLifecycleService>();
}
