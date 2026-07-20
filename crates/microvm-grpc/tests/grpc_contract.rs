//! Integration tests for the gRPC Unix socket API.
//!
//! These tests verify, deterministically and without KVM/root/Firecracker:
//! - **RPC handling**: all 7 `MicrovmService` RPCs dispatch to the lifecycle
//!   service and return correct responses (both in-process and end-to-end over
//!   a real Unix socket).
//! - **Error mapping**: every [`ErrorCode`] maps to a deterministic gRPC code,
//!   and the stable `error_code` survives in the status details.
//! - **REST parity**: the *same* request through REST and gRPC reaches the
//!   *same* service result, and the gRPC error details are byte-identical to
//!   the REST error body.
//! - **Authentication**: an unauthenticated peer receives `PermissionDenied`.
//! - **No-TCP**: the server source binds only a Unix socket (static scan).
//! - **No-reflection**: reflection stays disabled and unregistered.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hyper_util::rt::tokio::TokioIo;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_grpc::error::{error_body_from_status, error_code_to_grpc};
use microvm_grpc::peer::{
    PeerAuthenticator, PeerConnectInfo, PeerCredentials, StaticAuthenticator,
};
use microvm_grpc::proto::v1::microvm_service_client::MicrovmServiceClient;
use microvm_grpc::proto::v1::microvm_service_server::MicrovmService;
use microvm_grpc::proto::v1::{
    CreateVmRequest, GetVmMetricsRequest, GetVmStatusRequest, NetworkPolicy as ProtoNetworkPolicy,
    RestoreVmRequest, SnapshotVmRequest, StartVmRequest, StopVmRequest, VmState as ProtoVmState,
};
use microvm_grpc::server::REFLECTION_ENABLED;
use microvm_grpc::{GrpcServer, MicrovmGrpcService, SocketConfig};
use microvm_lifecycle::{LifecycleService, VmMetrics, VmState, VmStatus};
use microvm_metrics::VmMetricsRecord;
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, SnapshotId, TenantId, VmId};
use tonic::transport::{Channel, Uri};
use tonic::{Code, Request};

// ---------------------------------------------------------------------------
// Mock lifecycle service (deterministic, shared by REST + gRPC parity tests)
// ---------------------------------------------------------------------------

struct MockService {
    errors: Mutex<HashMap<String, MicrovmError>>,
    calls: Mutex<Vec<String>>,
}

impl MockService {
    fn new() -> Self {
        Self {
            errors: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with_error(self, key: &str, err: MicrovmError) -> Self {
        self.errors.lock().unwrap().insert(key.to_string(), err);
        self
    }

    fn check_error(&self, key: &str) -> Option<MicrovmError> {
        self.errors.lock().unwrap().get(key).cloned()
    }

    fn record(&self, op: &str) {
        self.calls.lock().unwrap().push(op.to_string());
    }
}

fn fixed_created_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

#[async_trait]
impl LifecycleService for MockService {
    async fn create(&self, spec: ResourceSpec, _owner: Principal) -> Result<VmId, MicrovmError> {
        self.record("create");
        if let Some(e) = self.check_error("create") {
            return Err(e);
        }
        let id = format!("vm-{}mib", spec.memory_mib());
        VmId::new(id).map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn start(&self, vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        self.record("start");
        if let Some(e) = self.check_error("start") {
            return Err(e);
        }
        if vm_id.as_str() == "missing-vm" {
            return Err(MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str()));
        }
        Ok(())
    }

    async fn stop(&self, vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        self.record("stop");
        if let Some(e) = self.check_error("stop") {
            return Err(e);
        }
        if vm_id.as_str() == "missing-vm" {
            return Err(MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str()));
        }
        Ok(())
    }

    async fn snapshot(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError> {
        self.record("snapshot");
        if let Some(e) = self.check_error("snapshot") {
            return Err(e);
        }
        if vm_id.as_str() == "missing-vm" {
            return Err(MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str()));
        }
        SnapshotId::new(format!("snap-{}", vm_id.as_str()))
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        _principal: &Principal,
    ) -> Result<VmId, MicrovmError> {
        self.record("restore");
        if let Some(e) = self.check_error("restore") {
            return Err(e);
        }
        if snapshot_id.as_str() == "missing-snap" {
            return Err(
                MicrovmError::new(ErrorCode::ArtifactNotFound, "no such snapshot")
                    .with_context("snapshot_id", snapshot_id.as_str()),
            );
        }
        VmId::new(format!("vm-restored-{}", snapshot_id.as_str()))
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn status(&self, vm_id: &VmId, _principal: &Principal) -> Result<VmStatus, MicrovmError> {
        self.record("status");
        if let Some(e) = self.check_error("status") {
            return Err(e);
        }
        if vm_id.as_str() == "missing-vm" {
            return Err(MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str()));
        }
        Ok(VmStatus {
            vm_id: vm_id.clone(),
            state: VmState::Running,
            created_at: fixed_created_at(),
            resource_spec: ResourceSpec::new(2, 512, 1024, NetworkPolicy::None).unwrap(),
        })
    }

    async fn metrics(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<VmMetrics, MicrovmError> {
        self.record("metrics");
        if let Some(e) = self.check_error("metrics") {
            return Err(e);
        }
        if vm_id.as_str() == "missing-vm" {
            return Err(MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str()));
        }
        Ok(VmMetrics {
            record: VmMetricsRecord::not_collected(
                vm_id.clone(),
                VmState::Running.metrics_phase(),
                Utc::now(),
                0,
            ),
            vm_id: vm_id.clone(),
            state: VmState::Running,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_principal() -> Principal {
    Principal::new(TenantId::new("test-tenant").unwrap(), Role::Owner)
}

/// Build a gRPC request carrying an authenticated peer principal in its
/// connection-info extensions (as the server would after `SO_PEERCRED`).
fn authed_request<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.extensions_mut().insert(PeerConnectInfo {
        creds: PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        },
        principal: Some(test_principal()),
    });
    req
}

fn grpc_service(mock: Arc<MockService>) -> MicrovmGrpcService {
    MicrovmGrpcService::new(mock as Arc<dyn LifecycleService>)
}

// ---------------------------------------------------------------------------
// RPC handling (in-process, direct service calls)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_vm_returns_assigned_id() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let resp = svc
        .create_vm(authed_request(CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        }))
        .await
        .unwrap();
    assert_eq!(resp.into_inner().vm_id, "vm-512mib");
}

#[tokio::test]
async fn create_vm_zero_vcpu_is_invalid_argument() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let err = svc
        .create_vm(authed_request(CreateVmRequest {
            vcpu_count: 0,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "invalid_resource_spec");
}

#[tokio::test]
async fn start_and_stop_succeed() {
    let svc = grpc_service(Arc::new(MockService::new()));
    svc.start_vm(authed_request(StartVmRequest {
        vm_id: "vm-001".into(),
    }))
    .await
    .unwrap();
    svc.stop_vm(authed_request(StopVmRequest {
        vm_id: "vm-001".into(),
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn snapshot_returns_snapshot_id() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let resp = svc
        .snapshot_vm(authed_request(SnapshotVmRequest {
            vm_id: "vm-001".into(),
        }))
        .await
        .unwrap();
    assert_eq!(resp.into_inner().snapshot_id, "snap-vm-001");
}

#[tokio::test]
async fn restore_returns_new_vm_id() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let resp = svc
        .restore_vm(authed_request(RestoreVmRequest {
            snapshot_id: "snap-001".into(),
        }))
        .await
        .unwrap();
    assert_eq!(resp.into_inner().vm_id, "vm-restored-snap-001");
}

#[tokio::test]
async fn get_vm_status_returns_state_and_spec() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let resp = svc
        .get_vm_status(authed_request(GetVmStatusRequest {
            vm_id: "vm-001".into(),
        }))
        .await
        .unwrap();
    let inner = resp.into_inner();
    assert_eq!(inner.vm_id, "vm-001");
    assert_eq!(inner.state, ProtoVmState::Running as i32);
    assert!(inner.created_at.contains("2026"));
    let spec = inner.resource_spec.expect("resource_spec present");
    assert_eq!(spec.vcpu_count, 2);
    assert_eq!(spec.memory_mib, 512);
    assert_eq!(spec.disk_mib, 1024);
}

#[tokio::test]
async fn get_vm_metrics_returns_state() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let resp = svc
        .get_vm_metrics(authed_request(GetVmMetricsRequest {
            vm_id: "vm-001".into(),
        }))
        .await
        .unwrap();
    let inner = resp.into_inner();
    assert_eq!(inner.vm_id, "vm-001");
    assert_eq!(inner.state, ProtoVmState::Running as i32);
}

#[tokio::test]
async fn invalid_vm_id_is_invalid_argument() {
    let svc = grpc_service(Arc::new(MockService::new()));
    // Uppercase is rejected by the identifier validator.
    let err = svc
        .start_vm(authed_request(StartVmRequest {
            vm_id: "BAD-ID".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "invalid_id");
}

#[tokio::test]
async fn missing_vm_maps_to_not_found() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let err = svc
        .get_vm_status(authed_request(GetVmStatusRequest {
            vm_id: "missing-vm".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "artifact_not_found");
    assert_eq!(body.context.get("vm_id").unwrap(), "missing-vm");
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_peer_is_permission_denied() {
    let svc = grpc_service(Arc::new(MockService::new()));
    // Request with NO connect info -> unauthenticated.
    let err = svc
        .create_vm(Request::new(CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "permission_denied");
}

#[tokio::test]
async fn peer_with_no_principal_is_permission_denied() {
    let svc = grpc_service(Arc::new(MockService::new()));
    let mut req = Request::new(StartVmRequest {
        vm_id: "vm-001".into(),
    });
    req.extensions_mut().insert(PeerConnectInfo {
        creds: PeerCredentials {
            pid: 9,
            uid: 1000,
            gid: 1000,
        },
        principal: None,
    });
    let err = svc.start_vm(req).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn cross_tenant_maps_to_permission_denied() {
    let svc: MicrovmGrpcService = MicrovmGrpcService::new(Arc::new(
        MockService::new().with_error(
            "start",
            MicrovmError::new(ErrorCode::PermissionDenied, "cross-tenant access denied")
                .with_context("vm_id", "vm-001"),
        ),
    ) as Arc<dyn LifecycleService>);
    let err = svc
        .start_vm(authed_request(StartVmRequest {
            vm_id: "vm-001".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "permission_denied");
    assert_eq!(body.message, "cross-tenant access denied");
    assert_eq!(body.context.get("vm_id").unwrap(), "vm-001");
}

// ---------------------------------------------------------------------------
// Error mapping (deterministic, total)
// ---------------------------------------------------------------------------

#[test]
fn all_error_codes_have_deterministic_grpc_mapping() {
    let expected: Vec<(ErrorCode, Code)> = vec![
        (ErrorCode::InvalidId, Code::InvalidArgument),
        (ErrorCode::InvalidResourceSpec, Code::InvalidArgument),
        (ErrorCode::InvalidTransition, Code::FailedPrecondition),
        (ErrorCode::PermissionDenied, Code::PermissionDenied),
        (ErrorCode::QuotaExceeded, Code::ResourceExhausted),
        (ErrorCode::ArtifactNotFound, Code::NotFound),
        (ErrorCode::DigestMismatch, Code::InvalidArgument),
        (ErrorCode::PathEscape, Code::InvalidArgument),
        (ErrorCode::BinaryProvenanceError, Code::InvalidArgument),
        (ErrorCode::LocalArtifactRequired, Code::InvalidArgument),
        (ErrorCode::CgroupUnavailable, Code::Internal),
        (ErrorCode::NetworkSetupError, Code::Internal),
        (ErrorCode::ProcessSpawnError, Code::Internal),
        (ErrorCode::SnapshotIncompatible, Code::FailedPrecondition),
        (ErrorCode::TransportError, Code::Internal),
        (ErrorCode::InternalError, Code::Internal),
    ];

    for (code, expected_grpc) in &expected {
        assert_eq!(
            error_code_to_grpc(*code),
            *expected_grpc,
            "ErrorCode {:?} should map to {:?}",
            code,
            expected_grpc
        );
    }
    // Ensure we covered every variant.
    assert_eq!(expected.len(), ErrorCode::all().len());
}

#[tokio::test]
async fn quota_exceeded_maps_to_resource_exhausted() {
    let svc: MicrovmGrpcService = MicrovmGrpcService::new(Arc::new(
        MockService::new().with_error(
            "create",
            MicrovmError::new(ErrorCode::QuotaExceeded, "vcpu limit reached")
                .with_context("tenant", "test-tenant"),
        ),
    ) as Arc<dyn LifecycleService>);
    let err = svc
        .create_vm(authed_request(CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "quota_exceeded");
}

#[tokio::test]
async fn invalid_transition_maps_to_failed_precondition() {
    let svc: MicrovmGrpcService = MicrovmGrpcService::new(Arc::new(MockService::new().with_error(
        "stop",
        MicrovmError::new(ErrorCode::InvalidTransition, "cannot stop a created VM"),
    )) as Arc<dyn LifecycleService>);
    let err = svc
        .stop_vm(authed_request(StopVmRequest {
            vm_id: "vm-001".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "invalid_transition");
}

#[tokio::test]
async fn internal_error_maps_to_internal() {
    let svc: MicrovmGrpcService = MicrovmGrpcService::new(Arc::new(MockService::new().with_error(
        "snapshot",
        MicrovmError::new(ErrorCode::InternalError, "unexpected backend failure"),
    )) as Arc<dyn LifecycleService>);
    let err = svc
        .snapshot_vm(authed_request(SnapshotVmRequest {
            vm_id: "vm-001".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "internal_error");
}

// ---------------------------------------------------------------------------
// REST parity: same request -> same service result, same error body bytes
// ---------------------------------------------------------------------------

use microvm_rest::router::{self, match_route};

#[tokio::test]
async fn parity_create_vm_same_result_rest_and_grpc() {
    let mock: Arc<MockService> = Arc::new(MockService::new());
    let principal = test_principal();

    // REST path.
    let rest_svc: Arc<dyn LifecycleService> = mock.clone();
    let body = br#"{"vcpu_count":2,"memory_mib":512,"disk_mib":1024}"#;
    let route = match_route("POST", "/vms").unwrap();
    let rest_resp = router::dispatch(&route, body, &principal, &rest_svc).await;
    assert_eq!(rest_resp.status, 201);
    let rest_json: serde_json::Value = serde_json::from_slice(&rest_resp.body).unwrap();

    // gRPC path (same mock instance).
    let svc = grpc_service(mock.clone());
    let grpc_resp = svc
        .create_vm(authed_request(CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        }))
        .await
        .unwrap();

    // Same service result: identical vm_id.
    assert_eq!(rest_json["vm_id"], "vm-512mib");
    assert_eq!(grpc_resp.into_inner().vm_id, "vm-512mib");
}

#[tokio::test]
async fn parity_status_same_result_rest_and_grpc() {
    let mock: Arc<MockService> = Arc::new(MockService::new());
    let principal = test_principal();

    let rest_svc: Arc<dyn LifecycleService> = mock.clone();
    let route = match_route("GET", "/vms/vm-001").unwrap();
    let rest_resp = router::dispatch(&route, b"", &principal, &rest_svc).await;
    assert_eq!(rest_resp.status, 200);
    let rest_json: serde_json::Value = serde_json::from_slice(&rest_resp.body).unwrap();

    let svc = grpc_service(mock.clone());
    let grpc_resp = svc
        .get_vm_status(authed_request(GetVmStatusRequest {
            vm_id: "vm-001".into(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(rest_json["vm_id"], "vm-001");
    assert_eq!(grpc_resp.vm_id, "vm-001");
    assert_eq!(rest_json["state"], "running");
    assert_eq!(grpc_resp.state, ProtoVmState::Running as i32);
    assert_eq!(rest_json["resource_spec"]["vcpu_count"], 2);
    assert_eq!(grpc_resp.resource_spec.unwrap().vcpu_count, 2);
}

#[tokio::test]
async fn parity_error_body_bytes_identical_rest_and_grpc() {
    // The same service error must produce a byte-identical structured error
    // body on both transports (REST HTTP body == gRPC status details).
    let make_err = || {
        MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
            .with_context("vm_id", "missing-vm")
    };

    // REST error body bytes.
    let rest_body = microvm_rest::error::ErrorBody::from_microvm_error(&make_err());
    let rest_bytes = rest_body.to_json_bytes();

    // gRPC error details bytes for the same error.
    let mock: Arc<MockService> = Arc::new(MockService::new());
    let svc = grpc_service(mock);
    let err = svc
        .get_vm_status(authed_request(GetVmStatusRequest {
            vm_id: "missing-vm".into(),
        }))
        .await
        .unwrap_err();
    let grpc_details = err.details().to_vec();

    assert_eq!(
        rest_bytes, grpc_details,
        "REST body and gRPC details must be byte-identical"
    );

    // And the gRPC code corresponds to the REST 404.
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(
        microvm_rest::error::error_to_http_status(ErrorCode::ArtifactNotFound).code(),
        404
    );
}

#[test]
fn parity_error_code_mapping_is_consistent() {
    // For every ErrorCode, the gRPC mapping must be defined whenever the REST
    // mapping is defined (both are total), and permission errors must agree on
    // the "denied" semantic across transports.
    for code in ErrorCode::all() {
        let _rest = microvm_rest::error::error_to_http_status(*code);
        let _grpc = error_code_to_grpc(*code);
    }
    // The acceptance-critical permission mapping agrees.
    assert_eq!(
        microvm_rest::error::error_to_http_status(ErrorCode::PermissionDenied).code(),
        403
    );
    assert_eq!(
        error_code_to_grpc(ErrorCode::PermissionDenied),
        Code::PermissionDenied
    );
}

// ---------------------------------------------------------------------------
// End-to-end over a real Unix socket (SO_PEERCRED + tonic transport)
// ---------------------------------------------------------------------------

async fn spawn_server(
    sock: PathBuf,
    service: Arc<dyn LifecycleService>,
    auth: Arc<dyn PeerAuthenticator>,
) {
    let config = SocketConfig::with_path(&sock).with_mode(0o660);
    let server = GrpcServer::new(config, service, auth);
    tokio::spawn(async move {
        let _ = server.serve().await;
    });
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(sock.exists(), "socket file was not created");
}

async fn connect_client(sock: PathBuf) -> MicrovmServiceClient<Channel> {
    // The connector ignores the URI authority and always dials the Unix socket;
    // the URI is a placeholder with no network address.
    let channel = tonic::transport::Endpoint::try_from("http://microvm.grpc".to_string())
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let sock = sock.clone();
            async move {
                Ok::<_, std::io::Error>(TokioIo::new(tokio::net::UnixStream::connect(sock).await?))
            }
        }))
        .await
        .unwrap();
    MicrovmServiceClient::new(channel)
}

#[tokio::test]
async fn end_to_end_unix_socket_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("grpc.sock");

    let my_uid = unsafe { libc::getuid() };
    let auth: Arc<dyn PeerAuthenticator> =
        Arc::new(StaticAuthenticator::new(my_uid, test_principal()));
    spawn_server(sock.clone(), Arc::new(MockService::new()), auth).await;

    let mut client = connect_client(sock).await;

    // CreateVm over the wire.
    let resp = client
        .create_vm(CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        })
        .await
        .unwrap();
    assert_eq!(resp.into_inner().vm_id, "vm-512mib");

    // GetVmStatus over the wire.
    let status = client
        .get_vm_status(GetVmStatusRequest {
            vm_id: "vm-001".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.vm_id, "vm-001");
    assert_eq!(status.state, ProtoVmState::Running as i32);

    // Error over the wire: missing VM -> NotFound with recoverable error_code.
    let err = client
        .get_vm_status(GetVmStatusRequest {
            vm_id: "missing-vm".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "artifact_not_found");
}

#[tokio::test]
async fn end_to_end_unauthenticated_peer_permission_denied() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("grpc.sock");

    // Authenticator expects a UID we do not have -> peer is unauthenticated.
    let auth: Arc<dyn PeerAuthenticator> =
        Arc::new(StaticAuthenticator::new(99999, test_principal()));
    spawn_server(sock.clone(), Arc::new(MockService::new()), auth).await;

    let mut client = connect_client(sock).await;
    let err = client
        .create_vm(CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: ProtoNetworkPolicy::None as i32,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let body = error_body_from_status(&err).unwrap();
    assert_eq!(body.error_code, "permission_denied");
}

#[tokio::test]
async fn end_to_end_socket_mode_is_0660() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("grpc.sock");

    let my_uid = unsafe { libc::getuid() };
    let auth: Arc<dyn PeerAuthenticator> =
        Arc::new(StaticAuthenticator::new(my_uid, test_principal()));
    spawn_server(sock.clone(), Arc::new(MockService::new()), auth).await;

    let meta = std::fs::metadata(&sock).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o660);
}

// ---------------------------------------------------------------------------
// No-TCP assertion (static source scan)
// ---------------------------------------------------------------------------

const SRC_FILES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("config.rs", include_str!("../src/config.rs")),
    ("peer.rs", include_str!("../src/peer.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("proto.rs", include_str!("../src/proto.rs")),
    ("server.rs", include_str!("../src/server.rs")),
    ("service.rs", include_str!("../src/service.rs")),
];

#[test]
fn no_tcp_patterns_in_server_source() {
    // Reuse the platform's canonical TCP scanner from the transport-contract
    // crate (todo 8) so the gRPC transport is held to the same rule.
    for (name, content) in SRC_FILES {
        let violations = microvm_transport_contract::scan_for_tcp_patterns(content);
        assert!(
            violations.is_empty(),
            "forbidden TCP pattern in {name}: {:?}",
            violations
        );
    }
}

#[test]
fn server_uses_unix_listener_not_tcp() {
    let server_src = include_str!("../src/server.rs");
    assert!(
        server_src.contains("UnixListener"),
        "server must use UnixListener"
    );
    assert!(
        server_src.contains("serve_with_incoming"),
        "server must serve over the Unix incoming stream"
    );
    for forbidden in ["TcpListener", "TcpStream", "to_socket_addrs", "TcpSocket"] {
        assert!(
            !server_src.contains(forbidden),
            "server must NOT reference {forbidden}"
        );
    }
    // No source file may bind a TCP listener type.
    for (name, content) in SRC_FILES {
        for forbidden in ["TcpListener", "TcpSocket", "to_socket_addrs"] {
            assert!(
                !content.contains(forbidden),
                "{name} must NOT reference {forbidden}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// No-reflection assertion
// ---------------------------------------------------------------------------

#[test]
fn reflection_is_disabled_and_unregistered() {
    // The documented default must be off (read through a binding so this is a
    // runtime check, not a tautological constant assertion).
    let enabled = REFLECTION_ENABLED;
    assert!(!enabled, "reflection must stay disabled");

    // The reflection crate must not be a dependency.
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("tonic-reflection"),
        "tonic-reflection must not be a dependency"
    );

    // No reflection service may be registered by the server.
    let server_src = include_str!("../src/server.rs");
    assert!(
        !server_src.contains("reflection_service"),
        "server must not register a reflection service"
    );
    assert!(
        !server_src.contains("FILE_DESCRIPTOR_SET"),
        "server must not embed a reflection descriptor set"
    );
}

// ---------------------------------------------------------------------------
// Backend bound: the production VmLifecycleService satisfies the backend
// ---------------------------------------------------------------------------

#[test]
fn vm_lifecycle_service_satisfies_backend_bound() {
    // Compile-time proof that the composed production service from
    // microvm-service can be used as the gRPC backend (same contract as REST).
    fn assert_backend<T: LifecycleService + 'static>() {}
    assert_backend::<microvm_service::VmLifecycleService>();
}
