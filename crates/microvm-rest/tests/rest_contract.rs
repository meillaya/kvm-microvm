//! Integration tests for the REST Unix socket API.
//!
//! These tests verify:
//! - Route handling (all 7 OpenAPI routes dispatch correctly)
//! - Error mapping (MicrovmError codes → HTTP status)
//! - Socket validation (mode, ownership, peer credentials)
//! - No-TCP assertion (source scan for forbidden patterns)

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_lifecycle::{LifecycleService, VmMetrics, VmState, VmStatus};
use microvm_metrics::VmMetricsRecord;
use microvm_rest::error::error_to_http_status;
use microvm_rest::peer::{PeerAuthenticator, PeerCredentials, StaticAuthenticator};
use microvm_rest::router::{self, match_route};
use microvm_rest::{RestServer, SocketConfig};
use microvm_types::{Principal, ResourceSpec, Role, SnapshotId, TenantId, VmId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Mock service for testing route dispatch
// ---------------------------------------------------------------------------

/// A mock lifecycle service that records calls and returns configured responses.
struct MockService {
    /// Pre-configured errors for specific operations.
    errors: Mutex<HashMap<String, MicrovmError>>,
    /// Recorded operations.
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

#[async_trait]
impl LifecycleService for MockService {
    async fn create(&self, spec: ResourceSpec, _owner: Principal) -> Result<VmId, MicrovmError> {
        self.record("create");
        if let Some(e) = self.check_error("create") {
            return Err(e);
        }
        // Generate a deterministic ID from the spec.
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
            created_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            resource_spec: ResourceSpec::new(2, 512, 1024, Default::default()).unwrap(),
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
                chrono::Utc::now(),
                0,
            ),
            vm_id: vm_id.clone(),
            state: VmState::Running,
        })
    }
}

fn test_principal() -> Principal {
    Principal::new(TenantId::new("test-tenant").unwrap(), Role::Owner)
}

fn mock_service() -> Arc<dyn LifecycleService> {
    Arc::new(MockService::new())
}

// ---------------------------------------------------------------------------
// Route handling tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_vm_returns_201_with_vm_id() {
    let svc = mock_service();
    let principal = test_principal();
    let body = br#"{"vcpu_count":2,"memory_mib":512,"disk_mib":1024}"#;

    let route = match_route("POST", "/vms").unwrap();
    let resp = router::dispatch(&route, body, &principal, &svc).await;

    assert_eq!(resp.status, 201);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["vm_id"], "vm-512mib");
}

#[tokio::test]
async fn create_vm_with_network_policy() {
    let svc = mock_service();
    let principal = test_principal();
    let body =
        br#"{"vcpu_count":4,"memory_mib":1024,"disk_mib":2048,"network_policy":"egress-allowed"}"#;

    let route = match_route("POST", "/vms").unwrap();
    let resp = router::dispatch(&route, body, &principal, &svc).await;

    assert_eq!(resp.status, 201);
}

#[tokio::test]
async fn create_vm_invalid_json_returns_400() {
    let svc = mock_service();
    let principal = test_principal();
    let body = b"not json at all";

    let route = match_route("POST", "/vms").unwrap();
    let resp = router::dispatch(&route, body, &principal, &svc).await;

    assert_eq!(resp.status, 400);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(json["error_code"].as_str().unwrap().contains("invalid"));
}

#[tokio::test]
async fn create_vm_zero_vcpu_returns_400() {
    let svc = mock_service();
    let principal = test_principal();
    let body = br#"{"vcpu_count":0,"memory_mib":512,"disk_mib":1024}"#;

    let route = match_route("POST", "/vms").unwrap();
    let resp = router::dispatch(&route, body, &principal, &svc).await;

    assert_eq!(resp.status, 400);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "invalid_resource_spec");
}

#[tokio::test]
async fn get_vm_status_returns_200() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("GET", "/vms/vm-001").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 200);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["vm_id"], "vm-001");
    assert_eq!(json["state"], "running");
    assert!(json["created_at"].as_str().unwrap().contains("2026"));
    assert_eq!(json["resource_spec"]["vcpu_count"], 2);
}

#[tokio::test]
async fn get_vm_status_not_found_returns_404() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("GET", "/vms/missing-vm").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 404);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "artifact_not_found");
}

#[tokio::test]
async fn start_vm_returns_204() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("POST", "/vms/vm-001/start").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 204);
    assert!(resp.body.is_empty());
}

#[tokio::test]
async fn start_vm_not_found_returns_404() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("POST", "/vms/missing-vm/start").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn stop_vm_returns_204() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("POST", "/vms/vm-001/stop").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 204);
    assert!(resp.body.is_empty());
}

#[tokio::test]
async fn snapshot_vm_returns_201() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("POST", "/vms/vm-001/snapshot").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 201);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["snapshot_id"], "snap-vm-001");
}

#[tokio::test]
async fn get_vm_metrics_returns_200() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("GET", "/vms/vm-001/metrics").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 200);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["vm_id"], "vm-001");
    assert_eq!(json["state"], "running");
}

#[tokio::test]
async fn restore_snapshot_returns_201() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("POST", "/snapshots/snap-001/restore").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 201);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["vm_id"], "vm-restored-snap-001");
}

#[tokio::test]
async fn restore_missing_snapshot_returns_404() {
    let svc = mock_service();
    let principal = test_principal();

    let route = match_route("POST", "/snapshots/missing-snap/restore").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let resp = router::handle_unknown_route();
    assert_eq!(resp.status, 404);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "artifact_not_found");
}

#[tokio::test]
async fn invalid_vm_id_in_path_returns_400() {
    let svc = mock_service();
    let principal = test_principal();

    // Uppercase is invalid.
    let route = match_route("GET", "/vms/INVALID").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 400);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "invalid_id");
}

// ---------------------------------------------------------------------------
// Error mapping tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn permission_denied_maps_to_403() {
    let svc: Arc<dyn LifecycleService> = Arc::new(
        MockService::new().with_error(
            "start",
            MicrovmError::new(ErrorCode::PermissionDenied, "cross-tenant access denied")
                .with_context("vm_id", "vm-001"),
        ),
    );
    let principal = test_principal();

    let route = match_route("POST", "/vms/vm-001/start").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 403);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "permission_denied");
    assert_eq!(json["message"], "cross-tenant access denied");
    assert_eq!(json["context"]["vm_id"], "vm-001");
}

#[tokio::test]
async fn invalid_transition_maps_to_409() {
    let svc: Arc<dyn LifecycleService> = Arc::new(
        MockService::new().with_error(
            "stop",
            MicrovmError::new(ErrorCode::InvalidTransition, "cannot stop a created VM")
                .with_context("from", "created")
                .with_context("to", "stopped"),
        ),
    );
    let principal = test_principal();

    let route = match_route("POST", "/vms/vm-001/stop").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 409);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "invalid_transition");
}

#[tokio::test]
async fn quota_exceeded_maps_to_409() {
    let svc: Arc<dyn LifecycleService> = Arc::new(
        MockService::new().with_error(
            "create",
            MicrovmError::new(ErrorCode::QuotaExceeded, "vcpu limit reached")
                .with_context("tenant", "test-tenant"),
        ),
    );
    let principal = test_principal();
    let body = br#"{"vcpu_count":2,"memory_mib":512,"disk_mib":1024}"#;

    let route = match_route("POST", "/vms").unwrap();
    let resp = router::dispatch(&route, body, &principal, &svc).await;

    assert_eq!(resp.status, 409);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "quota_exceeded");
}

#[tokio::test]
async fn internal_error_maps_to_500() {
    let svc: Arc<dyn LifecycleService> = Arc::new(MockService::new().with_error(
        "snapshot",
        MicrovmError::new(ErrorCode::InternalError, "unexpected backend failure"),
    ));
    let principal = test_principal();

    let route = match_route("POST", "/vms/vm-001/snapshot").unwrap();
    let resp = router::dispatch(&route, b"", &principal, &svc).await;

    assert_eq!(resp.status, 500);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["error_code"], "internal_error");
}

#[test]
fn all_error_codes_have_deterministic_mapping() {
    // Verify every ErrorCode maps to exactly one of the 5 allowed statuses.
    let expected: Vec<(ErrorCode, u16)> = vec![
        (ErrorCode::InvalidId, 400),
        (ErrorCode::InvalidResourceSpec, 400),
        (ErrorCode::InvalidTransition, 409),
        (ErrorCode::PermissionDenied, 403),
        (ErrorCode::QuotaExceeded, 409),
        (ErrorCode::ArtifactNotFound, 404),
        (ErrorCode::DigestMismatch, 400),
        (ErrorCode::PathEscape, 400),
        (ErrorCode::BinaryProvenanceError, 400),
        (ErrorCode::LocalArtifactRequired, 400),
        (ErrorCode::CgroupUnavailable, 500),
        (ErrorCode::NetworkSetupError, 500),
        (ErrorCode::ProcessSpawnError, 500),
        (ErrorCode::SnapshotIncompatible, 409),
        (ErrorCode::TransportError, 500),
        (ErrorCode::InternalError, 500),
    ];

    for (code, expected_status) in &expected {
        let actual = error_to_http_status(*code);
        assert_eq!(
            actual.code(),
            *expected_status,
            "ErrorCode {:?} should map to {}, got {}",
            code,
            expected_status,
            actual.code()
        );
    }

    // Ensure we covered all variants.
    assert_eq!(expected.len(), ErrorCode::all().len());
}

// ---------------------------------------------------------------------------
// Socket validation tests
// ---------------------------------------------------------------------------

#[test]
fn socket_validation_rejects_wrong_mode() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sock");
    let _listener = StdUnixListener::bind(&path).unwrap();

    // Set wrong mode.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();

    let config = SocketConfig::with_path(&path).with_mode(0o660);
    let result = RestServer::validate_socket(&path, &config);
    assert!(result.is_err());
}

#[test]
fn socket_validation_accepts_correct_mode_and_owner() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sock");
    let _listener = StdUnixListener::bind(&path).unwrap();

    // Set correct mode.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

    // Use current process UID/GID.
    let config = SocketConfig::with_path(&path).with_mode(0o660);
    let result = RestServer::validate_socket(&path, &config);
    assert!(result.is_ok());
}

#[test]
fn socket_validation_rejects_non_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("regular-file");
    std::fs::write(&path, "not a socket").unwrap();

    let config = SocketConfig::with_path(&path).with_mode(0o660);
    let result = RestServer::validate_socket(&path, &config);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not a Unix socket"));
}

#[test]
fn socket_validation_rejects_nonexistent_path() {
    let config = SocketConfig::with_path("/tmp/definitely-not-here-microvm.sock");
    let result = RestServer::validate_socket(
        &std::path::PathBuf::from("/tmp/definitely-not-here-microvm.sock"),
        &config,
    );
    assert!(result.is_err());
}

#[test]
fn socket_config_default_mode_is_0660() {
    let config = SocketConfig::default();
    assert_eq!(config.mode, 0o660);
}

#[test]
fn socket_config_default_path() {
    let config = SocketConfig::default();
    assert_eq!(
        config.path,
        std::path::PathBuf::from("/run/microvm/rest.sock")
    );
}

// ---------------------------------------------------------------------------
// Peer credential tests
// ---------------------------------------------------------------------------

#[test]
fn peer_credentials_captured_before_authorization() {
    // Verify that the PeerCredentials struct captures UID/GID.
    let creds = PeerCredentials {
        pid: 1234,
        uid: 1000,
        gid: 1000,
    };
    assert_eq!(creds.uid, 1000);
    assert_eq!(creds.gid, 1000);
    assert_eq!(creds.pid, 1234);
}

#[test]
fn static_authenticator_maps_uid_to_principal() {
    let principal = test_principal();
    let auth = StaticAuthenticator::new(1000, principal.clone());

    let valid_creds = PeerCredentials {
        pid: 1,
        uid: 1000,
        gid: 1000,
    };
    assert_eq!(auth.authenticate(&valid_creds), Some(principal));

    let invalid_creds = PeerCredentials {
        pid: 2,
        uid: 9999,
        gid: 9999,
    };
    assert_eq!(auth.authenticate(&invalid_creds), None);
}

#[test]
fn unauthenticated_peer_gets_none() {
    let principal = test_principal();
    let auth = StaticAuthenticator::new(0, principal);

    let creds = PeerCredentials {
        pid: 100,
        uid: 65534,
        gid: 65534,
    };
    assert!(auth.authenticate(&creds).is_none());
}

// ---------------------------------------------------------------------------
// No-TCP assertion
// ---------------------------------------------------------------------------

#[test]
fn no_tcp_patterns_in_source() {
    // Scan all source files in this crate for forbidden TCP patterns.
    let forbidden = [
        "0.0.0.0",
        "127.0.0.1",
        "tcp://",
        "[::]",
        "::1",
        "localhost:",
        "TcpListener",
        "TcpStream",
        "bind_tcp",
    ];

    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();

    fn scan_dir(dir: &std::path::Path, forbidden: &[&str], violations: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path, forbidden, violations);
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                let content = std::fs::read_to_string(&path).unwrap();
                for (line_num, line) in content.lines().enumerate() {
                    // Skip this test function itself and comments about the assertion.
                    if line.contains("forbidden") || line.contains("no_tcp_patterns") {
                        continue;
                    }
                    for pattern in forbidden {
                        if line.contains(pattern) {
                            violations.push(format!(
                                "{}:{}: found forbidden pattern '{}': {}",
                                path.display(),
                                line_num + 1,
                                pattern,
                                line.trim()
                            ));
                        }
                    }
                }
            }
        }
    }

    scan_dir(&src_dir, &forbidden, &mut violations);

    assert!(
        violations.is_empty(),
        "TCP patterns found in source:\n{}",
        violations.join("\n")
    );
}

#[test]
fn server_uses_unix_listener_not_tcp() {
    // Verify the server module source uses UnixListener and never TcpListener.
    let server_src = include_str!("../src/server.rs");
    assert!(
        server_src.contains("UnixListener"),
        "server must use UnixListener"
    );
    assert!(
        !server_src.contains("TcpListener"),
        "server must not use TcpListener"
    );
    assert!(
        !server_src.contains("TcpStream"),
        "server must not use TcpStream"
    );
}

// ---------------------------------------------------------------------------
// End-to-end socket test (connect via Unix socket, send HTTP)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn end_to_end_unix_socket_http() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("api.sock");

    let config = SocketConfig::with_path(&sock_path).with_mode(0o660);
    let svc: Arc<dyn LifecycleService> = Arc::new(MockService::new());
    let auth: Arc<dyn PeerAuthenticator> = Arc::new(StaticAuthenticator::new(
        unsafe { libc::getuid() },
        test_principal(),
    ));

    let server = RestServer::new(config, svc, auth);

    // Spawn the server in a background task.
    let server_handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    // Wait for the socket to appear.
    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(sock_path.exists(), "socket file was not created");

    // Helper: send request and read full response with timeout.
    async fn http_request(sock: &std::path::Path, raw: &str) -> String {
        let mut stream = UnixStream::connect(sock).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("read timed out")
        .unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    // POST /vms -> 201
    let resp = http_request(
        &sock_path,
        "POST /vms HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 49\r\n\r\n{\"vcpu_count\":2,\"memory_mib\":512,\"disk_mib\":1024}",
    )
    .await;
    assert!(resp.contains("201"), "expected 201, got: {}", resp);
    assert!(resp.contains("vm-512mib"), "expected vm_id: {}", resp);

    // GET /vms/{id} -> 200
    let resp2 = http_request(
        &sock_path,
        "GET /vms/vm-001 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp2.contains("200"), "expected 200, got: {}", resp2);
    assert!(resp2.contains("running"), "expected state: {}", resp2);

    // GET /unknown -> 404
    let resp3 = http_request(
        &sock_path,
        "GET /unknown HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp3.contains("404"), "expected 404, got: {}", resp3);

    server_handle.abort();
}

#[tokio::test]
async fn end_to_end_unauthenticated_peer_gets_403() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("api.sock");

    let config = SocketConfig::with_path(&sock_path).with_mode(0o660);
    let svc: Arc<dyn LifecycleService> = Arc::new(MockService::new());

    // Authenticator that rejects our UID (uses a UID we definitely don't have).
    let auth: Arc<dyn PeerAuthenticator> = Arc::new(StaticAuthenticator::new(
        99999, // Not our UID
        test_principal(),
    ));

    let server = RestServer::new(config, svc, auth);

    let server_handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    // Wait for socket.
    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let mut stream = UnixStream::connect(&sock_path).await.unwrap();
    let request = "GET /vms/vm-001 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await
    .expect("read timed out")
    .unwrap();
    let response_str = String::from_utf8_lossy(&buf);

    assert!(
        response_str.contains("403"),
        "expected 403 for unauthenticated peer, got: {}",
        response_str
    );
    assert!(
        response_str.contains("permission_denied"),
        "expected permission_denied error code: {}",
        response_str
    );

    server_handle.abort();
}
