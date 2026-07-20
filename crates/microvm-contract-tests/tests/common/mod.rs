//! Shared harness for the REST/gRPC transport contract tests (plan todo 18).
//!
//! The harness builds the composed [`VmLifecycleService`] over a deterministic
//! scripted backend (standing in for the Firecracker runtime — no KVM, root, or
//! real Firecracker binary is required), then drives the **same** service
//! instance through both the REST and gRPC Unix-socket adapters. This lets the
//! tests assert that the same request reaches the same service result on either
//! transport, that error codes agree, that the socket stays hardened, and that
//! denied requests emit exactly one audit event.
//!
//! Authorization is delegated entirely to the service; this harness only
//! configures which [`Principal`] each transport's peer-credential authenticator
//! maps the local test process to. It never duplicates or weakens policy.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_grpc::error::error_body_from_status;
use microvm_grpc::peer::{
    PeerAuthenticator as GrpcPeerAuthenticator, StaticAuthenticator as GrpcStaticAuthenticator,
};
use microvm_grpc::proto::v1::microvm_service_client::MicrovmServiceClient;
use microvm_grpc::proto::v1::{
    CreateVmRequest, GetVmMetricsRequest, GetVmStatusRequest, NetworkPolicy as ProtoNetworkPolicy,
    RestoreVmRequest, SnapshotVmRequest, StartVmRequest, StopVmRequest, VmState as ProtoVmState,
};
use microvm_grpc::{GrpcServer, SocketConfig as GrpcSocketConfig};
use microvm_lifecycle::policy::{AuditEvent, InMemoryAuditLog};
use microvm_lifecycle::{LifecycleService, VmMetrics, VmState, VmStatus};
use microvm_rest::peer::{
    PeerAuthenticator as RestPeerAuthenticator, StaticAuthenticator as RestStaticAuthenticator,
};
use microvm_rest::{RestServer, SocketConfig as RestSocketConfig};
use microvm_service::{ScriptedSupervisorProbe, VmLifecycleService};
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, SnapshotId, TenantId, VmId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Uri};

/// The tenant that owns the fixtures' resources.
pub const TENANT: &str = "acme";

// ---------------------------------------------------------------------------
// Scripted inner backend
// ---------------------------------------------------------------------------

/// A deterministic, in-memory [`LifecycleService`] used as the inner runtime
/// double for [`VmLifecycleService`].
///
/// It plays the role the Firecracker backend plays in production: the thing the
/// supervised service wraps. All supervision policy under test — authorization,
/// quota, idempotency, state mirroring, and audit — lives in
/// [`VmLifecycleService`], not here. Identifiers are derived deterministically
/// from the request so the same fixture yields the same result on both
/// transports.
pub struct ScriptedBackend;

#[async_trait]
impl LifecycleService for ScriptedBackend {
    async fn create(&self, spec: ResourceSpec, _owner: Principal) -> Result<VmId, MicrovmError> {
        VmId::new(format!("vm-{}mib", spec.memory_mib()))
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn start(&self, _vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        Ok(())
    }

    async fn stop(&self, _vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        Ok(())
    }

    async fn snapshot(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError> {
        SnapshotId::new(format!("snap-{}", vm_id.as_str()))
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        _principal: &Principal,
    ) -> Result<VmId, MicrovmError> {
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
        // The supervised service answers `status` from its own reconciled
        // registry and never delegates here; implemented for trait completeness.
        Ok(VmStatus {
            vm_id: vm_id.clone(),
            state: VmState::Running,
            created_at: chrono::Utc::now(),
            resource_spec: ResourceSpec::new(2, 512, 1024, NetworkPolicy::None).unwrap(),
        })
    }

    async fn metrics(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<VmMetrics, MicrovmError> {
        Ok(VmMetrics {
            vm_id: vm_id.clone(),
            state: VmState::Running,
        })
    }
}

// ---------------------------------------------------------------------------
// Rig: a supervised service plus audit handle
// ---------------------------------------------------------------------------

/// A fully wired [`VmLifecycleService`] (the backend under test) with an
/// inspectable audit log and ready-to-use principals.
pub struct Rig {
    /// The composed supervised service driving both transports.
    pub service: Arc<VmLifecycleService>,
    /// The service's audit sink (the single audit source).
    pub audit: Arc<InMemoryAuditLog>,
    /// Owner of the `acme` tenant (permitted for every operation).
    pub owner: Principal,
    /// Viewer of the `acme` tenant (read-only; denied mutating operations).
    pub viewer: Principal,
    /// The fixture tenant.
    pub tenant: TenantId,
    _tmp: tempfile::TempDir,
}

impl Rig {
    /// Build a fresh rig with an empty registry and audit log.
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let audit = Arc::new(InMemoryAuditLog::new());
        let service = Arc::new(
            VmLifecycleService::builder()
                .inner(Arc::new(ScriptedBackend))
                .supervisor_probe(Arc::new(ScriptedSupervisorProbe::new()))
                .audit_log(audit.clone())
                .build(),
        );
        let tenant = TenantId::new(TENANT).unwrap();
        let owner = Principal::new(tenant.clone(), Role::Owner);
        let viewer = Principal::new(tenant.clone(), Role::Viewer);
        Rig {
            service,
            audit,
            owner,
            viewer,
            tenant,
            _tmp: tmp,
        }
    }

    /// A unique socket path under the rig's temp dir.
    pub fn sock(&self, name: &str) -> PathBuf {
        self._tmp.path().join(name)
    }

    /// Current number of recorded audit events.
    pub fn audit_len(&self) -> usize {
        self.audit.len()
    }

    /// The most recently recorded audit event.
    pub fn last_audit(&self) -> AuditEvent {
        self.audit
            .events()
            .pop()
            .expect("at least one audit event must be recorded")
    }

    /// Spawn a REST + gRPC server pair backed by this rig's service, whose
    /// peer-credential authenticators map the local test process UID to
    /// `principal`. Returns a connected transport handle.
    pub async fn spawn(&self, principal: Principal, name: &str) -> Transport {
        let rest_sock = self.sock(format!("{name}-rest.sock").as_str());
        let grpc_sock = self.sock(format!("{name}-grpc.sock").as_str());

        let my_uid = unsafe { libc::getuid() };

        let rest_auth: Arc<dyn RestPeerAuthenticator> =
            Arc::new(RestStaticAuthenticator::new(my_uid, principal.clone()));
        let rest_server = RestServer::new(
            RestSocketConfig::with_path(&rest_sock).with_mode(0o660),
            self.service.clone(),
            rest_auth,
        );
        let rest_handle = tokio::spawn(async move {
            let _ = rest_server.serve().await;
        });

        let grpc_auth: Arc<dyn GrpcPeerAuthenticator> =
            Arc::new(GrpcStaticAuthenticator::new(my_uid, principal));
        let grpc_server = GrpcServer::new(
            GrpcSocketConfig::with_path(&grpc_sock).with_mode(0o660),
            self.service.clone(),
            grpc_auth,
        );
        let grpc_handle = tokio::spawn(async move {
            let _ = grpc_server.serve().await;
        });

        wait_for_socket(&rest_sock).await;
        wait_for_socket(&grpc_sock).await;

        Transport {
            rest_sock,
            grpc_sock,
            rest_handle,
            grpc_handle,
        }
    }
}

/// A running REST + gRPC server pair on their own Unix sockets.
pub struct Transport {
    pub rest_sock: PathBuf,
    pub grpc_sock: PathBuf,
    pub rest_handle: tokio::task::JoinHandle<()>,
    pub grpc_handle: tokio::task::JoinHandle<()>,
}

impl Transport {
    /// Connect a gRPC client over the Unix socket.
    pub async fn grpc(&self) -> MicrovmServiceClient<Channel> {
        grpc_connect(self.grpc_sock.clone()).await
    }

    /// Stop both servers.
    pub fn shutdown(self) {
        self.rest_handle.abort();
        self.grpc_handle.abort();
    }
}

async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("socket {} was not created", path.display());
}

// ---------------------------------------------------------------------------
// Normalized operation result (transport-neutral comparison unit)
// ---------------------------------------------------------------------------

/// A transport-neutral view of an operation outcome.
///
/// REST and gRPC performers both reduce to this enum so parity is asserted on
/// the *service result*, not on transport framing. Error variants carry the
/// stable `error_code`, which is identical across transports by construction.
#[derive(Debug, PartialEq, Eq)]
pub enum OpResult {
    Created(String),
    Started,
    Stopped,
    Snapshotted(String),
    Restored(String),
    Status {
        vm_id: String,
        state: String,
        vcpu: u32,
        mem: u64,
        disk: u64,
        policy: String,
    },
    Metrics {
        vm_id: String,
        state: String,
    },
    Error {
        code: String,
    },
}

// ---------------------------------------------------------------------------
// REST client (raw HTTP/1.1 over a Unix socket)
// ---------------------------------------------------------------------------

/// A parsed REST response.
pub struct RestOutcome {
    pub status: u16,
    pub body: serde_json::Value,
}

/// Send one HTTP/1.1 request over the Unix socket and parse the response.
pub async fn rest_call(
    sock: &Path,
    method: &str,
    path: &str,
    json_body: Option<&str>,
) -> RestOutcome {
    let mut stream = UnixStream::connect(sock)
        .await
        .expect("connect rest socket");
    let body = json_body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: microvm.local\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write rest request");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("rest read timed out")
        .expect("rest read failed");
    parse_http(&String::from_utf8_lossy(&buf))
}

fn parse_http(text: &str) -> RestOutcome {
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body_str = match text.find("\r\n\r\n") {
        Some(idx) => text[idx + 4..].trim(),
        None => "",
    };
    let body = if body_str.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(body_str).unwrap_or(serde_json::Value::Null)
    };
    RestOutcome { status, body }
}

fn rest_err_code(r: &RestOutcome) -> String {
    r.body["error_code"]
        .as_str()
        .unwrap_or("missing_error_code")
        .to_string()
}

// --- REST performers -------------------------------------------------------

pub async fn rest_create(sock: &Path, vcpu: u32, mem: u64, disk: u64) -> OpResult {
    let body = serde_json::json!({
        "vcpu_count": vcpu,
        "memory_mib": mem,
        "disk_mib": disk,
    })
    .to_string();
    let r = rest_call(sock, "POST", "/vms", Some(&body)).await;
    if r.status == 201 {
        OpResult::Created(r.body["vm_id"].as_str().unwrap().to_string())
    } else {
        OpResult::Error {
            code: rest_err_code(&r),
        }
    }
}

pub async fn rest_start(sock: &Path, vm_id: &str) -> OpResult {
    let r = rest_call(sock, "POST", &format!("/vms/{vm_id}/start"), Some("")).await;
    match r.status {
        204 => OpResult::Started,
        _ => OpResult::Error {
            code: rest_err_code(&r),
        },
    }
}

pub async fn rest_stop(sock: &Path, vm_id: &str) -> OpResult {
    let r = rest_call(sock, "POST", &format!("/vms/{vm_id}/stop"), Some("")).await;
    match r.status {
        204 => OpResult::Stopped,
        _ => OpResult::Error {
            code: rest_err_code(&r),
        },
    }
}

pub async fn rest_snapshot(sock: &Path, vm_id: &str) -> OpResult {
    let r = rest_call(sock, "POST", &format!("/vms/{vm_id}/snapshot"), Some("")).await;
    if r.status == 201 {
        OpResult::Snapshotted(r.body["snapshot_id"].as_str().unwrap().to_string())
    } else {
        OpResult::Error {
            code: rest_err_code(&r),
        }
    }
}

pub async fn rest_restore(sock: &Path, snapshot_id: &str) -> OpResult {
    let r = rest_call(
        sock,
        "POST",
        &format!("/snapshots/{snapshot_id}/restore"),
        Some(""),
    )
    .await;
    if r.status == 201 {
        OpResult::Restored(r.body["vm_id"].as_str().unwrap().to_string())
    } else {
        OpResult::Error {
            code: rest_err_code(&r),
        }
    }
}

pub async fn rest_status(sock: &Path, vm_id: &str) -> OpResult {
    let r = rest_call(sock, "GET", &format!("/vms/{vm_id}"), None).await;
    if r.status == 200 {
        OpResult::Status {
            vm_id: r.body["vm_id"].as_str().unwrap().to_string(),
            state: r.body["state"].as_str().unwrap().to_string(),
            vcpu: r.body["resource_spec"]["vcpu_count"].as_u64().unwrap() as u32,
            mem: r.body["resource_spec"]["memory_mib"].as_u64().unwrap(),
            disk: r.body["resource_spec"]["disk_mib"].as_u64().unwrap(),
            policy: r.body["resource_spec"]["network_policy"]
                .as_str()
                .unwrap()
                .to_string(),
        }
    } else {
        OpResult::Error {
            code: rest_err_code(&r),
        }
    }
}

pub async fn rest_metrics(sock: &Path, vm_id: &str) -> OpResult {
    let r = rest_call(sock, "GET", &format!("/vms/{vm_id}/metrics"), None).await;
    if r.status == 200 {
        OpResult::Metrics {
            vm_id: r.body["vm_id"].as_str().unwrap().to_string(),
            state: r.body["state"].as_str().unwrap().to_string(),
        }
    } else {
        OpResult::Error {
            code: rest_err_code(&r),
        }
    }
}

// ---------------------------------------------------------------------------
// gRPC client (tonic over a Unix socket)
// ---------------------------------------------------------------------------

/// Connect a tonic client that always dials the given Unix socket, ignoring the
/// placeholder URI authority (there is no network endpoint).
pub async fn grpc_connect(sock: PathBuf) -> MicrovmServiceClient<Channel> {
    let channel = tonic::transport::Endpoint::try_from("http://microvm.grpc".to_string())
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let sock = sock.clone();
            async move {
                Ok::<_, std::io::Error>(hyper_util::rt::tokio::TokioIo::new(
                    tokio::net::UnixStream::connect(sock).await?,
                ))
            }
        }))
        .await
        .expect("connect grpc channel");
    MicrovmServiceClient::new(channel)
}

fn grpc_err_code(status: &tonic::Status) -> String {
    error_body_from_status(status)
        .map(|b| b.error_code)
        .unwrap_or_else(|| format!("grpc:{:?}", status.code()))
}

fn proto_state_str(value: i32) -> String {
    match ProtoVmState::try_from(value) {
        Ok(ProtoVmState::Created) => "created".to_string(),
        Ok(ProtoVmState::Configured) => "configured".to_string(),
        Ok(ProtoVmState::Running) => "running".to_string(),
        Ok(ProtoVmState::Paused) => "paused".to_string(),
        Ok(ProtoVmState::Snapshotting) => "snapshotting".to_string(),
        Ok(ProtoVmState::Restoring) => "restoring".to_string(),
        Ok(ProtoVmState::Stopped) => "stopped".to_string(),
        Ok(ProtoVmState::Failed) => "failed".to_string(),
        _ => format!("unknown({value})"),
    }
}

fn proto_policy_str(value: i32) -> String {
    match ProtoNetworkPolicy::try_from(value) {
        Ok(ProtoNetworkPolicy::NatOnly) => "nat_only".to_string(),
        Ok(ProtoNetworkPolicy::FullEgress) => "egress_allowed".to_string(),
        // Unspecified and None both map to the domain default `none`.
        _ => "none".to_string(),
    }
}

// --- gRPC performers -------------------------------------------------------

pub async fn grpc_create(
    c: &mut MicrovmServiceClient<Channel>,
    vcpu: u32,
    mem: u64,
    disk: u64,
) -> OpResult {
    match c
        .create_vm(CreateVmRequest {
            vcpu_count: vcpu,
            memory_mib: mem,
            disk_mib: disk,
            network_policy: ProtoNetworkPolicy::None as i32,
        })
        .await
    {
        Ok(resp) => OpResult::Created(resp.into_inner().vm_id),
        Err(s) => OpResult::Error {
            code: grpc_err_code(&s),
        },
    }
}

pub async fn grpc_start(c: &mut MicrovmServiceClient<Channel>, vm_id: &str) -> OpResult {
    match c
        .start_vm(StartVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
    {
        Ok(_) => OpResult::Started,
        Err(s) => OpResult::Error {
            code: grpc_err_code(&s),
        },
    }
}

pub async fn grpc_stop(c: &mut MicrovmServiceClient<Channel>, vm_id: &str) -> OpResult {
    match c
        .stop_vm(StopVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
    {
        Ok(_) => OpResult::Stopped,
        Err(s) => OpResult::Error {
            code: grpc_err_code(&s),
        },
    }
}

pub async fn grpc_snapshot(c: &mut MicrovmServiceClient<Channel>, vm_id: &str) -> OpResult {
    match c
        .snapshot_vm(SnapshotVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
    {
        Ok(resp) => OpResult::Snapshotted(resp.into_inner().snapshot_id),
        Err(s) => OpResult::Error {
            code: grpc_err_code(&s),
        },
    }
}

pub async fn grpc_restore(c: &mut MicrovmServiceClient<Channel>, snapshot_id: &str) -> OpResult {
    match c
        .restore_vm(RestoreVmRequest {
            snapshot_id: snapshot_id.to_string(),
        })
        .await
    {
        Ok(resp) => OpResult::Restored(resp.into_inner().vm_id),
        Err(s) => OpResult::Error {
            code: grpc_err_code(&s),
        },
    }
}

pub async fn grpc_status(c: &mut MicrovmServiceClient<Channel>, vm_id: &str) -> OpResult {
    match c
        .get_vm_status(GetVmStatusRequest {
            vm_id: vm_id.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            let spec = r.resource_spec.expect("resource_spec present");
            OpResult::Status {
                vm_id: r.vm_id,
                state: proto_state_str(r.state),
                vcpu: spec.vcpu_count,
                mem: spec.memory_mib,
                disk: spec.disk_mib,
                policy: proto_policy_str(spec.network_policy),
            }
        }
        Err(s) => OpResult::Error {
            code: grpc_err_code(&s),
        },
    }
}

pub async fn grpc_metrics(c: &mut MicrovmServiceClient<Channel>, vm_id: &str) -> OpResult {
    match c
        .get_vm_metrics(GetVmMetricsRequest {
            vm_id: vm_id.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            OpResult::Metrics {
                vm_id: r.vm_id,
                state: proto_state_str(r.state),
            }
        }
        Err(s) => OpResult::Error {
            code: grpc_err_code(&s),
        },
    }
}

// ---------------------------------------------------------------------------
// Raw REST capture (for byte-identical error-body parity assertions)
// ---------------------------------------------------------------------------

/// A raw REST response with the body bytes preserved verbatim.
pub struct RestRaw {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Send one HTTP/1.1 request and return the response body bytes verbatim (no
/// JSON parsing), so error-body parity can be asserted byte-for-byte against the
/// gRPC status details.
pub async fn rest_call_raw(
    sock: &Path,
    method: &str,
    path: &str,
    json_body: Option<&str>,
) -> RestRaw {
    let mut stream = UnixStream::connect(sock)
        .await
        .expect("connect rest socket");
    let body = json_body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: microvm.local\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write rest request");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("rest read timed out")
        .expect("rest read failed");
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body_bytes = match text.find("\r\n\r\n") {
        Some(idx) => text[idx + 4..].trim().as_bytes().to_vec(),
        None => Vec::new(),
    };
    RestRaw {
        status,
        body: body_bytes,
    }
}
