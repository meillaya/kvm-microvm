//! Shared harness for the end-to-end REST/gRPC lifecycle tests (phase 2 story 2).
//!
//! Two deterministic backend lanes are provided, both wrapped in the composed
//! [`VmLifecycleService`] and driven through the real REST/gRPC Unix-socket
//! servers:
//!
//! 1. [`ScriptedBackend`]: a fully-scripted inner backend (no real Firecracker)
//!    that implements the *entire* lifecycle, including the snapshot/restore
//!    routes, with a realistic state machine, a concrete guest-health TCP
//!    endpoint (the "TAP IP:port" the orchestrator waits on), and real
//!    per-VM resource markers (API socket, cgroup leaf, netns, TAP) that are
//!    provisioned on start and released on stop. This drives the full
//!    create → start → health → status → snapshot → restore → stop → cleanup
//!    flow deterministically.
//! 2. [`ComposedRig`]: the genuine [`FirecrackerBackend`] wired with scripted
//!    launcher/API/readiness/prereq/cleanup doubles over temporary directories
//!    (a real digest-validated artifact store, a simulated cgroup-v2 hierarchy,
//!    and a netns root). This proves a real composed boot through the API and
//!    verifies post-stop resource cleanup (no leftover cgroup/netns/socket).
//!
//! Authorization is delegated entirely to the service; this harness only maps
//! the local test process UID to a [`Principal`] via each transport's
//! peer-credential authenticator. It never duplicates or weakens policy.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_grpc::error::error_body_from_status;
use microvm_grpc::peer::{
    PeerAuthenticator as GrpcPeerAuthenticator, StaticAuthenticator as GrpcStaticAuthenticator,
};
use microvm_grpc::proto::v1::microvm_service_client::MicrovmServiceClient;
use microvm_grpc::proto::v1::{
    CreateVmRequest, GetVmStatusRequest, NetworkPolicy as ProtoNetworkPolicy, RestoreVmRequest,
    SnapshotVmRequest, StartVmRequest, StopVmRequest, VmState as ProtoVmState,
};
use microvm_grpc::{GrpcServer, SocketConfig as GrpcSocketConfig};
use microvm_lifecycle::policy::InMemoryAuditLog;
use microvm_lifecycle::{LifecycleService, VmMetrics, VmState, VmStatus};
use microvm_metrics::VmMetricsRecord;
use microvm_rest::peer::{
    PeerAuthenticator as RestPeerAuthenticator, StaticAuthenticator as RestStaticAuthenticator,
};
use microvm_rest::{RestServer, SocketConfig as RestSocketConfig};
use microvm_service::{ScriptedSupervisorProbe, VmLifecycleService};
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, SnapshotId, TenantId, VmId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tonic::transport::{Channel, Uri};

/// The tenant that owns the fixtures' resources.
pub const TENANT: &str = "acme";

pub fn test_principal() -> Principal {
    Principal::new(TenantId::new(TENANT).unwrap(), Role::Owner)
}

// ===========================================================================
// Lane 1: fully-scripted inner backend (full lifecycle incl. snapshot/restore)
// ===========================================================================

/// Per-VM record held by the [`ScriptedBackend`].
struct VmRec {
    state: VmState,
    spec: ResourceSpec,
    created_at: chrono::DateTime<chrono::Utc>,
    /// The guest-health TCP endpoint provisioned on start (the "TAP IP:port").
    /// Holding the listener keeps the port listening; dropping it on stop
    /// closes the endpoint.
    health: Option<TcpListener>,
}

/// A deterministic, stateful [`LifecycleService`] used as the inner runtime
/// double for [`VmLifecycleService`].
///
/// It plays the role the Firecracker backend plays in production. Unlike the
/// real boot adapter (whose snapshot/restore land in a later todo), this double
/// implements the *whole* lifecycle so the e2e suite can exercise the
/// snapshot/restore API routes deterministically. It provisions real per-VM
/// resource markers under a temp root and a real guest-health TCP endpoint so
/// the "wait for health check on TAP IP:port" and "no leftover resources"
/// assertions are concrete rather than synthetic.
pub struct ScriptedBackend {
    root: PathBuf,
    next_vm: AtomicU64,
    next_snap: AtomicU64,
    vms: Mutex<HashMap<String, VmRec>>,
    /// snapshot_id -> source vm_id
    snapshots: Mutex<HashMap<String, String>>,
}

impl ScriptedBackend {
    pub fn new(root: PathBuf) -> Self {
        std::fs::create_dir_all(&root).unwrap();
        Self {
            root,
            next_vm: AtomicU64::new(1),
            next_snap: AtomicU64::new(1),
            vms: Mutex::new(HashMap::new()),
            snapshots: Mutex::new(HashMap::new()),
        }
    }

    /// The per-VM resource directory (holds the socket/cgroup/netns/TAP markers).
    pub fn vm_dir(&self, vm_id: &str) -> PathBuf {
        self.root.join(vm_id)
    }

    pub fn socket_marker(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("api.sock")
    }
    pub fn cgroup_marker(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("cgroup")
    }
    pub fn netns_marker(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("netns")
    }
    pub fn tap_marker(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("tap0")
    }

    /// The guest-health TCP address for a running VM, if provisioned.
    pub fn health_addr(&self, vm_id: &str) -> Option<std::net::SocketAddr> {
        self.vms
            .lock()
            .unwrap()
            .get(vm_id)
            .and_then(|r| r.health.as_ref())
            .map(|l| l.local_addr().unwrap())
    }

    /// Whether every per-VM resource marker is absent (post-stop cleanup check).
    pub fn resources_released(&self, vm_id: &str) -> bool {
        !self.vm_dir(vm_id).exists()
    }

    /// Provision the per-VM resource markers (API socket, cgroup, netns, TAP).
    fn provision(&self, vm_id: &str) {
        let dir = self.vm_dir(vm_id);
        std::fs::create_dir_all(&dir).unwrap();
        for marker in ["api.sock", "cgroup", "netns", "tap0"] {
            std::fs::write(dir.join(marker), b"").unwrap();
        }
    }

    /// Release every per-VM resource marker.
    fn release(&self, vm_id: &str) {
        let _ = std::fs::remove_dir_all(self.vm_dir(vm_id));
    }
}

#[async_trait]
impl LifecycleService for ScriptedBackend {
    async fn create(&self, spec: ResourceSpec, _owner: Principal) -> Result<VmId, MicrovmError> {
        let n = self.next_vm.fetch_add(1, Ordering::SeqCst);
        let id = VmId::new(format!("vm-{n:04}"))
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))?;
        self.vms.lock().unwrap().insert(
            id.as_str().to_string(),
            VmRec {
                state: VmState::Created,
                spec,
                created_at: chrono::Utc::now(),
                health: None,
            },
        );
        Ok(id)
    }

    async fn start(&self, vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        let mut guard = self.vms.lock().unwrap();
        let rec = guard
            .get_mut(vm_id.as_str())
            .ok_or_else(|| not_found(vm_id))?;
        // Provision resources and the guest-health endpoint (the "TAP IP:port").
        self.provision(vm_id.as_str());
        // Bind the health endpoint on loopback (the deterministic stand-in for
        // the guest agent listening on the TAP address). Holding the listener
        // keeps the port in LISTEN; a health probe completes the TCP handshake
        // against the listen backlog, so reachability proves readiness. Dropping
        // the listener on stop closes the endpoint.
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.to_string()))?;
        std_listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(std_listener)
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.to_string()))?;
        rec.health = Some(listener);
        rec.state = VmState::Running;
        Ok(())
    }

    async fn stop(&self, vm_id: &VmId, _principal: &Principal) -> Result<(), MicrovmError> {
        let mut guard = self.vms.lock().unwrap();
        let rec = guard
            .get_mut(vm_id.as_str())
            .ok_or_else(|| not_found(vm_id))?;
        rec.health = None; // drop the health endpoint
        rec.state = VmState::Stopped;
        self.release(vm_id.as_str());
        Ok(())
    }

    async fn snapshot(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError> {
        {
            let guard = self.vms.lock().unwrap();
            let rec = guard.get(vm_id.as_str()).ok_or_else(|| not_found(vm_id))?;
            if !matches!(rec.state, VmState::Running | VmState::Paused) {
                return Err(MicrovmError::new(
                    ErrorCode::InvalidTransition,
                    format!("cannot snapshot VM in {} state", rec.state),
                )
                .with_context("vm_id", vm_id.as_str()));
            }
        }
        let n = self.next_snap.fetch_add(1, Ordering::SeqCst);
        let snap = SnapshotId::new(format!("snap-{n:04}"))
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))?;
        self.snapshots
            .lock()
            .unwrap()
            .insert(snap.as_str().to_string(), vm_id.as_str().to_string());
        Ok(snap)
    }

    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        _principal: &Principal,
    ) -> Result<VmId, MicrovmError> {
        let source = self
            .snapshots
            .lock()
            .unwrap()
            .get(snapshot_id.as_str())
            .cloned()
            .ok_or_else(|| {
                MicrovmError::new(ErrorCode::ArtifactNotFound, "no such snapshot")
                    .with_context("snapshot_id", snapshot_id.as_str())
            })?;
        // The restored VM inherits the source VM's resource spec.
        let spec = {
            let guard = self.vms.lock().unwrap();
            guard
                .get(&source)
                .map(|r| r.spec.clone())
                .unwrap_or_else(|| ResourceSpec::new(2, 512, 1024, NetworkPolicy::None).unwrap())
        };
        let n = self.next_vm.fetch_add(1, Ordering::SeqCst);
        let id = VmId::new(format!("vm-{n:04}"))
            .map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))?;
        // A restored VM comes up running with its own resources + health endpoint.
        self.provision(id.as_str());
        let std_keep = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_keep.set_nonblocking(true).unwrap();
        let keep = TcpListener::from_std(std_keep).unwrap();
        self.vms.lock().unwrap().insert(
            id.as_str().to_string(),
            VmRec {
                state: VmState::Running,
                spec,
                created_at: chrono::Utc::now(),
                health: Some(keep),
            },
        );
        Ok(id)
    }

    async fn status(&self, vm_id: &VmId, _principal: &Principal) -> Result<VmStatus, MicrovmError> {
        // The supervised service answers `status` from its own reconciled
        // registry and never delegates here; implemented for trait completeness.
        let guard = self.vms.lock().unwrap();
        let rec = guard.get(vm_id.as_str()).ok_or_else(|| not_found(vm_id))?;
        Ok(VmStatus {
            vm_id: vm_id.clone(),
            state: rec.state,
            created_at: rec.created_at,
            resource_spec: rec.spec.clone(),
        })
    }

    async fn metrics(
        &self,
        vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<VmMetrics, MicrovmError> {
        let guard = self.vms.lock().unwrap();
        let rec = guard.get(vm_id.as_str()).ok_or_else(|| not_found(vm_id))?;
        Ok(VmMetrics {
            record: VmMetricsRecord::not_collected(
                vm_id.clone(),
                rec.state.metrics_phase(),
                chrono::Utc::now(),
                0,
            ),
            vm_id: vm_id.clone(),
            state: rec.state,
        })
    }
}

fn not_found(vm_id: &VmId) -> MicrovmError {
    MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
        .with_context("vm_id", vm_id.as_str())
}

// ===========================================================================
// Rig: supervised service over the scripted backend + REST/gRPC servers
// ===========================================================================

/// A fully wired [`VmLifecycleService`] over the [`ScriptedBackend`], with a
/// handle to the inner backend for resource assertions.
pub struct Rig {
    pub service: Arc<VmLifecycleService>,
    pub backend: Arc<ScriptedBackend>,
    pub audit: Arc<InMemoryAuditLog>,
    pub owner: Principal,
    _tmp: tempfile::TempDir,
}

impl Rig {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let backend = Arc::new(ScriptedBackend::new(tmp.path().join("resources")));
        let audit = Arc::new(InMemoryAuditLog::new());
        let service = Arc::new(
            VmLifecycleService::builder()
                .inner(backend.clone())
                .supervisor_probe(Arc::new(ScriptedSupervisorProbe::new()))
                .audit_log(audit.clone())
                .build(),
        );
        Rig {
            service,
            backend,
            audit,
            owner: test_principal(),
            _tmp: tmp,
        }
    }

    pub fn sock(&self, name: &str) -> PathBuf {
        self._tmp.path().join(name)
    }

    /// Spawn a REST server backed by this rig's service and return its socket.
    pub async fn spawn_rest(&self, name: &str) -> PathBuf {
        let sock = self.sock(name);
        spawn_rest_server(sock.clone(), self.service.clone()).await;
        sock
    }

    /// Spawn a gRPC server backed by this rig's service and return its socket.
    pub async fn spawn_grpc(&self, name: &str) -> PathBuf {
        let sock = self.sock(name);
        spawn_grpc_server(sock.clone(), self.service.clone()).await;
        sock
    }
}

/// The UID of the current process (used to map peer credentials to a principal).
pub fn my_uid() -> u32 {
    // SAFETY: getuid is async-signal-safe and always succeeds; the test harness
    // runs as a normal process. This is the same approach the transport contract
    // suite uses.
    unsafe { libc::getuid() }
}

pub async fn spawn_rest_server(sock: PathBuf, service: Arc<VmLifecycleService>) {
    let auth: Arc<dyn RestPeerAuthenticator> =
        Arc::new(RestStaticAuthenticator::new(my_uid(), test_principal()));
    let server = RestServer::new(
        RestSocketConfig::with_path(&sock).with_mode(0o660),
        service,
        auth,
    );
    tokio::spawn(async move {
        let _ = server.serve().await;
    });
    wait_for_socket(&sock).await;
}

pub async fn spawn_grpc_server(sock: PathBuf, service: Arc<VmLifecycleService>) {
    let auth: Arc<dyn GrpcPeerAuthenticator> =
        Arc::new(GrpcStaticAuthenticator::new(my_uid(), test_principal()));
    let server = GrpcServer::new(
        GrpcSocketConfig::with_path(&sock).with_mode(0o660),
        service,
        auth,
    );
    tokio::spawn(async move {
        let _ = server.serve().await;
    });
    wait_for_socket(&sock).await;
}

pub async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("socket {} was not created", path.display());
}

// ===========================================================================
// REST client (raw HTTP/1.1 over a Unix socket)
// ===========================================================================

/// A parsed REST response.
pub struct RestOutcome {
    pub status: u16,
    pub body: serde_json::Value,
}

/// Send one HTTP/1.1 request over the Unix socket and parse the JSON response.
pub async fn rest_call(
    sock: &Path,
    method: &str,
    path: &str,
    json_body: Option<&str>,
) -> RestOutcome {
    let mut stream = UnixStream::connect(sock).await.expect("connect rest");
    let body = json_body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: microvm.local\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.expect("write rest");
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

pub async fn rest_create(sock: &Path, vcpu: u32, mem: u64, disk: u64) -> (u16, String) {
    rest_create_with_policy(sock, vcpu, mem, disk, "none").await
}

/// Create a VM with an explicit network policy string.
pub async fn rest_create_with_policy(
    sock: &Path,
    vcpu: u32,
    mem: u64,
    disk: u64,
    policy: &str,
) -> (u16, String) {
    let body = serde_json::json!({
        "vcpu_count": vcpu,
        "memory_mib": mem,
        "disk_mib": disk,
        "network_policy": policy,
    })
    .to_string();
    let r = rest_call(sock, "POST", "/vms", Some(&body)).await;
    let vm_id = r.body["vm_id"].as_str().unwrap_or("").to_string();
    (r.status, vm_id)
}

pub async fn rest_start(sock: &Path, vm_id: &str) -> u16 {
    rest_call(sock, "POST", &format!("/vms/{vm_id}/start"), Some(""))
        .await
        .status
}

pub async fn rest_stop(sock: &Path, vm_id: &str) -> u16 {
    rest_call(sock, "POST", &format!("/vms/{vm_id}/stop"), Some(""))
        .await
        .status
}

pub async fn rest_snapshot(sock: &Path, vm_id: &str) -> (u16, String) {
    let r = rest_call(sock, "POST", &format!("/vms/{vm_id}/snapshot"), Some("")).await;
    let snap = r.body["snapshot_id"].as_str().unwrap_or("").to_string();
    (r.status, snap)
}

pub async fn rest_restore(sock: &Path, snapshot_id: &str) -> (u16, String) {
    let r = rest_call(
        sock,
        "POST",
        &format!("/snapshots/{snapshot_id}/restore"),
        Some(""),
    )
    .await;
    let vm_id = r.body["vm_id"].as_str().unwrap_or("").to_string();
    (r.status, vm_id)
}

pub async fn rest_status(sock: &Path, vm_id: &str) -> (u16, String) {
    let r = rest_call(sock, "GET", &format!("/vms/{vm_id}"), None).await;
    let state = r.body["state"].as_str().unwrap_or("").to_string();
    (r.status, state)
}

/// Poll `GET /vms/{id}` until the state reaches `want` (the API-level "wait for
/// health/readiness" step), or time out.
pub async fn rest_wait_for_state(sock: &Path, vm_id: &str, want: &str) {
    for _ in 0..200 {
        let (status, state) = rest_status(sock, vm_id).await;
        if status == 200 && state == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("VM {vm_id} did not reach state {want}");
}

/// Perform the guest health check against the backend's "TAP IP:port" endpoint.
pub async fn wait_for_health(backend: &ScriptedBackend, vm_id: &str) {
    let mut addr = None;
    for _ in 0..200 {
        if let Some(a) = backend.health_addr(vm_id) {
            addr = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let addr = addr.unwrap_or_else(|| panic!("health endpoint for {vm_id} was never provisioned"));
    // Connect: a completed handshake against the listen backlog proves the
    // guest-health endpoint (the "TAP IP:port") is reachable.
    let _stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("health endpoint reachable");
}

// ===========================================================================
// gRPC client (tonic over a Unix socket)
// ===========================================================================

/// Connect a tonic client that always dials the given Unix socket.
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

pub fn grpc_err_code(status: &tonic::Status) -> String {
    error_body_from_status(status)
        .map(|b| b.error_code)
        .unwrap_or_else(|| format!("grpc:{:?}", status.code()))
}

pub fn proto_state_str(value: i32) -> String {
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

pub async fn grpc_create(
    c: &mut MicrovmServiceClient<Channel>,
    vcpu: u32,
    mem: u64,
    disk: u64,
) -> Result<String, tonic::Status> {
    grpc_create_with_policy(c, vcpu, mem, disk, ProtoNetworkPolicy::None).await
}

/// Create a VM with an explicit network policy.
pub async fn grpc_create_with_policy(
    c: &mut MicrovmServiceClient<Channel>,
    vcpu: u32,
    mem: u64,
    disk: u64,
    policy: ProtoNetworkPolicy,
) -> Result<String, tonic::Status> {
    c.create_vm(CreateVmRequest {
        vcpu_count: vcpu,
        memory_mib: mem,
        disk_mib: disk,
        network_policy: policy as i32,
    })
    .await
    .map(|r| r.into_inner().vm_id)
}

pub async fn grpc_start(
    c: &mut MicrovmServiceClient<Channel>,
    vm_id: &str,
) -> Result<(), tonic::Status> {
    c.start_vm(StartVmRequest {
        vm_id: vm_id.to_string(),
    })
    .await
    .map(|_| ())
}

pub async fn grpc_stop(
    c: &mut MicrovmServiceClient<Channel>,
    vm_id: &str,
) -> Result<(), tonic::Status> {
    c.stop_vm(StopVmRequest {
        vm_id: vm_id.to_string(),
    })
    .await
    .map(|_| ())
}

pub async fn grpc_snapshot(
    c: &mut MicrovmServiceClient<Channel>,
    vm_id: &str,
) -> Result<String, tonic::Status> {
    c.snapshot_vm(SnapshotVmRequest {
        vm_id: vm_id.to_string(),
    })
    .await
    .map(|r| r.into_inner().snapshot_id)
}

pub async fn grpc_restore(
    c: &mut MicrovmServiceClient<Channel>,
    snapshot_id: &str,
) -> Result<String, tonic::Status> {
    c.restore_vm(RestoreVmRequest {
        snapshot_id: snapshot_id.to_string(),
    })
    .await
    .map(|r| r.into_inner().vm_id)
}

pub async fn grpc_status(
    c: &mut MicrovmServiceClient<Channel>,
    vm_id: &str,
) -> Result<String, tonic::Status> {
    c.get_vm_status(GetVmStatusRequest {
        vm_id: vm_id.to_string(),
    })
    .await
    .map(|r| proto_state_str(r.into_inner().state))
}

/// Poll `GetVmStatus` until the state reaches `want`.
pub async fn grpc_wait_for_state(c: &mut MicrovmServiceClient<Channel>, vm_id: &str, want: &str) {
    for _ in 0..200 {
        if let Ok(state) = grpc_status(c, vm_id).await {
            if state == want {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("VM {vm_id} did not reach state {want}");
}

// ===========================================================================
// Lane 2: genuine FirecrackerBackend wired with scripted doubles
// ===========================================================================

use microvm_artifacts::{compute_sha256, ArtifactStore};
use microvm_firecracker::backend::{ApiFactory, BackendConfig, FirecrackerBackend};
use microvm_firecracker::config::{BootConfig, NetworkBootConfig};
use microvm_firecracker::testing::{
    RecordingApi, ScriptedApiFactory, ScriptedLauncher, ScriptedPrereq, ScriptedProbe,
};
use microvm_isolation::{
    CgroupManager, CleanupBackend, CleanupManager, NetManager, RecordingCleanupBackend,
};
use microvm_service::IsolationCleanup;

pub const KERNEL_BYTES: &[u8] = b"guest-kernel-bzimage-v1";
pub const ROOTFS_BYTES: &[u8] = b"guest-rootfs-ext4-v1";

/// A `Send + Sync` wrapper around [`RecordingCleanupBackend`] (which uses a
/// `RefCell` internally and is therefore not `Sync`).
#[derive(Debug, Default)]
pub struct SyncRecordingCleanup {
    inner: Mutex<RecordingCleanupBackend>,
}

impl SyncRecordingCleanup {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RecordingCleanupBackend::new()),
        }
    }
}

impl CleanupBackend for SyncRecordingCleanup {
    fn kill_process(&self, pid: u32) -> Result<bool, MicrovmError> {
        self.inner.lock().unwrap().kill_process(pid)
    }
    fn flush_nft_table(&self, table: &str) -> Result<bool, MicrovmError> {
        self.inner.lock().unwrap().flush_nft_table(table)
    }
    fn delete_tap(&self, netns: &str, tap: &str) -> Result<bool, MicrovmError> {
        self.inner.lock().unwrap().delete_tap(netns, tap)
    }
    fn remove_netns(&self, netns: &str) -> Result<bool, MicrovmError> {
        self.inner.lock().unwrap().remove_netns(netns)
    }
}

/// Build a simulated cgroup-v2 hierarchy whose parent exposes all controllers.
fn simulated_cgroup(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("cgroup.controllers"), "cpu memory pids io").unwrap();
    std::fs::write(root.join("cgroup.subtree_control"), "").unwrap();
    let parent = root.join("microvm");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::write(parent.join("cgroup.controllers"), "cpu memory pids io").unwrap();
    std::fs::write(parent.join("cgroup.subtree_control"), "").unwrap();
}

/// A genuine [`FirecrackerBackend`] (scripted doubles over temp dirs) wrapped in
/// the composed [`VmLifecycleService`], with path handles for cleanup checks.
pub struct ComposedRig {
    pub service: Arc<VmLifecycleService>,
    pub socket_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub netns_root: PathBuf,
    pub owner: Principal,
    pub spec: ResourceSpec,
    _tmp: tempfile::TempDir,
}

impl ComposedRig {
    pub async fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();

        // Digest-validated artifact store with a real kernel/rootfs.
        std::fs::create_dir_all(base.join("artifacts")).unwrap();
        let store = ArtifactStore::new(base.join("artifacts")).unwrap();
        let tenant = TenantId::new(TENANT).unwrap();
        let troot = store.tenant_root(&tenant);
        std::fs::create_dir_all(troot.join("images")).unwrap();
        std::fs::write(troot.join("images/vmlinux"), KERNEL_BYTES).unwrap();
        std::fs::write(troot.join("images/rootfs.ext4"), ROOTFS_BYTES).unwrap();
        let kernel_digest = compute_sha256(KERNEL_BYTES).unwrap();
        let rootfs_digest = compute_sha256(ROOTFS_BYTES).unwrap();

        let boot = BootConfig::builder()
            .kernel_path("images/vmlinux")
            .kernel_sha256(kernel_digest)
            .rootfs_path("images/rootfs.ext4")
            .rootfs_sha256(rootfs_digest)
            .vcpu_count(2)
            .mem_size_mib(512)
            .boot_args("console=ttyS0 reboot=k panic=1 pci=off")
            .network(NetworkBootConfig::new(NetworkPolicy::NatOnly).unwrap())
            .build()
            .unwrap();

        // Isolation managers over a simulated cgroup-v2 hierarchy + netns root.
        let cgroup_root = base.join("cgroup");
        simulated_cgroup(&cgroup_root);
        let cgroup = CgroupManager::new(&cgroup_root);
        let netns_root = base.join("netns");
        let net = NetManager::new(&netns_root);
        let socket_root = base.join("sockets");
        let chroot_root = base.join("chroot");
        let cleanup_manager = CleanupManager::new(&cgroup_root, &chroot_root, &socket_root);

        // Scripted doubles.
        let launcher = Arc::new(
            ScriptedLauncher::new()
                .with_outcome(microvm_firecracker::testing::SpawnOutcome::Auto)
                .with_socket_on_spawn(),
        );
        let api = Arc::new(RecordingApi::new());
        let api_factory: Arc<dyn ApiFactory> = Arc::new(ScriptedApiFactory::new(api.clone()));
        let readiness = Arc::new(ScriptedProbe::ready());
        let prereq = Arc::new(ScriptedPrereq::ok());
        let cleanup_backend = Arc::new(SyncRecordingCleanup::new());

        let config = BackendConfig {
            socket_root: socket_root.clone(),
            ..BackendConfig::default()
        };

        let backend = Arc::new(
            FirecrackerBackend::builder()
                .config(config)
                .launcher(launcher)
                .api_factory(api_factory)
                .probe(readiness)
                .prereq(prereq)
                .cleanup_backend(cleanup_backend.clone())
                .artifacts(store)
                .cgroup(cgroup)
                .net(net)
                .cleanup(cleanup_manager.clone())
                .default_boot(boot)
                .build(),
        );

        let isolation_cleanup = Arc::new(IsolationCleanup::new(
            cleanup_manager,
            cleanup_backend,
            socket_root.clone(),
        ));

        let service = Arc::new(
            VmLifecycleService::builder()
                .firecracker(backend)
                .supervisor_probe(Arc::new(ScriptedSupervisorProbe::new()))
                .audit_log(Arc::new(InMemoryAuditLog::new()))
                .cleanup(isolation_cleanup)
                .build(),
        );

        let owner = Principal::new(tenant, Role::Owner);
        let spec = ResourceSpec::new(2, 512, 1024, NetworkPolicy::NatOnly).unwrap();

        ComposedRig {
            service,
            socket_root,
            cgroup_root,
            netns_root,
            owner,
            spec,
            _tmp: tmp,
        }
    }

    pub fn socket_path(&self, vm: &str) -> PathBuf {
        self.socket_root.join(vm).join("api.sock")
    }
    pub fn cgroup_leaf(&self, vm: &str) -> PathBuf {
        self.cgroup_root.join("microvm").join(vm)
    }
    pub fn netns_file(&self, vm: &str) -> PathBuf {
        self.netns_root.join(format!("microvm-{vm}"))
    }
}
