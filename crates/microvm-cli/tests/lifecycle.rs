//! Mocked complete-lifecycle integration test for the `microvm` CLI.
//!
//! Spins up a real [`microvm_rest::RestServer`] over a temp Unix socket,
//! backed by an in-memory mock [`LifecycleService`], then drives the CLI
//! [`Client`] and [`execute`] dispatch through a full lifecycle:
//! create → start → status → snapshot → restore → metrics → stop.
//!
//! Also asserts the documented failure exit codes:
//! - status of a missing VM → exit 3 (not found),
//! - `run --image nginx:latest` → exit 4 (local artifact required) with
//!   no network activity.
//!
//! No `/dev/kvm`, no real Firecracker, no TCP, no network egress.

use async_trait::async_trait;
use microvm_cli::{Cli, Client, ExitCode};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_lifecycle::{LifecycleService, VmMetrics, VmState, VmStatus};
use microvm_metrics::VmMetricsRecord;
use microvm_rest::peer::StaticAuthenticator;
use microvm_rest::{RestServer, SocketConfig};
use microvm_types::{Principal, ResourceSpec, Role, SnapshotId, TenantId, VmId};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Mock lifecycle service (in-memory state machine)
// ---------------------------------------------------------------------------

struct MockVm {
    state: VmState,
    spec: ResourceSpec,
}

struct MockService {
    vms: Mutex<HashMap<String, MockVm>>,
    snapshots: Mutex<HashMap<String, String>>, // snapshot_id -> source vm_id
    counter: Mutex<u64>,
}

impl MockService {
    fn new() -> Self {
        Self {
            vms: Mutex::new(HashMap::new()),
            snapshots: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        }
    }

    fn next_id(&self, prefix: &str) -> String {
        let mut c = self.counter.lock().unwrap();
        *c += 1;
        format!("{prefix}-{:03}", *c)
    }
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

#[async_trait]
impl LifecycleService for MockService {
    async fn create(&self, spec: ResourceSpec, _owner: Principal) -> Result<VmId, MicrovmError> {
        let id = self.next_id("vm");
        self.vms.lock().unwrap().insert(
            id.clone(),
            MockVm {
                state: VmState::Created,
                spec,
            },
        );
        VmId::new(id).map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn start(&self, vm_id: &VmId, _p: &Principal) -> Result<(), MicrovmError> {
        let mut vms = self.vms.lock().unwrap();
        let vm = vms
            .get_mut(vm_id.as_str())
            .ok_or_else(|| MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM"))?;
        vm.state = VmState::Running;
        Ok(())
    }

    async fn stop(&self, vm_id: &VmId, _p: &Principal) -> Result<(), MicrovmError> {
        let mut vms = self.vms.lock().unwrap();
        let vm = vms
            .get_mut(vm_id.as_str())
            .ok_or_else(|| MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM"))?;
        vm.state = VmState::Stopped;
        Ok(())
    }

    async fn snapshot(&self, vm_id: &VmId, _p: &Principal) -> Result<SnapshotId, MicrovmError> {
        {
            let vms = self.vms.lock().unwrap();
            if !vms.contains_key(vm_id.as_str()) {
                return Err(MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM"));
            }
        }
        let snap_id = self.next_id("snap");
        self.snapshots
            .lock()
            .unwrap()
            .insert(snap_id.clone(), vm_id.as_str().to_string());
        SnapshotId::new(snap_id).map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        _p: &Principal,
    ) -> Result<VmId, MicrovmError> {
        let source = self
            .snapshots
            .lock()
            .unwrap()
            .get(snapshot_id.as_str())
            .cloned()
            .ok_or_else(|| MicrovmError::new(ErrorCode::ArtifactNotFound, "no such snapshot"))?;
        let spec = {
            let vms = self.vms.lock().unwrap();
            vms.get(&source)
                .map(|vm| vm.spec.clone())
                .unwrap_or_else(|| ResourceSpec::new(1, 512, 1024, Default::default()).unwrap())
        };
        let id = self.next_id("vm");
        self.vms.lock().unwrap().insert(
            id.clone(),
            MockVm {
                state: VmState::Running,
                spec,
            },
        );
        VmId::new(id).map_err(|e| MicrovmError::new(ErrorCode::InternalError, e.reason))
    }

    async fn status(&self, vm_id: &VmId, _p: &Principal) -> Result<VmStatus, MicrovmError> {
        let vms = self.vms.lock().unwrap();
        let vm = vms
            .get(vm_id.as_str())
            .ok_or_else(|| MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM"))?;
        Ok(VmStatus {
            vm_id: vm_id.clone(),
            state: vm.state,
            created_at: now(),
            resource_spec: vm.spec.clone(),
        })
    }

    async fn metrics(&self, vm_id: &VmId, _p: &Principal) -> Result<VmMetrics, MicrovmError> {
        let vms = self.vms.lock().unwrap();
        let vm = vms
            .get(vm_id.as_str())
            .ok_or_else(|| MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM"))?;
        Ok(VmMetrics {
            vm_id: vm_id.clone(),
            state: vm.state,
            record: VmMetricsRecord::not_collected(
                vm_id.clone(),
                vm.state.metrics_phase(),
                now(),
                0,
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Test harness: start a server, return the socket path
// ---------------------------------------------------------------------------

async fn start_server(socket_path: PathBuf) {
    let config = SocketConfig::with_path(&socket_path).with_mode(0o660);
    let uid = unsafe { libc::getuid() };
    let principal = Principal::new(TenantId::new("test-tenant").unwrap(), Role::Owner);
    let authenticator = StaticAuthenticator::new(uid, principal);
    let server = RestServer::new(
        config,
        Arc::new(MockService::new()),
        Arc::new(authenticator),
    );
    tokio::spawn(async move {
        let _ = server.serve().await;
    });
    // Wait for the socket file to appear.
    for _ in 0..100 {
        if socket_path.exists() {
            // Give the listener a moment to be ready.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server socket did not appear");
}

fn cli_for(socket: &Path, args: &[&str]) -> Cli {
    use clap::Parser;
    let mut full = vec!["microvm"];
    full.extend_from_slice(args);
    full.push("--socket");
    // Leak is fine in tests.
    let s: &'static str = Box::leak(socket.to_string_lossy().into_owned().into_boxed_str());
    full.push(s);
    Cli::parse_from(full)
}

// ---------------------------------------------------------------------------
// The mocked complete lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mocked_complete_lifecycle_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rest.sock");
    start_server(socket.clone()).await;

    // 1. create
    let digest = format!("sha256:{}", "a".repeat(64));
    let cli = cli_for(
        &socket,
        &[
            "create",
            "--image",
            &digest,
            "--vcpu",
            "2",
            "--memory-mib",
            "512",
        ],
    );
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "create failed: {out}");
    assert!(out.starts_with("created vm "), "create output: {out}");
    let vm_id = out.trim_start_matches("created vm ").to_string();

    // 2. start
    let cli = cli_for(&socket, &["start", "--vm-id", &vm_id]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "start failed: {out}");

    // 3. status (should be running)
    let cli = cli_for(&socket, &["status", "--vm-id", &vm_id]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "status failed: {out}");
    assert!(out.contains("state=running"), "status output: {out}");
    assert!(out.contains("vcpu=2"), "status output: {out}");

    // 4. snapshot
    let cli = cli_for(&socket, &["snapshot", "--vm-id", &vm_id]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "snapshot failed: {out}");
    assert!(
        out.starts_with("created snapshot "),
        "snapshot output: {out}"
    );
    let snap_id = out.trim_start_matches("created snapshot ").to_string();

    // 5. restore
    let cli = cli_for(&socket, &["restore", "--snapshot-id", &snap_id]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "restore failed: {out}");
    assert!(out.starts_with("restored vm "), "restore output: {out}");

    // 6. metrics
    let cli = cli_for(&socket, &["metrics", "--vm-id", &vm_id]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "metrics failed: {out}");
    assert!(
        out.contains("vm_id") || out.contains(&vm_id),
        "metrics output: {out}"
    );

    // 7. stop
    let cli = cli_for(&socket, &["stop", "--vm-id", &vm_id]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "stop failed: {out}");

    // 8. status (should be stopped)
    let cli = cli_for(&socket, &["status", "--vm-id", &vm_id]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "status after stop failed: {out}");
    assert!(out.contains("state=stopped"), "status output: {out}");
}

#[tokio::test]
async fn status_of_missing_vm_is_not_found_exit_3() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rest.sock");
    start_server(socket.clone()).await;

    let cli = cli_for(&socket, &["status", "--vm-id", "missing-vm"]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::NotFound, "expected exit 3, got: {out}");
    assert!(out.contains("artifact_not_found"), "output: {out}");
}

#[tokio::test]
async fn stop_of_missing_vm_is_not_found_exit_3() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rest.sock");
    start_server(socket.clone()).await;

    let cli = cli_for(&socket, &["stop", "--vm-id", "missing-vm"]);
    let (code, _out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::NotFound);
}

#[tokio::test]
async fn run_with_remote_tag_is_local_artifact_required_exit_4_no_network() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rest.sock");
    // Note: we do not need a running server; the reference is rejected
    // before any socket contact. But start one anyway to prove no network
    // activity is required for the rejection.
    start_server(socket.clone()).await;

    let cli = cli_for(&socket, &["run", "--image", "nginx:latest"]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(
        code,
        ExitCode::LocalArtifactRequired,
        "expected exit 4, got: {out}"
    );
    assert!(out.contains("local_artifact_required"), "output: {out}");
}

#[tokio::test]
async fn create_with_remote_image_is_local_artifact_required_exit_4() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rest.sock");
    start_server(socket.clone()).await;

    let cli = cli_for(&socket, &["create", "--image", "docker://nginx:latest"]);
    let (code, _out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::LocalArtifactRequired);
}

#[tokio::test]
async fn client_to_missing_socket_is_not_found_exit_3() {
    // No server started; socket path does not exist.
    let socket = PathBuf::from("/tmp/definitely-not-here-microvm.sock");
    let client = Client::new(&socket);
    let err = client.get_status("vm-001").await.expect_err("must fail");
    assert_eq!(err.exit_code, ExitCode::NotFound);
    // Must not leak the host path.
    assert!(!err.message.contains("/tmp/definitely-not-here"));
}

#[tokio::test]
async fn run_local_layout_imports_and_runs() {
    // Build a real local OCI-like layout and run it end-to-end through the
    // constrained importer + mock service.
    use microvm_oci::MEDIA_ANNOTATION;
    use serde_json::json;

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rest.sock");
    start_server(socket.clone()).await;

    let layout = dir.path().join("layout");
    let blobs = layout.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs).unwrap();

    let kernel = b"microvm-guest-kernel-bzimage-v1";
    let rootfs = b"microvm-guest-rootfs-ext4-v1-bytes";
    let kernel_hex = microvm_artifacts::compute_sha256(&kernel[..])
        .unwrap()
        .to_hex();
    let rootfs_hex = microvm_artifacts::compute_sha256(&rootfs[..])
        .unwrap()
        .to_hex();
    std::fs::write(blobs.join(&kernel_hex), kernel).unwrap();
    std::fs::write(blobs.join(&rootfs_hex), rootfs).unwrap();

    let mut labels = serde_json::Map::new();
    labels.insert("org.microvm.vcpu".into(), json!("2"));
    labels.insert("org.microvm.memory-mib".into(), json!("512"));
    labels.insert("org.microvm.disk-mib".into(), json!("1024"));
    labels.insert("org.microvm.network".into(), json!("nat-only"));
    let config = json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Labels": labels },
        "rootfs": { "type": "layers", "diff_ids": [] },
    });
    let config_bytes = serde_json::to_vec(&config).unwrap();
    let config_hex = microvm_artifacts::compute_sha256(&config_bytes[..])
        .unwrap()
        .to_hex();
    std::fs::write(blobs.join(&config_hex), &config_bytes).unwrap();

    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{config_hex}"),
            "size": config_bytes.len(),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": format!("sha256:{kernel_hex}"),
                "size": kernel.len(),
                "annotations": { MEDIA_ANNOTATION: "kernel" },
            },
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": format!("sha256:{rootfs_hex}"),
                "size": rootfs.len(),
                "annotations": { MEDIA_ANNOTATION: "rootfs" },
            },
        ],
    });
    std::fs::write(
        layout.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let layout_str = layout.to_string_lossy().to_string();
    let cli = cli_for(&socket, &["run", "--image", &layout_str]);
    let (code, out) = microvm_cli::execute(&cli).await;
    assert_eq!(code, ExitCode::Success, "run failed: {out}");
    assert!(out.starts_with("running vm "), "run output: {out}");
}
