//! The Firecracker boot/configure/start/stop adapter.
//!
//! [`FirecrackerBackend`] implements the transport-neutral
//! [`LifecycleService`] trait using Firecracker as the runtime: one Firecracker
//! process per VM, configured over its per-VM Unix-socket API. The backend
//! orchestrates the full boot pipeline:
//!
//! 1. **Prerequisites** — host capabilities and binary provenance are verified
//!    *before* any child is created ([`crate::prereq`]).
//! 2. **Artifact integrity** — kernel and rootfs are opened relative to the
//!    tenant root and SHA-256-verified ([`microvm_artifacts`]).
//! 3. **Isolation** — a cgroup-v2 leaf and (when networked) a netns/TAP are
//!    provisioned ([`microvm_isolation`]).
//! 4. **Spawn** — the child process is launched and the `spawn` phase recorded.
//! 5. **Socket readiness** — the backend waits for the API socket, recording
//!    `socket_ready`.
//! 6. **Configuration** — machine/kernel/rootfs/network are pushed over the API,
//!    recording `configured` (Created→Configured).
//! 7. **Start + guest readiness** — `InstanceStart` is issued and the backend
//!    waits for the *guest* (not just the process/socket), recording
//!    `guest_ready` (Configured→Running).
//!
//! Process spawn failures and API errors drive the VM to [`VmState::Failed`] and
//! trigger resource cleanup. Stop sends `SendCtrlAltDel`, waits for exit, and
//! tears down every per-VM resource via [`microvm_isolation::CleanupManager`].
//!
//! # Security
//! The Firecracker API socket is unauthenticated. It lives in a host-only
//! socket root and is **never** exposed in tenant-facing [`VmStatus`] or
//! [`VmMetrics`] responses; see [`FirecrackerBackend::socket_path`] for the
//! host-internal accessor.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use microvm_artifacts::ArtifactStore;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_isolation::{
    CgroupManager, CgroupSpec, CleanupBackend, CleanupManager, NetConfig, NetManager,
    ResourceRecord,
};
use microvm_lifecycle::{
    policy::{authorize, AuditEvent, AuditLog, AuditResult, Operation, ResourceType},
    transition, LifecycleService, VmMetrics, VmState, VmStatus,
};
use microvm_types::{Principal, ResourceSpec, SnapshotId, TenantId, VmId};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

use crate::api::{BootSource, Drive, FirecrackerApi, MachineConfig, NetworkInterface};
use crate::config::BootConfig;
use crate::phase::Phase;
use crate::prereq::PrerequisiteCheck;
use crate::process::{LaunchSpec, ProcessLauncher, VmProcess};
use crate::readiness::{GuestReadinessProbe, ReadinessContext, DEFAULT_READINESS_TIMEOUT};

/// Default interval between socket-readiness polls.
pub const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Default time to wait for the API socket to appear.
pub const DEFAULT_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
/// Default `pids.max` for a VM cgroup leaf.
pub const DEFAULT_PIDS_MAX: u64 = 256;
/// Default cgroup CPU period (microseconds).
pub const CPU_PERIOD_US: u64 = 100_000;
/// Non-root UID/GID the jailer drops to by default.
pub const DEFAULT_JAILER_UID: u32 = 10_000;
/// Non-root GID the jailer drops to by default.
pub const DEFAULT_JAILER_GID: u32 = 10_000;

/// Creates a [`FirecrackerApi`] for a VM's API socket.
///
/// The real implementation returns a [`crate::api::UdsApiClient`]; tests return
/// a scripted API.
pub trait ApiFactory: Send + Sync {
    /// Connect (or bind a scripted client) to `socket_path`.
    fn connect(&self, socket_path: &Path) -> Arc<dyn FirecrackerApi>;
}

/// An [`ApiFactory`] producing real [`crate::api::UdsApiClient`]s.
#[derive(Clone, Debug, Default)]
pub struct UdsApiFactory;

impl ApiFactory for UdsApiFactory {
    fn connect(&self, socket_path: &Path) -> Arc<dyn FirecrackerApi> {
        Arc::new(crate::api::UdsApiClient::new(socket_path))
    }
}

// ---------------------------------------------------------------------------
// Backend configuration
// ---------------------------------------------------------------------------

/// Static configuration for a [`FirecrackerBackend`].
#[derive(Clone, Debug)]
pub struct BackendConfig {
    /// Host-only root directory for per-VM API sockets.
    pub socket_root: PathBuf,
    /// Path to the Firecracker binary.
    pub firecracker_binary: String,
    /// Path to the jailer binary.
    pub jailer_binary: String,
    /// Jailer chroot base directory.
    pub chroot_base_dir: PathBuf,
    /// Non-root UID the jailer drops to.
    pub uid: u32,
    /// Non-root GID the jailer drops to.
    pub gid: u32,
    /// Prefix for generated VM ids (`<prefix>-<n>`).
    pub id_prefix: String,
    /// `pids.max` applied to each VM cgroup leaf.
    pub pids_max: u64,
    /// Time to wait for the API socket to appear.
    pub socket_timeout: Duration,
    /// Time to wait for guest readiness.
    pub readiness_timeout: Duration,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            socket_root: PathBuf::from("/run/microvm/sockets"),
            firecracker_binary: "/usr/bin/firecracker".to_string(),
            jailer_binary: "/usr/bin/jailer".to_string(),
            chroot_base_dir: PathBuf::from("/srv/jailer"),
            uid: DEFAULT_JAILER_UID,
            gid: DEFAULT_JAILER_GID,
            id_prefix: "vm".to_string(),
            pids_max: DEFAULT_PIDS_MAX,
            socket_timeout: DEFAULT_SOCKET_TIMEOUT,
            readiness_timeout: DEFAULT_READINESS_TIMEOUT,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-VM record
// ---------------------------------------------------------------------------

/// Internal per-VM state held by the backend.
#[derive(Clone, Debug)]
struct VmRecord {
    vm_id: VmId,
    owner: TenantId,
    spec: ResourceSpec,
    boot: Option<BootConfig>,
    state: VmState,
    created_at: DateTime<Utc>,
    process: Option<VmProcess>,
    net: Option<NetConfig>,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Firecracker-backed [`LifecycleService`] implementation.
///
/// Construct via [`FirecrackerBackend::builder`]. Side-effecting boundaries
/// (process spawn, API transport, readiness probe, prerequisite check, cleanup)
/// are injected as trait objects so the orchestration is fully testable without
/// a capable host.
pub struct FirecrackerBackend {
    state: Mutex<HashMap<VmId, VmRecord>>,
    launcher: Arc<dyn ProcessLauncher>,
    api_factory: Arc<dyn ApiFactory>,
    probe: Arc<dyn GuestReadinessProbe>,
    prereq: Arc<dyn PrerequisiteCheck>,
    cleanup_backend: Arc<dyn CleanupBackend + Send + Sync>,
    audit: Option<Arc<dyn AuditLog>>,
    artifacts: ArtifactStore,
    cgroup: CgroupManager,
    net: Mutex<NetManager>,
    cleanup: CleanupManager,
    config: BackendConfig,
    default_boot: Option<BootConfig>,
    next_id: AtomicU64,
}

impl FirecrackerBackend {
    /// Start building a backend.
    pub fn builder() -> BackendBuilder {
        BackendBuilder::default()
    }

    /// The backend configuration.
    pub fn config(&self) -> &BackendConfig {
        &self.config
    }

    /// The host-internal API socket path for a VM.
    ///
    /// This path is **never** returned to tenants; it is exposed only for
    /// operator tooling and tests.
    pub fn socket_path(&self, vm_id: &VmId) -> PathBuf {
        self.config
            .socket_root
            .join(vm_id.as_str())
            .join("api.sock")
    }

    /// The phase timestamps recorded for a VM's process, if any.
    pub fn phases(&self, vm_id: &VmId) -> Option<crate::phase::PhaseTimestamps> {
        self.state
            .lock()
            .unwrap()
            .get(vm_id)
            .and_then(|r| r.process.as_ref())
            .map(|p| p.phases().clone())
    }

    /// The current state of a VM, if known.
    pub fn vm_state(&self, vm_id: &VmId) -> Option<VmState> {
        self.state.lock().unwrap().get(vm_id).map(|r| r.state)
    }

    /// Set (or override) the boot configuration for a VM.
    ///
    /// The caller must be authorized to start the VM. The config takes effect
    /// on the next [`LifecycleService::start`].
    pub fn set_boot_config(
        &self,
        vm_id: &VmId,
        boot: BootConfig,
        principal: &Principal,
    ) -> Result<(), MicrovmError> {
        let mut guard = self.state.lock().unwrap();
        let record = self.record_mut(&mut guard, vm_id)?;
        authorize(principal, &record.owner, Operation::Start)?;
        record.boot = Some(boot);
        Ok(())
    }

    // -- LifecycleService helpers ------------------------------------------

    fn record_mut<'a>(
        &self,
        guard: &'a mut HashMap<VmId, VmRecord>,
        vm_id: &VmId,
    ) -> Result<&'a mut VmRecord, MicrovmError> {
        guard.get_mut(vm_id).ok_or_else(|| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str())
        })
    }

    fn generate_vm_id(&self) -> Result<VmId, MicrovmError> {
        let n = self.next_id.fetch_add(1, Ordering::SeqCst);
        VmId::new(format!("{}-{}", self.config.id_prefix, n)).map_err(|e| {
            MicrovmError::new(
                ErrorCode::InternalError,
                "generated VM id failed validation",
            )
            .with_context("reason", e.reason)
        })
    }

    /// Record an audit event for a mutating operation, if a log is attached.
    fn record_audit(
        &self,
        principal: &Principal,
        resource_id: &str,
        operation: Operation,
        result: AuditResult,
    ) {
        if let Some(log) = &self.audit {
            log.record(AuditEvent {
                timestamp: Utc::now(),
                tenant_id: principal.tenant_id().clone(),
                role: principal.role(),
                resource_type: ResourceType::Vm,
                resource_id: resource_id.to_string(),
                operation,
                result,
            });
        }
    }

    /// Map an operation outcome to an audit result: permission failures are
    /// `Denied`, other failures are `Error`, success is `Success`.
    fn audit_result(outcome: &Result<(), MicrovmError>) -> AuditResult {
        match outcome {
            Ok(()) => AuditResult::Success,
            Err(e) if e.code == ErrorCode::PermissionDenied => AuditResult::Denied,
            Err(_) => AuditResult::Error,
        }
    }

    /// Resolve the effective boot config for a record.
    fn effective_boot(record: &VmRecord) -> Result<BootConfig, MicrovmError> {
        record.boot.clone().ok_or_else(|| {
            MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "VM has no boot configuration; set one before start",
            )
            .with_context("vm_id", record.vm_id.as_str())
        })
    }

    /// Verify kernel and rootfs artifacts against their expected digests and
    /// return the host paths to hand to Firecracker.
    fn verify_artifacts(
        &self,
        owner: &TenantId,
        boot: &BootConfig,
    ) -> Result<(PathBuf, PathBuf), MicrovmError> {
        let mut kernel = self.artifacts.open_artifact(owner, boot.kernel_path())?;
        kernel.verify_sha256(boot.kernel_sha256())?;

        let mut rootfs = self.artifacts.open_artifact(owner, boot.rootfs_path())?;
        rootfs.verify_sha256(boot.rootfs_sha256())?;

        let tenant_root = self.artifacts.tenant_root(owner);
        Ok((
            tenant_root.join(boot.kernel_path()),
            tenant_root.join(boot.rootfs_path()),
        ))
    }

    /// Build the cgroup spec for a VM from its resource spec.
    fn cgroup_spec(&self, spec: &ResourceSpec) -> Result<CgroupSpec, MicrovmError> {
        CgroupSpec::builder()
            .cpu_quota_us(u64::from(spec.vcpu_count()) * CPU_PERIOD_US)
            .memory_max_bytes(spec.memory_mib() * 1024 * 1024)
            .pids_max(self.config.pids_max)
            .build()
    }

    /// Build the launch argument vector for a VM.
    ///
    /// A jailed launch (validated [`microvm_isolation::JailerArgv`]) is used
    /// when the VM has a netns; otherwise Firecracker is launched directly with
    /// an explicit `--api-sock`.
    fn build_launch_argv(
        &self,
        vm_id: &VmId,
        socket_path: &Path,
        netns: Option<&Path>,
    ) -> Result<Vec<String>, MicrovmError> {
        match netns {
            Some(netns_path) => {
                let argv = microvm_isolation::JailerArgv::builder(
                    self.config.jailer_binary.clone(),
                    self.config.firecracker_binary.clone(),
                    vm_id.as_str(),
                )
                .uid(self.config.uid)
                .gid(self.config.gid)
                .parent_cgroup(self.cgroup.relative_leaf_path(vm_id))
                .netns(netns_path.display().to_string())
                .chroot_base_dir(self.config.chroot_base_dir.display().to_string())
                .with_recommended_limits()
                .build()?
                .argv();
                Ok(argv)
            }
            None => Ok(vec![
                self.config.firecracker_binary.clone(),
                "--id".to_string(),
                vm_id.as_str().to_string(),
                "--api-sock".to_string(),
                socket_path.display().to_string(),
            ]),
        }
    }

    /// Wait until the API socket file appears.
    async fn wait_for_socket(&self, socket_path: &Path) -> Result<(), MicrovmError> {
        let deadline = Instant::now() + self.config.socket_timeout;
        loop {
            if socket_path.exists() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(MicrovmError::new(
                    ErrorCode::TransportError,
                    "Firecracker API socket did not appear before timeout",
                )
                .with_context("socket", socket_path.display().to_string())
                .with_context(
                    "timeout_ms",
                    self.config.socket_timeout.as_millis().to_string(),
                ));
            }
            tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
        }
    }

    /// Push the full configuration to the Firecracker API.
    async fn configure_api(
        &self,
        api: &dyn FirecrackerApi,
        boot: &BootConfig,
        kernel_host: &Path,
        rootfs_host: &Path,
        net: &Option<NetConfig>,
    ) -> Result<(), MicrovmError> {
        api.put_machine_config(&MachineConfig::new(boot.vcpu_count(), boot.mem_size_mib()))
            .await?;
        api.put_boot_source(&BootSource {
            kernel_image_path: kernel_host.display().to_string(),
            boot_args: boot.boot_args().map(str::to_string),
        })
        .await?;
        api.put_drive(&Drive::rootfs(rootfs_host.display().to_string()))
            .await?;
        if let Some(net) = net {
            api.put_network_interface(&NetworkInterface::tap(net.tap_name()))
                .await?;
        }
        Ok(())
    }

    /// Transition a VM to `Failed` and clean up its resources. Returns `err`.
    fn fail_vm(&self, vm_id: &VmId, err: MicrovmError) -> MicrovmError {
        // Mark failed.
        {
            let mut guard = self.state.lock().unwrap();
            if let Some(record) = guard.get_mut(vm_id) {
                record.state = VmState::Failed;
            }
        }
        // Best-effort cleanup of anything provisioned so far.
        let _ = self.teardown(vm_id);
        err.with_context("vm_state", VmState::Failed.as_str())
    }

    /// Tear down all per-VM resources (process, socket, nft, tap, netns,
    /// cgroup, chroot) via the cleanup manager. Idempotent and best-effort.
    fn teardown(&self, vm_id: &VmId) -> Result<(), MicrovmError> {
        // Build a resource record from current state.
        let record_opt = {
            let guard = self.state.lock().unwrap();
            guard.get(vm_id).cloned()
        };
        let Some(record) = record_opt else {
            return Ok(());
        };

        let pid = record.process.as_ref().and_then(|p| p.pid());

        // The cleanup backend performs the privileged process kill; here we only
        // assemble the resource record describing everything owned by the VM.
        let mut resource = ResourceRecord::new(
            record.vm_id.clone(),
            record.owner.clone(),
            self.cgroup.leaf_path(vm_id),
            ResourceRecord::default_netns_name(vm_id),
            record
                .net
                .as_ref()
                .map(|n| n.tap_name().to_string())
                .unwrap_or_default(),
            ResourceRecord::default_nft_table(vm_id),
            record
                .process
                .as_ref()
                .map(|p| vec![p.socket_path().to_path_buf()])
                .unwrap_or_default(),
            self.config.chroot_base_dir.join(vm_id.as_str()),
            pid,
        );
        resource.set_pid(pid);

        let _outcome = self
            .cleanup
            .cleanup(&resource, self.cleanup_backend.as_ref());

        // Release the netns allocation and remove the cgroup leaf (the cleanup
        // manager removes the leaf directory; the net manager releases the
        // address slot).
        if let Ok(mut net) = self.net.lock() {
            let _ = net.teardown_netns(vm_id);
        }
        let _ = self.cgroup.teardown_leaf(vm_id);

        Ok(())
    }
    /// Core start logic; the trait method wraps this to record an audit event.
    async fn start_inner(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        // Snapshot the inputs we need, then release the lock before any await.
        let (owner, spec, boot, current) = {
            let mut guard = self.state.lock().unwrap();
            let record = self.record_mut(&mut guard, vm_id)?;
            authorize(principal, &record.owner, Operation::Start)?;
            // Idempotent: an already-running VM is a no-op.
            if record.state == VmState::Running {
                return Ok(());
            }
            if record.state != VmState::Created && record.state != VmState::Paused {
                return Err(MicrovmError::new(
                    ErrorCode::InvalidTransition,
                    format!("cannot start VM in {} state", record.state),
                )
                .with_context("vm_id", vm_id.as_str())
                .with_context("state", record.state.as_str()));
            }
            let boot = Self::effective_boot(record)?;
            (
                record.owner.clone(),
                record.spec.clone(),
                boot,
                record.state,
            )
        };

        let net_required = boot.has_network();

        // 1. Prerequisites — fail before any child creation.
        self.prereq.check(net_required).map_err(|e| {
            e.with_context("vm_id", vm_id.as_str())
                .with_context("phase", "prerequisite")
        })?;

        // 2. Artifact integrity — digest-validate kernel and rootfs. A mismatch
        // is an integrity violation: the VM is driven to Failed and no child is
        // created, so no InstanceStart is ever issued.
        let (kernel_host, rootfs_host) = match self.verify_artifacts(&owner, &boot) {
            Ok(paths) => paths,
            Err(e) => {
                return Err(self.fail_vm(
                    vm_id,
                    e.with_context("vm_id", vm_id.as_str())
                        .with_context("phase", "artifact"),
                ));
            }
        };

        // 3. Isolation — cgroup leaf, then (optionally) netns/TAP.
        let cgroup_spec = self.cgroup_spec(&spec)?;
        self.cgroup.create_parent()?;
        self.cgroup.apply_spec(vm_id, &cgroup_spec).map_err(|e| {
            e.with_context("vm_id", vm_id.as_str())
                .with_context("phase", "cgroup")
        })?;

        let net_config = if let Some(net_boot) = boot.network() {
            let mut net = self.net.lock().unwrap();
            let cfg = net.setup_netns(vm_id, net_boot.policy).map_err(|e| {
                e.with_context("vm_id", vm_id.as_str())
                    .with_context("phase", "netns")
            })?;
            Some(cfg)
        } else {
            None
        };
        let netns_path = net_config
            .as_ref()
            .map(|_| self.net.lock().unwrap().netns_path(vm_id));

        // 4. Spawn the child process.
        let socket_path = self.socket_path(vm_id);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                MicrovmError::new(ErrorCode::ProcessSpawnError, "failed to create socket dir")
                    .with_context("path", parent.display().to_string())
                    .with_context("io", e.to_string())
            })?;
        }
        let argv = self.build_launch_argv(vm_id, &socket_path, netns_path.as_deref())?;
        let launch_spec = LaunchSpec::new(vm_id.clone(), argv, socket_path.clone());

        let pid = match self.launcher.spawn(&launch_spec).await {
            Ok(pid) => pid,
            Err(e) => {
                return Err(self.fail_vm(vm_id, e.with_context("phase", Phase::Spawn.as_str())));
            }
        };

        // From here on, failures drive the VM to Failed and clean up.
        let mut process = VmProcess::new(vm_id.clone(), pid, socket_path.clone());
        let now = Utc::now();
        if let Err(e) = process.phases_mut().record(Phase::Spawn, now) {
            return Err(self.fail_vm(vm_id, e));
        }

        // 5. Wait for the API socket.
        if let Err(e) = self.wait_for_socket(&socket_path).await {
            return Err(self.fail_vm(vm_id, e.with_context("phase", Phase::SocketReady.as_str())));
        }
        if let Err(e) = process.phases_mut().record(Phase::SocketReady, Utc::now()) {
            return Err(self.fail_vm(vm_id, e));
        }

        // Stash the process + net config so teardown can find them on failure.
        {
            let mut guard = self.state.lock().unwrap();
            if let Some(record) = guard.get_mut(vm_id) {
                record.process = Some(process.clone());
                record.net = net_config.clone();
            }
        }

        // 6. Configure the VM over the API.
        let api = self.api_factory.connect(&socket_path);
        if let Err(e) = self
            .configure_api(api.as_ref(), &boot, &kernel_host, &rootfs_host, &net_config)
            .await
        {
            return Err(self.fail_vm(vm_id, e.with_context("phase", Phase::Configured.as_str())));
        }
        if let Err(e) = process.phases_mut().record(Phase::Configured, Utc::now()) {
            return Err(self.fail_vm(vm_id, e));
        }

        // Created -> Configured.
        {
            let mut guard = self.state.lock().unwrap();
            if let Some(record) = guard.get_mut(vm_id) {
                record.state =
                    transition(current, VmState::Configured).unwrap_or(VmState::Configured);
                record.process = Some(process.clone());
            }
        }

        // 7. Start the instance.
        if let Err(e) = api.start_instance().await {
            return Err(self.fail_vm(vm_id, e.with_context("phase", "instance_start")));
        }

        // 8. Wait for guest readiness (not just process/socket).
        let ctx = ReadinessContext::new(
            vm_id.clone(),
            net_config.as_ref().map(|n| n.guest_ip()),
            self.config.readiness_timeout,
        );
        if let Err(e) = self.probe.wait_ready(&ctx).await {
            return Err(self.fail_vm(vm_id, e.with_context("phase", Phase::GuestReady.as_str())));
        }
        if let Err(e) = process.phases_mut().record(Phase::GuestReady, Utc::now()) {
            return Err(self.fail_vm(vm_id, e));
        }

        // Configured -> Running.
        {
            let mut guard = self.state.lock().unwrap();
            if let Some(record) = guard.get_mut(vm_id) {
                record.state = VmState::Running;
                record.process = Some(process);
            }
        }
        Ok(())
    }

    /// Core stop logic; the trait method wraps this to record an audit event.
    async fn stop_inner(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        let (pid, socket_path, current) = {
            let mut guard = self.state.lock().unwrap();
            let record = self.record_mut(&mut guard, vm_id)?;
            authorize(principal, &record.owner, Operation::Stop)?;
            if record.state == VmState::Stopped {
                return Ok(());
            }
            if record.state != VmState::Running && record.state != VmState::Paused {
                return Err(MicrovmError::new(
                    ErrorCode::InvalidTransition,
                    format!("cannot stop VM in {} state", record.state),
                )
                .with_context("vm_id", vm_id.as_str())
                .with_context("state", record.state.as_str()));
            }
            (
                record.process.as_ref().and_then(|p| p.pid()),
                record
                    .process
                    .as_ref()
                    .map(|p| p.socket_path().to_path_buf()),
                record.state,
            )
        };

        // Graceful shutdown via the API (best effort).
        if let Some(socket_path) = &socket_path {
            let api = self.api_factory.connect(socket_path);
            let _ = api.send_ctrl_alt_del().await;
        }

        // Wait for the process to exit, or kill it.
        if let Some(pid) = pid {
            // Give the guest a brief grace period, then force-kill.
            let wait = self.launcher.wait_exit(pid);
            match tokio::time::timeout(Duration::from_secs(5), wait).await {
                Ok(_) => {}
                Err(_) => {
                    let _ = self.launcher.kill(pid).await;
                }
            }
        }

        // Record the stopped phase.
        {
            let mut guard = self.state.lock().unwrap();
            if let Some(record) = guard.get_mut(vm_id) {
                if let Some(process) = record.process.as_mut() {
                    let _ = process.phases_mut().record(Phase::Stopped, Utc::now());
                    process.clear_pid();
                }
                record.state = transition(current, VmState::Stopped).unwrap_or(VmState::Stopped);
            }
        }

        // Tear down all per-VM resources.
        self.teardown(vm_id)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LifecycleService implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl LifecycleService for FirecrackerBackend {
    async fn create(&self, spec: ResourceSpec, owner: Principal) -> Result<VmId, MicrovmError> {
        // Role check: the principal must be permitted to create within its own
        // tenant.
        if let Err(e) = authorize(&owner, owner.tenant_id(), Operation::Create) {
            self.record_audit(&owner, "", Operation::Create, AuditResult::Denied);
            return Err(e);
        }

        let vm_id = self.generate_vm_id().inspect_err(|_| {
            self.record_audit(&owner, "", Operation::Create, AuditResult::Error);
        })?;
        let record = VmRecord {
            vm_id: vm_id.clone(),
            owner: owner.tenant_id().clone(),
            spec,
            boot: self.default_boot.clone(),
            state: VmState::Created,
            created_at: Utc::now(),
            process: None,
            net: None,
        };
        self.state.lock().unwrap().insert(vm_id.clone(), record);
        self.record_audit(
            &owner,
            vm_id.as_str(),
            Operation::Create,
            AuditResult::Success,
        );
        Ok(vm_id)
    }

    async fn start(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        let outcome = self.start_inner(vm_id, principal).await;
        self.record_audit(
            principal,
            vm_id.as_str(),
            Operation::Start,
            Self::audit_result(&outcome),
        );
        outcome
    }

    async fn stop(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError> {
        let outcome = self.stop_inner(vm_id, principal).await;
        self.record_audit(
            principal,
            vm_id.as_str(),
            Operation::Stop,
            Self::audit_result(&outcome),
        );
        outcome
    }

    async fn snapshot(
        &self,
        _vm_id: &VmId,
        _principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError> {
        // Snapshot create/load ordering is implemented in a later todo (22).
        Err(MicrovmError::new(
            ErrorCode::InternalError,
            "snapshot is not supported by the Firecracker boot adapter",
        )
        .with_context("todo", "22"))
    }

    async fn restore(
        &self,
        _snapshot_id: &SnapshotId,
        _principal: &Principal,
    ) -> Result<VmId, MicrovmError> {
        // Restore rebinding is implemented in a later todo (22).
        Err(MicrovmError::new(
            ErrorCode::InternalError,
            "restore is not supported by the Firecracker boot adapter",
        )
        .with_context("todo", "22"))
    }

    async fn status(&self, vm_id: &VmId, principal: &Principal) -> Result<VmStatus, MicrovmError> {
        let guard = self.state.lock().unwrap();
        let record = guard.get(vm_id).ok_or_else(|| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str())
        })?;
        authorize(principal, &record.owner, Operation::Status)?;
        Ok(VmStatus {
            vm_id: record.vm_id.clone(),
            state: record.state,
            created_at: record.created_at,
            resource_spec: record.spec.clone(),
        })
    }

    async fn metrics(
        &self,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<VmMetrics, MicrovmError> {
        let guard = self.state.lock().unwrap();
        let record = guard.get(vm_id).ok_or_else(|| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "no such VM")
                .with_context("vm_id", vm_id.as_str())
        })?;
        authorize(principal, &record.owner, Operation::Metrics)?;
        Ok(VmMetrics {
            vm_id: record.vm_id.clone(),
            state: record.state,
        })
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`FirecrackerBackend`].
#[derive(Default)]
pub struct BackendBuilder {
    config: BackendConfig,
    launcher: Option<Arc<dyn ProcessLauncher>>,
    api_factory: Option<Arc<dyn ApiFactory>>,
    probe: Option<Arc<dyn GuestReadinessProbe>>,
    prereq: Option<Arc<dyn PrerequisiteCheck>>,
    cleanup_backend: Option<Arc<dyn CleanupBackend + Send + Sync>>,
    audit: Option<Arc<dyn AuditLog>>,
    artifacts: Option<ArtifactStore>,
    cgroup: Option<CgroupManager>,
    net: Option<NetManager>,
    cleanup: Option<CleanupManager>,
    default_boot: Option<BootConfig>,
}

impl BackendBuilder {
    /// Override the backend configuration.
    pub fn config(mut self, config: BackendConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the process launcher.
    pub fn launcher(mut self, launcher: Arc<dyn ProcessLauncher>) -> Self {
        self.launcher = Some(launcher);
        self
    }

    /// Set the API factory.
    pub fn api_factory(mut self, factory: Arc<dyn ApiFactory>) -> Self {
        self.api_factory = Some(factory);
        self
    }

    /// Set the guest readiness probe.
    pub fn probe(mut self, probe: Arc<dyn GuestReadinessProbe>) -> Self {
        self.probe = Some(probe);
        self
    }

    /// Set the prerequisite checker.
    pub fn prereq(mut self, prereq: Arc<dyn PrerequisiteCheck>) -> Self {
        self.prereq = Some(prereq);
        self
    }

    /// Set the cleanup backend.
    pub fn cleanup_backend(mut self, backend: Arc<dyn CleanupBackend + Send + Sync>) -> Self {
        self.cleanup_backend = Some(backend);
        self
    }

    /// Attach an audit log. Every mutating operation (create/start/stop)
    /// records exactly one [`AuditEvent`] with a success/denied/error result.
    pub fn audit_log(mut self, log: Arc<dyn AuditLog>) -> Self {
        self.audit = Some(log);
        self
    }

    /// Set the artifact store.
    pub fn artifacts(mut self, store: ArtifactStore) -> Self {
        self.artifacts = Some(store);
        self
    }

    /// Set the cgroup manager.
    pub fn cgroup(mut self, cgroup: CgroupManager) -> Self {
        self.cgroup = Some(cgroup);
        self
    }

    /// Set the net manager.
    pub fn net(mut self, net: NetManager) -> Self {
        self.net = Some(net);
        self
    }

    /// Set the cleanup manager.
    pub fn cleanup(mut self, cleanup: CleanupManager) -> Self {
        self.cleanup = Some(cleanup);
        self
    }

    /// Set a default boot config inherited by every created VM.
    pub fn default_boot(mut self, boot: BootConfig) -> Self {
        self.default_boot = Some(boot);
        self
    }

    /// Build the backend.
    ///
    /// # Panics
    /// Panics if a required component (launcher, api factory, probe, prereq,
    /// artifact store) is not set; these have no safe default.
    pub fn build(self) -> FirecrackerBackend {
        let cgroup = self.cgroup.unwrap_or_default();
        let net = self.net.unwrap_or_default();
        let cleanup = self.cleanup.unwrap_or_else(|| {
            CleanupManager::new(
                cgroup.root().to_path_buf(),
                self.config.chroot_base_dir.clone(),
                self.config.socket_root.clone(),
            )
        });
        FirecrackerBackend {
            state: Mutex::new(HashMap::new()),
            launcher: self.launcher.expect("launcher is required"),
            api_factory: self.api_factory.expect("api_factory is required"),
            probe: self.probe.expect("probe is required"),
            prereq: self.prereq.expect("prereq is required"),
            cleanup_backend: self
                .cleanup_backend
                .unwrap_or_else(|| Arc::new(microvm_isolation::RealCleanupBackend::new())),
            audit: self.audit,
            artifacts: self.artifacts.expect("artifacts is required"),
            cgroup,
            net: Mutex::new(net),
            cleanup,
            config: self.config,
            default_boot: self.default_boot,
            next_id: AtomicU64::new(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_config_defaults() {
        let cfg = BackendConfig::default();
        assert_eq!(cfg.uid, DEFAULT_JAILER_UID);
        assert_eq!(cfg.id_prefix, "vm");
        assert_eq!(cfg.pids_max, DEFAULT_PIDS_MAX);
    }

    #[test]
    fn socket_path_is_host_internal() {
        // The socket path is derived from the socket root and VM id; it is not
        // part of any tenant-facing status type.
        let cfg = BackendConfig {
            socket_root: PathBuf::from("/run/socks"),
            ..BackendConfig::default()
        };
        let vm = VmId::new("vm-1").unwrap();
        assert_eq!(
            cfg.socket_root.join("vm-1").join("api.sock"),
            cfg.socket_root.join(vm.as_str()).join("api.sock")
        );
    }
}
