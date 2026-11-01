//! Shared deterministic test harness for the supervised lifecycle service.
//!
//! Builds a fully-scripted [`FirecrackerBackend`] over temporary directories (a
//! real digest-validated [`ArtifactStore`], a simulated cgroup-v2 hierarchy, and
//! scripted launcher/API/readiness/prereq/cleanup doubles), then wraps it in a
//! [`VmLifecycleService`] with a scripted supervisor probe, an in-memory audit
//! log, and an isolation-cleanup bridge. This exercises the entire composed
//! supervision layer: idempotency, serialization, quota, reconciliation, and
//! audit: without a capable host, KVM, root, or a real Firecracker binary.
//!
//! The inner backend is built without an audit log: the service is the
//! single audit source.

#![allow(dead_code)]

use microvm_artifacts::{compute_sha256, ArtifactStore, Digest};
use microvm_errors::MicrovmError;
use microvm_firecracker::backend::{ApiFactory, BackendConfig, FirecrackerBackend};
use microvm_firecracker::config::{BootConfig, NetworkBootConfig};
use microvm_firecracker::testing::{
    ApiCall, RecordingApi, ScriptedApiFactory, ScriptedLauncher, ScriptedPrereq, ScriptedProbe,
    SpawnOutcome,
};
use microvm_isolation::{
    CgroupManager, CleanupBackend, CleanupManager, NetManager, RecordingCleanupBackend,
};
use microvm_lifecycle::policy::{InMemoryAuditLog, TenantQuota};
use microvm_lifecycle::LifecycleService;
use microvm_service::{IsolationCleanup, ScriptedSupervisorProbe, VmLifecycleService};
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, TenantId};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

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

    pub fn recorded(&self) -> Vec<(String, bool)> {
        self.inner.lock().unwrap().recorded()
    }

    pub fn mark_pid_alive(&self, pid: u32) {
        self.inner.lock().unwrap().alive_pids.insert(pid);
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

/// Options controlling how a [`Rig`] is assembled.
#[derive(Clone)]
pub struct RigOptions {
    pub net_policy: NetworkPolicy,
    pub spawn_outcome: SpawnOutcome,
    /// Whether the guest readiness probe reports ready.
    pub probe_ready: bool,
    /// Per-tenant quota override for the `acme` tenant.
    pub quota: Option<TenantQuota>,
}

impl Default for RigOptions {
    fn default() -> Self {
        Self {
            net_policy: NetworkPolicy::NatOnly,
            spawn_outcome: SpawnOutcome::Auto,
            probe_ready: true,
            quota: None,
        }
    }
}

impl RigOptions {
    /// A rig whose guest never signals readiness.
    pub fn guest_not_ready() -> Self {
        Self {
            probe_ready: false,
            ..Self::default()
        }
    }

    /// A rig with no network attachment (simpler cleanup assertions).
    pub fn no_net() -> Self {
        Self {
            net_policy: NetworkPolicy::None,
            ..Self::default()
        }
    }
}

/// A fully wired, scripted supervised service plus handles for assertions.
pub struct Rig {
    pub service: Arc<VmLifecycleService>,
    pub backend: Arc<FirecrackerBackend>,
    pub launcher: Arc<ScriptedLauncher>,
    pub api: Arc<RecordingApi>,
    pub readiness: Arc<ScriptedProbe>,
    pub supervisor: Arc<ScriptedSupervisorProbe>,
    pub audit: Arc<InMemoryAuditLog>,
    pub cleanup: Arc<SyncRecordingCleanup>,
    pub owner: Principal,
    pub operator: Principal,
    pub viewer: Principal,
    pub other_tenant: Principal,
    pub tenant: TenantId,
    pub spec: ResourceSpec,
    pub boot: BootConfig,
    pub socket_root: PathBuf,
    pub cgroup_root: PathBuf,
    _tmp: TempDir,
}

/// Build a simulated cgroup-v2 hierarchy whose parent exposes all controllers.
fn simulated_cgroup(root: &Path) {
    fs::create_dir_all(root).unwrap();
    fs::write(root.join("cgroup.controllers"), "cpu memory pids io").unwrap();
    fs::write(root.join("cgroup.subtree_control"), "").unwrap();
    let parent = root.join("microvm");
    fs::create_dir_all(&parent).unwrap();
    fs::write(parent.join("cgroup.controllers"), "cpu memory pids io").unwrap();
    fs::write(parent.join("cgroup.subtree_control"), "").unwrap();
}

impl Rig {
    /// Assemble a rig with the given options.
    pub async fn new(opts: RigOptions) -> Self {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        // -- Artifact store: digest-validated kernel + rootfs ----------------
        fs::create_dir_all(base.join("artifacts")).unwrap();
        let store = ArtifactStore::new(base.join("artifacts")).unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let images = store.tenant_root(&tenant).join("images");
        fs::create_dir_all(&images).unwrap();
        fs::write(images.join("vmlinux"), KERNEL_BYTES).unwrap();
        fs::write(images.join("rootfs.ext4"), ROOTFS_BYTES).unwrap();

        let kernel_digest: Digest = compute_sha256(KERNEL_BYTES).unwrap();
        let rootfs_digest: Digest = compute_sha256(ROOTFS_BYTES).unwrap();

        // -- Boot config (installed as the backend default) ------------------
        let mut boot_builder = BootConfig::builder()
            .kernel_path("images/vmlinux")
            .kernel_sha256(kernel_digest)
            .rootfs_path("images/rootfs.ext4")
            .rootfs_sha256(rootfs_digest)
            .vcpu_count(2)
            .mem_size_mib(512)
            .boot_args("console=ttyS0 reboot=k panic=1 pci=off");
        if opts.net_policy != NetworkPolicy::None {
            boot_builder = boot_builder.network(NetworkBootConfig::new(opts.net_policy).unwrap());
        }
        let boot = boot_builder.build().unwrap();

        // -- Isolation managers ---------------------------------------------
        let cgroup_root = base.join("cgroup");
        simulated_cgroup(&cgroup_root);
        let cgroup = CgroupManager::new(&cgroup_root);
        let net = NetManager::new(base.join("netns"));
        let socket_root = base.join("sockets");
        let chroot_root = base.join("chroot");
        let cleanup_manager = CleanupManager::new(&cgroup_root, &chroot_root, &socket_root);

        // -- Scripted doubles ------------------------------------------------
        let launcher = Arc::new(
            ScriptedLauncher::new()
                .with_outcome(opts.spawn_outcome.clone())
                .with_socket_on_spawn(),
        );
        let api = Arc::new(RecordingApi::new());
        let api_factory: Arc<dyn ApiFactory> = Arc::new(ScriptedApiFactory::new(api.clone()));
        let readiness = Arc::new(if opts.probe_ready {
            ScriptedProbe::ready()
        } else {
            ScriptedProbe::not_ready()
        });
        let prereq = Arc::new(ScriptedPrereq::ok());
        let cleanup_backend = Arc::new(SyncRecordingCleanup::new());

        let config = BackendConfig {
            socket_root: socket_root.clone(),
            ..BackendConfig::default()
        };

        // The backend is the runtime; it is built WITHOUT an audit log so the
        // service is the single audit source. `default_boot` makes every created
        // VM immediately startable.
        let backend = Arc::new(
            FirecrackerBackend::builder()
                .config(config)
                .launcher(launcher.clone())
                .api_factory(api_factory)
                .probe(readiness.clone())
                .prereq(prereq)
                .cleanup_backend(cleanup_backend.clone())
                .artifacts(store)
                .cgroup(cgroup)
                .net(net)
                .cleanup(cleanup_manager.clone())
                .default_boot(boot.clone())
                .build(),
        );

        // -- Supervised service ---------------------------------------------
        let supervisor = Arc::new(ScriptedSupervisorProbe::new());
        let audit = Arc::new(InMemoryAuditLog::new());
        let isolation_cleanup = Arc::new(IsolationCleanup::new(
            cleanup_manager,
            cleanup_backend.clone(),
            socket_root.clone(),
        ));

        let mut builder = VmLifecycleService::builder()
            .firecracker(backend.clone())
            .supervisor_probe(supervisor.clone())
            .audit_log(audit.clone())
            .cleanup(isolation_cleanup);
        if let Some(quota) = opts.quota {
            builder = builder.tenant_quota(tenant.clone(), quota);
        }
        let service = Arc::new(builder.build());

        let owner = Principal::new(tenant.clone(), Role::Owner);
        let operator = Principal::new(tenant.clone(), Role::Operator);
        let viewer = Principal::new(tenant.clone(), Role::Viewer);
        let other_tenant = Principal::new(TenantId::new("globex").unwrap(), Role::Owner);
        let spec = ResourceSpec::new(2, 512, 1024, opts.net_policy).unwrap();

        Rig {
            service,
            backend,
            launcher,
            api,
            readiness,
            supervisor,
            audit,
            cleanup: cleanup_backend,
            owner,
            operator,
            viewer,
            other_tenant,
            tenant,
            spec,
            boot,
            socket_root,
            cgroup_root,
            _tmp: tmp,
        }
    }

    /// Convenience: a healthy networked rig.
    pub async fn healthy() -> Self {
        Self::new(RigOptions::default()).await
    }

    /// Create a VM through the service (trait surface) as the owner.
    pub async fn create_vm(&self) -> microvm_types::VmId {
        self.service
            .create(self.spec.clone(), self.owner.clone())
            .await
            .unwrap()
    }

    /// Create and start a VM through the service; returns the VM id.
    pub async fn create_and_start(&self) -> microvm_types::VmId {
        let vm_id = self.create_vm().await;
        self.service.start(&vm_id, &self.owner).await.unwrap();
        vm_id
    }

    /// The number of `InstanceStart` API calls the backend issued.
    pub fn instance_start_count(&self) -> usize {
        self.api
            .calls()
            .iter()
            .filter(|c| matches!(c, ApiCall::StartInstance))
            .count()
    }

    /// The number of VM child processes the launcher spawned.
    pub fn spawn_count(&self) -> usize {
        self.launcher.spawned().len()
    }
}
