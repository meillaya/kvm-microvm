//! Shared deterministic test harness for the Firecracker adapter.
//!
//! Builds a fully-scripted [`FirecrackerBackend`] over temporary directories:
//! a real [`ArtifactStore`] holding digest-validated kernel/rootfs files, a
//! simulated cgroup-v2 hierarchy, and scripted launcher/API/probe/prereq/cleanup
//! doubles. This exercises the entire boot/stop orchestration without a capable
//! host.

#![allow(dead_code)]

use microvm_artifacts::{compute_sha256, ArtifactStore, Digest};
use microvm_errors::MicrovmError;
use microvm_firecracker::backend::{ApiFactory, BackendConfig, FirecrackerBackend};
use microvm_firecracker::config::{BootConfig, NetworkBootConfig};
use microvm_firecracker::prereq::HostPrerequisiteChecker;
use microvm_firecracker::testing::{
    FailPoint, RecordingApi, ScriptedApiFactory, ScriptedLauncher, ScriptedPrereq, ScriptedProbe,
    SpawnOutcome,
};
use microvm_isolation::{
    CgroupManager, CleanupBackend, CleanupManager, NetManager, RecordingCleanupBackend,
};
use microvm_lifecycle::policy::InMemoryAuditLog;
use microvm_lifecycle::LifecycleService;
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, TenantId, VmId};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// A `Send + Sync` wrapper around [`RecordingCleanupBackend`] (which uses a
/// `RefCell` internally and is therefore not `Sync`). The backend requires a
/// `Sync` cleanup backend, so tests wrap the recorder in a mutex.
#[derive(Debug, Default)]
pub struct SyncRecordingCleanup {
    inner: std::sync::Mutex<RecordingCleanupBackend>,
}

impl SyncRecordingCleanup {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(RecordingCleanupBackend::new()),
        }
    }

    pub fn recorded(&self) -> Vec<(String, bool)> {
        self.inner.lock().unwrap().recorded()
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

pub const KERNEL_BYTES: &[u8] = b"guest-kernel-bzimage-v1";
pub const ROOTFS_BYTES: &[u8] = b"guest-rootfs-ext4-v1";

/// How the rig's prerequisite check behaves.
#[derive(Clone)]
pub enum PrereqMode {
    /// Scripted: prerequisites always satisfied.
    Ok,
    /// Scripted: prerequisites fail with a typed error.
    ScriptedFail,
    /// Real [`HostPrerequisiteChecker`] whose KVM device path does not exist,
    /// proving the backend runs prerequisites before spawning a child.
    RealMissingKvm,
}

/// Options controlling how a [`Rig`] is assembled.
#[derive(Clone)]
pub struct RigOptions {
    pub net_policy: NetworkPolicy,
    pub spawn_outcome: SpawnOutcome,
    pub api_failure: Option<FailPoint>,
    pub probe_ready: bool,
    pub prereq: PrereqMode,
    /// Write rootfs bytes that do not match the boot config digest.
    pub corrupt_rootfs: bool,
    /// Omit the boot config entirely (VM has no boot configuration).
    pub no_boot: bool,
}

impl Default for RigOptions {
    fn default() -> Self {
        Self {
            net_policy: NetworkPolicy::NatOnly,
            spawn_outcome: SpawnOutcome::Auto,
            api_failure: None,
            probe_ready: true,
            prereq: PrereqMode::Ok,
            corrupt_rootfs: false,
            no_boot: false,
        }
    }
}

/// A fully wired, scripted backend plus handles for assertions.
pub struct Rig {
    pub backend: FirecrackerBackend,
    pub launcher: Arc<ScriptedLauncher>,
    pub api: Arc<RecordingApi>,
    pub probe: Arc<ScriptedProbe>,
    pub cleanup: Arc<SyncRecordingCleanup>,
    pub audit: Arc<InMemoryAuditLog>,
    pub boot: BootConfig,
    pub owner: Principal,
    pub spec: ResourceSpec,
    pub vm_id: VmId,
    pub socket_root: std::path::PathBuf,
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
    /// Assemble a rig with the given options and create one VM in `Created`.
    pub async fn new(opts: RigOptions) -> Self {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        // -- Artifact store with kernel + rootfs ----------------------------
        fs::create_dir_all(base.join("artifacts")).unwrap();
        let store = ArtifactStore::new(base.join("artifacts")).unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let images = store.tenant_root(&tenant).join("images");
        fs::create_dir_all(&images).unwrap();
        fs::write(images.join("vmlinux"), KERNEL_BYTES).unwrap();
        let rootfs_on_disk: &[u8] = if opts.corrupt_rootfs {
            b"corrupt-rootfs-does-not-match"
        } else {
            ROOTFS_BYTES
        };
        fs::write(images.join("rootfs.ext4"), rootfs_on_disk).unwrap();

        let kernel_digest: Digest = compute_sha256(KERNEL_BYTES).unwrap();
        let rootfs_digest: Digest = compute_sha256(ROOTFS_BYTES).unwrap();

        // -- Boot config ----------------------------------------------------
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
        let cleanup = CleanupManager::new(&cgroup_root, base.join("chroot"), &socket_root);

        // -- Scripted doubles -----------------------------------------------
        let launcher = Arc::new(
            ScriptedLauncher::new()
                .with_outcome(opts.spawn_outcome.clone())
                .with_socket_on_spawn(),
        );
        let api = Arc::new(match opts.api_failure {
            Some(fp) => RecordingApi::new().with_failure(fp),
            None => RecordingApi::new(),
        });
        let api_factory: Arc<dyn ApiFactory> = Arc::new(ScriptedApiFactory::new(api.clone()));
        let probe = Arc::new(if opts.probe_ready {
            ScriptedProbe::ready()
        } else {
            ScriptedProbe::not_ready()
        });
        let prereq: Arc<dyn microvm_firecracker::prereq::PrerequisiteCheck> = match opts.prereq {
            PrereqMode::Ok => Arc::new(ScriptedPrereq::ok()),
            PrereqMode::ScriptedFail => {
                Arc::new(ScriptedPrereq::fail(microvm_errors::MicrovmError::new(
                    microvm_errors::ErrorCode::CgroupUnavailable,
                    "scripted prerequisite failure",
                )))
            }
            PrereqMode::RealMissingKvm => Arc::new(
                HostPrerequisiteChecker::builder()
                    .kvm_device(base.join("missing-kvm"))
                    .tun_device(base.join("missing-tun"))
                    .firecracker_binary(base.join("firecracker"))
                    .jailer_binary(base.join("jailer"))
                    .cgroup(CgroupManager::new(&cgroup_root))
                    .build(),
            ),
        };
        let cleanup_backend = Arc::new(SyncRecordingCleanup::new());
        let audit = Arc::new(InMemoryAuditLog::new());

        let config = BackendConfig {
            socket_root: socket_root.clone(),
            ..BackendConfig::default()
        };

        let backend = FirecrackerBackend::builder()
            .config(config)
            .launcher(launcher.clone())
            .api_factory(api_factory)
            .probe(probe.clone())
            .prereq(prereq)
            .cleanup_backend(cleanup_backend.clone())
            .audit_log(audit.clone())
            .artifacts(store)
            .cgroup(cgroup)
            .net(net)
            .cleanup(cleanup)
            .build();

        // -- Create one VM --------------------------------------------------
        let owner = Principal::new(tenant.clone(), Role::Owner);
        let spec = ResourceSpec::new(2, 512, 1024, opts.net_policy).unwrap();
        let vm_id = backend.create(spec.clone(), owner.clone()).await.unwrap();
        if !opts.no_boot {
            backend
                .set_boot_config(&vm_id, boot.clone(), &owner)
                .unwrap();
        }

        Rig {
            backend,
            launcher,
            api,
            probe,
            cleanup: cleanup_backend,
            audit,
            boot,
            owner,
            spec,
            vm_id,
            socket_root,
            _tmp: tmp,
        }
    }

    /// Convenience: a healthy networked rig.
    pub async fn healthy() -> Self {
        Self::new(RigOptions::default()).await
    }
}
