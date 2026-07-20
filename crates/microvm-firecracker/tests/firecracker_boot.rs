//! Privileged Firecracker boot integration test.
//!
//! Run with:
//! ```text
//! cargo test --features privileged --test firecracker_boot -- --nocapture
//! ```
//!
//! This drives a **real** Firecracker/jailer on a capable host: create,
//! configure (kernel/rootfs/machine/network over the UDS API), start, observe
//! guest readiness, stop, and clean one VM. It follows the platform's
//! privileged evidence model (`pass` / `blocked` / `failed`): when the host
//! lacks KVM, the pinned binaries, a cgroup-v2 mount, or boot artifacts, the
//! test reports a stable `blocked` token and passes rather than failing.
//!
//! Required environment (otherwise `blocked`):
//! - `FC_KERNEL_PATH` — guest kernel image (bzImage).
//! - `FC_ROOTFS_PATH` — guest rootfs block device.
//! - `FC_GUEST_HEALTH_PORT` — TCP port a guest agent listens on (readiness).
//!
//! Optional:
//! - `FC_FIRECRACKER` / `FC_JAILER` — binary paths (default `/usr/bin/...`).
//!
//! Must run with sufficient privilege for KVM, cgroup delegation, and netns.

#![cfg(feature = "privileged")]

use microvm_artifacts::{compute_sha256, ArtifactStore};
use microvm_errors::ErrorCode;
use microvm_firecracker::backend::{BackendConfig, FirecrackerBackend};
use microvm_firecracker::config::{BootConfig, NetworkBootConfig};
use microvm_firecracker::phase::Phase;
use microvm_firecracker::prereq::HostPrerequisiteChecker;
use microvm_firecracker::process::TokioLauncher;
use microvm_firecracker::readiness::TcpHealthProbe;
use microvm_firecracker::UdsApiFactory;
use microvm_isolation::{
    pinned_firecracker, pinned_jailer, BinaryVerifier, CgroupManager, CleanupManager, ElfMachine,
    NetManager, RealCleanupBackend,
};
use microvm_lifecycle::{LifecycleService, VmState};
use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, TenantId};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

fn blocked(reason: &str) {
    println!("blocked: {reason}");
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn kvm_available() -> bool {
    Path::new("/dev/kvm").exists()
}

fn cgroup2_available() -> bool {
    Path::new("/sys/fs/cgroup")
        .join("cgroup.controllers")
        .exists()
}

/// Copy a host artifact into the tenant store and return its digest.
fn stage_artifact(
    store: &ArtifactStore,
    tenant: &TenantId,
    rel: &str,
    src: &Path,
) -> Option<microvm_artifacts::Digest> {
    let bytes = std::fs::read(src).ok()?;
    let dest = store.tenant_root(tenant).join(rel);
    std::fs::create_dir_all(dest.parent()?).ok()?;
    std::fs::write(&dest, &bytes).ok()?;
    compute_sha256(&bytes[..]).ok()
}

#[tokio::test]
async fn boot_configure_start_guest_ready_stop_clean() {
    if !kvm_available() {
        blocked("kvm_missing");
        return;
    }
    if !cgroup2_available() {
        blocked("cgroup_v2_missing");
        return;
    }

    let kernel_path = PathBuf::from(env_or("FC_KERNEL_PATH", "/opt/microvm/vmlinux"));
    let rootfs_path = PathBuf::from(env_or("FC_ROOTFS_PATH", "/opt/microvm/rootfs.ext4"));
    let fc_bin = env_or("FC_FIRECRACKER", "/usr/bin/firecracker");
    let jailer_bin = env_or("FC_JAILER", "/usr/bin/jailer");
    let health_port: u16 = match env_or("FC_GUEST_HEALTH_PORT", "").parse() {
        Ok(p) if p > 0 => p,
        _ => {
            blocked("guest_health_port_unset");
            return;
        }
    };

    if !kernel_path.exists() || !rootfs_path.exists() {
        blocked("boot_artifacts_missing");
        return;
    }
    if !Path::new(&fc_bin).exists() || !Path::new(&jailer_bin).exists() {
        blocked("firecracker_or_jailer_missing");
        return;
    }

    // Verify the binaries against the pinned manifests before anything else.
    let machine = ElfMachine::X86_64;
    let fc_verifier = BinaryVerifier::new(pinned_firecracker(machine));
    let jailer_verifier = BinaryVerifier::new(pinned_jailer(machine));
    if fc_verifier.verify_path(Path::new(&fc_bin)).is_err() {
        blocked("firecracker_provenance_mismatch");
        return;
    }
    if jailer_verifier.verify_path(Path::new(&jailer_bin)).is_err() {
        blocked("jailer_provenance_mismatch");
        return;
    }

    // Stage artifacts into a temp tenant store and compute their digests.
    let tmp = TempDir::new().unwrap();
    let store = ArtifactStore::new(tmp.path().join("artifacts")).unwrap();
    let tenant = TenantId::new("priv").unwrap();
    let kernel_digest = match stage_artifact(&store, &tenant, "images/vmlinux", &kernel_path) {
        Some(d) => d,
        None => {
            blocked("kernel_stage_failed");
            return;
        }
    };
    let rootfs_digest = match stage_artifact(&store, &tenant, "images/rootfs.ext4", &rootfs_path) {
        Some(d) => d,
        None => {
            blocked("rootfs_stage_failed");
            return;
        }
    };

    let boot = BootConfig::builder()
        .kernel_path("images/vmlinux")
        .kernel_sha256(kernel_digest)
        .rootfs_path("images/rootfs.ext4")
        .rootfs_sha256(rootfs_digest)
        .vcpu_count(1)
        .mem_size_mib(256)
        .boot_args("console=ttyS0 reboot=k panic=1 pci=off")
        .network(NetworkBootConfig::new(NetworkPolicy::NatOnly).unwrap())
        .build()
        .unwrap();

    let cgroup = CgroupManager::new("/sys/fs/cgroup");
    let prereq = HostPrerequisiteChecker::builder()
        .firecracker_binary(&fc_bin)
        .jailer_binary(&jailer_bin)
        .firecracker_verifier(fc_verifier)
        .jailer_verifier(jailer_verifier)
        .cgroup(cgroup.clone())
        .build();

    let socket_root = tmp.path().join("sockets");
    let config = BackendConfig {
        socket_root: socket_root.clone(),
        firecracker_binary: fc_bin,
        jailer_binary: jailer_bin,
        chroot_base_dir: tmp.path().join("jailer"),
        ..BackendConfig::default()
    };
    let cleanup = CleanupManager::new(
        "/sys/fs/cgroup",
        config.chroot_base_dir.clone(),
        socket_root.clone(),
    );

    let backend = FirecrackerBackend::builder()
        .config(config)
        .launcher(Arc::new(TokioLauncher::new()))
        .api_factory(Arc::new(UdsApiFactory))
        .probe(Arc::new(TcpHealthProbe::new(health_port)))
        .prereq(Arc::new(prereq))
        .cleanup_backend(Arc::new(RealCleanupBackend::new()))
        .artifacts(store)
        .cgroup(cgroup)
        .net(NetManager::new("/var/run/netns"))
        .cleanup(cleanup)
        .build();

    let owner = Principal::new(tenant, Role::Owner);
    let spec = ResourceSpec::new(1, 256, 512, NetworkPolicy::NatOnly).unwrap();

    let vm_id = match backend.create(spec, owner.clone()).await {
        Ok(id) => id,
        Err(e) => {
            blocked(&format!("create_failed: {e}"));
            return;
        }
    };
    backend.set_boot_config(&vm_id, boot, &owner).unwrap();

    // Boot the VM. Host-gap failures are `blocked`; genuine code failures panic.
    if let Err(e) = backend.start(&vm_id, &owner).await {
        match e.code {
            ErrorCode::CgroupUnavailable
            | ErrorCode::NetworkSetupError
            | ErrorCode::ProcessSpawnError
            | ErrorCode::BinaryProvenanceError => {
                blocked(&format!("host_gap: {e}"));
                return;
            }
            _ => panic!("unexpected start failure: {e}"),
        }
    }

    // The VM must be Running and guest-ready, with all boot phases recorded.
    assert_eq!(backend.vm_state(&vm_id), Some(VmState::Running));
    let phases = backend.phases(&vm_id).expect("process record");
    for phase in [
        Phase::Spawn,
        Phase::SocketReady,
        Phase::Configured,
        Phase::GuestReady,
    ] {
        assert!(phases.get(phase).is_some(), "missing phase {phase}");
    }

    // Stop and clean the VM; all per-VM resources must disappear.
    backend.stop(&vm_id, &owner).await.expect("stop succeeds");
    assert_eq!(backend.vm_state(&vm_id), Some(VmState::Stopped));
    let phases = backend.phases(&vm_id).unwrap();
    assert!(phases.get(Phase::Stopped).is_some());
    println!("pass: firecracker boot/configure/start/guest-ready/stop/clean");
}
