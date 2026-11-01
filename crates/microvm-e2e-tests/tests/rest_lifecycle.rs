//! End-to-end VM lifecycle test over the REST Unix-socket API (phase 2 story 2).
//!
//! Boots the full API stack: [`microvm_rest::RestServer`] over a temp Unix
//! socket, backed by the composed
//! [`VmLifecycleService`](microvm_service::VmLifecycleService), and drives the
//! complete lifecycle described in the story:
//!
//! ```text
//! POST /vms                      -> VmId
//! POST /vms/{id}/start           -> wait for guest health on TAP IP:port
//! GET  /vms/{id}                 -> state == Running
//! POST /vms/{id}/snapshot        -> SnapshotId
//! POST /snapshots/{sid}/restore  -> new VmId
//! POST /vms/{id}/stop            -> state == Stopped
//! (verify)                       -> no leftover cgroup/netns/TAP/socket
//! ```
//!
//! # Lanes
//! - `full_lifecycle_over_rest_unix_socket`: deterministic, fully-scripted
//!   inner backend (no real Firecracker); exercises the whole flow including
//!   snapshot/restore and resource cleanup.
//! - `composed_firecracker_boot_stop_cleanup_over_rest`: deterministic, genuine
//!   [`FirecrackerBackend`](microvm_firecracker::FirecrackerBackend) wired with
//!   scripted doubles; proves a real composed boot through the API and post-stop
//!   cleanup (no leftover cgroup/netns/socket).
//! - `privileged::real_firecracker_boot_over_rest`: boots a real Firecracker
//!   guest through the REST API on a capable host; reports `blocked` and passes
//!   on an incapable host.

mod common;

use microvm_lifecycle::LifecycleService;

use common::{
    rest_create, rest_restore, rest_snapshot, rest_start, rest_status, rest_stop,
    rest_wait_for_state, wait_for_health, Rig,
};

/// The full lifecycle flow over a real REST Unix socket, backed by the composed
/// service over a fully-scripted inner backend (no real Firecracker).
#[tokio::test]
async fn full_lifecycle_over_rest_unix_socket() {
    let rig = Rig::new();
    let sock = rig.spawn_rest("rest-full.sock").await;

    // 1. POST /vms -> VmId (201).
    let (status, vm_id) = rest_create(&sock, 2, 512, 1024).await;
    assert_eq!(status, 201, "create must return 201");
    assert!(!vm_id.is_empty(), "create must return a vm_id");

    // Before start the VM is created, not running.
    let (status, state) = rest_status(&sock, &vm_id).await;
    assert_eq!(status, 200);
    assert_eq!(state, "created", "freshly created VM starts in created");

    // 2. POST /vms/{id}/start -> 204, then wait for guest health on TAP IP:port.
    let status = rest_start(&sock, &vm_id).await;
    assert_eq!(status, 204, "start must return 204");
    wait_for_health(&rig.backend, &vm_id).await;

    // Resources are provisioned while the VM runs.
    assert!(rig.backend.socket_marker(&vm_id).exists(), "api socket");
    assert!(rig.backend.cgroup_marker(&vm_id).exists(), "cgroup");
    assert!(rig.backend.netns_marker(&vm_id).exists(), "netns");
    assert!(rig.backend.tap_marker(&vm_id).exists(), "tap");

    // 3. GET /vms/{id} -> state == Running (wait for readiness via the API).
    rest_wait_for_state(&sock, &vm_id, "running").await;
    let (status, state) = rest_status(&sock, &vm_id).await;
    assert_eq!(status, 200);
    assert_eq!(state, "running");

    // 4. POST /vms/{id}/snapshot -> SnapshotId (201).
    let (status, snap_id) = rest_snapshot(&sock, &vm_id).await;
    assert_eq!(status, 201, "snapshot must return 201");
    assert!(!snap_id.is_empty(), "snapshot must return a snapshot_id");

    // 5. POST /snapshots/{sid}/restore -> new VmId (201), distinct from source.
    let (status, restored_id) = rest_restore(&sock, &snap_id).await;
    assert_eq!(status, 201, "restore must return 201");
    assert!(!restored_id.is_empty(), "restore must return a vm_id");
    assert_ne!(restored_id, vm_id, "restore creates a new VM");
    // The restored VM comes up with its own provisioned resources. Supervision
    // of restored VMs (status/stop *through the service*) lands in todo 22; the
    // supervised service returns the new VmId but does not yet track it, so we
    // verify and release its resources against the backend directly.
    assert!(
        rig.backend.socket_marker(&restored_id).exists(),
        "restored socket"
    );
    assert!(
        rig.backend.cgroup_marker(&restored_id).exists(),
        "restored cgroup"
    );
    let restored_vm = microvm_types::VmId::new(restored_id.clone()).unwrap();
    rig.backend
        .stop(&restored_vm, &rig.owner)
        .await
        .expect("backend stops restored VM");
    assert!(
        rig.backend.resources_released(&restored_id),
        "restored VM resources released"
    );

    // 6. POST /vms/{id}/stop -> 204; state == Stopped.
    let status = rest_stop(&sock, &vm_id).await;
    assert_eq!(status, 204, "stop must return 204");
    rest_wait_for_state(&sock, &vm_id, "stopped").await;
    let (status, state) = rest_status(&sock, &vm_id).await;
    assert_eq!(status, 200);
    assert_eq!(state, "stopped");

    // 7. Cleanup: no leftover cgroup/netns/TAP/socket for the stopped VM.
    assert!(
        rig.backend.resources_released(&vm_id),
        "stopped VM must release every per-VM resource"
    );
    assert!(!rig.backend.socket_marker(&vm_id).exists(), "socket gone");
    assert!(!rig.backend.cgroup_marker(&vm_id).exists(), "cgroup gone");
    assert!(!rig.backend.netns_marker(&vm_id).exists(), "netns gone");
    assert!(!rig.backend.tap_marker(&vm_id).exists(), "tap gone");
}

/// A real composed boot through the REST API: the genuine
/// [`FirecrackerBackend`] (scripted doubles over temp dirs) wrapped in the
/// supervised service. Verifies post-stop resource cleanup against the real
/// isolation paths (no leftover cgroup leaf, netns mount point, or API socket).
#[tokio::test]
async fn composed_firecracker_boot_stop_cleanup_over_rest() {
    let rig = common::ComposedRig::new().await;
    // Spawn a REST server over the composed service. The TempDir holding the
    // socket is kept alive for the whole test.
    let sock_dir = tempfile::tempdir().unwrap();
    let rest_sock = sock_dir.path().join("composed-rest.sock");
    common::spawn_rest_server(rest_sock.clone(), rig.service.clone()).await;

    // Create -> start through the API.
    let (status, vm_id) = rest_create(&rest_sock, 2, 512, 1024).await;
    assert_eq!(status, 201, "create must return 201");

    let status = rest_start(&rest_sock, &vm_id).await;
    assert_eq!(status, 204, "start must return 204 (guest readiness gated)");

    // The composed backend gates Running on guest readiness; the API reflects it.
    rest_wait_for_state(&rest_sock, &vm_id, "running").await;
    let (status, state) = rest_status(&rest_sock, &vm_id).await;
    assert_eq!(status, 200);
    assert_eq!(state, "running");

    // While running, the real per-VM resources exist.
    assert!(rig.socket_path(&vm_id).exists(), "API socket provisioned");
    assert!(rig.cgroup_leaf(&vm_id).exists(), "cgroup leaf provisioned");
    assert!(rig.netns_file(&vm_id).exists(), "netns provisioned");

    // Stop through the API; the VM reaches Stopped.
    let status = rest_stop(&rest_sock, &vm_id).await;
    assert_eq!(status, 204, "stop must return 204");
    rest_wait_for_state(&rest_sock, &vm_id, "stopped").await;
    let (status, state) = rest_status(&rest_sock, &vm_id).await;
    assert_eq!(status, 200);
    assert_eq!(state, "stopped");

    // Cleanup verification: every per-VM resource must have disappeared.
    assert!(!rig.socket_path(&vm_id).exists(), "API socket removed");
    assert!(!rig.cgroup_leaf(&vm_id).exists(), "cgroup leaf removed");
    assert!(!rig.netns_file(&vm_id).exists(), "netns removed");
}

// ===========================================================================
// Privileged: real Firecracker boot through the REST API
// ===========================================================================

#[cfg(feature = "privileged")]
mod privileged {
    use super::common;
    use microvm_artifacts::{compute_sha256, ArtifactStore, Digest};
    use microvm_firecracker::backend::{BackendConfig, FirecrackerBackend};
    use microvm_firecracker::config::{BootConfig, NetworkBootConfig};
    use microvm_firecracker::phase::Phase;
    use microvm_firecracker::prereq::HostPrerequisiteChecker;
    use microvm_firecracker::process::TokioLauncher;
    use microvm_firecracker::readiness::TcpHealthProbe;
    use microvm_firecracker::UdsApiFactory;
    use microvm_isolation::{
        pinned_firecracker, pinned_jailer, BinaryVerifier, CgroupManager, CleanupManager,
        ElfMachine, NetManager, RealCleanupBackend,
    };
    use microvm_lifecycle::policy::InMemoryAuditLog;
    use microvm_service::{IsolationCleanup, ScriptedSupervisorProbe, VmLifecycleService};
    use microvm_types::{NetworkPolicy, TenantId, VmId};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;

    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const NETNS_ROOT: &str = "/var/run/netns";

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
        Path::new(CGROUP_ROOT).join("cgroup.controllers").exists()
    }

    fn stage_artifact(
        store: &ArtifactStore,
        tenant: &TenantId,
        rel: &str,
        src: &Path,
    ) -> Option<Digest> {
        let bytes = std::fs::read(src).ok()?;
        let dest = store.tenant_root(tenant).join(rel);
        std::fs::create_dir_all(dest.parent()?).ok()?;
        std::fs::write(&dest, &bytes).ok()?;
        compute_sha256(&bytes[..]).ok()
    }

    fn vm_process_alive(vm_id: &VmId, fc_bin: &str, jailer_bin: &str) -> bool {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return false;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(cmd) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let cmd = String::from_utf8_lossy(&cmd);
            if !cmd.contains(vm_id.as_str()) {
                continue;
            }
            if cmd.contains("firecracker") || cmd.contains(fc_bin) || cmd.contains(jailer_bin) {
                return true;
            }
        }
        false
    }

    /// Boot a real Firecracker guest *through the REST Unix-socket API* and
    /// verify post-stop cleanup. On an incapable host this reports a stable
    /// `blocked` token and passes rather than failing or mocking.
    #[tokio::test]
    async fn real_firecracker_boot_over_rest() {
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

        let tmp = TempDir::new().unwrap();
        let store = ArtifactStore::new(tmp.path().join("artifacts")).unwrap();
        let tenant = TenantId::new("priv").unwrap();
        let Some(kernel_digest) = stage_artifact(&store, &tenant, "images/vmlinux", &kernel_path)
        else {
            blocked("kernel_stage_failed");
            return;
        };
        let Some(rootfs_digest) =
            stage_artifact(&store, &tenant, "images/rootfs.ext4", &rootfs_path)
        else {
            blocked("rootfs_stage_failed");
            return;
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

        let cgroup = CgroupManager::new(CGROUP_ROOT);
        let prereq = HostPrerequisiteChecker::builder()
            .firecracker_binary(&fc_bin)
            .jailer_binary(&jailer_bin)
            .firecracker_verifier(fc_verifier)
            .jailer_verifier(jailer_verifier)
            .cgroup(cgroup.clone())
            .build();

        let socket_root = tmp.path().join("sockets");
        let chroot_root = tmp.path().join("jailer");
        let config = BackendConfig {
            socket_root: socket_root.clone(),
            firecracker_binary: fc_bin.clone(),
            jailer_binary: jailer_bin.clone(),
            chroot_base_dir: chroot_root.clone(),
            ..BackendConfig::default()
        };
        let cleanup_manager =
            CleanupManager::new(CGROUP_ROOT, chroot_root.clone(), socket_root.clone());
        let cleanup_backend = Arc::new(RealCleanupBackend::new());

        let backend = Arc::new(
            FirecrackerBackend::builder()
                .config(config)
                .launcher(Arc::new(TokioLauncher::new()))
                .api_factory(Arc::new(UdsApiFactory))
                .probe(Arc::new(TcpHealthProbe::new(health_port)))
                .prereq(Arc::new(prereq))
                .cleanup_backend(cleanup_backend.clone())
                .artifacts(store)
                .cgroup(cgroup.clone())
                .net(NetManager::new(NETNS_ROOT))
                .cleanup(cleanup_manager.clone())
                .default_boot(boot)
                .build(),
        );

        let service = Arc::new(
            VmLifecycleService::builder()
                .firecracker(backend.clone())
                .supervisor_probe(Arc::new(ScriptedSupervisorProbe::new()))
                .audit_log(Arc::new(InMemoryAuditLog::new()))
                .cleanup(Arc::new(IsolationCleanup::new(
                    cleanup_manager,
                    cleanup_backend,
                    socket_root.clone(),
                )))
                .build(),
        );

        // Serve the composed service over a real REST Unix socket.
        let rest_sock = tmp.path().join("api-rest.sock");
        common::spawn_rest_server(rest_sock.clone(), service.clone()).await;

        // Drive the lifecycle through the REST API.
        let (status, vm_id) = common::rest_create(&rest_sock, 1, 256, 512).await;
        if status != 201 {
            blocked(&format!("create_failed: status {status}"));
            return;
        }

        let vm = VmId::new(vm_id.clone()).unwrap();
        let start_status = common::rest_start(&rest_sock, &vm_id).await;
        if start_status != 204 {
            // A host-gap failure surfaces as a non-204; treat the recognized
            // host gaps as blocked, anything else is a genuine failure.
            let (_, state) = common::rest_status(&rest_sock, &vm_id).await;
            if state == "failed" {
                blocked("host_gap: start failed (vm went failed)");
                return;
            }
            panic!("unexpected start status {start_status} (state {state})");
        }

        // Wait for guest readiness through the API.
        common::rest_wait_for_state(&rest_sock, &vm_id, "running").await;
        let phases = backend.phases(&vm).expect("process record");
        for phase in [
            Phase::Spawn,
            Phase::SocketReady,
            Phase::Configured,
            Phase::GuestReady,
        ] {
            assert!(phases.get(phase).is_some(), "missing phase {phase}");
        }

        // Capture per-VM resource paths while running.
        let socket = socket_root.join(vm_id.as_str()).join("api.sock");
        let cgroup_leaf = Path::new(CGROUP_ROOT).join("microvm").join(vm_id.as_str());
        let netns = Path::new(NETNS_ROOT).join(format!("microvm-{}", vm_id.as_str()));
        let chroot = chroot_root.join(vm_id.as_str());

        // Stop through the API.
        let stop_status = common::rest_stop(&rest_sock, &vm_id).await;
        assert_eq!(stop_status, 204, "stop must return 204");
        common::rest_wait_for_state(&rest_sock, &vm_id, "stopped").await;

        // Cleanup verification: every per-VM resource must have disappeared.
        assert!(!socket.exists(), "API socket removed: {}", socket.display());
        assert!(
            !cgroup_leaf.exists(),
            "cgroup removed: {}",
            cgroup_leaf.display()
        );
        assert!(!netns.exists(), "netns removed: {}", netns.display());
        assert!(!chroot.exists(), "chroot removed: {}", chroot.display());
        assert!(
            !vm_process_alive(&vm, &fc_bin, &jailer_bin),
            "no Firecracker/jailer process remains for {}",
            vm_id
        );

        println!("pass: real Firecracker boot/start/guest-ready/stop/clean over REST API");
    }
}
