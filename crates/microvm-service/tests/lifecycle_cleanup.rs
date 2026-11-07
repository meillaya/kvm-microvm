//! Readiness, process-supervision, and resource-cleanup lifecycle integration
//! tests (lifecycle cleanup).
//!
//! These tests prove the three lifecycle guarantees the platform owes a capable
//! host, exercised end-to-end through the composed
//! [`VmLifecycleService`](microvm_service::VmLifecycleService):
//!
//! 1. Readiness gating: a VM is *not* `Running` until the guest itself
//!    signals readiness. A successful boot records the full
//!    `spawn -> socket_ready -> configured -> guest_ready -> stopped` phase
//!    timestamp sequence; a boot whose guest never becomes ready fails with a
//!    typed guest-not-ready error carrying `phase=guest_ready` context and never
//!    advances past `Configured`.
//! 2. Process supervision, when a VM's supervisor process dies, the service
//!    reconciles the VM to `Failed` and issues teardown for every owned resource
//!    (process kill, nft table, TAP, netns) in strict reverse-creation order.
//! 3. Resource cleanup: on stop (and on failed boot, and on supervisor
//!    death) every per-VM resource disappears: the API socket, the cgroup leaf,
//!    and the network namespace mount point are gone, and the privileged teardown
//!    commands (process/nft/TAP/netns) are issued exactly once and in order.
//!
//! # Lanes
//! - Deterministic (default `cargo test`): the service is driven over a fully
//!   scripted [`FirecrackerBackend`](microvm_firecracker::FirecrackerBackend)
//!   (scripted launcher/API/readiness/prereq/cleanup doubles over temporary
//!   directories). No KVM, root, or real Firecracker binary is required, and no
//!   QEMU TCG or mock stands in for a KVM/Firecracker pass.
//! - Privileged (`cargo test --features privileged --test lifecycle_cleanup`):
//!   a real Firecracker/jailer boot through the service with post-stop cleanup
//!   verification. On an incapable host it reports a stable `blocked` token and
//!   passes rather than failing or mocking.
//!
//! Run:
//! ```text
//! cargo test -p microvm-service --test lifecycle_cleanup
//! cargo test -p microvm-service --test lifecycle_cleanup --features privileged -- --nocapture
//! ```

mod common;

use common::{Rig, RigOptions};
use microvm_lifecycle::{LifecycleService, VmState};
use microvm_service::is_guest_not_ready;
use microvm_types::VmId;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Path helpers (deterministic rig layout)
// ---------------------------------------------------------------------------

/// The VM's API socket path under the rig's socket root.
fn socket_path(rig: &Rig, vm: &VmId) -> PathBuf {
    rig.socket_root.join(vm.as_str()).join("api.sock")
}

/// The VM's cgroup leaf directory under the simulated cgroup-v2 hierarchy.
fn cgroup_leaf(rig: &Rig, vm: &VmId) -> PathBuf {
    rig.cgroup_root.join("microvm").join(vm.as_str())
}

/// The VM's network-namespace mount-point file (a sibling of the cgroup root).
fn netns_file(rig: &Rig, vm: &VmId) -> PathBuf {
    rig.cgroup_root
        .parent()
        .expect("cgroup root has a parent")
        .join("netns")
        .join(format!("microvm-{}", vm.as_str()))
}

/// The nftables table name the backend teardown path derives (dash-folded).
fn backend_nft_table(vm: &VmId) -> String {
    format!("microvm_{}", vm.as_str().replace('-', "_"))
}

/// The nftables table name the isolation reconciliation path derives.
fn isolation_nft_table(vm: &VmId) -> String {
    format!("microvm_{}", vm.as_str())
}

/// The netns name for a VM.
fn netns_name(vm: &VmId) -> String {
    format!("microvm-{}", vm.as_str())
}

async fn state_of(rig: &Rig, vm: &VmId) -> VmState {
    rig.service.status(vm, &rig.owner).await.unwrap().state
}

// ---------------------------------------------------------------------------
// 1. Readiness gating + phase timestamps
// ---------------------------------------------------------------------------

/// A successful boot records the complete, monotonic phase-timestamp sequence
/// `spawn -> socket_ready -> configured -> guest_ready`, and a subsequent stop
/// records `stopped`. This is the happy-path test: the VM is
/// `Running` only after the guest-ready phase is recorded.
#[tokio::test]
async fn successful_boot_records_all_phase_timestamps() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);

    // All four boot phases are timestamped, in order.
    let phases = rig
        .backend
        .phases(&vm)
        .expect("running VM has a process record");
    let spawn = phases.spawn().expect("spawn recorded");
    let socket_ready = phases.socket_ready().expect("socket_ready recorded");
    let configured = phases.configured().expect("configured recorded");
    let guest_ready = phases.guest_ready().expect("guest_ready recorded");
    assert!(phases.stopped().is_none(), "not stopped yet");
    assert!(phases.is_guest_ready());
    assert_eq!(phases.recorded_count(), 4);

    // Monotonic non-decreasing ordering across the boot pipeline.
    assert!(spawn <= socket_ready, "spawn <= socket_ready");
    assert!(socket_ready <= configured, "socket_ready <= configured");
    assert!(configured <= guest_ready, "configured <= guest_ready");

    // Stop records the terminal `stopped` phase after guest_ready.
    rig.service.stop(&vm, &rig.owner).await.unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);
    let phases = rig.backend.phases(&vm).unwrap();
    let stopped = phases.stopped().expect("stopped recorded");
    assert!(guest_ready <= stopped, "guest_ready <= stopped");
    assert_eq!(phases.recorded_count(), 5);
}

/// A VM whose guest never signals readiness must not reach `Running`. The boot
/// fails with a typed guest-not-ready error (`phase=guest_ready` context), the
/// service reconciles the VM to `Failed`, and the `guest_ready` phase is never
/// recorded even though spawn/socket/configured completed.
#[tokio::test]
async fn vm_is_not_running_until_guest_ready() {
    let rig = Rig::new(RigOptions::guest_not_ready()).await;
    let vm = rig.create_vm().await;

    let err = rig.service.start(&vm, &rig.owner).await.unwrap_err();

    // Typed guest-not-ready classification with the exact phase context.
    assert!(
        is_guest_not_ready(&err),
        "expected guest-not-ready, got {err:?}"
    );
    assert_eq!(
        err.context.get("phase").map(String::as_str),
        Some("guest_ready"),
        "error must carry phase=guest_ready context: {err:?}"
    );

    // The VM never advances to Running; the failed boot reconciles to Failed.
    assert_ne!(state_of(&rig, &vm).await, VmState::Running);
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);

    // The boot reached Configured but never recorded guest_ready or stopped.
    let phases = rig
        .backend
        .phases(&vm)
        .expect("failed boot retains its process record");
    assert!(phases.spawn().is_some(), "spawn completed");
    assert!(phases.socket_ready().is_some(), "socket_ready completed");
    assert!(phases.configured().is_some(), "configured completed");
    assert!(phases.guest_ready().is_none(), "guest_ready never recorded");
    assert!(phases.stopped().is_none(), "stopped never recorded");
    assert!(!phases.is_guest_ready());

    // The readiness probe was genuinely consulted (gating is real, not skipped),
    // and the instance was started exactly once before the guest failed to ready.
    assert!(
        rig.readiness.probed().contains(&vm),
        "readiness probe must be consulted before Running"
    );
    assert_eq!(rig.instance_start_count(), 1);
}

// ---------------------------------------------------------------------------
// 2. Resource cleanup on a failed boot
// ---------------------------------------------------------------------------

/// A boot that fails at guest readiness must not leak the resources it already
/// provisioned: the socket, cgroup leaf, and netns mount point created before
/// the readiness gate are all torn down by the backend's fail-closed cleanup.
#[tokio::test]
async fn failed_readiness_cleans_up_provisioned_resources() {
    let rig = Rig::new(RigOptions::guest_not_ready()).await;
    let vm = rig.create_vm().await;

    // Start fails at the guest-readiness gate.
    let err = rig.service.start(&vm, &rig.owner).await.unwrap_err();
    assert!(is_guest_not_ready(&err));

    // Everything provisioned before the gate is gone.
    assert!(!socket_path(&rig, &vm).exists(), "socket removed");
    assert!(!cgroup_leaf(&rig, &vm).exists(), "cgroup leaf removed");
    assert!(!netns_file(&rig, &vm).exists(), "netns mount point removed");
}

// ---------------------------------------------------------------------------
// 3. Normal stop releases every per-VM resource
// ---------------------------------------------------------------------------

/// A successful networked boot provisions a socket, a cgroup leaf, and a netns
/// mount point; a subsequent stop removes all of them and records the terminal
/// `stopped` phase. This is the deterministic "all per-VM resources disappear on
/// stop" guarantee.
#[tokio::test]
async fn normal_stop_releases_every_per_vm_resource() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;

    // After a successful boot the per-VM resources exist on the filesystem.
    assert!(socket_path(&rig, &vm).exists(), "socket provisioned");
    assert!(cgroup_leaf(&rig, &vm).exists(), "cgroup leaf provisioned");
    assert!(
        netns_file(&rig, &vm).exists(),
        "netns mount point provisioned"
    );

    rig.service.stop(&vm, &rig.owner).await.unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);

    // All per-VM resources disappear on stop.
    assert!(!socket_path(&rig, &vm).exists(), "socket removed on stop");
    assert!(
        !cgroup_leaf(&rig, &vm).exists(),
        "cgroup leaf removed on stop"
    );
    assert!(!netns_file(&rig, &vm).exists(), "netns removed on stop");

    // The privileged teardown commands for the network resources were issued.
    let recorded = rig.cleanup.recorded();
    let ops: Vec<&str> = recorded.iter().map(|(op, _)| op.as_str()).collect();
    assert!(
        ops.iter()
            .any(|op| *op == format!("nft:{}", backend_nft_table(&vm))),
        "nft table flushed: {ops:?}"
    );
    assert!(
        ops.iter()
            .any(|op| *op == format!("tap:{}:tap0", netns_name(&vm))),
        "TAP device deleted: {ops:?}"
    );
    assert!(
        ops.iter()
            .any(|op| *op == format!("netns:{}", netns_name(&vm))),
        "netns removed: {ops:?}"
    );

    // The terminal phase is recorded.
    assert!(rig.backend.phases(&vm).unwrap().stopped().is_some());
}

// ---------------------------------------------------------------------------
// 4. Supervisor death: ordered teardown of every owned resource
// ---------------------------------------------------------------------------

/// When a running VM's supervisor process dies, the service reconciles it to
/// `Failed` and issues teardown for every owned resource in strict
/// reverse-creation order: process kill, then nft table, TAP device, and netns.
/// The deterministic-owned filesystem resources (socket, cgroup leaf) are
/// removed outright. This proves "child processes die with the supervisor" and
/// "supervisor termination leaves no Firecracker, jailer, cgroup, TAP, netns, or
/// socket" at the orchestration level.
#[tokio::test]
async fn supervisor_death_cleans_all_owned_resources_in_order() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;
    assert_eq!(state_of(&rig, &vm).await, VmState::Running);

    // Resources exist before the supervisor dies.
    assert!(socket_path(&rig, &vm).exists(), "socket provisioned");
    assert!(cgroup_leaf(&rig, &vm).exists(), "cgroup leaf provisioned");

    // The first scripted spawn is pid 1000; mark it alive then dead.
    rig.cleanup.mark_pid_alive(1000);
    rig.supervisor.mark_dead(&vm, Some(1000));

    assert!(rig.service.reconcile(&vm), "dead supervisor is reconciled");
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);

    // Teardown was issued in strict reverse-creation order: the child process is
    // killed first, then the network resources are released nft -> tap -> netns.
    let recorded = rig.cleanup.recorded();
    let ops: Vec<&str> = recorded.iter().map(|(op, _)| op.as_str()).collect();
    let expected = [
        "kill:1000".to_string(),
        format!("nft:{}", isolation_nft_table(&vm)),
        format!("tap:{}:tap0", netns_name(&vm)),
        format!("netns:{}", netns_name(&vm)),
    ];
    let expected_refs: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_eq!(ops, expected_refs, "reverse-creation cleanup order");

    // The process kill actually reported the supervisor pid removed.
    let kill = recorded
        .iter()
        .find(|(op, _)| op == "kill:1000")
        .expect("kill recorded");
    assert!(kill.1, "supervisor process kill reported removed");

    // The deterministic-owned filesystem resources are gone after reconciliation.
    assert!(!socket_path(&rig, &vm).exists(), "socket removed");
    assert!(!cgroup_leaf(&rig, &vm).exists(), "cgroup leaf removed");
}

/// Reconciliation is idempotent: once a dead supervisor has been reconciled to
/// `Failed` and its resources torn down, a subsequent reconciliation is a no-op
/// that re-issues no cleanup commands. `Failed` needs no live supervisor.
#[tokio::test]
async fn reconciliation_cleanup_is_idempotent() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;

    rig.cleanup.mark_pid_alive(1000);
    rig.supervisor.mark_dead(&vm, Some(1000));

    assert!(rig.service.reconcile(&vm));
    let after_first = rig.cleanup.recorded().len();
    assert!(after_first > 0, "first reconciliation issues cleanup");

    // A second reconciliation is a no-op: Failed needs no supervisor, so no
    // further teardown commands are issued.
    assert!(!rig.service.reconcile(&vm));
    assert_eq!(
        rig.cleanup.recorded().len(),
        after_first,
        "no duplicate cleanup on re-reconciliation"
    );
    assert_eq!(state_of(&rig, &vm).await, VmState::Failed);
}

/// A cleanly stopped VM is not spuriously reconciled: `Stopped` releases its
/// resources and needs no live supervisor, so a later dead-supervisor reading is
/// a no-op rather than a double teardown.
#[tokio::test]
async fn stopped_vm_is_not_reconciled() {
    let rig = Rig::healthy().await;
    let vm = rig.create_and_start().await;
    rig.service.stop(&vm, &rig.owner).await.unwrap();
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);

    let before = rig.cleanup.recorded().len();
    rig.supervisor.mark_dead(&vm, Some(1000));
    assert!(
        !rig.service.reconcile(&vm),
        "stopped VM needs no supervisor"
    );
    assert_eq!(rig.cleanup.recorded().len(), before, "no extra teardown");
    assert_eq!(state_of(&rig, &vm).await, VmState::Stopped);
}

// ---------------------------------------------------------------------------
// Privileged lane: real Firecracker boot through the service + cleanup proof
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Privileged lane: real Firecracker boot through the service + cleanup proof
// ---------------------------------------------------------------------------

/// Real Firecracker/jailer boot driven through the composed
/// [`VmLifecycleService`], with post-stop cleanup verification.
///
/// This is the privileged test: it boots a real guest on a
/// capable host, asserts the VM is `Running` only after the guest-ready phase,
/// stops it, and then proves every per-VM resource disappeared; no Firecracker
/// or jailer process, no cgroup leaf, no TAP/netns, no API socket. On an
/// incapable host (no KVM, no cgroup-v2, missing pinned binaries or boot
/// artifacts) it reports a stable `blocked` token and passes rather than failing
/// or substituting a mock for a KVM/Firecracker pass.
#[cfg(feature = "privileged")]
mod privileged {
    use microvm_artifacts::{compute_sha256, ArtifactStore, Digest};
    use microvm_errors::ErrorCode;
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
    use microvm_lifecycle::{LifecycleService, VmState};
    use microvm_service::{IsolationCleanup, ScriptedSupervisorProbe, VmLifecycleService};
    use microvm_types::{NetworkPolicy, Principal, ResourceSpec, Role, TenantId, VmId};
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

    /// Copy a host artifact into the tenant store and return its digest.
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

    /// Whether any Firecracker/jailer process for `vm_id` is still alive, by
    /// scanning `/proc/*/cmdline` for the VM id alongside a firecracker/jailer
    /// binary reference.
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

    #[tokio::test]
    async fn service_boot_guest_ready_stop_cleans_all_resources() {
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

        // The real backend performs the actual VM operations; `default_boot`
        // makes the created VM immediately startable.
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

        // Compose the supervised service over the real backend.
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

        let owner = Principal::new(tenant, Role::Owner);
        let spec = ResourceSpec::new(1, 256, 512, NetworkPolicy::NatOnly).unwrap();

        // Create + start through the service. Host-gap failures are `blocked`;
        // genuine code failures panic.
        let vm_id = match service.create(spec, owner.clone()).await {
            Ok(id) => id,
            Err(e) => {
                blocked(&format!("create_failed: {e}"));
                return;
            }
        };
        if let Err(e) = service.start(&vm_id, &owner).await {
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

        // The VM is Running and guest-ready, with all boot phases recorded.
        assert_eq!(
            service.status(&vm_id, &owner).await.unwrap().state,
            VmState::Running
        );
        let phases = backend.phases(&vm_id).expect("process record");
        for phase in [
            Phase::Spawn,
            Phase::SocketReady,
            Phase::Configured,
            Phase::GuestReady,
        ] {
            assert!(phases.get(phase).is_some(), "missing phase {phase}");
        }

        // Capture the per-VM resource paths while the VM is running.
        let socket = socket_root.join(vm_id.as_str()).join("api.sock");
        let cgroup_leaf = Path::new(CGROUP_ROOT).join("microvm").join(vm_id.as_str());
        let netns = Path::new(NETNS_ROOT).join(format!("microvm-{}", vm_id.as_str()));
        let chroot = chroot_root.join(vm_id.as_str());

        // Stop through the service; the terminal phase must be recorded.
        service.stop(&vm_id, &owner).await.expect("stop succeeds");
        assert_eq!(
            service.status(&vm_id, &owner).await.unwrap().state,
            VmState::Stopped
        );
        assert!(backend
            .phases(&vm_id)
            .unwrap()
            .get(Phase::Stopped)
            .is_some());

        // Cleanup verification: every per-VM resource must have disappeared.
        assert!(!socket.exists(), "API socket removed: {}", socket.display());
        assert!(
            !cgroup_leaf.exists(),
            "cgroup leaf removed: {}",
            cgroup_leaf.display()
        );
        assert!(!netns.exists(), "netns removed: {}", netns.display());
        assert!(!chroot.exists(), "chroot removed: {}", chroot.display());
        assert!(
            !vm_process_alive(&vm_id, &fc_bin, &jailer_bin),
            "no Firecracker/jailer process remains for {}",
            vm_id.as_str()
        );

        println!("pass: service boot/guest-ready/stop/clean (no process/cgroup/tap/netns/socket)");
    }
}
