//! End-to-end VM lifecycle test over the gRPC Unix-socket API (phase 2 story 2).
//!
//! The same lifecycle flow as [`rest_lifecycle`](crate), driven over the gRPC
//! `microvm.v1` service ([`microvm_grpc::GrpcServer`]) on a temp Unix socket,
//! backed by the composed
//! [`VmLifecycleService`](microvm_service::VmLifecycleService):
//!
//! ```text
//! CreateVm     -> VmId
//! StartVm      -> wait for guest health on TAP IP:port
//! GetVmStatus  -> state == RUNNING
//! SnapshotVm   -> SnapshotId
//! RestoreVm    -> new VmId
//! StopVm       -> state == STOPPED
//! (verify)     -> no leftover cgroup/netns/TAP/socket
//! ```
//!
//! # Lanes
//! - `full_lifecycle_over_grpc_unix_socket`: deterministic, fully-scripted
//!   inner backend (no real Firecracker); exercises the whole flow including
//!   snapshot/restore and resource cleanup.
//! - `composed_firecracker_boot_stop_cleanup_over_grpc`: deterministic, genuine
//!   [`FirecrackerBackend`](microvm_firecracker::FirecrackerBackend) wired with
//!   scripted doubles; proves a real composed boot through the gRPC API and
//!   post-stop cleanup.

mod common;

use microvm_lifecycle::LifecycleService;

use common::{
    grpc_connect, grpc_create, grpc_restore, grpc_snapshot, grpc_start, grpc_status, grpc_stop,
    grpc_wait_for_state, wait_for_health, Rig,
};

/// The full lifecycle flow over a real gRPC Unix socket, backed by the composed
/// service over a fully-scripted inner backend (no real Firecracker).
#[tokio::test]
async fn full_lifecycle_over_grpc_unix_socket() {
    let rig = Rig::new();
    let sock = rig.spawn_grpc("grpc-full.sock").await;
    let mut client = grpc_connect(sock).await;

    // 1. CreateVm -> VmId.
    let vm_id = grpc_create(&mut client, 2, 512, 1024)
        .await
        .expect("create succeeds");
    assert!(!vm_id.is_empty(), "create must return a vm_id");

    // Before start the VM is created, not running.
    assert_eq!(grpc_status(&mut client, &vm_id).await.unwrap(), "created");

    // 2. StartVm, then wait for guest health on TAP IP:port.
    grpc_start(&mut client, &vm_id)
        .await
        .expect("start succeeds");
    wait_for_health(&rig.backend, &vm_id).await;

    // Resources are provisioned while the VM runs.
    assert!(rig.backend.socket_marker(&vm_id).exists(), "api socket");
    assert!(rig.backend.cgroup_marker(&vm_id).exists(), "cgroup");
    assert!(rig.backend.netns_marker(&vm_id).exists(), "netns");
    assert!(rig.backend.tap_marker(&vm_id).exists(), "tap");

    // 3. GetVmStatus -> RUNNING (wait for readiness via the API).
    grpc_wait_for_state(&mut client, &vm_id, "running").await;
    assert_eq!(grpc_status(&mut client, &vm_id).await.unwrap(), "running");

    // 4. SnapshotVm -> SnapshotId.
    let snap_id = grpc_snapshot(&mut client, &vm_id)
        .await
        .expect("snapshot succeeds");
    assert!(!snap_id.is_empty(), "snapshot must return a snapshot_id");

    // 5. RestoreVm -> new VmId, distinct from source.
    let restored_id = grpc_restore(&mut client, &snap_id)
        .await
        .expect("restore succeeds");
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

    // 6. StopVm -> STOPPED.
    grpc_stop(&mut client, &vm_id).await.expect("stop succeeds");
    grpc_wait_for_state(&mut client, &vm_id, "stopped").await;
    assert_eq!(grpc_status(&mut client, &vm_id).await.unwrap(), "stopped");

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

/// A real composed boot through the gRPC API: the genuine
/// [`FirecrackerBackend`] (scripted doubles over temp dirs) wrapped in the
/// supervised service. Verifies post-stop resource cleanup against the real
/// isolation paths (no leftover cgroup leaf, netns mount point, or API socket).
#[tokio::test]
async fn composed_firecracker_boot_stop_cleanup_over_grpc() {
    let rig = common::ComposedRig::new().await;
    let sock_dir = tempfile::tempdir().unwrap();
    let grpc_sock = sock_dir.path().join("composed-grpc.sock");
    common::spawn_grpc_server(grpc_sock.clone(), rig.service.clone()).await;
    let mut client = grpc_connect(grpc_sock).await;

    // Create -> start through the API.
    let vm_id = grpc_create(&mut client, 2, 512, 1024)
        .await
        .expect("create succeeds");
    grpc_start(&mut client, &vm_id)
        .await
        .expect("start succeeds");

    // The composed backend gates Running on guest readiness; the API reflects it.
    grpc_wait_for_state(&mut client, &vm_id, "running").await;
    assert_eq!(grpc_status(&mut client, &vm_id).await.unwrap(), "running");

    // While running, the real per-VM resources exist.
    assert!(rig.socket_path(&vm_id).exists(), "API socket provisioned");
    assert!(rig.cgroup_leaf(&vm_id).exists(), "cgroup leaf provisioned");
    assert!(rig.netns_file(&vm_id).exists(), "netns provisioned");

    // Stop through the API; the VM reaches Stopped.
    grpc_stop(&mut client, &vm_id).await.expect("stop succeeds");
    grpc_wait_for_state(&mut client, &vm_id, "stopped").await;
    assert_eq!(grpc_status(&mut client, &vm_id).await.unwrap(), "stopped");

    // Cleanup verification: every per-VM resource must have disappeared.
    assert!(!rig.socket_path(&vm_id).exists(), "API socket removed");
    assert!(!rig.cgroup_leaf(&vm_id).exists(), "cgroup leaf removed");
    assert!(!rig.netns_file(&vm_id).exists(), "netns removed");
}
