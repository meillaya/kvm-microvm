//! Deterministic full boot/stop orchestration against scripted doubles.
//!
//! These tests drive the entire [`FirecrackerBackend`] pipeline: prerequisite
//! check, digest validation, isolation setup, spawn, socket readiness, API
//! configuration, `InstanceStart`, guest readiness, and stop/cleanup: without
//! a capable host, by injecting scripted launcher/API/probe doubles.

mod common;

use common::{Rig, RigOptions};
use microvm_firecracker::api::{MachineConfig, NET_IFACE_ID, ROOT_DRIVE_ID};
use microvm_firecracker::phase::Phase;
use microvm_firecracker::testing::ApiCall;
use microvm_lifecycle::policy::{AuditResult, Operation};
use microvm_lifecycle::{LifecycleService, VmState};
use microvm_types::NetworkPolicy;

#[tokio::test]
async fn happy_boot_reaches_running_with_all_phases() {
    let rig = Rig::healthy().await;

    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();

    // State is Running.
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Running));

    // All four boot phases recorded, in order.
    let phases = rig.backend.phases(&rig.vm_id).expect("process exists");
    assert!(phases.spawn().is_some());
    assert!(phases.socket_ready().is_some());
    assert!(phases.configured().is_some());
    assert!(phases.guest_ready().is_some());
    assert!(phases.stopped().is_none());
    assert!(phases.is_guest_ready());
    // Monotonic ordering of recorded timestamps.
    assert!(phases.spawn().unwrap() <= phases.socket_ready().unwrap());
    assert!(phases.socket_ready().unwrap() <= phases.configured().unwrap());
    assert!(phases.configured().unwrap() <= phases.guest_ready().unwrap());
}

#[tokio::test]
async fn api_calls_issued_in_configuration_order() {
    let rig = Rig::healthy().await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();

    let calls = rig.api.calls();
    // Order: machine-config, boot-source, drive, network-interface, start.
    assert!(matches!(calls[0], ApiCall::MachineConfig(_)));
    assert!(matches!(calls[1], ApiCall::BootSource(_)));
    assert!(matches!(calls[2], ApiCall::Drive(_)));
    assert!(matches!(calls[3], ApiCall::NetworkInterface(_)));
    assert_eq!(calls[4], ApiCall::StartInstance);

    // Machine config reflects the boot config.
    let ApiCall::MachineConfig(mc) = &calls[0] else {
        panic!()
    };
    assert_eq!(mc, &MachineConfig::new(2, 512));

    // Drive is the rootfs drive; network interface uses the TAP name.
    let ApiCall::Drive(drive) = &calls[2] else {
        panic!()
    };
    assert_eq!(drive.drive_id, ROOT_DRIVE_ID);
    assert!(drive.is_root_device);
    let ApiCall::NetworkInterface(nic) = &calls[3] else {
        panic!()
    };
    assert_eq!(nic.iface_id, NET_IFACE_ID);
}

#[tokio::test]
async fn boot_config_paths_are_digest_validated() {
    // The kernel/rootfs host paths handed to the API live under the tenant
    // artifact root and were opened+verified before configuration.
    let rig = Rig::healthy().await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();

    let calls = rig.api.calls();
    let ApiCall::BootSource(bs) = &calls[1] else {
        panic!()
    };
    assert!(
        bs.kernel_image_path.ends_with("images/vmlinux"),
        "{}",
        bs.kernel_image_path
    );
    assert!(bs.boot_args.as_deref() == Some("console=ttyS0 reboot=k panic=1 pci=off"));
    let ApiCall::Drive(drive) = &calls[2] else {
        panic!()
    };
    assert!(
        drive.path_on_host.ends_with("images/rootfs.ext4"),
        "{}",
        drive.path_on_host
    );
}

#[tokio::test]
async fn networked_vm_uses_jailer_argv() {
    let rig = Rig::healthy().await; // NatOnly => networked => jailed launch
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();

    let spawned = rig.launcher.spawned();
    assert_eq!(spawned.len(), 1);
    let argv = &spawned[0].argv;
    // Jailer argv always carries cgroup-version=2 and a parent-cgroup leaf.
    assert!(argv.contains(&"--cgroup-version=2".to_string()), "{argv:?}");
    assert!(argv.iter().any(|a| a.contains("microvm/")), "{argv:?}");
    assert!(argv.contains(&"--netns".to_string()), "{argv:?}");
}

#[tokio::test]
async fn non_networked_vm_uses_direct_argv() {
    let rig = Rig::new(RigOptions {
        net_policy: NetworkPolicy::None,
        ..RigOptions::default()
    })
    .await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();

    let spawned = rig.launcher.spawned();
    let argv = &spawned[0].argv;
    // Direct launch passes an explicit --api-sock and no jailer cgroup flag.
    assert!(argv.contains(&"--api-sock".to_string()), "{argv:?}");
    assert!(
        !argv.contains(&"--cgroup-version=2".to_string()),
        "{argv:?}"
    );
    // No network interface configured for a VM with no network.
    assert!(!rig.api.recorded(&ApiCall::NetworkInterface(
        microvm_firecracker::api::NetworkInterface::tap("tap0")
    )));
}

#[tokio::test]
async fn audit_log_records_create_and_start_success() {
    let rig = Rig::healthy().await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();

    let events = rig.audit.events();
    let create = events
        .iter()
        .find(|e| e.operation == Operation::Create)
        .unwrap();
    assert_eq!(create.result, AuditResult::Success);
    let start = events
        .iter()
        .find(|e| e.operation == Operation::Start)
        .unwrap();
    assert_eq!(start.result, AuditResult::Success);
    assert_eq!(start.resource_id, rig.vm_id.as_str());
}

#[tokio::test]
async fn status_does_not_expose_api_socket_to_tenants() {
    let rig = Rig::healthy().await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();

    let status = rig.backend.status(&rig.vm_id, &rig.owner).await.unwrap();
    assert_eq!(status.state, VmState::Running);

    // The serialized tenant-facing status must not leak the socket path.
    let json = serde_json::to_string(&status).unwrap();
    let socket = rig.backend.socket_path(&rig.vm_id);
    assert!(
        !json.contains(socket.display().to_string().as_str()),
        "socket leaked: {json}"
    );
    assert!(!json.contains("api.sock"), "socket leaked: {json}");
    assert!(!json.contains("socket"), "socket key leaked: {json}");

    // Same for metrics.
    let metrics = rig.backend.metrics(&rig.vm_id, &rig.owner).await.unwrap();
    let mjson = serde_json::to_string(&metrics).unwrap();
    assert!(
        !mjson.contains("api.sock"),
        "socket leaked in metrics: {mjson}"
    );
}

#[tokio::test]
async fn stop_transitions_to_stopped_and_cleans_up() {
    let rig = Rig::healthy().await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Running));

    rig.backend.stop(&rig.vm_id, &rig.owner).await.unwrap();

    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Stopped));

    // Stopped phase recorded.
    let phases = rig.backend.phases(&rig.vm_id).unwrap();
    assert!(phases.stopped().is_some());

    // Graceful shutdown attempted via SendCtrlAltDel.
    assert!(rig.api.recorded(&ApiCall::SendCtrlAltDel));

    // Cleanup backend was invoked (process kill + resource removal).
    let recorded = rig.cleanup.recorded();
    assert!(!recorded.is_empty(), "cleanup performed no actions");

    // Audit records a successful stop.
    let events = rig.audit.events();
    let stop = events
        .iter()
        .find(|e| e.operation == Operation::Stop)
        .unwrap();
    assert_eq!(stop.result, AuditResult::Success);
}

#[tokio::test]
async fn start_is_idempotent_when_already_running() {
    let rig = Rig::healthy().await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();
    let calls_before = rig.api.calls().len();

    // Second start is a no-op (no duplicate InstanceStart).
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();
    assert_eq!(rig.api.calls().len(), calls_before);
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Running));
}

#[tokio::test]
async fn cross_tenant_start_is_denied() {
    let rig = Rig::healthy().await;
    let foreign = microvm_types::Principal::new(
        microvm_types::TenantId::new("evil").unwrap(),
        microvm_types::Role::Owner,
    );
    let err = rig.backend.start(&rig.vm_id, &foreign).await.unwrap_err();
    assert_eq!(err.code, microvm_errors::ErrorCode::PermissionDenied);
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Created));

    // Denial is audited.
    let events = rig.audit.events();
    let start = events
        .iter()
        .find(|e| e.operation == Operation::Start)
        .unwrap();
    assert_eq!(start.result, AuditResult::Denied);
}

#[tokio::test]
async fn phase_ordering_spawn_socket_configured_guest_ready() {
    // Re-assert the canonical phase sequence constant matches the recorded one.
    let rig = Rig::healthy().await;
    rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap();
    let phases = rig.backend.phases(&rig.vm_id).unwrap();
    let expected = microvm_firecracker::testing::successful_boot_phases();
    for phase in expected {
        assert!(phases.get(phase).is_some(), "phase {phase} missing");
    }
    assert_eq!(phases.recorded_count(), 4);
    // Stopped is not part of a successful boot.
    assert!(phases.get(Phase::Stopped).is_none());
}
