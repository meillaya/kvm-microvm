//! Deterministic snapshot create/load ordering and restore-rebinding tests
//! (public API).
//!
//! Covers the four protocol guarantees without a real Firecracker binary:
//! request-sequence validation, deprecated-field rejection, load-before-config
//! ordering, and network/vsock disconnect semantics.

use std::sync::Arc;

use microvm_errors::ErrorCode;
use microvm_firecracker::snapshot::{
    network_connection_continuity_after_restore, reject_deprecated_mem_file_path,
    vsock_connection_continuity_after_restore, MemBackend, RecordingSnapshotApi, RestoreProtocol,
    RestoreStage, SnapshotCall, SnapshotCreateRequest, SnapshotLoadRequest, VmState, VsockOverride,
    DEPRECATED_MEM_FILE_PATH, LOAD_PRE_CONFIG,
};
use microvm_firecracker::{NetworkInterface, NET_IFACE_ID};

fn recording() -> Arc<RecordingSnapshotApi> {
    Arc::new(RecordingSnapshotApi::new())
}

// ---------------------------------------------------------------------------
// Request sequence validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_sequence_is_pause_then_create() {
    let api = recording();
    let req = SnapshotCreateRequest::full("/snap/state.vmstate", "/snap/mem.img");
    req.execute(api.as_ref()).await.unwrap();

    let calls = api.calls();
    assert_eq!(calls.len(), 2, "pause + create, nothing else");
    assert_eq!(calls[0], SnapshotCall::PatchVm(VmState::Paused));
    match &calls[1] {
        SnapshotCall::SnapshotCreate(p) => {
            assert_eq!(p.snapshot_path, "/snap/state.vmstate");
            assert_eq!(p.mem_file_path, "/snap/mem.img");
            assert!(!serde_json::to_string(p).unwrap().contains("mem_backend"));
        }
        other => panic!("expected snapshot create, got {other:?}"),
    }
}

#[tokio::test]
async fn restore_sequence_is_load_rebind_resume() {
    let api = recording();
    let proto = RestoreProtocol::new(api.clone());
    let req = SnapshotLoadRequest::new("/snap/state.vmstate", MemBackend::file("/snap/mem.img"))
        .with_network_override(NetworkInterface::tap("tap0"))
        .with_vsock_override(VsockOverride::new("vsock0", 3, "/snap/vsock.sock"));
    proto.run(&req).await.unwrap();
    assert_eq!(proto.stage(), RestoreStage::Resumed);

    let calls = api.calls();
    assert!(matches!(calls[0], SnapshotCall::SnapshotLoad(_)));
    assert!(matches!(calls[1], SnapshotCall::NetworkInterface(_)));
    assert!(matches!(calls[2], SnapshotCall::Vsock(_)));
    assert_eq!(calls[3], SnapshotCall::PatchVm(VmState::Resumed));
}

#[test]
fn load_params_never_emit_deprecated_field_and_never_auto_resume() {
    let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"));
    let json = serde_json::to_string(req.params()).unwrap();
    assert!(json.contains("\"backend_path\":\"/m\""));
    assert!(json.contains("\"resume_vm\":false"));
    assert!(!json.contains(DEPRECATED_MEM_FILE_PATH));
}

// ---------------------------------------------------------------------------
// Deprecated field rejection
// ---------------------------------------------------------------------------

#[test]
fn deprecated_mem_file_path_rejected_at_ingest() {
    let spec = serde_json::json!({
        "snapshot_path": "/snap/state.vmstate",
        "mem_file_path": "/snap/mem.img",
    });
    let err = SnapshotLoadRequest::from_raw_spec(&spec).unwrap_err();
    assert_eq!(err.code, ErrorCode::SnapshotIncompatible);
    assert_eq!(
        err.context.get("field").map(String::as_str),
        Some(DEPRECATED_MEM_FILE_PATH)
    );
}

#[test]
fn reject_helper_flags_deprecated_field() {
    let bad = serde_json::json!({ "mem_file_path": "/m" });
    assert!(reject_deprecated_mem_file_path(&bad).is_err());
    let good = serde_json::json!({ "mem_backend": { "backend_path": "/m" } });
    assert!(reject_deprecated_mem_file_path(&good).is_ok());
}

// ---------------------------------------------------------------------------
// Load-before-config ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rebind_and_resume_require_a_prior_load() {
    let api = recording();
    let proto = RestoreProtocol::new(api.clone());
    assert!(proto.resume().await.is_err());
    assert!(proto
        .rebind_network(&NetworkInterface::tap("tap0"))
        .await
        .is_err());
    assert!(
        api.calls().is_empty(),
        "no out-of-order call reaches the backend"
    );
    assert_eq!(proto.stage(), RestoreStage::Fresh);
}

#[tokio::test]
async fn fresh_boot_config_after_load_is_rejected_with_load_pre_config() {
    let api = recording();
    let proto = RestoreProtocol::new(api.clone());
    let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"));
    proto.load(&req).await.unwrap();

    let err = proto.configure_boot_source().unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
    assert_eq!(
        err.context.get("rule").map(String::as_str),
        Some(LOAD_PRE_CONFIG)
    );
    assert!(proto.configure_drive().is_err());
    assert!(proto.configure_machine_config().is_err());

    // No corrupted state: backend saw only the load, stage unchanged.
    assert_eq!(proto.stage(), RestoreStage::Loaded);
    assert_eq!(
        api.calls(),
        vec![SnapshotCall::SnapshotLoad(req.params().clone())]
    );
}

// ---------------------------------------------------------------------------
// Network / vsock disconnect semantics
// ---------------------------------------------------------------------------

#[test]
fn restore_does_not_claim_connection_continuity() {
    assert!(!network_connection_continuity_after_restore());
    assert!(!vsock_connection_continuity_after_restore());
}

#[tokio::test]
async fn rebind_reattaches_host_tap_without_continuity() {
    let api = recording();
    let proto = RestoreProtocol::new(api.clone());
    let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"))
        .with_network_override(NetworkInterface::tap("tap-restored"));
    proto.load(&req).await.unwrap();
    proto.apply_overrides(&req).await.unwrap();

    // The rebind reattaches the standard iface id to a fresh host TAP.
    assert!(
        api.recorded(&SnapshotCall::NetworkInterface(NetworkInterface {
            iface_id: NET_IFACE_ID.to_string(),
            host_dev_name: "tap-restored".to_string(),
        }))
    );
    // ...and the contract still reports no connection continuity.
    assert!(!network_connection_continuity_after_restore());
}
