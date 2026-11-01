//! Firecracker snapshot create/load ordering and restore rebinding.
//!
//! This module implements the Firecracker snapshot protocol the orchestrator
//! relies on for pause→snapshot and fresh-process restore. It models the
//! v1.16.1 snapshot routes faithfully and, crucially, encodes the *ordering*
//! and *rebinding* invariants as executable, deterministic state rather than
//! prose:
//!
//! | Method & path | Purpose |
//! |---|---|
//! | `PATCH /vm` | Pause / resume the instance (`{"state":"Paused"|"Resumed"}`) |
//! | `PUT /snapshot/create` | Write a full/diff snapshot (state + memory) |
//! | `PUT /snapshot/load` | Load a snapshot on a fresh process |
//! | `PUT /network-interfaces/{id}` | Rebind the host TAP after load |
//! | `PUT /vsock` | Rebind the host vsock socket after load |
//!
//! # Protocol invariants (enforced here, not assumed)
//!
//! 1. Pause before create. [`SnapshotCreateRequest::execute`] issues
//!    `PATCH /vm {"state":"Paused"}` *before* `PUT /snapshot/create`. A create
//!    against a running VM is rejected by Firecracker; we make the pause
//!    explicit and ordered.
//! 2. Fresh-process load via `mem_backend.backend_path`. Restore loads on a
//!    brand-new VMM process *before* any ordinary boot configuration, using the
//!    supported [`MemBackend`] (`backend_path` + `backend_type`). The
//!    deprecated top-level `mem_file_path` field is never emitted and is
//!    rejected when ingesting an external spec
//!    ([`reject_deprecated_mem_file_path`]).
//! 3. Rebind, don't assume continuity. After load, host-side network (TAP)
//!    and vsock resources are reattached through load overrides. Established
//!    guest network/vsock *connections* are not preserved across
//!    snapshot/restore; see [`network_connection_continuity_after_restore`] and
//!    [`vsock_connection_continuity_after_restore`], both of which report
//!    `false` by contract.
//! 4. Explicit resume. [`SnapshotLoadRequest`] loads with `resume_vm=false`;
//!    the VM reaches `Resumed` only through [`RestoreProtocol::resume`], which
//!    issues `PATCH /vm {"state":"Resumed"}` via the supported backend
//!    contract. There is no backdoor to `Resumed`.
//! 5. No fresh-boot configuration on restore. A restored VM derives its
//!    boot source, drives, and machine shape from the snapshot. Attempting to
//!    configure them as if the restore were a fresh boot is rejected with
//!    [`ErrorCode::InvalidTransition`] labelled [`LOAD_PRE_CONFIG`].
//!
//! # Determinism
//! All ordering, deprecated-field rejection, and rebinding semantics are pure
//! and exercised against [`RecordingSnapshotApi`]. The real transport
//! ([`UdsSnapshotApi`]) reuses the boot adapter's HTTP/1.1-over-UDS client.
//!
//! # Security
//! The snapshot memory file holds the full guest memory image (including any
//! secrets the guest held). It is a host-only artifact: the API socket and the
//! memory/state paths are never surfaced in tenant-facing status or metrics.
//! Firecracker's optional CRC guards only against accidental corruption and is
//! never treated as authentication; integrity/compatibility gating lives in
//! `microvm-snapshots`.

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::api::{NetworkInterface, UdsApiClient};

/// The deprecated top-level snapshot memory field that must not be used.
///
/// Firecracker replaced `mem_file_path` with the structured `mem_backend`
/// object. We reject the deprecated field outright rather than translate it,
/// so a stale manifest or spec cannot silently steer a restore onto the
/// deprecated path.
pub const DEPRECATED_MEM_FILE_PATH: &str = "mem_file_path";

/// Error label for an attempt to apply fresh-boot configuration to a VM that
/// was (or is being) restored from a snapshot.
///
/// Restore derives boot source, drives, and machine shape from the snapshot;
/// configuring them as if the restore were a fresh boot is an ordering
/// violation (`load` must precede and *replace* config, not follow it).
pub const LOAD_PRE_CONFIG: &str = "load_pre_config";

// ---------------------------------------------------------------------------
// PATCH /vm
// ---------------------------------------------------------------------------

/// Target instance state for `PATCH /vm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmState {
    /// Pause the instance (required before snapshot create).
    Paused,
    /// Resume a paused instance (the only supported path to `Resumed` after a
    /// load that requested `resume_vm=false`).
    Resumed,
}

impl VmState {
    /// The Firecracker state string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Paused => "Paused",
            Self::Resumed => "Resumed",
        }
    }
}

/// `PATCH /vm` body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmPatch {
    /// The target instance state.
    pub state: VmState,
}

impl VmPatch {
    /// Build a pause request.
    pub fn pause() -> Self {
        Self {
            state: VmState::Paused,
        }
    }

    /// Build a resume request.
    pub fn resume() -> Self {
        Self {
            state: VmState::Resumed,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory backend (the supported, non-deprecated memory field)
// ---------------------------------------------------------------------------

/// The backing transport for a snapshot memory file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemBackendType {
    /// A host file managed by the orchestrator.
    File,
    /// A userfaultfd handler for demand paging.
    Uffd,
}

impl MemBackendType {
    /// The Firecracker `backend_type` string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "File",
            Self::Uffd => "Uffd",
        }
    }
}

/// The structured memory backend object (`mem_backend`).
///
/// This is the supported replacement for the deprecated top-level
/// `mem_file_path`. `backend_path` points at the memory file (for
/// [`MemBackendType::File`]) or the uffd socket (for [`MemBackendType::Uffd`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemBackend {
    /// Path to the memory file or uffd socket.
    pub backend_path: String,
    /// The backend transport type.
    pub backend_type: MemBackendType,
}

impl MemBackend {
    /// Build a file-backed memory backend.
    pub fn file(backend_path: impl Into<String>) -> Self {
        Self {
            backend_path: backend_path.into(),
            backend_type: MemBackendType::File,
        }
    }

    /// Build a uffd-backed memory backend.
    pub fn uffd(backend_path: impl Into<String>) -> Self {
        Self {
            backend_path: backend_path.into(),
            backend_type: MemBackendType::Uffd,
        }
    }
}

// ---------------------------------------------------------------------------
// PUT /snapshot/create
// ---------------------------------------------------------------------------

/// The kind of snapshot to create.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotType {
    /// A complete snapshot (state + full memory image).
    #[default]
    Full,
    /// A differential snapshot (memory pages dirtied since the last full).
    Diff,
}

impl SnapshotType {
    /// The Firecracker `snapshot_type` string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Diff => "Diff",
        }
    }
}

/// `PUT /snapshot/create` body.
///
/// Deliberately has no `mem_file_path` field: the memory destination is
/// expressed only through [`MemBackend`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    /// Path where the microVM state file is written.
    pub snapshot_path: String,
    /// Memory backend (destination for the memory image).
    pub mem_backend: MemBackend,
    /// Full or differential snapshot.
    #[serde(default)]
    pub snapshot_type: SnapshotType,
    /// Optional target snapshot version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// PUT /snapshot/load
// ---------------------------------------------------------------------------

/// `PUT /snapshot/load` body.
///
/// Deliberately has no `mem_file_path` field: the memory source is
/// expressed only through [`MemBackend`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLoadParams {
    /// Path to the microVM state file to load.
    pub snapshot_path: String,
    /// Memory backend (source of the memory image).
    pub mem_backend: MemBackend,
    /// Whether to enable diff snapshots after load.
    #[serde(default)]
    pub enable_diff_snapshots: bool,
    /// Whether Firecracker should resume the VM itself after load.
    ///
    /// The restore protocol always sets this to `false` and resumes explicitly
    /// via `PATCH /vm {"state":"Resumed"}` so the `Resumed` transition is
    /// observable and contract-driven.
    #[serde(default)]
    pub resume_vm: bool,
}

/// `PUT /vsock` body used to rebind the host-side vsock socket after load.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsockOverride {
    /// Vsock identifier.
    pub vsock_id: String,
    /// Guest context ID.
    pub guest_cid: u64,
    /// Host-side Unix socket path the vsock device is reattached to.
    pub uds_path: String,
}

impl VsockOverride {
    /// Build a vsock rebind override.
    pub fn new(vsock_id: impl Into<String>, guest_cid: u64, uds_path: impl Into<String>) -> Self {
        Self {
            vsock_id: vsock_id.into(),
            guest_cid,
            uds_path: uds_path.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Deprecated-field rejection
// ---------------------------------------------------------------------------

/// Reject a raw snapshot spec that uses the deprecated `mem_file_path` field.
///
/// Used when ingesting an externally supplied create/load spec (for example a
/// stored restore request). The supported contract requires
/// `mem_backend.backend_path`; a spec still carrying `mem_file_path` fails
/// closed with [`ErrorCode::SnapshotIncompatible`] rather than being silently
/// translated.
pub fn reject_deprecated_mem_file_path(spec: &serde_json::Value) -> Result<(), MicrovmError> {
    if spec.get(DEPRECATED_MEM_FILE_PATH).is_some() {
        return Err(MicrovmError::new(
            ErrorCode::SnapshotIncompatible,
            "deprecated snapshot memory field is not supported",
        )
        .with_context("field", DEPRECATED_MEM_FILE_PATH)
        .with_context("use", "mem_backend.backend_path"));
    }
    Ok(())
}

fn missing_field(field: &'static str) -> MicrovmError {
    MicrovmError::new(
        ErrorCode::InvalidResourceSpec,
        "snapshot spec is missing a required field",
    )
    .with_context("field", field)
}

// ---------------------------------------------------------------------------
// Snapshot API trait
// ---------------------------------------------------------------------------

/// Abstract Firecracker snapshot API operations.
///
/// Implemented by [`UdsSnapshotApi`] for real VMs and by
/// [`RecordingSnapshotApi`] in deterministic tests. Every method maps
/// transport/API failures to [`ErrorCode::TransportError`].
#[async_trait]
pub trait SnapshotApi: Send + Sync {
    /// Pause or resume the instance (`PATCH /vm`).
    async fn patch_vm(&self, state: VmState) -> Result<(), MicrovmError>;
    /// Create a snapshot (`PUT /snapshot/create`).
    async fn put_snapshot_create(&self, params: &SnapshotCreateParams) -> Result<(), MicrovmError>;
    /// Load a snapshot on a fresh process (`PUT /snapshot/load`).
    async fn put_snapshot_load(&self, params: &SnapshotLoadParams) -> Result<(), MicrovmError>;
    /// Rebind a network interface's host TAP (`PUT /network-interfaces/{id}`).
    async fn put_network_interface(&self, cfg: &NetworkInterface) -> Result<(), MicrovmError>;
    /// Rebind the host-side vsock socket (`PUT /vsock`).
    async fn put_vsock(&self, cfg: &VsockOverride) -> Result<(), MicrovmError>;
}

// ---------------------------------------------------------------------------
// Real UDS client
// ---------------------------------------------------------------------------

/// A [`SnapshotApi`] speaking to a real Firecracker process over its Unix
/// domain socket, reusing the boot adapter's HTTP/1.1 transport.
#[derive(Clone, Debug)]
pub struct UdsSnapshotApi {
    client: UdsApiClient,
}

impl UdsSnapshotApi {
    /// Create a snapshot API client bound to `socket_path`.
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            client: UdsApiClient::new(socket_path),
        }
    }

    /// Wrap an existing boot-adapter client (same socket).
    pub fn from_client(client: UdsApiClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SnapshotApi for UdsSnapshotApi {
    async fn patch_vm(&self, state: VmState) -> Result<(), MicrovmError> {
        self.client
            .send_json("PATCH", "/vm", &VmPatch { state })
            .await
    }

    async fn put_snapshot_create(&self, params: &SnapshotCreateParams) -> Result<(), MicrovmError> {
        self.client
            .send_json("PUT", "/snapshot/create", params)
            .await
    }

    async fn put_snapshot_load(&self, params: &SnapshotLoadParams) -> Result<(), MicrovmError> {
        self.client.send_json("PUT", "/snapshot/load", params).await
    }

    async fn put_network_interface(&self, cfg: &NetworkInterface) -> Result<(), MicrovmError> {
        let path = format!("/network-interfaces/{}", cfg.iface_id);
        self.client.send_json("PUT", &path, cfg).await
    }

    async fn put_vsock(&self, cfg: &VsockOverride) -> Result<(), MicrovmError> {
        self.client.send_json("PUT", "/vsock", cfg).await
    }
}

// ---------------------------------------------------------------------------
// Snapshot create request (pause -> create)
// ---------------------------------------------------------------------------

/// A pause→snapshot-create sequence.
///
/// Bundles the create parameters and executes the required ordering:
/// `PATCH /vm {"state":"Paused"}` before `PUT /snapshot/create`.
#[derive(Clone, Debug)]
pub struct SnapshotCreateRequest {
    params: SnapshotCreateParams,
}

impl SnapshotCreateRequest {
    /// Build a full-snapshot create request writing state to `snapshot_path`
    /// and the memory image to `mem_backend_path` (file backend).
    pub fn full(snapshot_path: impl Into<String>, mem_backend_path: impl Into<String>) -> Self {
        Self {
            params: SnapshotCreateParams {
                snapshot_path: snapshot_path.into(),
                mem_backend: MemBackend::file(mem_backend_path),
                snapshot_type: SnapshotType::Full,
                version: None,
            },
        }
    }

    /// Build a create request from explicit parameters.
    pub fn from_params(params: SnapshotCreateParams) -> Self {
        Self { params }
    }

    /// The create parameters this request will submit.
    pub fn params(&self) -> &SnapshotCreateParams {
        &self.params
    }

    /// Execute the pause→create sequence against `api`, in order.
    ///
    /// The VM is paused first; only then is the snapshot created. If the pause
    /// fails, no create is attempted.
    pub async fn execute(&self, api: &dyn SnapshotApi) -> Result<(), MicrovmError> {
        api.patch_vm(VmState::Paused)
            .await
            .map_err(|e| e.with_context("snapshot_phase", "pause_before_create"))?;
        api.put_snapshot_create(&self.params)
            .await
            .map_err(|e| e.with_context("snapshot_phase", "create"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Snapshot load request (fresh-process load + overrides)
// ---------------------------------------------------------------------------

/// A fresh-process snapshot load request with network/vsock rebinding
/// overrides.
///
/// The load is built with `resume_vm=false`: reaching `Resumed` is the
/// explicit responsibility of [`RestoreProtocol::resume`].
#[derive(Clone, Debug)]
pub struct SnapshotLoadRequest {
    params: SnapshotLoadParams,
    network_overrides: Vec<NetworkInterface>,
    vsock_override: Option<VsockOverride>,
}

impl SnapshotLoadRequest {
    /// Build a load request from a state path and a file-backed memory backend.
    ///
    /// `resume_vm` is forced to `false`; resume happens explicitly through the
    /// restore protocol.
    pub fn new(snapshot_path: impl Into<String>, mem_backend: MemBackend) -> Self {
        Self {
            params: SnapshotLoadParams {
                snapshot_path: snapshot_path.into(),
                mem_backend,
                enable_diff_snapshots: false,
                resume_vm: false,
            },
            network_overrides: Vec::new(),
            vsock_override: None,
        }
    }

    /// Parse a load request from a raw, externally supplied JSON spec.
    ///
    /// Fails closed if the spec uses the deprecated `mem_file_path` field, or
    /// if `snapshot_path` / `mem_backend.backend_path` are absent. Any
    /// `resume_vm` value in the spec is ignored and forced to `false`.
    pub fn from_raw_spec(spec: &serde_json::Value) -> Result<Self, MicrovmError> {
        reject_deprecated_mem_file_path(spec)?;

        let snapshot_path = spec
            .get("snapshot_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| missing_field("snapshot_path"))?
            .to_string();

        let backend = spec
            .get("mem_backend")
            .ok_or_else(|| missing_field("mem_backend"))?;
        let backend_path = backend
            .get("backend_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| missing_field("mem_backend.backend_path"))?
            .to_string();
        let backend_type = match backend
            .get("backend_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("File")
        {
            "Uffd" => MemBackendType::Uffd,
            _ => MemBackendType::File,
        };

        let enable_diff_snapshots = spec
            .get("enable_diff_snapshots")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        Ok(Self {
            params: SnapshotLoadParams {
                snapshot_path,
                mem_backend: MemBackend {
                    backend_path,
                    backend_type,
                },
                enable_diff_snapshots,
                // Always explicit-resume; never let the spec auto-resume.
                resume_vm: false,
            },
            network_overrides: Vec::new(),
            vsock_override: None,
        })
    }

    /// Add a network interface rebind override (host TAP reattachment).
    pub fn with_network_override(mut self, iface: NetworkInterface) -> Self {
        self.network_overrides.push(iface);
        self
    }

    /// Set the vsock rebind override (host socket reattachment).
    pub fn with_vsock_override(mut self, vsock: VsockOverride) -> Self {
        self.vsock_override = Some(vsock);
        self
    }

    /// Enable differential snapshots after load.
    pub fn with_diff_snapshots(mut self, enable: bool) -> Self {
        self.params.enable_diff_snapshots = enable;
        self
    }

    /// The load parameters this request will submit (`resume_vm` always false).
    pub fn params(&self) -> &SnapshotLoadParams {
        &self.params
    }

    /// The network rebind overrides, in order.
    pub fn network_overrides(&self) -> &[NetworkInterface] {
        &self.network_overrides
    }

    /// The vsock rebind override, if any.
    pub fn vsock_override(&self) -> Option<&VsockOverride> {
        self.vsock_override.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Connection-continuity contract (explicitly: none)
// ---------------------------------------------------------------------------

/// Whether guest network connections survive snapshot/restore.
///
/// Always `false` by contract. Rebinding reattaches the host-side TAP device;
/// it does not preserve established guest TCP/UDP flows. Callers must not
/// advertise connection continuity across restore.
pub const fn network_connection_continuity_after_restore() -> bool {
    false
}

/// Whether guest vsock connections survive snapshot/restore.
///
/// Always `false` by contract. Rebinding reattaches the host-side vsock
/// socket; established vsock connections are dropped.
pub const fn vsock_connection_continuity_after_restore() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Restore protocol (load -> rebind -> resume, with ordering guards)
// ---------------------------------------------------------------------------

/// The stage of a restore sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreStage {
    /// Fresh process spawned; nothing loaded yet.
    Fresh,
    /// Snapshot loaded; network/vsock may be rebound; not yet resumed.
    Loaded,
    /// VM explicitly resumed via `PATCH /vm {"state":"Resumed"}`.
    Resumed,
}

/// A recorded restore-protocol operation (for deterministic assertions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreCall {
    /// `PUT /snapshot/load`.
    Load(SnapshotLoadParams),
    /// `PUT /network-interfaces/{id}` rebind.
    RebindNetwork(NetworkInterface),
    /// `PUT /vsock` rebind.
    RebindVsock(VsockOverride),
    /// `PATCH /vm {"state":"Resumed"}`.
    Resume,
}

/// The operation a [`RecordingSnapshotApi`] should fail, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotFailPoint {
    /// Fail `PATCH /vm`.
    PatchVm,
    /// Fail `PUT /snapshot/create`.
    Create,
    /// Fail `PUT /snapshot/load`.
    Load,
    /// Fail `PUT /network-interfaces/{id}`.
    NetworkInterface,
    /// Fail `PUT /vsock`.
    Vsock,
}

impl SnapshotFailPoint {
    fn error(self) -> MicrovmError {
        MicrovmError::new(ErrorCode::TransportError, "scripted snapshot API failure")
            .with_context("fail_point", self.label())
    }

    fn label(self) -> &'static str {
        match self {
            Self::PatchVm => "patch_vm",
            Self::Create => "snapshot_create",
            Self::Load => "snapshot_load",
            Self::NetworkInterface => "network_interface",
            Self::Vsock => "vsock",
        }
    }
}

fn load_pre_config_error(operation: &'static str) -> MicrovmError {
    MicrovmError::new(
        ErrorCode::InvalidTransition,
        "fresh-boot configuration is not permitted on a restored VM",
    )
    .with_context("rule", LOAD_PRE_CONFIG)
    .with_context("operation", operation)
}

fn stage_error(operation: &'static str, current: RestoreStage) -> MicrovmError {
    MicrovmError::new(
        ErrorCode::InvalidTransition,
        "snapshot restore operation issued out of order",
    )
    .with_context("operation", operation)
    .with_context("stage", format!("{current:?}"))
}

/// Orchestrates the full restore sequence over a [`SnapshotApi`].
///
/// Enforces, as executable state, that:
/// - `load` happens on a fresh process before any rebinding or resume;
/// - network/vsock rebinding happens only after a successful load;
/// - the VM reaches `Resumed` only through an explicit [`resume`](Self::resume)
///   (`PATCH /vm {"state":"Resumed"}`);
/// - fresh-boot configuration (boot source / drives / machine config) is
///   rejected with [`LOAD_PRE_CONFIG`], never forwarded to the backend.
pub struct RestoreProtocol {
    api: Arc<dyn SnapshotApi>,
    inner: Mutex<RestoreInner>,
}

#[derive(Debug)]
struct RestoreInner {
    stage: RestoreStage,
    calls: Vec<RestoreCall>,
}

impl RestoreProtocol {
    /// Start a restore protocol over `api`, in the [`RestoreStage::Fresh`]
    /// stage (a freshly spawned, unconfigured VMM process).
    pub fn new(api: Arc<dyn SnapshotApi>) -> Self {
        Self {
            api,
            inner: Mutex::new(RestoreInner {
                stage: RestoreStage::Fresh,
                calls: Vec::new(),
            }),
        }
    }

    /// The current restore stage.
    pub fn stage(&self) -> RestoreStage {
        self.inner.lock().unwrap().stage
    }

    /// The recorded restore operations, in order.
    pub fn calls(&self) -> Vec<RestoreCall> {
        self.inner.lock().unwrap().calls.clone()
    }

    /// Load the snapshot on the fresh process (`PUT /snapshot/load`).
    ///
    /// Only valid from [`RestoreStage::Fresh`]. The load is submitted with
    /// `resume_vm=false`; the VM is not running afterward.
    pub async fn load(&self, req: &SnapshotLoadRequest) -> Result<(), MicrovmError> {
        {
            let inner = self.inner.lock().unwrap();
            if inner.stage != RestoreStage::Fresh {
                return Err(stage_error("load", inner.stage));
            }
        }
        self.api.put_snapshot_load(req.params()).await?;
        let mut inner = self.inner.lock().unwrap();
        inner.stage = RestoreStage::Loaded;
        inner.calls.push(RestoreCall::Load(req.params().clone()));
        Ok(())
    }

    /// Rebind a network interface's host TAP after load.
    ///
    /// Only valid from [`RestoreStage::Loaded`]. Reattaches the host-side TAP;
    /// does not preserve guest network connections.
    pub async fn rebind_network(&self, iface: &NetworkInterface) -> Result<(), MicrovmError> {
        {
            let inner = self.inner.lock().unwrap();
            if inner.stage != RestoreStage::Loaded {
                return Err(stage_error("rebind_network", inner.stage));
            }
        }
        self.api.put_network_interface(iface).await?;
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(RestoreCall::RebindNetwork(iface.clone()));
        Ok(())
    }

    /// Rebind the host-side vsock socket after load.
    ///
    /// Only valid from [`RestoreStage::Loaded`]. Reattaches the host socket;
    /// does not preserve guest vsock connections.
    pub async fn rebind_vsock(&self, vsock: &VsockOverride) -> Result<(), MicrovmError> {
        {
            let inner = self.inner.lock().unwrap();
            if inner.stage != RestoreStage::Loaded {
                return Err(stage_error("rebind_vsock", inner.stage));
            }
        }
        self.api.put_vsock(vsock).await?;
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(RestoreCall::RebindVsock(vsock.clone()));
        Ok(())
    }

    /// Apply a load request's network/vsock overrides, in order.
    ///
    /// Convenience wrapper over [`rebind_network`](Self::rebind_network) and
    /// [`rebind_vsock`](Self::rebind_vsock).
    pub async fn apply_overrides(&self, req: &SnapshotLoadRequest) -> Result<(), MicrovmError> {
        for iface in req.network_overrides() {
            self.rebind_network(iface).await?;
        }
        if let Some(vsock) = req.vsock_override() {
            self.rebind_vsock(vsock).await?;
        }
        Ok(())
    }

    /// Explicitly resume the loaded VM (`PATCH /vm {"state":"Resumed"}`).
    ///
    /// Only valid from [`RestoreStage::Loaded`]. This is the only path to
    /// [`RestoreStage::Resumed`].
    pub async fn resume(&self) -> Result<(), MicrovmError> {
        {
            let inner = self.inner.lock().unwrap();
            if inner.stage != RestoreStage::Loaded {
                return Err(stage_error("resume", inner.stage));
            }
        }
        self.api.patch_vm(VmState::Resumed).await?;
        let mut inner = self.inner.lock().unwrap();
        inner.stage = RestoreStage::Resumed;
        inner.calls.push(RestoreCall::Resume);
        Ok(())
    }

    /// Run the full restore sequence: load → apply overrides → resume.
    pub async fn run(&self, req: &SnapshotLoadRequest) -> Result<(), MicrovmError> {
        self.load(req).await?;
        self.apply_overrides(req).await?;
        self.resume().await?;
        Ok(())
    }

    // -- fresh-boot configuration guards (always rejected on restore) -------

    /// Reject a fresh-boot `PUT /boot-source` on a restored VM.
    ///
    /// Always returns [`ErrorCode::InvalidTransition`] labelled
    /// [`LOAD_PRE_CONFIG`] and records nothing: a restored VM's boot source
    /// comes from the snapshot.
    pub fn configure_boot_source(&self) -> Result<(), MicrovmError> {
        Err(load_pre_config_error("put_boot_source"))
    }

    /// Reject a fresh-boot `PUT /drives/{id}` on a restored VM.
    pub fn configure_drive(&self) -> Result<(), MicrovmError> {
        Err(load_pre_config_error("put_drive"))
    }

    /// Reject a fresh-boot `PUT /machine-config` on a restored VM.
    pub fn configure_machine_config(&self) -> Result<(), MicrovmError> {
        Err(load_pre_config_error("put_machine_config"))
    }
}

// ---------------------------------------------------------------------------
// Recording double (deterministic tests)
// ---------------------------------------------------------------------------

/// A recorded snapshot API call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotCall {
    /// `PATCH /vm` with a target state.
    PatchVm(VmState),
    /// `PUT /snapshot/create`.
    SnapshotCreate(SnapshotCreateParams),
    /// `PUT /snapshot/load`.
    SnapshotLoad(SnapshotLoadParams),
    /// `PUT /network-interfaces/{id}`.
    NetworkInterface(NetworkInterface),
    /// `PUT /vsock`.
    Vsock(VsockOverride),
}

/// A [`SnapshotApi`] that records calls and can fail on a configured op.
#[derive(Debug, Default)]
pub struct RecordingSnapshotApi {
    inner: Mutex<RecordingSnapshotApiInner>,
}

#[derive(Debug, Default)]
struct RecordingSnapshotApiInner {
    calls: Vec<SnapshotCall>,
    fail_on: Option<SnapshotFailPoint>,
}

impl RecordingSnapshotApi {
    /// Create a recording snapshot API that succeeds on every call.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the API to fail on `point`.
    pub fn with_failure(self, point: SnapshotFailPoint) -> Self {
        self.inner.lock().unwrap().fail_on = Some(point);
        self
    }

    /// The calls recorded so far, in order.
    pub fn calls(&self) -> Vec<SnapshotCall> {
        self.inner.lock().unwrap().calls.clone()
    }

    /// True if `call` was recorded.
    pub fn recorded(&self, call: &SnapshotCall) -> bool {
        self.inner.lock().unwrap().calls.contains(call)
    }

    fn push(&self, call: SnapshotCall) {
        self.inner.lock().unwrap().calls.push(call);
    }

    fn check_fail(&self, point: SnapshotFailPoint) -> Result<(), MicrovmError> {
        if self.inner.lock().unwrap().fail_on == Some(point) {
            Err(point.error())
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl SnapshotApi for RecordingSnapshotApi {
    async fn patch_vm(&self, state: VmState) -> Result<(), MicrovmError> {
        self.push(SnapshotCall::PatchVm(state));
        self.check_fail(SnapshotFailPoint::PatchVm)
    }

    async fn put_snapshot_create(&self, params: &SnapshotCreateParams) -> Result<(), MicrovmError> {
        self.push(SnapshotCall::SnapshotCreate(params.clone()));
        self.check_fail(SnapshotFailPoint::Create)
    }

    async fn put_snapshot_load(&self, params: &SnapshotLoadParams) -> Result<(), MicrovmError> {
        self.push(SnapshotCall::SnapshotLoad(params.clone()));
        self.check_fail(SnapshotFailPoint::Load)
    }

    async fn put_network_interface(&self, cfg: &NetworkInterface) -> Result<(), MicrovmError> {
        self.push(SnapshotCall::NetworkInterface(cfg.clone()));
        self.check_fail(SnapshotFailPoint::NetworkInterface)
    }

    async fn put_vsock(&self, cfg: &VsockOverride) -> Result<(), MicrovmError> {
        self.push(SnapshotCall::Vsock(cfg.clone()));
        self.check_fail(SnapshotFailPoint::Vsock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::NET_IFACE_ID;

    fn arc_recording() -> Arc<RecordingSnapshotApi> {
        Arc::new(RecordingSnapshotApi::new())
    }

    // -- serialization ------------------------------------------------------

    #[test]
    fn create_params_serialize_with_mem_backend_not_deprecated_field() {
        let req = SnapshotCreateRequest::full("/snap/state.vmstate", "/snap/mem.img");
        let json = serde_json::to_string(req.params()).unwrap();
        assert!(json.contains("\"mem_backend\""));
        assert!(json.contains("\"backend_path\":\"/snap/mem.img\""));
        assert!(json.contains("\"backend_type\":\"File\""));
        assert!(json.contains("\"snapshot_type\":\"Full\""));
        // The deprecated field must never be emitted.
        assert!(!json.contains(DEPRECATED_MEM_FILE_PATH));
    }

    #[test]
    fn load_params_serialize_with_mem_backend_and_no_auto_resume() {
        let req =
            SnapshotLoadRequest::new("/snap/state.vmstate", MemBackend::file("/snap/mem.img"));
        let json = serde_json::to_string(req.params()).unwrap();
        assert!(json.contains("\"mem_backend\""));
        assert!(json.contains("\"backend_path\":\"/snap/mem.img\""));
        assert!(json.contains("\"resume_vm\":false"));
        assert!(!json.contains(DEPRECATED_MEM_FILE_PATH));
    }

    #[test]
    fn vm_patch_serializes_state_strings() {
        assert_eq!(
            serde_json::to_string(&VmPatch::pause()).unwrap(),
            "{\"state\":\"Paused\"}"
        );
        assert_eq!(
            serde_json::to_string(&VmPatch::resume()).unwrap(),
            "{\"state\":\"Resumed\"}"
        );
    }

    // -- deprecated field rejection -----------------------------------------

    #[test]
    fn deprecated_mem_file_path_is_rejected_on_load_ingest() {
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
    fn deprecated_field_rejected_even_when_mem_backend_present() {
        let spec = serde_json::json!({
            "snapshot_path": "/s",
            "mem_file_path": "/m",
            "mem_backend": { "backend_path": "/m", "backend_type": "File" },
        });
        assert!(reject_deprecated_mem_file_path(&spec).is_err());
    }

    #[test]
    fn raw_spec_requires_snapshot_path_and_backend_path() {
        let no_path = serde_json::json!({ "mem_backend": { "backend_path": "/m" } });
        assert_eq!(
            SnapshotLoadRequest::from_raw_spec(&no_path)
                .unwrap_err()
                .code,
            ErrorCode::InvalidResourceSpec
        );

        let no_backend = serde_json::json!({ "snapshot_path": "/s" });
        assert_eq!(
            SnapshotLoadRequest::from_raw_spec(&no_backend)
                .unwrap_err()
                .code,
            ErrorCode::InvalidResourceSpec
        );

        let no_backend_path =
            serde_json::json!({ "snapshot_path": "/s", "mem_backend": { "backend_type": "File" } });
        assert_eq!(
            SnapshotLoadRequest::from_raw_spec(&no_backend_path)
                .unwrap_err()
                .code,
            ErrorCode::InvalidResourceSpec
        );
    }

    #[test]
    fn raw_spec_forces_explicit_resume_off() {
        let spec = serde_json::json!({
            "snapshot_path": "/s",
            "mem_backend": { "backend_path": "/m", "backend_type": "Uffd" },
            "resume_vm": true,
        });
        let req = SnapshotLoadRequest::from_raw_spec(&spec).unwrap();
        assert!(!req.params().resume_vm);
        assert_eq!(req.params().mem_backend.backend_type, MemBackendType::Uffd);
    }

    // -- create ordering ----------------------------------------------------

    #[tokio::test]
    async fn create_pauses_before_snapshot_create() {
        let api = arc_recording();
        let req = SnapshotCreateRequest::full("/snap/state.vmstate", "/snap/mem.img");
        req.execute(api.as_ref()).await.unwrap();

        let calls = api.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], SnapshotCall::PatchVm(VmState::Paused));
        assert!(matches!(calls[1], SnapshotCall::SnapshotCreate(_)));
    }

    #[tokio::test]
    async fn create_does_not_call_snapshot_create_when_pause_fails() {
        let api = Arc::new(RecordingSnapshotApi::new().with_failure(SnapshotFailPoint::PatchVm));
        let req = SnapshotCreateRequest::full("/s", "/m");
        let err = req.execute(api.as_ref()).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::TransportError);
        // Only the pause was attempted; no create reached the backend.
        let calls = api.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], SnapshotCall::PatchVm(VmState::Paused));
    }

    // -- restore ordering ---------------------------------------------------

    #[tokio::test]
    async fn restore_runs_load_rebind_resume_in_order() {
        let api = arc_recording();
        let proto = RestoreProtocol::new(api.clone());
        let req =
            SnapshotLoadRequest::new("/snap/state.vmstate", MemBackend::file("/snap/mem.img"))
                .with_network_override(NetworkInterface::tap("tap0"))
                .with_vsock_override(VsockOverride::new("vsock0", 3, "/snap/vsock.sock"));

        proto.run(&req).await.unwrap();

        assert_eq!(proto.stage(), RestoreStage::Resumed);
        let calls = proto.calls();
        assert_eq!(
            calls,
            vec![
                RestoreCall::Load(req.params().clone()),
                RestoreCall::RebindNetwork(NetworkInterface::tap("tap0")),
                RestoreCall::RebindVsock(VsockOverride::new("vsock0", 3, "/snap/vsock.sock")),
                RestoreCall::Resume,
            ]
        );

        // The backend saw load first, then rebinds, then an explicit resume.
        let backend = api.calls();
        assert!(matches!(backend[0], SnapshotCall::SnapshotLoad(_)));
        assert_eq!(
            backend.last().unwrap(),
            &SnapshotCall::PatchVm(VmState::Resumed)
        );
    }

    #[tokio::test]
    async fn load_is_required_before_rebind_and_resume() {
        let api = arc_recording();
        let proto = RestoreProtocol::new(api.clone());

        // Rebind before load -> out of order.
        let err = proto
            .rebind_network(&NetworkInterface::tap("tap0"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidTransition);

        // Resume before load -> out of order.
        let err = proto.resume().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidTransition);

        // Nothing reached the backend.
        assert!(api.calls().is_empty());
        assert_eq!(proto.stage(), RestoreStage::Fresh);
    }

    #[tokio::test]
    async fn load_cannot_run_twice() {
        let api = arc_recording();
        let proto = RestoreProtocol::new(api.clone());
        let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"));
        proto.load(&req).await.unwrap();
        let err = proto.load(&req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidTransition);
        // Exactly one load reached the backend.
        assert_eq!(
            api.calls()
                .iter()
                .filter(|c| matches!(c, SnapshotCall::SnapshotLoad(_)))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn loaded_vm_reaches_resumed_only_through_explicit_resume() {
        let api = arc_recording();
        let proto = RestoreProtocol::new(api.clone());
        let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"));
        proto.load(&req).await.unwrap();

        // After load (resume_vm=false) the VM is not resumed yet.
        assert_eq!(proto.stage(), RestoreStage::Loaded);
        assert!(!req.params().resume_vm);

        proto.resume().await.unwrap();
        assert_eq!(proto.stage(), RestoreStage::Resumed);

        // The only Resumed signal sent to the backend is the explicit PATCH.
        let resumed: Vec<_> = api
            .calls()
            .into_iter()
            .filter(|c| *c == SnapshotCall::PatchVm(VmState::Resumed))
            .collect();
        assert_eq!(resumed.len(), 1);
    }

    #[tokio::test]
    async fn resume_before_load_fails_and_records_nothing() {
        let api = arc_recording();
        let proto = RestoreProtocol::new(api.clone());
        assert!(proto.resume().await.is_err());
        assert!(api.calls().is_empty());
    }

    // -- fresh-boot config rejection (LoadPreConfig) ------------------------

    #[tokio::test]
    async fn fresh_boot_config_is_rejected_after_load_with_load_pre_config() {
        let api = arc_recording();
        let proto = RestoreProtocol::new(api.clone());
        let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"));
        proto.load(&req).await.unwrap();

        for err in [
            proto.configure_boot_source().unwrap_err(),
            proto.configure_drive().unwrap_err(),
            proto.configure_machine_config().unwrap_err(),
        ] {
            assert_eq!(err.code, ErrorCode::InvalidTransition);
            assert_eq!(
                err.context.get("rule").map(String::as_str),
                Some(LOAD_PRE_CONFIG)
            );
        }

        // No boot-source/drive/machine-config reached the backend, and the
        // stage is unchanged (no corrupted state): the backend only saw the
        // load.
        assert_eq!(proto.stage(), RestoreStage::Loaded);
        assert_eq!(
            api.calls(),
            vec![SnapshotCall::SnapshotLoad(req.params().clone())]
        );
    }

    #[test]
    fn fresh_boot_config_is_rejected_even_before_load() {
        let proto = RestoreProtocol::new(arc_recording());
        assert_eq!(
            proto.configure_boot_source().unwrap_err().code,
            ErrorCode::InvalidTransition
        );
    }

    // -- connection-continuity contract -------------------------------------

    #[test]
    fn no_network_or_vsock_connection_continuity_after_restore() {
        assert!(!network_connection_continuity_after_restore());
        assert!(!vsock_connection_continuity_after_restore());
    }

    #[tokio::test]
    async fn rebind_reattaches_host_resources_without_continuity_claim() {
        let api = arc_recording();
        let proto = RestoreProtocol::new(api.clone());
        let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"))
            .with_network_override(NetworkInterface::tap("tap-restored"));
        proto.load(&req).await.unwrap();
        proto.apply_overrides(&req).await.unwrap();

        // Rebinding records a fresh host-TAP attach for the standard iface id.
        assert!(
            api.recorded(&SnapshotCall::NetworkInterface(NetworkInterface {
                iface_id: NET_IFACE_ID.to_string(),
                host_dev_name: "tap-restored".to_string(),
            }))
        );
        // ...while the contract still reports no connection continuity.
        assert!(!network_connection_continuity_after_restore());
    }

    // -- failure containment ------------------------------------------------

    #[tokio::test]
    async fn load_failure_leaves_protocol_fresh() {
        let api = Arc::new(RecordingSnapshotApi::new().with_failure(SnapshotFailPoint::Load));
        let proto = RestoreProtocol::new(api.clone());
        let req = SnapshotLoadRequest::new("/s", MemBackend::file("/m"));
        let err = proto.load(&req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::TransportError);
        // Stage unchanged; resume is still impossible.
        assert_eq!(proto.stage(), RestoreStage::Fresh);
        assert!(proto.resume().await.is_err());
    }
}
