//! Deterministic, dependency-free test doubles for the Firecracker adapter.
//!
//! These scripted implementations let tests (here and in downstream crates such
//! as the lifecycle service) drive the full boot/stop orchestration without a
//! real Firecracker binary, KVM device, or guest. They record every call so
//! assertions can verify the exact sequence of operations the backend issued.
//!
//! All types use interior mutability and are `Send + Sync`, so they slot into
//! the backend's `Arc<dyn _>` slots directly.

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::VmId;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::api::{
    BootSource, Drive, FirecrackerApi, InstanceInfo, MachineConfig, NetworkInterface,
};
use crate::phase::Phase;
use crate::prereq::PrerequisiteCheck;
use crate::process::{LaunchSpec, ProcessLauncher};
use crate::readiness::{GuestReadinessProbe, ReadinessContext};

// ---------------------------------------------------------------------------
// Scripted process launcher
// ---------------------------------------------------------------------------

/// How a [`ScriptedLauncher`] responds to spawn requests.
#[derive(Clone, Debug)]
pub enum SpawnOutcome {
    /// Assign incrementing PIDs starting at 1000.
    Auto,
    /// Always return this fixed PID.
    Fixed(u32),
    /// Fail every spawn with this error.
    Fail(MicrovmError),
}

/// A [`ProcessLauncher`] that scripts spawn/exit/kill without real processes.
#[derive(Debug)]
pub struct ScriptedLauncher {
    inner: Mutex<ScriptedLauncherInner>,
}

#[derive(Debug)]
struct ScriptedLauncherInner {
    outcome: SpawnOutcome,
    next_pid: u32,
    spawned: Vec<LaunchSpec>,
    killed: Vec<u32>,
    exit_code: i32,
    alive: bool,
    create_socket: bool,
}

impl ScriptedLauncher {
    /// Create a launcher that auto-assigns PIDs.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ScriptedLauncherInner {
                outcome: SpawnOutcome::Auto,
                next_pid: 1000,
                spawned: Vec::new(),
                killed: Vec::new(),
                exit_code: 0,
                alive: true,
                create_socket: false,
            }),
        }
    }

    /// Set the spawn outcome.
    pub fn with_outcome(self, outcome: SpawnOutcome) -> Self {
        self.inner.lock().unwrap().outcome = outcome;
        self
    }

    /// Set the exit code returned by `wait_exit`.
    pub fn with_exit_code(self, code: i32) -> Self {
        self.inner.lock().unwrap().exit_code = code;
        self
    }

    /// Create the API socket file (and its parent directory) on spawn,
    /// simulating the VMM bringing up its API socket so the backend's
    /// socket-readiness wait succeeds deterministically.
    pub fn with_socket_on_spawn(self) -> Self {
        self.inner.lock().unwrap().create_socket = true;
        self
    }

    /// The launch specs passed to `spawn`, in order.
    pub fn spawned(&self) -> Vec<LaunchSpec> {
        self.inner.lock().unwrap().spawned.clone()
    }

    /// The PIDs passed to `kill`, in order.
    pub fn killed(&self) -> Vec<u32> {
        self.inner.lock().unwrap().killed.clone()
    }
}

impl Default for ScriptedLauncher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProcessLauncher for ScriptedLauncher {
    async fn spawn(&self, spec: &LaunchSpec) -> Result<u32, MicrovmError> {
        let mut inner = self.inner.lock().unwrap();
        inner.spawned.push(spec.clone());
        let create_socket = inner.create_socket;
        let result = match &inner.outcome {
            SpawnOutcome::Auto => {
                let pid = inner.next_pid;
                inner.next_pid += 1;
                Ok(pid)
            }
            SpawnOutcome::Fixed(pid) => Ok(*pid),
            SpawnOutcome::Fail(err) => Err(err.clone()),
        };
        // Simulate the VMM creating its API socket once a spawn succeeds.
        if result.is_ok() && create_socket {
            if let Some(parent) = spec.socket_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&spec.socket_path, b"");
        }
        result
    }

    async fn wait_exit(&self, _pid: u32) -> Result<i32, MicrovmError> {
        let code = self.inner.lock().unwrap().exit_code;
        Ok(code)
    }

    async fn kill(&self, pid: u32) -> Result<(), MicrovmError> {
        self.inner.lock().unwrap().killed.push(pid);
        self.inner.lock().unwrap().alive = false;
        Ok(())
    }

    fn is_alive(&self, _pid: u32) -> bool {
        self.inner.lock().unwrap().alive
    }
}

// ---------------------------------------------------------------------------
// Recording API
// ---------------------------------------------------------------------------

/// A recorded Firecracker API call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiCall {
    MachineConfig(MachineConfig),
    BootSource(BootSource),
    Drive(Drive),
    NetworkInterface(NetworkInterface),
    StartInstance,
    SendCtrlAltDel,
    InstanceInfo,
}

/// The operation a [`RecordingApi`] should fail, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailPoint {
    MachineConfig,
    BootSource,
    Drive,
    NetworkInterface,
    StartInstance,
    SendCtrlAltDel,
    InstanceInfo,
}

impl FailPoint {
    fn error(self) -> MicrovmError {
        MicrovmError::new(ErrorCode::TransportError, "scripted API failure")
            .with_context("fail_point", self.label())
    }

    fn label(self) -> &'static str {
        match self {
            Self::MachineConfig => "machine_config",
            Self::BootSource => "boot_source",
            Self::Drive => "drive",
            Self::NetworkInterface => "network_interface",
            Self::StartInstance => "start_instance",
            Self::SendCtrlAltDel => "send_ctrl_alt_del",
            Self::InstanceInfo => "instance_info",
        }
    }
}

/// A [`FirecrackerApi`] that records calls and can fail on a configured op.
#[derive(Debug, Default)]
pub struct RecordingApi {
    inner: Mutex<RecordingApiInner>,
}

#[derive(Debug)]
struct RecordingApiInner {
    calls: Vec<ApiCall>,
    fail_on: Option<FailPoint>,
    instance_state: String,
}

impl Default for RecordingApiInner {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            fail_on: None,
            instance_state: "Running".to_string(),
        }
    }
}

impl RecordingApi {
    /// Create a recording API that succeeds on every call.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the API to fail on `point`.
    pub fn with_failure(self, point: FailPoint) -> Self {
        self.inner.lock().unwrap().fail_on = Some(point);
        self
    }

    /// Configure the instance state reported by `instance_info`.
    pub fn with_instance_state(self, state: impl Into<String>) -> Self {
        self.inner.lock().unwrap().instance_state = state.into();
        self
    }

    /// The calls recorded so far, in order.
    pub fn calls(&self) -> Vec<ApiCall> {
        self.inner.lock().unwrap().calls.clone()
    }

    /// True if `call` was recorded.
    pub fn recorded(&self, call: &ApiCall) -> bool {
        self.inner.lock().unwrap().calls.contains(call)
    }

    fn push(&self, call: ApiCall) {
        self.inner.lock().unwrap().calls.push(call);
    }

    fn check_fail(&self, point: FailPoint) -> Result<(), MicrovmError> {
        if self.inner.lock().unwrap().fail_on == Some(point) {
            Err(point.error())
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl FirecrackerApi for RecordingApi {
    async fn put_machine_config(&self, cfg: &MachineConfig) -> Result<(), MicrovmError> {
        self.push(ApiCall::MachineConfig(cfg.clone()));
        self.check_fail(FailPoint::MachineConfig)
    }

    async fn put_boot_source(&self, cfg: &BootSource) -> Result<(), MicrovmError> {
        self.push(ApiCall::BootSource(cfg.clone()));
        self.check_fail(FailPoint::BootSource)
    }

    async fn put_drive(&self, cfg: &Drive) -> Result<(), MicrovmError> {
        self.push(ApiCall::Drive(cfg.clone()));
        self.check_fail(FailPoint::Drive)
    }

    async fn put_network_interface(&self, cfg: &NetworkInterface) -> Result<(), MicrovmError> {
        self.push(ApiCall::NetworkInterface(cfg.clone()));
        self.check_fail(FailPoint::NetworkInterface)
    }

    async fn start_instance(&self) -> Result<(), MicrovmError> {
        self.push(ApiCall::StartInstance);
        self.check_fail(FailPoint::StartInstance)
    }

    async fn send_ctrl_alt_del(&self) -> Result<(), MicrovmError> {
        self.push(ApiCall::SendCtrlAltDel);
        self.check_fail(FailPoint::SendCtrlAltDel)
    }

    async fn instance_info(&self) -> Result<InstanceInfo, MicrovmError> {
        self.push(ApiCall::InstanceInfo);
        self.check_fail(FailPoint::InstanceInfo)?;
        let state = self.inner.lock().unwrap().instance_state.clone();
        Ok(InstanceInfo {
            id: String::new(),
            state,
            vmm_version: "1.16.1".to_string(),
        })
    }
}

/// An API factory that always returns a shared [`RecordingApi`].
#[derive(Debug, Clone)]
pub struct ScriptedApiFactory {
    api: Arc<RecordingApi>,
}

impl ScriptedApiFactory {
    /// Wrap a shared recording API.
    pub fn new(api: Arc<RecordingApi>) -> Self {
        Self { api }
    }

    /// The shared recording API (for assertions).
    pub fn api(&self) -> Arc<RecordingApi> {
        self.api.clone()
    }
}

impl crate::backend::ApiFactory for ScriptedApiFactory {
    fn connect(&self, _socket_path: &Path) -> Arc<dyn FirecrackerApi> {
        self.api.clone()
    }
}

// ---------------------------------------------------------------------------
// Scripted readiness probe
// ---------------------------------------------------------------------------

/// A [`GuestReadinessProbe`] that returns a configured outcome.
#[derive(Debug)]
pub struct ScriptedProbe {
    outcome: Mutex<Result<(), MicrovmError>>,
    probed: Mutex<Vec<VmId>>,
}

impl ScriptedProbe {
    /// A probe that always reports ready.
    pub fn ready() -> Self {
        Self {
            outcome: Mutex::new(Ok(())),
            probed: Mutex::new(Vec::new()),
        }
    }

    /// A probe that always fails with a guest-not-ready error.
    pub fn not_ready() -> Self {
        Self {
            outcome: Mutex::new(Err(MicrovmError::new(
                ErrorCode::InternalError,
                "guest did not become ready before timeout",
            )
            .with_context("phase", "guest_ready"))),
            probed: Mutex::new(Vec::new()),
        }
    }

    /// The VMs probed, in order.
    pub fn probed(&self) -> Vec<VmId> {
        self.probed.lock().unwrap().clone()
    }
}

#[async_trait]
impl GuestReadinessProbe for ScriptedProbe {
    async fn wait_ready(&self, ctx: &ReadinessContext) -> Result<(), MicrovmError> {
        self.probed.lock().unwrap().push(ctx.vm_id.clone());
        self.outcome.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Scripted prerequisite check
// ---------------------------------------------------------------------------

/// A [`PrerequisiteCheck`] that returns a configured outcome.
#[derive(Clone, Debug)]
pub struct ScriptedPrereq {
    outcome: Result<(), MicrovmError>,
}

impl ScriptedPrereq {
    /// Prerequisites always satisfied.
    pub fn ok() -> Self {
        Self { outcome: Ok(()) }
    }

    /// Prerequisites fail with `err`.
    pub fn fail(err: MicrovmError) -> Self {
        Self { outcome: Err(err) }
    }
}

impl PrerequisiteCheck for ScriptedPrereq {
    fn check(&self, _net_required: bool) -> Result<(), MicrovmError> {
        self.outcome.clone()
    }
}

/// Convenience: the phase sequence a successful full boot records.
pub fn successful_boot_phases() -> [Phase; 4] {
    [
        Phase::Spawn,
        Phase::SocketReady,
        Phase::Configured,
        Phase::GuestReady,
    ]
}

/// A socket path under a temp root, for tests.
pub fn socket_path(root: &Path, vm_id: &VmId) -> PathBuf {
    root.join(vm_id.as_str()).join("api.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::MachineConfig;

    #[tokio::test]
    async fn scripted_launcher_auto_pids() {
        let l = ScriptedLauncher::new();
        let spec = LaunchSpec::new(
            VmId::new("vm-1").unwrap(),
            vec!["fc".into()],
            PathBuf::from("/s"),
        );
        assert_eq!(l.spawn(&spec).await.unwrap(), 1000);
        assert_eq!(l.spawn(&spec).await.unwrap(), 1001);
        assert_eq!(l.spawned().len(), 2);
    }

    #[tokio::test]
    async fn scripted_launcher_fail() {
        let l = ScriptedLauncher::new().with_outcome(SpawnOutcome::Fail(MicrovmError::new(
            ErrorCode::ProcessSpawnError,
            "nope",
        )));
        let spec = LaunchSpec::new(
            VmId::new("vm-1").unwrap(),
            vec!["fc".into()],
            PathBuf::from("/s"),
        );
        let err = l.spawn(&spec).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::ProcessSpawnError);
    }

    #[tokio::test]
    async fn recording_api_records_in_order() {
        let api = RecordingApi::new();
        api.put_machine_config(&MachineConfig::new(2, 512))
            .await
            .unwrap();
        api.start_instance().await.unwrap();
        let calls = api.calls();
        assert_eq!(calls.len(), 2);
        assert!(matches!(calls[0], ApiCall::MachineConfig(_)));
        assert_eq!(calls[1], ApiCall::StartInstance);
    }

    #[tokio::test]
    async fn recording_api_fails_on_configured_point() {
        let api = RecordingApi::new().with_failure(FailPoint::StartInstance);
        api.put_machine_config(&MachineConfig::new(1, 128))
            .await
            .unwrap();
        let err = api.start_instance().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::TransportError);
        assert_eq!(
            err.context.get("fail_point").map(String::as_str),
            Some("start_instance")
        );
    }

    #[tokio::test]
    async fn scripted_probe_ready_and_not_ready() {
        let ctx = ReadinessContext::new(
            VmId::new("vm-1").unwrap(),
            None,
            std::time::Duration::from_secs(1),
        );
        assert!(ScriptedProbe::ready().wait_ready(&ctx).await.is_ok());
        assert!(ScriptedProbe::not_ready().wait_ready(&ctx).await.is_err());
    }

    #[test]
    fn scripted_prereq_outcomes() {
        assert!(ScriptedPrereq::ok().check(true).is_ok());
        let fail = ScriptedPrereq::fail(MicrovmError::new(ErrorCode::CgroupUnavailable, "x"));
        assert_eq!(
            fail.check(false).unwrap_err().code,
            ErrorCode::CgroupUnavailable
        );
    }
}
