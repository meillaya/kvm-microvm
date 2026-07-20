//! Child-process tracking and the process-launch abstraction.
//!
//! One Firecracker (or jailer) child process backs exactly one VM. The backend
//! never calls `tokio::process` directly; it goes through the
//! [`ProcessLauncher`] trait so deterministic tests can script spawn/exit/kill
//! behavior without a real binary. [`TokioLauncher`] is the real implementation
//! used on a capable host.
//!
//! [`VmProcess`] is the per-VM record of the spawned child: its PID, the API
//! socket path, and the [`PhaseTimestamps`] accumulated during boot/stop.

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::VmId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::phase::PhaseTimestamps;

/// Everything the launcher needs to start a VM's child process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSpec {
    /// The VM this process backs.
    pub vm_id: VmId,
    /// Full argument vector (`argv[0]` is the program). For a jailed launch
    /// this is the validated jailer argv; for a direct launch it is the
    /// Firecracker argv.
    pub argv: Vec<String>,
    /// The API socket path the VMM will create and the backend will connect to.
    pub socket_path: PathBuf,
    /// Extra environment variables for the child (sorted for determinism).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl LaunchSpec {
    /// Create a launch spec.
    pub fn new(vm_id: VmId, argv: Vec<String>, socket_path: PathBuf) -> Self {
        Self {
            vm_id,
            argv,
            socket_path,
            env: BTreeMap::new(),
        }
    }

    /// The program (`argv[0]`), if any.
    pub fn program(&self) -> Option<&str> {
        self.argv.first().map(String::as_str)
    }
}

/// Abstracts spawning and supervising a VM's child process.
#[async_trait]
pub trait ProcessLauncher: Send + Sync {
    /// Spawn the child described by `spec`, returning its PID.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ProcessSpawnError`] if the child cannot be started.
    async fn spawn(&self, spec: &LaunchSpec) -> Result<u32, MicrovmError>;

    /// Wait for `pid` to exit, returning its exit code (signal deaths map to
    /// `-1`).
    async fn wait_exit(&self, pid: u32) -> Result<i32, MicrovmError>;

    /// Forcefully kill `pid`. Idempotent: killing an unknown or already-exited
    /// PID is a no-op.
    async fn kill(&self, pid: u32) -> Result<(), MicrovmError>;

    /// Best-effort liveness check for `pid`.
    fn is_alive(&self, pid: u32) -> bool;
}

/// Per-VM process record: child PID, API socket, and phase timestamps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmProcess {
    vm_id: VmId,
    pid: Option<u32>,
    socket_path: PathBuf,
    phases: PhaseTimestamps,
}

impl VmProcess {
    /// Create a process record for a spawned child.
    pub fn new(vm_id: VmId, pid: u32, socket_path: PathBuf) -> Self {
        Self {
            vm_id,
            pid: Some(pid),
            socket_path,
            phases: PhaseTimestamps::new(),
        }
    }

    /// Create a process record with no live PID (e.g. after the child exited).
    pub fn exited(vm_id: VmId, socket_path: PathBuf) -> Self {
        Self {
            vm_id,
            pid: None,
            socket_path,
            phases: PhaseTimestamps::new(),
        }
    }

    /// The VM this process backs.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }

    /// The child PID, if still tracked.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// The API socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Mutable access to the phase timestamps.
    pub fn phases_mut(&mut self) -> &mut PhaseTimestamps {
        &mut self.phases
    }

    /// The phase timestamps.
    pub fn phases(&self) -> &PhaseTimestamps {
        &self.phases
    }

    /// Clear the tracked PID (after the child has exited).
    pub fn clear_pid(&mut self) {
        self.pid = None;
    }
}

// ---------------------------------------------------------------------------
// Real launcher (tokio::process)
// ---------------------------------------------------------------------------

/// A [`ProcessLauncher`] backed by `tokio::process`.
///
/// Spawned children are tracked by PID in an internal map so they can be waited
/// on and killed. The map uses a `tokio::sync::Mutex` because waiting holds a
/// child across an `.await`.
#[derive(Debug, Default)]
pub struct TokioLauncher {
    children: tokio::sync::Mutex<std::collections::HashMap<u32, tokio::process::Child>>,
}

impl TokioLauncher {
    /// Create an empty launcher.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ProcessLauncher for TokioLauncher {
    async fn spawn(&self, spec: &LaunchSpec) -> Result<u32, MicrovmError> {
        let program = spec.program().ok_or_else(|| {
            MicrovmError::new(ErrorCode::ProcessSpawnError, "launch spec has empty argv")
                .with_context("vm_id", spec.vm_id.as_str())
        })?;

        let mut cmd = tokio::process::Command::new(program);
        if spec.argv.len() > 1 {
            cmd.args(&spec.argv[1..]);
        }
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        // Detach the child's stdio so it does not inherit the supervisor's
        // terminal; Firecracker logs via its own logger/metrics configuration.
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let child = cmd.spawn().map_err(|e| {
            MicrovmError::new(
                ErrorCode::ProcessSpawnError,
                "failed to spawn child process",
            )
            .with_context("vm_id", spec.vm_id.as_str())
            .with_context("program", program)
            .with_context("io", e.to_string())
        })?;

        let pid = child.id().ok_or_else(|| {
            MicrovmError::new(ErrorCode::ProcessSpawnError, "spawned child has no PID")
                .with_context("vm_id", spec.vm_id.as_str())
        })?;

        self.children.lock().await.insert(pid, child);
        Ok(pid)
    }

    async fn wait_exit(&self, pid: u32) -> Result<i32, MicrovmError> {
        let child = self.children.lock().await.remove(&pid);
        let Some(mut child) = child else {
            // Unknown PID: treat as already exited.
            return Ok(0);
        };
        let status = child.wait().await.map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "failed to wait on child process")
                .with_context("pid", pid.to_string())
                .with_context("io", e.to_string())
        })?;
        Ok(status.code().unwrap_or(-1))
    }

    async fn kill(&self, pid: u32) -> Result<(), MicrovmError> {
        let mut guard = self.children.lock().await;
        if let Some(child) = guard.get_mut(&pid) {
            // Best effort: ignore errors from an already-exited child.
            let _ = child.start_kill();
            let _ = child.kill().await;
        }
        guard.remove(&pid);
        Ok(())
    }

    fn is_alive(&self, pid: u32) -> bool {
        // Synchronous best-effort check: we cannot await here, so we use a
        // non-blocking try_wait via a short-lived block is not possible without
        // a runtime handle. Conservatively report `true` if we still track the
        // child; the authoritative liveness check happens in wait_exit.
        self.children
            .try_lock()
            .map(|g| g.contains_key(&pid))
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_spec_program() {
        let spec = LaunchSpec::new(
            VmId::new("vm-1").unwrap(),
            vec![
                "/usr/bin/jailer".to_string(),
                "--id".to_string(),
                "vm-1".to_string(),
            ],
            PathBuf::from("/run/vm-1/api.sock"),
        );
        assert_eq!(spec.program(), Some("/usr/bin/jailer"));
        assert_eq!(spec.socket_path, PathBuf::from("/run/vm-1/api.sock"));
    }

    #[test]
    fn launch_spec_empty_argv_has_no_program() {
        let spec = LaunchSpec::new(VmId::new("vm-1").unwrap(), vec![], PathBuf::from("/s"));
        assert_eq!(spec.program(), None);
    }

    #[test]
    fn vm_process_tracks_pid_and_socket() {
        let mut p = VmProcess::new(
            VmId::new("vm-1").unwrap(),
            4242,
            PathBuf::from("/run/vm-1/api.sock"),
        );
        assert_eq!(p.pid(), Some(4242));
        assert_eq!(p.socket_path(), Path::new("/run/vm-1/api.sock"));
        assert_eq!(p.phases().recorded_count(), 0);
        p.clear_pid();
        assert_eq!(p.pid(), None);
    }

    #[test]
    fn vm_process_exited_has_no_pid() {
        let p = VmProcess::exited(VmId::new("vm-1").unwrap(), PathBuf::from("/s"));
        assert_eq!(p.pid(), None);
    }

    #[test]
    fn launch_spec_serde_roundtrip() {
        let mut spec = LaunchSpec::new(
            VmId::new("vm-1").unwrap(),
            vec!["/usr/bin/firecracker".to_string()],
            PathBuf::from("/run/api.sock"),
        );
        spec.env.insert("FC_LOG".to_string(), "1".to_string());
        let json = serde_json::to_string(&spec).unwrap();
        let back: LaunchSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }
}
