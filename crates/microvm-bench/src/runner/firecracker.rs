//! The Firecracker snapshot/restore benchmark lane.
//!
//! Measures the host-monotonic time to restore a prepared snapshot into a
//! fresh Firecracker process: spawn → API-socket-ready → `PUT /snapshot/load`
//! → `PATCH /vm {"state":"Resumed"}`. This is the snapshot/restore distribution
//! the harness measures, timed with a monotonic clock and compared
//! against the Docker lane running the same pinned payload (the contract,
//! 7, 9).
//!
//! The lane reuses [`microvm_firecracker`] for process launch and the snapshot
//! protocol (which already encodes the load-before-config and explicit-resume
//! contract). It is blocked with evidence when `/dev/kvm`, the `firecracker`
//! binary, or the prepared snapshot artifacts are unavailable, and never
//! fabricates samples.
//!
//! Per the Firecracker snapshot docs, there is no universal restore-latency
//! SLA; [`SNAPSHOT_RESTORE_TARGET_MS`] is a reference target recorded as
//! metadata only, never a pass/fail gate.

use crate::host::{drop_page_cache, firecracker_lane_block, HostProbe};
use crate::outcome::{BlockedReason, LaneOutcome};
use crate::result::Unit;
use crate::runner::{LaneRunner, SampleCondition};
use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_firecracker::{
    LaunchSpec, MemBackend, ProcessLauncher, SnapshotApi, SnapshotLoadParams, TokioLauncher,
    UdsSnapshotApi, VmState,
};
use microvm_types::VmId;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Reference restore-latency target in ms (metadata only; never a gate).
///
/// Mirrors the harness's documented `<200 ms` reference. Firecracker publishes no
/// universal SLA, so this is recorded in `target_ms` for reviewer context.
pub const SNAPSHOT_RESTORE_TARGET_MS: f64 = 200.0;

/// Timeout for waiting on the Firecracker API socket per sample.
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for the API socket.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// A Firecracker snapshot/restore benchmark lane.
pub struct FirecrackerSnapshotLane {
    name: String,
    target_ms: f64,
    firecracker_bin: String,
    /// Prepared microVM state file to load.
    snapshot_path: PathBuf,
    /// Prepared guest memory file (the `mem_backend` source).
    memfile_path: PathBuf,
    /// Directory for per-sample API sockets.
    socket_dir: PathBuf,
    probe: HostProbe,
    launcher: TokioLauncher,
    counter: AtomicU64,
}

impl FirecrackerSnapshotLane {
    /// Build a lane that restores `snapshot_path` + `memfile_path`, creating
    /// per-sample sockets under `socket_dir`.
    pub fn new(
        snapshot_path: PathBuf,
        memfile_path: PathBuf,
        socket_dir: PathBuf,
        probe: HostProbe,
    ) -> Self {
        Self {
            name: "snapshot_restore".to_string(),
            target_ms: SNAPSHOT_RESTORE_TARGET_MS,
            firecracker_bin: "firecracker".to_string(),
            snapshot_path,
            memfile_path,
            socket_dir,
            probe,
            launcher: TokioLauncher::new(),
            counter: AtomicU64::new(0),
        }
    }

    /// Override the firecracker binary path/name.
    #[must_use]
    pub fn with_firecracker_bin(mut self, bin: impl Into<String>) -> Self {
        self.firecracker_bin = bin.into();
        self
    }

    /// Override the benchmark name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Override the target (metadata).
    #[must_use]
    pub fn with_target_ms(mut self, target_ms: f64) -> Self {
        self.target_ms = target_ms;
        self
    }

    /// Restore once and return the monotonic spawn→resumed duration in ms.
    async fn restore_once(&self) -> Result<f64, MicrovmError> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let vm_id = VmId::new(format!("bench-{}", n)).map_err(|e| {
            MicrovmError::new(ErrorCode::InvalidId, "benchmark vm id rejected")
                .with_context("reason", e.to_string())
        })?;
        let socket_path = self.socket_dir.join(format!("{}.sock", vm_id.as_str()));
        // Ensure the socket directory exists.
        std::fs::create_dir_all(&self.socket_dir).map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "cannot create socket dir")
                .with_context("io", e.to_string())
        })?;

        let argv = vec![
            self.firecracker_bin.clone(),
            "--api-sock".to_string(),
            socket_path.display().to_string(),
        ];
        let spec = LaunchSpec::new(vm_id.clone(), argv, socket_path.clone());

        let start = Instant::now();
        let pid = self.launcher.spawn(&spec).await?;
        let result = self.drive_restore(&socket_path).await;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Always clean up the child and socket, regardless of outcome.
        let _ = self.launcher.kill(pid).await;
        let _ = std::fs::remove_file(&socket_path);

        result.map(|()| elapsed_ms)
    }

    /// Wait for the socket, load the snapshot, and resume.
    async fn drive_restore(&self, socket_path: &Path) -> Result<(), MicrovmError> {
        wait_for_socket(socket_path, SOCKET_READY_TIMEOUT).await?;
        let api = UdsSnapshotApi::new(socket_path.to_path_buf());
        let params = SnapshotLoadParams {
            snapshot_path: self.snapshot_path.display().to_string(),
            mem_backend: MemBackend::file(self.memfile_path.display().to_string()),
            enable_diff_snapshots: false,
            resume_vm: false,
        };
        api.put_snapshot_load(&params).await?;
        api.patch_vm(VmState::Resumed).await?;
        Ok(())
    }
}

/// Poll until the API socket path exists or `timeout` elapses.
async fn wait_for_socket(socket_path: &Path, timeout: Duration) -> Result<(), MicrovmError> {
    let start = Instant::now();
    loop {
        if socket_path.exists() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(MicrovmError::new(
                ErrorCode::TransportError,
                "timed out waiting for firecracker API socket",
            )
            .with_context("path", socket_path.display().to_string()));
        }
        tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
    }
}

#[async_trait]
impl LaneRunner for FirecrackerSnapshotLane {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn target_ms(&self) -> f64 {
        self.target_ms
    }

    fn unit(&self) -> Unit {
        Unit::Ms
    }

    async fn probe(&self) -> LaneOutcome {
        if let Some(reason) = firecracker_lane_block(&self.probe) {
            return LaneOutcome::blocked(
                reason,
                format!(
                    "firecracker lane prerequisite missing (kvm_device={})",
                    self.probe.kvm_device.display()
                ),
            );
        }
        if !self.snapshot_path.is_file() || !self.memfile_path.is_file() {
            return LaneOutcome::blocked(
                BlockedReason::ArtifactMissing,
                format!(
                    "prepared snapshot artifacts missing (snapshot={}, memfile={})",
                    self.snapshot_path.display(),
                    self.memfile_path.display()
                ),
            );
        }
        LaneOutcome::Completed
    }

    async fn prepare(&mut self, condition: SampleCondition) -> Result<(), MicrovmError> {
        match condition {
            SampleCondition::Cold => drop_page_cache(&self.probe.proc_root),
            SampleCondition::Warm => Ok(()),
        }
    }

    async fn run_sample(&mut self, _condition: SampleCondition) -> Result<f64, MicrovmError> {
        self.restore_once().await
    }
}
