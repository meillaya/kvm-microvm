//! The Docker comparison lane.
//!
//! Measures the pinned payload under Docker Engine so the harness can publish a
//! Firecracker-vs-Docker distribution for identical artifact content
//!. The lane is blocked with [`BlockedReason::DockerMissing`]
//! when the `docker` binary or daemon is unavailable: it never fabricates
//! samples.
//!
//! The measured quantity is the wall-time (host-monotonic) to run the pinned
//! image to completion via `docker run --rm <image>`. Cold samples drop the
//! page cache first; warm samples reuse it.

use crate::host::{docker_lane_block, drop_page_cache};
use crate::outcome::LaneOutcome;
use crate::result::Unit;
use crate::runner::{LaneRunner, SampleCondition};
use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

/// Default reference target for Docker cold start (metadata only, never a gate).
pub const DOCKER_START_TARGET_MS: f64 = 800.0;

/// A Docker `docker run --rm` lane for the pinned payload image.
pub struct DockerStartLane {
    name: String,
    target_ms: f64,
    /// Pinned image reference (by digest) derived from the shared payload hash.
    image: String,
    /// procfs root used for page-cache drops.
    proc_root: PathBuf,
}

impl DockerStartLane {
    /// Build a lane that runs `image` (which must be built from the same pinned
    /// payload as the VM rootfs).
    pub fn new(image: impl Into<String>, proc_root: PathBuf) -> Self {
        Self {
            name: "docker_start_cold".to_string(),
            target_ms: DOCKER_START_TARGET_MS,
            image: image.into(),
            proc_root,
        }
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
}

#[async_trait]
impl LaneRunner for DockerStartLane {
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
        match docker_lane_block() {
            Some(reason) => LaneOutcome::blocked(
                reason,
                format!(
                    "docker binary or daemon unavailable for image {}",
                    self.image
                ),
            ),
            None => LaneOutcome::Completed,
        }
    }

    async fn prepare(&mut self, condition: SampleCondition) -> Result<(), MicrovmError> {
        match condition {
            SampleCondition::Cold => drop_page_cache(&self.proc_root),
            SampleCondition::Warm => Ok(()),
        }
    }

    async fn run_sample(&mut self, _condition: SampleCondition) -> Result<f64, MicrovmError> {
        let image = self.image.clone();
        // Run the blocking `docker run` off the async runtime so it does not
        // stall other lanes, and time it with a host-monotonic clock.
        let result = tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let output = Command::new("docker")
                .args(["run", "--rm", &image])
                .output()
                .map_err(|e| {
                    MicrovmError::new(ErrorCode::ProcessSpawnError, "failed to invoke docker")
                        .with_context("io", e.to_string())
                })?;
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            if !output.status.success() {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    "docker run exited non-zero",
                )
                .with_context("status", output.status.to_string())
                .with_context(
                    "stderr",
                    String::from_utf8_lossy(&output.stderr).trim().to_string(),
                ));
            }
            Ok(elapsed_ms)
        })
        .await
        .map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "docker sample task panicked")
                .with_context("join", e.to_string())
        })?;
        result
    }
}
