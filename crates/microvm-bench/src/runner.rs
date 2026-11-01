//! The [`LaneRunner`] abstraction: one benchmark lane (e.g. Firecracker
//! snapshot/restore, Docker start) that the [`crate::marker::BenchMarker`]
//! drives.
//!
//! A lane reports a stable name, a target (metadata, never a pass
//! threshold), a probe outcome (ran vs blocked-with-evidence), and produces
//! per-sample monotonic durations under cold and warm conditions. Sample
//! failures are returned as `Err` so the marker can record them without counting
//! them (requirement 6).
//!
//! The deterministic test suite uses [`ScriptedLane`]; the real Firecracker and
//! Docker lanes live in [`crate::runner`] submodules and are exercised only on
//! privileged hosts.

pub mod docker;
pub mod firecracker;

use crate::outcome::{BlockedReason, LaneOutcome};
use crate::result::Unit;
use async_trait::async_trait;
use microvm_errors::MicrovmError;
use std::collections::VecDeque;

/// The page-cache condition a sample is measured under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleCondition {
    /// Caches dropped before the sample (cold start).
    Cold,
    /// Caches primed and reused (warm start).
    Warm,
}

impl SampleCondition {
    /// Stable token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
        }
    }
}

/// A single benchmark lane the marker can drive.
#[async_trait]
pub trait LaneRunner: Send + Sync {
    /// Stable benchmark identifier (e.g. `snapshot_restore`, `docker_start_cold`).
    fn name(&self) -> String;

    /// Reference target in `unit()`. Metadata only; never a pass threshold.
    fn target_ms(&self) -> f64;

    /// Unit of the produced samples. Defaults to milliseconds.
    fn unit(&self) -> Unit {
        Unit::Ms
    }

    /// Probe whether this lane can run on the current host.
    ///
    /// Returns [`LaneOutcome::Completed`] when the lane is runnable, or
    /// [`LaneOutcome::Blocked`] with a stable [`BlockedReason`] and evidence when
    /// a prerequisite (KVM, Docker daemon, firecracker binary, …) is missing. A
    /// probe never fabricates success: if it cannot verify the prerequisite, it
    /// blocks.
    async fn probe(&self) -> LaneOutcome;

    /// Prepare the page-cache condition before sampling (e.g. drop caches for
    /// [`SampleCondition::Cold`], prime for [`SampleCondition::Warm`]).
    ///
    /// # Errors
    /// Returns an error when the condition cannot be established honestly (e.g.
    /// `drop_caches` is not permitted). The marker then records zero samples for
    /// that condition rather than measuring under the wrong cache state.
    async fn prepare(&mut self, condition: SampleCondition) -> Result<(), MicrovmError>;

    /// Run one sample and return the measured duration in `unit()`.
    ///
    /// # Errors
    /// Returns an error when the sample attempt fails; the marker records the
    /// failure and does not count it as a sample.
    async fn run_sample(&mut self, condition: SampleCondition) -> Result<f64, MicrovmError>;
}

/// A deterministic, scriptable lane for tests.
///
/// Configured with a probe outcome and a fixed queue of sample results per
/// condition. `run_sample` pops the next scripted result; an empty queue yields
/// a sample failure so a test can model exhaustion deterministically.
pub struct ScriptedLane {
    name: String,
    target_ms: f64,
    unit: Unit,
    probe_outcome: LaneOutcome,
    prepare_ok: bool,
    cold: VecDeque<Result<f64, String>>,
    warm: VecDeque<Result<f64, String>>,
}

impl ScriptedLane {
    /// Build a lane that probes `Completed` and yields the given cold/warm
    /// sample sequences (each `Ok(ms)` is a measured sample, `Err` a failure).
    pub fn new(
        name: impl Into<String>,
        target_ms: f64,
        cold: Vec<Result<f64, String>>,
        warm: Vec<Result<f64, String>>,
    ) -> Self {
        Self {
            name: name.into(),
            target_ms,
            unit: Unit::Ms,
            probe_outcome: LaneOutcome::Completed,
            prepare_ok: true,
            cold: cold.into(),
            warm: warm.into(),
        }
    }

    /// Build a lane whose probe is blocked with `reason`.
    pub fn blocked(
        name: impl Into<String>,
        target_ms: f64,
        reason: BlockedReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            target_ms,
            unit: Unit::Ms,
            probe_outcome: LaneOutcome::blocked(reason, detail),
            prepare_ok: true,
            cold: VecDeque::new(),
            warm: VecDeque::new(),
        }
    }

    /// Make `prepare` fail (models an unsupported page-cache condition).
    #[must_use]
    pub fn with_prepare_failure(mut self) -> Self {
        self.prepare_ok = false;
        self
    }

    /// Override the unit.
    #[must_use]
    pub fn with_unit(mut self, unit: Unit) -> Self {
        self.unit = unit;
        self
    }
}

#[async_trait]
impl LaneRunner for ScriptedLane {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn target_ms(&self) -> f64 {
        self.target_ms
    }

    fn unit(&self) -> Unit {
        self.unit
    }

    async fn probe(&self) -> LaneOutcome {
        self.probe_outcome.clone()
    }

    async fn prepare(&mut self, _condition: SampleCondition) -> Result<(), MicrovmError> {
        if self.prepare_ok {
            Ok(())
        } else {
            Err(microvm_errors::MicrovmError::new(
                microvm_errors::ErrorCode::InternalError,
                "page-cache condition unsupported",
            ))
        }
    }

    async fn run_sample(&mut self, condition: SampleCondition) -> Result<f64, MicrovmError> {
        let queue = match condition {
            SampleCondition::Cold => &mut self.cold,
            SampleCondition::Warm => &mut self.warm,
        };
        match queue.pop_front() {
            Some(Ok(ms)) => Ok(ms),
            Some(Err(detail)) => Err(microvm_errors::MicrovmError::new(
                microvm_errors::ErrorCode::InternalError,
                "scripted sample failure",
            )
            .with_context("detail", detail)),
            None => Err(microvm_errors::MicrovmError::new(
                microvm_errors::ErrorCode::InternalError,
                "scripted sample queue exhausted",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_condition_tokens() {
        assert_eq!(SampleCondition::Cold.as_str(), "cold");
        assert_eq!(SampleCondition::Warm.as_str(), "warm");
    }

    #[tokio::test]
    async fn scripted_lane_yields_scripted_samples() {
        let mut lane = ScriptedLane::new(
            "snapshot_restore",
            30.0,
            vec![Ok(150.0), Ok(160.0)],
            vec![Ok(14.0), Err("boom".into())],
        );
        assert!(lane.probe().await.is_completed());
        lane.prepare(SampleCondition::Cold).await.unwrap();
        assert_eq!(lane.run_sample(SampleCondition::Cold).await.unwrap(), 150.0);
        assert_eq!(lane.run_sample(SampleCondition::Cold).await.unwrap(), 160.0);
        // Warm: first ok, second is a scripted failure.
        assert_eq!(lane.run_sample(SampleCondition::Warm).await.unwrap(), 14.0);
        assert!(lane.run_sample(SampleCondition::Warm).await.is_err());
        // Exhausted queue is a failure, not a panic.
        assert!(lane.run_sample(SampleCondition::Cold).await.is_err());
    }

    #[tokio::test]
    async fn scripted_blocked_lane_probes_blocked() {
        let lane = ScriptedLane::blocked(
            "docker_start_cold",
            800.0,
            BlockedReason::DockerMissing,
            "daemon down",
        );
        let outcome = lane.probe().await;
        assert!(outcome.is_blocked());
        assert_eq!(outcome.blocked_reason(), Some(BlockedReason::DockerMissing));
    }

    #[tokio::test]
    async fn prepare_failure_is_surfaced() {
        let mut lane = ScriptedLane::new("x", 1.0, vec![], vec![]).with_prepare_failure();
        assert!(lane.prepare(SampleCondition::Cold).await.is_err());
    }
}
