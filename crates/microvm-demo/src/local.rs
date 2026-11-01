//! An in-process [`VmRestorer`] that models the warm-function protocol locally
//! (plan todo 28).
//!
//! [`LocalFunctionRestorer`] drives the same snapshot/restore protocol the
//! privileged Firecracker backend would, but entirely in-process: it exercises
//! the real [`HttpFunction`] handler for guest-readiness and request handling and
//! records real host-monotonic timestamps via [`SystemClock`]. This lets the
//! `microvm-demo` binary produce a concrete cold/warm report on any host, with no
//! `/dev/kvm`, no Firecracker, and no network.
//!
//! # Honesty boundary
//! This restorer is a *model*, not a Firecracker restore. It measures the
//! function-handling path in-process; it does not measure real VM boot or
//! snapshot-restore latency. A privileged Firecracker-backed restorer (out of
//! scope for this deterministic crate) would implement the same [`VmRestorer`]
//! trait and report [`LaneOutcome::Blocked`] when `/dev/kvm` or the binary is
//! absent. The deterministic test suite uses [`ScriptedRestorer`] instead.

use crate::function::{HttpFunction, HttpRequest};
use crate::restore::{ColdStart, DemoPhase, PhaseLog, RestoredVm, SnapshotArtifact, VmRestorer};
use async_trait::async_trait;
use microvm_bench::{ns_to_ms, LaneOutcome};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_metrics::{Clock, SystemClock};

/// An in-process restorer that models the warm-function protocol with real
/// monotonic timing.
#[derive(Debug)]
pub struct LocalFunctionRestorer {
    name: String,
    clock: SystemClock,
    function: Option<HttpFunction>,
}

impl LocalFunctionRestorer {
    /// Build a local in-process restorer.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            clock: SystemClock::new(),
            function: None,
        }
    }

    /// Measure one function invocation in milliseconds using the monotonic clock.
    fn measure_request(&self, function: &HttpFunction) -> f64 {
        let req = HttpRequest::invoke();
        let start = self.clock.now_monotonic_ns();
        let _ = function.handle(&req);
        let end = self.clock.now_monotonic_ns();
        ns_to_ms(end.saturating_sub(start))
    }
}

impl Default for LocalFunctionRestorer {
    fn default() -> Self {
        Self::new("local-in-process")
    }
}

#[async_trait]
impl VmRestorer for LocalFunctionRestorer {
    fn name(&self) -> String {
        self.name.clone()
    }

    async fn probe(&self) -> LaneOutcome {
        // The in-process model has no external prerequisite; it always runs.
        LaneOutcome::Completed
    }

    async fn cold_start(&mut self, function: &HttpFunction) -> Result<ColdStart, MicrovmError> {
        self.function = Some(function.clone());
        let mut phases = PhaseLog::new();
        phases.record(DemoPhase::Spawn, self.clock.now_monotonic_ns())?;
        phases.record(DemoPhase::SocketReady, self.clock.now_monotonic_ns())?;
        phases.record(DemoPhase::Configured, self.clock.now_monotonic_ns())?;

        // Guest readiness: actually probe the handler (GET /health -> 200).
        let health = HttpRequest::health();
        let ready = function.handle(&health);
        if !function.is_ready(&health, &ready) {
            return Err(MicrovmError::new(
                ErrorCode::InternalError,
                "guest service never became ready",
            )
            .with_context("stage", "guest_readiness")
            .with_context("function", function.name.clone()));
        }
        phases.record(DemoPhase::GuestReady, self.clock.now_monotonic_ns())?;

        // Snapshot AFTER service readiness.
        let snapshot = SnapshotArtifact::for_function(function);
        phases.record(DemoPhase::SnapshotReady, self.clock.now_monotonic_ns())?;

        // First request (the cold first call).
        let _ = function.handle(&HttpRequest::invoke());
        phases.record(DemoPhase::Request, self.clock.now_monotonic_ns())?;

        let first_call_ms = phases.total_ms().unwrap_or(0.0);
        Ok(ColdStart {
            snapshot,
            phases,
            first_call_ms,
        })
    }

    async fn restore(&mut self, snapshot: &SnapshotArtifact) -> Result<RestoredVm, MicrovmError> {
        let function = self.function.clone().ok_or_else(|| {
            MicrovmError::new(
                ErrorCode::InvalidTransition,
                "restore attempted before cold start established a snapshot",
            )
            .with_context("snapshot", snapshot.sha256.to_hex())
        })?;
        let mut phases = PhaseLog::new();
        phases.record(DemoPhase::Spawn, self.clock.now_monotonic_ns())?;
        phases.record(DemoPhase::SocketReady, self.clock.now_monotonic_ns())?;
        phases.record(DemoPhase::Configured, self.clock.now_monotonic_ns())?;
        phases.record(DemoPhase::RestoreReady, self.clock.now_monotonic_ns())?;
        let request_latency_ms = self.measure_request(&function);
        Ok(RestoredVm::new(function, phases, request_latency_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::Rootfs;
    use microvm_artifacts::Digest;

    fn function() -> HttpFunction {
        let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
        HttpFunction::new("hello-http", rootfs).unwrap()
    }

    #[tokio::test]
    async fn local_cold_start_snapshots_after_readiness() {
        let mut r = LocalFunctionRestorer::new("local");
        assert!(r.probe().await.is_completed());
        let cs = r.cold_start(&function()).await.unwrap();
        let guest = cs.phases.get(DemoPhase::GuestReady).unwrap();
        let snap = cs.phases.get(DemoPhase::SnapshotReady).unwrap();
        assert!(guest <= snap);
        assert!(cs.first_call_ms >= 0.0);
    }

    #[tokio::test]
    async fn local_restore_serves_a_warm_request() {
        let mut r = LocalFunctionRestorer::new("local");
        let cs = r.cold_start(&function()).await.unwrap();
        let vm = r.restore(&cs.snapshot).await.unwrap();
        let inv = vm.invoke(&HttpRequest::invoke());
        assert!(inv.response.is_success());
        assert!(inv.request_ms >= 0.0);
        assert!(vm.restore_ready_ms().is_some());
    }

    #[tokio::test]
    async fn local_restore_before_cold_start_is_rejected() {
        let mut r = LocalFunctionRestorer::new("local");
        let snap = SnapshotArtifact::for_function(&function());
        assert!(r.restore(&snap).await.is_err());
    }
}
