//! The snapshot/restore protocol the demo drives "through the orchestrator"
//! (plan todo 28, requirements 2 and 3).
//!
//! The demo models the warm-function lifecycle as an ordered phase protocol:
//!
//! - **Cold path** (one-time, per function version):
//!   `spawn -> socket_ready -> configured -> guest_ready -> snapshot_ready -> request`.
//!   The snapshot is taken **after service readiness** (`guest_ready`), exactly
//!   as requirement 2 demands.
//! - **Warm path** (per pooled instance):
//!   `spawn -> socket_ready -> configured -> restore_ready -> request`.
//!   A pre-restored VM skips guest boot and reaches `restore_ready` directly.
//!
//! [`PhaseLog`] records the monotonic timestamp of each phase and enforces the
//! ordering invariant (strictly increasing phase rank, non-decreasing time). The
//! orchestrator seam is the [`VmRestorer`] trait: the deterministic
//! [`ScriptedRestorer`] drives tests with fixed phase timings, while a real
//! privileged backend (out of scope for this deterministic crate) would restore
//! through Firecracker and report [`LaneOutcome::Blocked`] when `/dev/kvm` or
//! the binary is absent.
//!
//! # Determinism
//! [`PhaseLog`] is pure given the supplied timestamps; [`ScriptedRestorer`]
//! builds phase logs from fixed millisecond steps, so every cold/warm timing is
//! reproducible with no clock, no VM, and no `/dev/kvm`.

use crate::function::{HttpFunction, HttpRequest, HttpResponse};
use async_trait::async_trait;
use microvm_artifacts::{compute_sha256, Digest};
use microvm_bench::{ns_to_ms, BlockedReason, LaneOutcome};
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Nanoseconds per millisecond (for building scripted phase timings).
const NS_PER_MS: f64 = 1_000_000.0;

/// Convert a millisecond count to whole nanoseconds.
fn ms_to_ns(ms: f64) -> u64 {
    (ms * NS_PER_MS).round() as u64
}

/// The ordered lifecycle phases a demo function instance passes through.
///
/// `SnapshotReady` (cold path) and `RestoreReady` (warm path) share a rank: a
/// valid timeline contains exactly one of them, never both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemoPhase {
    /// The VM process has been spawned.
    Spawn,
    /// The API socket accepts connections.
    SocketReady,
    /// Machine/kernel/rootfs configuration has been accepted.
    Configured,
    /// The guest HTTP service has signalled readiness (`GET /health` -> 200).
    GuestReady,
    /// A snapshot has been taken **after** service readiness (cold path).
    SnapshotReady,
    /// A pre-restored VM has reached readiness from a snapshot (warm path).
    RestoreReady,
    /// The first/served request has completed.
    Request,
}

impl DemoPhase {
    /// Stable `snake_case` token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::SocketReady => "socket_ready",
            Self::Configured => "configured",
            Self::GuestReady => "guest_ready",
            Self::SnapshotReady => "snapshot_ready",
            Self::RestoreReady => "restore_ready",
            Self::Request => "request",
        }
    }

    /// Ordering rank. `SnapshotReady` and `RestoreReady` share rank 4 (mutually
    /// exclusive branches); `Request` is always last.
    fn rank(self) -> u8 {
        match self {
            Self::Spawn => 0,
            Self::SocketReady => 1,
            Self::Configured => 2,
            Self::GuestReady => 3,
            Self::SnapshotReady | Self::RestoreReady => 4,
            Self::Request => 5,
        }
    }

    /// All phases, for exhaustive tests.
    pub fn all() -> &'static [DemoPhase] {
        &[
            Self::Spawn,
            Self::SocketReady,
            Self::Configured,
            Self::GuestReady,
            Self::SnapshotReady,
            Self::RestoreReady,
            Self::Request,
        ]
    }
}

impl std::fmt::Display for DemoPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An ordered, monotonic record of phase timestamps for one instance timeline.
///
/// Invariants enforced by [`PhaseLog::record`]:
/// 1. **Strictly increasing rank** — phases advance forward; `SnapshotReady` and
///    `RestoreReady` are mutually exclusive (same rank, so the second is
///    rejected), and a phase is never recorded twice.
/// 2. **Non-decreasing time** — a timestamp never precedes the previous one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseLog {
    entries: Vec<(DemoPhase, u64)>,
}

impl PhaseLog {
    /// An empty log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a phase at an explicit monotonic timestamp (pure).
    ///
    /// # Errors
    /// Returns [`ErrorCode::InternalError`] when the phase rank does not strictly
    /// exceed the previous phase's rank, or when `monotonic_ns` precedes the
    /// previous timestamp.
    pub fn record(&mut self, phase: DemoPhase, monotonic_ns: u64) -> Result<(), MicrovmError> {
        if let Some((prev_phase, prev_ns)) = self.entries.last() {
            if phase.rank() <= prev_phase.rank() {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    "demo phase recorded out of order",
                )
                .with_context("phase", phase.as_str())
                .with_context("prev_phase", prev_phase.as_str()));
            }
            if monotonic_ns < *prev_ns {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    "demo phase timestamps must be monotonic",
                )
                .with_context("phase", phase.as_str())
                .with_context("monotonic_ns", monotonic_ns.to_string())
                .with_context("prev_monotonic_ns", prev_ns.to_string()));
            }
        }
        self.entries.push((phase, monotonic_ns));
        Ok(())
    }

    /// Build a log from ordered `(phase, delta_ns)` pairs, accumulating absolute
    /// monotonic timestamps from `0`. Convenient for deterministic scripts.
    ///
    /// # Errors
    /// Propagates any [`PhaseLog::record`] ordering/monotonicity violation.
    pub fn from_deltas(deltas: &[(DemoPhase, u64)]) -> Result<Self, MicrovmError> {
        let mut log = Self::new();
        let mut abs = 0u64;
        for (phase, delta) in deltas {
            abs = abs.saturating_add(*delta);
            log.record(*phase, abs)?;
        }
        Ok(log)
    }

    /// The recorded `(phase, monotonic_ns)` entries in order.
    pub fn phases(&self) -> &[(DemoPhase, u64)] {
        &self.entries
    }

    /// The monotonic timestamp for `phase`, if recorded.
    pub fn get(&self, phase: DemoPhase) -> Option<u64> {
        self.entries
            .iter()
            .find(|(p, _)| *p == phase)
            .map(|(_, ns)| *ns)
    }

    /// True when `phase` has been recorded.
    pub fn contains(&self, phase: DemoPhase) -> bool {
        self.get(phase).is_some()
    }

    /// Duration in milliseconds between two phases, or `None` if either is
    /// absent. Always non-negative when present.
    pub fn duration_ms(&self, from: DemoPhase, to: DemoPhase) -> Option<f64> {
        let start = self.get(from)?;
        let end = self.get(to)?;
        Some(ns_to_ms(end.saturating_sub(start)))
    }

    /// Duration in milliseconds from `Spawn` to `phase`, or `None` if either is
    /// absent. This is a phase-to-phase span: it excludes the spawn stage's own
    /// duration (the time from process initiation to `Spawn`).
    pub fn spawn_to_ms(&self, phase: DemoPhase) -> Option<f64> {
        self.duration_ms(DemoPhase::Spawn, phase)
    }

    /// Elapsed milliseconds from process initiation (`t = 0`) to `phase`, or
    /// `None` when `phase` is absent. Phase timestamps are completion times
    /// measured from `t = 0`, so this is the natural "time since start" for a
    /// phase and is used for the demo's headline latencies (cold first call,
    /// warm restore-ready).
    pub fn elapsed_ms(&self, phase: DemoPhase) -> Option<f64> {
        self.get(phase).map(ns_to_ms)
    }

    /// Total span from first to last phase in milliseconds, or `None` when fewer
    /// than two phases are recorded.
    pub fn total_ms(&self) -> Option<f64> {
        if self.entries.len() < 2 {
            return None;
        }
        let start = self.entries.first().unwrap().1;
        let end = self.entries.last().unwrap().1;
        Some(ns_to_ms(end.saturating_sub(start)))
    }
}

/// A local, content-addressed snapshot artifact taken after service readiness.
///
/// The digest is the orchestrator's own content hash of the snapshot bytes
/// (derived here deterministically from the function rootfs hash plus a fixed
/// domain separator). It is local-only: no cross-host transfer, signing, or
/// encryption is implied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotArtifact {
    /// Name of the function this snapshot captures.
    pub function_name: String,
    /// SHA-256 of the snapshot content.
    pub sha256: Digest,
}

impl SnapshotArtifact {
    /// Derive the snapshot artifact for `function` deterministically.
    pub fn for_function(function: &HttpFunction) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"microvm-demo/snapshot/v1:");
        bytes.extend_from_slice(function.rootfs.sha256.as_bytes());
        let sha256 = compute_sha256(&bytes[..]).unwrap_or(function.rootfs.sha256);
        Self {
            function_name: function.name.clone(),
            sha256,
        }
    }
}

/// The result of a cold start: a snapshot taken after readiness, the full cold
/// phase log, and the cold first-call latency.
#[derive(Clone, Debug, PartialEq)]
pub struct ColdStart {
    /// The snapshot taken after service readiness.
    pub snapshot: SnapshotArtifact,
    /// Cold-path phase log (`spawn..snapshot_ready..request`).
    pub phases: PhaseLog,
    /// Cold first-call latency in milliseconds (`spawn -> request`).
    pub first_call_ms: f64,
}

/// The result of serving one request on a warm VM.
#[derive(Clone, Debug, PartialEq)]
pub struct Invocation {
    /// The function's response.
    pub response: HttpResponse,
    /// The warm request latency in milliseconds.
    pub request_ms: f64,
}

/// A pre-restored (warm) VM ready to serve requests.
#[derive(Clone, Debug)]
pub struct RestoredVm {
    function: HttpFunction,
    phases: PhaseLog,
    request_latency_ms: f64,
}

impl RestoredVm {
    /// Build a restored VM from its restore phase log and modeled request
    /// latency.
    pub fn new(function: HttpFunction, phases: PhaseLog, request_latency_ms: f64) -> Self {
        Self {
            function,
            phases,
            request_latency_ms,
        }
    }

    /// The function this VM serves.
    pub fn function(&self) -> &HttpFunction {
        &self.function
    }

    /// The warm-restore phase log (`spawn..restore_ready`).
    pub fn phases(&self) -> &PhaseLog {
        &self.phases
    }

    /// Elapsed milliseconds from process initiation to `restore_ready`, if
    /// recorded (the warm restore latency).
    pub fn restore_ready_ms(&self) -> Option<f64> {
        self.phases.elapsed_ms(DemoPhase::RestoreReady)
    }

    /// Serve one request, returning the response and the warm request latency.
    pub fn invoke(&self, req: &HttpRequest) -> Invocation {
        let response = self.function.handle(req);
        Invocation {
            response,
            request_ms: self.request_latency_ms,
        }
    }
}

/// The orchestrator restore seam the demo drives.
///
/// A restorer reports whether it can run ([`VmRestorer::probe`]), performs the
/// one-time cold start that snapshots after readiness
/// ([`VmRestorer::cold_start`]), and restores warm instances from that snapshot
/// ([`VmRestorer::restore`]). The deterministic [`ScriptedRestorer`] implements
/// this with fixed timings; a privileged Firecracker-backed restorer would
/// implement the same trait and report [`LaneOutcome::Blocked`] when `/dev/kvm`
/// or the binary is absent.
#[async_trait]
pub trait VmRestorer: Send + Sync {
    /// Stable restorer identifier.
    fn name(&self) -> String;

    /// Probe whether this restorer can run on the current host.
    ///
    /// Returns [`LaneOutcome::Completed`] when runnable, or
    /// [`LaneOutcome::Blocked`] with a stable [`BlockedReason`] when a
    /// prerequisite is missing. A probe never fabricates success.
    async fn probe(&self) -> LaneOutcome;

    /// Cold start: spawn, configure, wait for guest readiness, snapshot, and
    /// serve the first request.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InternalError`] (labelled `guest_readiness`) when the
    /// guest service never becomes ready, so no snapshot can be taken.
    async fn cold_start(&mut self, function: &HttpFunction) -> Result<ColdStart, MicrovmError>;

    /// Restore one warm VM from `snapshot`.
    ///
    /// # Errors
    /// Returns an error when the restore attempt fails; the caller records the
    /// failure and does not count it as a warm sample.
    async fn restore(&mut self, snapshot: &SnapshotArtifact) -> Result<RestoredVm, MicrovmError>;
}

/// One scripted warm-restore outcome: the per-phase step and the request
/// latency the restored VM will report.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScriptedRestore {
    /// Per-phase step in milliseconds for the restore timeline.
    pub step_ms: f64,
    /// The warm request latency in milliseconds the restored VM reports.
    pub request_ms: f64,
}

impl ScriptedRestore {
    /// Build a scripted restore.
    pub fn new(step_ms: f64, request_ms: f64) -> Self {
        Self {
            step_ms,
            request_ms,
        }
    }
}

/// A deterministic, scriptable [`VmRestorer`] for tests.
///
/// Configured with a probe outcome, cold-start behaviour, and a queue of restore
/// outcomes. Cold-start and restore timings are built from fixed millisecond
/// steps via [`PhaseLog::from_deltas`], so every measurement is reproducible with
/// no clock and no VM.
pub struct ScriptedRestorer {
    name: String,
    function: Option<HttpFunction>,
    probe: LaneOutcome,
    cold_start_ok: bool,
    cold_step_ms: f64,
    cold_request_ms: f64,
    restore_script: VecDeque<Result<ScriptedRestore, String>>,
}

impl ScriptedRestorer {
    /// A restorer that probes `Completed`, cold-starts successfully, and yields
    /// the given restore outcomes (in order).
    pub fn ok(
        name: impl Into<String>,
        cold_step_ms: f64,
        cold_request_ms: f64,
        restores: Vec<Result<ScriptedRestore, String>>,
    ) -> Self {
        Self {
            name: name.into(),
            function: None,
            probe: LaneOutcome::Completed,
            cold_start_ok: true,
            cold_step_ms,
            cold_request_ms,
            restore_script: restores.into(),
        }
    }

    /// A restorer whose probe is blocked with `reason`.
    pub fn blocked(
        name: impl Into<String>,
        reason: BlockedReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            function: None,
            probe: LaneOutcome::blocked(reason, detail),
            cold_start_ok: false,
            cold_step_ms: 0.0,
            cold_request_ms: 0.0,
            restore_script: VecDeque::new(),
        }
    }

    /// A restorer whose guest service never becomes ready: cold start fails and
    /// every restore fails, so no snapshot exists and no request is ever warm.
    pub fn guest_never_ready(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            function: None,
            probe: LaneOutcome::Completed,
            cold_start_ok: false,
            cold_step_ms: 1.0,
            cold_request_ms: 1.0,
            restore_script: VecDeque::new(),
        }
    }

    fn cold_timeline(&self, function: &HttpFunction) -> Result<ColdStart, MicrovmError> {
        let step = ms_to_ns(self.cold_step_ms);
        let req = ms_to_ns(self.cold_request_ms);
        let phases = PhaseLog::from_deltas(&[
            (DemoPhase::Spawn, step),
            (DemoPhase::SocketReady, step),
            (DemoPhase::Configured, step),
            (DemoPhase::GuestReady, step),
            (DemoPhase::SnapshotReady, step),
            (DemoPhase::Request, req),
        ])?;
        let first_call_ms = phases.elapsed_ms(DemoPhase::Request).unwrap_or(0.0);
        Ok(ColdStart {
            snapshot: SnapshotArtifact::for_function(function),
            phases,
            first_call_ms,
        })
    }

    fn warm_timeline(
        &self,
        function: &HttpFunction,
        r: ScriptedRestore,
    ) -> Result<RestoredVm, MicrovmError> {
        let step = ms_to_ns(r.step_ms);
        let phases = PhaseLog::from_deltas(&[
            (DemoPhase::Spawn, step),
            (DemoPhase::SocketReady, step),
            (DemoPhase::Configured, step),
            (DemoPhase::RestoreReady, step),
        ])?;
        Ok(RestoredVm::new(function.clone(), phases, r.request_ms))
    }
}

#[async_trait]
impl VmRestorer for ScriptedRestorer {
    fn name(&self) -> String {
        self.name.clone()
    }

    async fn probe(&self) -> LaneOutcome {
        self.probe.clone()
    }

    async fn cold_start(&mut self, function: &HttpFunction) -> Result<ColdStart, MicrovmError> {
        self.function = Some(function.clone());
        if !self.cold_start_ok {
            return Err(MicrovmError::new(
                ErrorCode::InternalError,
                "guest service never became ready",
            )
            .with_context("stage", "guest_readiness")
            .with_context("function", function.name.clone()));
        }
        self.cold_timeline(function)
    }

    async fn restore(&mut self, snapshot: &SnapshotArtifact) -> Result<RestoredVm, MicrovmError> {
        let function = self.function.clone().ok_or_else(|| {
            MicrovmError::new(
                ErrorCode::InvalidTransition,
                "restore attempted before cold start established a snapshot",
            )
            .with_context("snapshot", snapshot.sha256.to_hex())
        })?;
        match self.restore_script.pop_front() {
            Some(Ok(r)) => self.warm_timeline(&function, r),
            Some(Err(detail)) => Err(MicrovmError::new(
                ErrorCode::InternalError,
                "scripted restore failed",
            )
            .with_context("detail", detail)),
            None => Err(MicrovmError::new(
                ErrorCode::InternalError,
                "scripted restore outcomes exhausted",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::Rootfs;

    fn function() -> HttpFunction {
        let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
        HttpFunction::new("hello-http", rootfs).unwrap()
    }

    #[test]
    fn phase_ranks_order_the_timeline() {
        assert!(DemoPhase::Spawn.rank() < DemoPhase::SocketReady.rank());
        assert!(DemoPhase::GuestReady.rank() < DemoPhase::SnapshotReady.rank());
        assert_eq!(
            DemoPhase::SnapshotReady.rank(),
            DemoPhase::RestoreReady.rank()
        );
        assert!(DemoPhase::RestoreReady.rank() < DemoPhase::Request.rank());
    }

    #[test]
    fn phase_tokens_are_stable() {
        assert_eq!(DemoPhase::Spawn.as_str(), "spawn");
        assert_eq!(DemoPhase::SocketReady.as_str(), "socket_ready");
        assert_eq!(DemoPhase::Configured.as_str(), "configured");
        assert_eq!(DemoPhase::GuestReady.as_str(), "guest_ready");
        assert_eq!(DemoPhase::SnapshotReady.as_str(), "snapshot_ready");
        assert_eq!(DemoPhase::RestoreReady.as_str(), "restore_ready");
        assert_eq!(DemoPhase::Request.as_str(), "request");
        assert_eq!(DemoPhase::all().len(), 7);
    }

    #[test]
    fn cold_timeline_records_all_cold_phases() {
        let log = PhaseLog::from_deltas(&[
            (DemoPhase::Spawn, 1_000_000),
            (DemoPhase::SocketReady, 1_000_000),
            (DemoPhase::Configured, 1_000_000),
            (DemoPhase::GuestReady, 1_000_000),
            (DemoPhase::SnapshotReady, 1_000_000),
            (DemoPhase::Request, 2_000_000),
        ])
        .unwrap();
        for p in [
            DemoPhase::Spawn,
            DemoPhase::SocketReady,
            DemoPhase::Configured,
            DemoPhase::GuestReady,
            DemoPhase::SnapshotReady,
            DemoPhase::Request,
        ] {
            assert!(log.contains(p), "missing {p}");
        }
        assert!(!log.contains(DemoPhase::RestoreReady));
        // Timestamps are completion times from t=0: Spawn@1ms .. Request@7ms.
        assert_eq!(log.elapsed_ms(DemoPhase::Request), Some(7.0));
        assert_eq!(log.elapsed_ms(DemoPhase::GuestReady), Some(4.0));
        // Phase-to-phase span excludes the spawn stage's own duration.
        assert_eq!(log.spawn_to_ms(DemoPhase::Request), Some(6.0));
        assert_eq!(
            log.duration_ms(DemoPhase::Spawn, DemoPhase::GuestReady),
            Some(3.0)
        );
    }

    #[test]
    fn warm_timeline_skips_guest_boot() {
        let log = PhaseLog::from_deltas(&[
            (DemoPhase::Spawn, 500_000),
            (DemoPhase::SocketReady, 500_000),
            (DemoPhase::Configured, 500_000),
            (DemoPhase::RestoreReady, 500_000),
        ])
        .unwrap();
        assert!(log.contains(DemoPhase::RestoreReady));
        assert!(!log.contains(DemoPhase::GuestReady));
        assert!(!log.contains(DemoPhase::SnapshotReady));
        // RestoreReady completes at t=2ms from process initiation.
        assert_eq!(log.elapsed_ms(DemoPhase::RestoreReady), Some(2.0));
    }

    #[test]
    fn out_of_order_phase_is_rejected() {
        let mut log = PhaseLog::new();
        log.record(DemoPhase::Spawn, 1).unwrap();
        log.record(DemoPhase::GuestReady, 2).unwrap();
        // Configured (rank 2) after GuestReady (rank 3) is out of order.
        assert!(log.record(DemoPhase::Configured, 3).is_err());
    }

    #[test]
    fn snapshot_and_restore_are_mutually_exclusive() {
        let mut log = PhaseLog::new();
        log.record(DemoPhase::Spawn, 1).unwrap();
        log.record(DemoPhase::SnapshotReady, 2).unwrap();
        // RestoreReady shares SnapshotReady's rank, so it is rejected.
        assert!(log.record(DemoPhase::RestoreReady, 3).is_err());
    }

    #[test]
    fn duplicate_phase_is_rejected() {
        let mut log = PhaseLog::new();
        log.record(DemoPhase::Spawn, 1).unwrap();
        assert!(log.record(DemoPhase::Spawn, 2).is_err());
    }

    #[test]
    fn backwards_timestamp_is_rejected() {
        let mut log = PhaseLog::new();
        log.record(DemoPhase::Spawn, 10).unwrap();
        assert!(log.record(DemoPhase::SocketReady, 5).is_err());
    }

    #[test]
    fn snapshot_artifact_is_deterministic_and_pinned() {
        let f = function();
        let a = SnapshotArtifact::for_function(&f);
        let b = SnapshotArtifact::for_function(&f);
        assert_eq!(a, b);
        assert_eq!(a.function_name, "hello-http");
        // The snapshot hash differs from the raw rootfs hash (domain-separated).
        assert_ne!(a.sha256, f.rootfs.sha256);
    }

    #[tokio::test]
    async fn scripted_cold_start_snapshots_after_readiness() {
        let mut r = ScriptedRestorer::ok("scripted", 2.0, 3.0, vec![]);
        let cs = r.cold_start(&function()).await.unwrap();
        // Snapshot phase is recorded after guest readiness and before request.
        let guest = cs.phases.get(DemoPhase::GuestReady).unwrap();
        let snap = cs.phases.get(DemoPhase::SnapshotReady).unwrap();
        let req = cs.phases.get(DemoPhase::Request).unwrap();
        assert!(guest < snap && snap < req);
        // 5 steps of 2ms + one 3ms request = 13ms cold first call.
        assert_eq!(cs.first_call_ms, 13.0);
    }

    #[tokio::test]
    async fn scripted_restore_builds_a_warm_vm() {
        let mut r = ScriptedRestorer::ok(
            "scripted",
            1.0,
            1.0,
            vec![Ok(ScriptedRestore::new(1.0, 0.5))],
        );
        let cs = r.cold_start(&function()).await.unwrap();
        let vm = r.restore(&cs.snapshot).await.unwrap();
        assert_eq!(vm.restore_ready_ms(), Some(4.0));
        let inv = vm.invoke(&HttpRequest::invoke());
        assert!(inv.response.is_success());
        assert_eq!(inv.request_ms, 0.5);
    }

    #[tokio::test]
    async fn guest_never_ready_fails_cold_start() {
        let mut r = ScriptedRestorer::guest_never_ready("scripted");
        let err = r.cold_start(&function()).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("stage").map(String::as_str),
            Some("guest_readiness")
        );
    }

    #[tokio::test]
    async fn restore_before_cold_start_is_rejected() {
        let mut r = ScriptedRestorer::ok("scripted", 1.0, 1.0, vec![]);
        let snap = SnapshotArtifact::for_function(&function());
        let err = r.restore(&snap).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidTransition);
    }

    #[tokio::test]
    async fn exhausted_restore_script_fails() {
        let mut r = ScriptedRestorer::ok("scripted", 1.0, 1.0, vec![]);
        let cs = r.cold_start(&function()).await.unwrap();
        let err = r.restore(&cs.snapshot).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
    }

    #[tokio::test]
    async fn blocked_probe_is_reported() {
        let r = ScriptedRestorer::blocked("scripted", BlockedReason::KvmUnavailable, "no /dev/kvm");
        let outcome = r.probe().await;
        assert!(outcome.is_blocked());
        assert_eq!(
            outcome.blocked_reason(),
            Some(BlockedReason::KvmUnavailable)
        );
    }
}
