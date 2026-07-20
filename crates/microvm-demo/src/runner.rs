//! The [`DemoRunner`]: orchestrates the warm HTTP-function demo with blocked /
//! completed outcomes (plan todo 28).
//!
//! For one run the runner:
//! 1. **Probes** the restorer. A blocked probe yields a blocked report (null cold
//!    call, empty warm distribution, recorded reason) — samples are never
//!    fabricated.
//! 2. **Cold-starts** the function: spawn → readiness → snapshot → first request,
//!    recording the cold first-call latency and phase durations.
//! 3. **Fills the warm pool** by restoring through the orchestrator, then serves
//!    `N` warm requests, recording successes and failures separately.
//! 4. **Cleans up** every pooled VM and discards the snapshot, recording the
//!    cleanup evidence.
//!
//! # Outcome semantics (NOT a performance verdict)
//! [`DemoOutcome`] describes whether the demo **ran**, not whether a latency
//! target was met. `Completed` means the lane produced measurements; `Blocked`
//! means a prerequisite was unavailable. There is no notion of the demo "passing"
//! or "failing" against `<200 ms`; the report carries numbers only.
//!
//! # Determinism
//! The runner is generic over [`VmRestorer`]; tests drive it with the
//! deterministic [`ScriptedRestorer`](crate::restore::ScriptedRestorer), so the
//! full cold/warm/blocked behaviour is reproducible with no `/dev/kvm`.

use crate::function::HttpFunction;
use crate::measure::ColdWarmMeasurement;
use crate::pool::FunctionPool;
use crate::report::{CleanupEvidence, ColdPhaseDurations, DemoReport};
use crate::restore::VmRestorer;
use microvm_bench::{BlockedReason, HostMetadata, Workload, MIN_SAMPLES};
use microvm_errors::{ErrorCode, MicrovmError};

/// The demo's execution outcome: ran (`Completed`) vs prerequisite-unavailable
/// (`Blocked`). Never a performance pass/fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DemoOutcome {
    /// The demo ran and produced measurements (which may still be all-failures if
    /// e.g. the guest never became ready).
    Completed,
    /// The demo could not run because a prerequisite is unavailable.
    Blocked {
        /// Stable blocked-reason token.
        reason: BlockedReason,
        /// Human-readable evidence.
        detail: String,
    },
}

impl DemoOutcome {
    /// True when blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// True when completed.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// The blocked-reason token, if blocked.
    pub fn blocked_reason(&self) -> Option<BlockedReason> {
        match self {
            Self::Blocked { reason, .. } => Some(*reason),
            _ => None,
        }
    }
}

impl DemoReport {
    /// The demo's execution outcome derived from the report.
    pub fn outcome(&self) -> DemoOutcome {
        match &self.blocked_reason {
            Some(reason) => {
                let parsed = BlockedReason::all()
                    .iter()
                    .copied()
                    .find(|r| r.as_str() == reason)
                    .unwrap_or(BlockedReason::ArtifactMissing);
                DemoOutcome::Blocked {
                    reason: parsed,
                    detail: self.blocked_detail.clone().unwrap_or_default(),
                }
            }
            None => DemoOutcome::Completed,
        }
    }
}

/// Configuration for one demo run.
#[derive(Clone, Debug, PartialEq)]
pub struct DemoConfig {
    /// The single HTTP function the demo serves.
    pub function: HttpFunction,
    /// Warm request sample budget (the `N` in `N >= 100`).
    pub samples: usize,
    /// Warm pool size (number of VMs pre-restored during warmup).
    pub pool_size: usize,
}

impl DemoConfig {
    /// The minimum warm-sample count for an unblocked run (reused from the
    /// benchmark harness floor).
    pub const MIN_SAMPLES: usize = MIN_SAMPLES;

    /// Build a configuration.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] when `samples == 0` or
    /// `pool_size == 0`.
    pub fn new(
        function: HttpFunction,
        samples: usize,
        pool_size: usize,
    ) -> Result<Self, MicrovmError> {
        if samples == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "demo sample count must be at least 1",
            )
            .with_context("field", "samples"));
        }
        if pool_size == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "demo pool size must be at least 1",
            )
            .with_context("field", "pool_size"));
        }
        Ok(Self {
            function,
            samples,
            pool_size,
        })
    }

    /// True when the sample budget meets the plan's `N >= 100` floor.
    pub fn meets_minimum_samples(&self) -> bool {
        self.samples >= Self::MIN_SAMPLES
    }

    /// The pinned workload (function name + rootfs content hash) recorded in the
    /// report.
    pub fn workload(&self) -> Workload {
        Workload::new(self.function.name.clone(), self.function.rootfs.sha256).unwrap_or_else(
            |_| {
                Workload::new("demo-function", self.function.rootfs.sha256)
                    .expect("static name is valid")
            },
        )
    }
}

/// Orchestrates the warm HTTP-function demo.
#[derive(Clone, Debug)]
pub struct DemoRunner {
    config: DemoConfig,
}

impl DemoRunner {
    /// Create a runner for `config`.
    pub fn new(config: DemoConfig) -> Self {
        Self { config }
    }

    /// The configuration this runner runs under.
    pub fn config(&self) -> &DemoConfig {
        &self.config
    }

    /// Run the demo against `restorer`, capturing `host` metadata verbatim.
    ///
    /// A blocked probe yields a blocked report. Otherwise the runner cold-starts,
    /// fills the warm pool, serves `N` warm requests (recording every trial), and
    /// cleans up. The result never contains a pass/fail gate.
    pub async fn run<R: VmRestorer + ?Sized>(
        &self,
        host: HostMetadata,
        restorer: &mut R,
    ) -> DemoReport {
        let workload = self.config.workload();

        // 1. Probe: a blocked restorer yields a blocked report (no fabrication).
        match restorer.probe().await {
            microvm_bench::LaneOutcome::Blocked { reason, detail } => {
                return DemoReport::blocked(
                    host,
                    workload,
                    reason,
                    detail,
                    CleanupEvidence::default(),
                );
            }
            microvm_bench::LaneOutcome::Failed { detail } => {
                // A probe-time fatal failure is reported as blocked with a stable
                // token; samples are never fabricated.
                return DemoReport::blocked(
                    host,
                    workload,
                    BlockedReason::ArtifactMissing,
                    format!("lane_failed: {detail}"),
                    CleanupEvidence::default(),
                );
            }
            microvm_bench::LaneOutcome::Completed => {}
        }

        let mut cleanup = CleanupEvidence::default();

        // 2. Cold start: snapshot after readiness, measure the cold first call.
        let (cold_ms, snapshot, cold_log) = match restorer.cold_start(&self.config.function).await {
            Ok(cs) => {
                cleanup.snapshot_discarded = true;
                (Some(cs.first_call_ms), Some(cs.snapshot), Some(cs.phases))
            }
            Err(_) => (None, None, None),
        };

        // 3. Warm pool + N warm requests.
        let mut warm_samples: Vec<f64> = Vec::with_capacity(self.config.samples);
        let mut warm_failures = 0usize;
        let mut restore_trials = 0usize;
        let mut restore_failures = 0usize;
        let mut warmup_count = 0usize;
        let mut warm_restore_log = None;

        let mut pool = FunctionPool::empty();
        if let Some(snap) = &snapshot {
            pool = FunctionPool::fill(restorer, snap, self.config.pool_size).await;
            warmup_count = pool.warmup_count();
            restore_trials = restore_trials.saturating_add(self.config.pool_size);
            restore_failures = restore_failures.saturating_add(pool.fill_failures());
        }

        let invoke_req = crate::function::HttpRequest::invoke();
        for _ in 0..self.config.samples {
            let vm = match pool.acquire() {
                Some(vm) => vm,
                None => {
                    // Pool drained (or never filled): restore on demand, or record
                    // a failure when no snapshot exists to restore from.
                    restore_trials = restore_trials.saturating_add(1);
                    match &snapshot {
                        Some(snap) => match restorer.restore(snap).await {
                            Ok(vm) => {
                                warmup_count = warmup_count.saturating_add(1);
                                vm
                            }
                            Err(_) => {
                                restore_failures = restore_failures.saturating_add(1);
                                warm_failures = warm_failures.saturating_add(1);
                                continue;
                            }
                        },
                        None => {
                            restore_failures = restore_failures.saturating_add(1);
                            warm_failures = warm_failures.saturating_add(1);
                            continue;
                        }
                    }
                }
            };

            if warm_restore_log.is_none() {
                warm_restore_log = Some(vm.phases().clone());
            }
            let inv = vm.invoke(&invoke_req);
            if inv.response.is_success() && inv.request_ms.is_finite() && inv.request_ms >= 0.0 {
                warm_samples.push(inv.request_ms);
            } else {
                warm_failures = warm_failures.saturating_add(1);
            }
            pool.release(vm);
        }

        // 4. Cleanup: release every pooled VM.
        cleanup.released_vms = pool.drain();

        let measurement = ColdWarmMeasurement::new(
            cold_ms,
            &warm_samples,
            warm_failures,
            self.config.samples,
            warmup_count,
            restore_trials,
            restore_failures,
        );
        let cold_phases = cold_log
            .as_ref()
            .map(|cold| ColdPhaseDurations::from_logs(cold, warm_restore_log.as_ref()));

        DemoReport::completed(host, workload, measurement, cold_phases, cleanup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::Rootfs;
    use crate::restore::{ScriptedRestore, ScriptedRestorer};
    use microvm_artifacts::Digest;
    use microvm_bench::PageCachePolicy;

    fn function() -> HttpFunction {
        let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
        HttpFunction::new("hello-http", rootfs).unwrap()
    }

    fn host() -> HostMetadata {
        HostMetadata {
            cpu: "test-cpu".into(),
            kernel: "7.1.3-test".into(),
            kvm_api_version: 12,
            page_cache_state: PageCachePolicy::Mixed,
            memory_size_mib: 65536,
            vcpu_count: 32,
            cgroup_v2: true,
            nested: false,
        }
    }

    fn config(samples: usize, pool_size: usize) -> DemoConfig {
        DemoConfig::new(function(), samples, pool_size).unwrap()
    }

    #[test]
    fn config_rejects_zero_samples_and_pool() {
        assert!(DemoConfig::new(function(), 0, 4).is_err());
        assert!(DemoConfig::new(function(), 100, 0).is_err());
        assert!(DemoConfig::new(function(), 100, 4).is_ok());
    }

    #[test]
    fn meets_minimum_samples_boundary() {
        assert!(!config(99, 4).meets_minimum_samples());
        assert!(config(100, 4).meets_minimum_samples());
        assert_eq!(DemoConfig::MIN_SAMPLES, 100);
    }

    #[test]
    fn workload_pins_function_rootfs_hash() {
        let w = config(100, 4).workload();
        assert_eq!(w.name, "hello-http");
        assert_eq!(w.payload_sha256, Digest::from_bytes([7; 32]));
    }

    #[tokio::test]
    async fn happy_path_records_cold_and_warm() {
        // Pool of 4 VMs with distinct warm latencies 1..=4 ms.
        let restores: Vec<Result<ScriptedRestore, String>> = (1..=4)
            .map(|i| Ok(ScriptedRestore::new(1.0, i as f64)))
            .collect();
        let mut restorer = ScriptedRestorer::ok("s", 2.0, 3.0, restores);
        let runner = DemoRunner::new(config(100, 4));
        let report = runner.run(host(), &mut restorer).await;

        assert!(!report.is_blocked());
        assert_eq!(report.outcome(), DemoOutcome::Completed);
        // Cold first call = 5 steps of 2ms + 3ms request = 13ms.
        assert_eq!(report.cold_first_call_ms, Some(13.0));
        // Warm: 100 requests cycling latencies {1,2,3,4}.
        assert_eq!(report.warm.samples, 100);
        assert_eq!(report.warm.failures, 0);
        assert_eq!(report.request_trials, 100);
        assert_eq!(report.warmup_count, 4);
        assert!(report.warm_p50_ms.is_some());
        assert!(report.warm_p99_ms.is_some());
        assert!(report.warm_p50_ms <= report.warm_p99_ms);
        // Cleanup evidence present.
        assert_eq!(report.cleanup.released_vms, 4);
        assert!(report.cleanup.snapshot_discarded);
        // Cold phases recorded including snapshot after readiness.
        let phases = report.cold_phases.unwrap();
        assert_eq!(phases.request_ms, Some(13.0));
        assert!(phases.snapshot_ready_ms.is_some());
        assert!(phases.restore_ready_ms.is_some());
    }

    #[tokio::test]
    async fn blocked_restorer_yields_blocked_report() {
        let mut restorer =
            ScriptedRestorer::blocked("s", BlockedReason::FirecrackerMissing, "no firecracker bin");
        let runner = DemoRunner::new(config(100, 4));
        let report = runner.run(host(), &mut restorer).await;

        assert!(report.is_blocked());
        assert_eq!(
            report.blocked_reason.as_deref(),
            Some("firecracker_missing")
        );
        assert!(report.cold_first_call_ms.is_none());
        assert!(report.warm_p50_ms.is_none());
        assert_eq!(report.warm.samples, 0);
        assert_eq!(report.request_trials, 0);
        assert_eq!(report.warmup_count, 0);
        assert!(report.outcome().is_blocked());
        assert_eq!(
            report.outcome().blocked_reason(),
            Some(BlockedReason::FirecrackerMissing)
        );
    }

    #[tokio::test]
    async fn guest_never_ready_records_every_trial_as_failure() {
        let mut restorer = ScriptedRestorer::guest_never_ready("s");
        let runner = DemoRunner::new(config(100, 4));
        let report = runner.run(host(), &mut restorer).await;

        // The demo ran (not blocked) but produced no warm data.
        assert!(!report.is_blocked());
        assert_eq!(report.outcome(), DemoOutcome::Completed);
        assert!(report.cold_first_call_ms.is_none());
        assert!(report.cold_phases.is_none());
        // No request is counted as warm.
        assert_eq!(report.warm.samples, 0);
        assert_eq!(report.warm.failures, 100);
        assert_eq!(report.request_trials, 100);
        // Every timed-out trial is recorded as a restore failure.
        assert_eq!(report.restore_trials, 100);
        assert_eq!(report.restore_failures, 100);
        assert_eq!(report.warmup_count, 0);
        // Cleanup evidence is present.
        assert_eq!(report.cleanup.released_vms, 0);
        assert!(!report.cleanup.snapshot_discarded);
    }

    #[tokio::test]
    async fn restore_failures_are_recorded_not_counted_as_warm() {
        // Pool of 4: two succeed, two fail. Then on-demand restores are exhausted
        // (script empty) so drained-pool attempts fail too. Use pool_size == samples
        // so the pool is never drained and only fill failures occur.
        let restores: Vec<Result<ScriptedRestore, String>> = vec![
            Ok(ScriptedRestore::new(1.0, 1.0)),
            Err("restore blew up".into()),
            Ok(ScriptedRestore::new(1.0, 2.0)),
            Err("restore blew up".into()),
        ];
        let mut restorer = ScriptedRestorer::ok("s", 1.0, 1.0, restores);
        // samples == pool_size == 4: fill restores 4 (2 ok, 2 fail), then the 4
        // warm requests cycle the 2 pooled VMs.
        let runner = DemoRunner::new(config(4, 4));
        let report = runner.run(host(), &mut restorer).await;

        assert_eq!(report.warmup_count, 2);
        assert_eq!(report.restore_failures, 2);
        assert_eq!(report.warm.samples, 4);
        assert_eq!(report.warm.failures, 0);
        assert_eq!(report.cleanup.released_vms, 2);
    }

    #[tokio::test]
    async fn every_trial_is_accounted_for_invariant() {
        let restores: Vec<Result<ScriptedRestore, String>> = (0..8)
            .map(|i| Ok(ScriptedRestore::new(1.0, (i % 3 + 1) as f64)))
            .collect();
        let mut restorer = ScriptedRestorer::ok("s", 1.0, 1.0, restores);
        let runner = DemoRunner::new(config(100, 8));
        let report = runner.run(host(), &mut restorer).await;
        assert_eq!(
            report.warm.samples + report.warm.failures,
            report.request_trials
        );
        assert_eq!(report.request_trials, 100);
    }

    #[tokio::test]
    async fn report_has_no_pass_field_anywhere() {
        fn no_pass(value: &serde_json::Value) -> bool {
            match value {
                serde_json::Value::Object(map) => map.iter().all(|(k, v)| {
                    !matches!(k.to_ascii_lowercase().as_str(), "pass" | "passed") && no_pass(v)
                }),
                serde_json::Value::Array(items) => items.iter().all(no_pass),
                _ => true,
            }
        }
        let restores: Vec<Result<ScriptedRestore, String>> =
            (0..4).map(|_| Ok(ScriptedRestore::new(1.0, 1.0))).collect();
        let mut restorer = ScriptedRestorer::ok("s", 1.0, 1.0, restores);
        let runner = DemoRunner::new(config(100, 4));
        let report = runner.run(host(), &mut restorer).await;
        let json = serde_json::to_value(&report).unwrap();
        assert!(no_pass(&json));
    }
}
