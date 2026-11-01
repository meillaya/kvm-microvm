//! The [`BenchMarker`]: drives benchmark lanes and assembles a
//! [`BenchmarkResult`] (plan todo 27).
//!
//! For each lane the marker:
//! 1. Probes availability. A blocked probe yields a blocked item (zero
//!    samples, null percentiles, recorded `blocked_reason`): samples are never
//!    fabricated (requirement 11).
//! 2. Collects `N` cold and `N` warm samples, recording failures separately
//!    from successful samples (requirement 6).
//! 3. Summarises each condition into a [`Distribution`] (p50/p95/p99 + min/max).
//!
//! The marker is generic over [`LaneRunner`], so the same orchestration drives
//! the deterministic [`ScriptedLane`] in tests and the real Firecracker/Docker
//! lanes on a privileged host. It performs no statistics fabrication and emits
//! no pass/fail verdict: `target_ms` is carried through as metadata only
//! (requirement 10).

use crate::config::BenchmarkConfig;
use crate::config::RuntimeVersions;
use crate::outcome::LaneOutcome;
use crate::percentiles::Distribution;
use crate::result::{BenchmarkItem, BenchmarkResult, HostMetadata};
use crate::runner::{LaneRunner, SampleCondition};

/// Drives benchmark lanes and assembles results.
#[derive(Clone, Debug)]
pub struct BenchMarker {
    config: BenchmarkConfig,
}

impl BenchMarker {
    /// Create a marker for `config`. The config's `samples` is the per-condition
    /// `N`.
    pub fn new(config: BenchmarkConfig) -> Self {
        Self { config }
    }

    /// The configuration this marker runs under.
    pub fn config(&self) -> &BenchmarkConfig {
        &self.config
    }

    /// Run every lane and assemble a [`BenchmarkResult`].
    ///
    /// `host` and `versions` are captured by the caller (the I/O shell) and
    /// recorded verbatim. Each lane is probed then sampled; a blocked lane
    /// produces a blocked item, never fabricated samples.
    pub async fn run(
        &self,
        host: HostMetadata,
        versions: RuntimeVersions,
        lanes: Vec<Box<dyn LaneRunner>>,
    ) -> BenchmarkResult {
        let mut benchmarks = Vec::with_capacity(lanes.len());
        for mut lane in lanes {
            benchmarks.push(self.run_lane(lane.as_mut()).await);
        }
        BenchmarkResult::new(host, self.config.workload.clone(), versions, benchmarks)
    }

    /// Drive a single lane to a [`BenchmarkItem`].
    async fn run_lane(&self, lane: &mut dyn LaneRunner) -> BenchmarkItem {
        let name = lane.name();
        let target = lane.target_ms();
        let unit = lane.unit();

        match lane.probe().await {
            LaneOutcome::Completed => {
                let cold = self.collect(lane, SampleCondition::Cold).await;
                let warm = self.collect(lane, SampleCondition::Warm).await;
                BenchmarkItem::new(name, target, unit, cold, warm, None)
            }
            LaneOutcome::Blocked { reason, .. } => {
                BenchmarkItem::blocked(name, target, unit, reason.as_str())
            }
            LaneOutcome::Failed { detail } => {
                // A probe-time fatal failure is reported as a blocked item with a
                // stable token; the detail is preserved in the item name's lane log
                // by the caller. Samples are never fabricated.
                let _ = detail;
                BenchmarkItem::blocked(name, target, unit, "lane_failed")
            }
        }
    }

    /// Collect up to `N` samples for one condition.
    ///
    /// If `prepare` fails (the condition cannot be established honestly, e.g.
    /// `drop_caches` is unsupported), returns an empty distribution with zero
    /// samples rather than measuring under the wrong cache state. Sample
    /// failures are counted in [`Distribution::failures`] and excluded from the
    /// statistics.
    async fn collect(&self, lane: &mut dyn LaneRunner, condition: SampleCondition) -> Distribution {
        if lane.prepare(condition).await.is_err() {
            return Distribution::empty();
        }
        let n = self.config.samples;
        let mut ok = Vec::with_capacity(n);
        let mut failures = 0usize;
        for _ in 0..n {
            match lane.run_sample(condition).await {
                Ok(ms) if ms.is_finite() && ms >= 0.0 => ok.push(ms),
                Ok(_) => failures += 1, // non-finite/negative measurement: discard
                Err(_) => failures += 1,
            }
        }
        Distribution::from_samples_with_failures(&ok, failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Conditions, Workload};
    use crate::outcome::BlockedReason;
    use crate::runner::ScriptedLane;
    use microvm_artifacts::Digest;

    fn config(samples: usize) -> BenchmarkConfig {
        let w = Workload::new("snapshot-restore", Digest::from_bytes([1; 32])).unwrap();
        BenchmarkConfig::new(w, samples, Conditions::default()).unwrap()
    }

    fn host() -> HostMetadata {
        HostMetadata {
            cpu: "test-cpu".into(),
            kernel: "7.1.3-test".into(),
            kvm_api_version: 12,
            page_cache_state: crate::config::PageCachePolicy::Mixed,
            memory_size_mib: 65536,
            vcpu_count: 32,
            cgroup_v2: true,
            nested: false,
        }
    }

    fn ok_seq(n: usize, base: f64) -> Vec<Result<f64, String>> {
        (0..n).map(|i| Ok(base + i as f64)).collect()
    }

    #[tokio::test]
    async fn completed_lane_produces_cold_and_warm_distributions() {
        let marker = BenchMarker::new(config(100));
        let lane = ScriptedLane::new(
            "snapshot_restore",
            30.0,
            ok_seq(100, 150.0),
            ok_seq(100, 10.0),
        );
        let result = marker
            .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
            .await;

        assert_eq!(result.benchmarks.len(), 1);
        let item = &result.benchmarks[0];
        assert_eq!(item.name, "snapshot_restore");
        assert!(!item.is_blocked());
        assert_eq!(item.cold.samples, 100);
        assert_eq!(item.warm.samples, 100);
        assert_eq!(item.cold.failures, 0);
        // Headline prefers warm.
        assert_eq!(item.p50, item.warm.p50);
        assert!(!result.has_blocked_lane());
    }

    #[tokio::test]
    async fn blocked_lane_yields_zero_samples_and_reason() {
        let marker = BenchMarker::new(config(100));
        let lane = ScriptedLane::blocked(
            "docker_start_cold",
            800.0,
            BlockedReason::DockerMissing,
            "no daemon",
        );
        let result = marker
            .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
            .await;

        let item = &result.benchmarks[0];
        assert!(item.is_blocked());
        assert_eq!(item.blocked_reason.as_deref(), Some("docker_missing"));
        assert_eq!(item.cold.samples, 0);
        assert_eq!(item.warm.samples, 0);
        assert!(item.p50.is_none() && item.p95.is_none() && item.p99.is_none());
        assert!(result.has_blocked_lane());
    }

    #[tokio::test]
    async fn sample_failures_are_recorded_not_counted() {
        let marker = BenchMarker::new(config(5));
        // Cold: 3 ok + 2 failures; warm: all ok.
        let cold = vec![
            Ok(10.0),
            Err("e".into()),
            Ok(20.0),
            Err("e".into()),
            Ok(30.0),
        ];
        let warm = ok_seq(5, 1.0);
        let lane = ScriptedLane::new("x", 30.0, cold, warm);
        let result = marker
            .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
            .await;

        let item = &result.benchmarks[0];
        assert_eq!(item.cold.samples, 3);
        assert_eq!(item.cold.failures, 2);
        assert_eq!(item.warm.samples, 5);
        assert_eq!(item.warm.failures, 0);
    }

    #[tokio::test]
    async fn prepare_failure_yields_empty_condition() {
        let marker = BenchMarker::new(config(5));
        let lane =
            ScriptedLane::new("x", 30.0, ok_seq(5, 1.0), ok_seq(5, 1.0)).with_prepare_failure();
        let result = marker
            .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
            .await;
        let item = &result.benchmarks[0];
        // prepare fails for both conditions -> zero samples, lane not "blocked"
        // at probe level so blocked_reason stays null but no data is fabricated.
        assert_eq!(item.cold.samples, 0);
        assert_eq!(item.warm.samples, 0);
        assert!(item.blocked_reason.is_none());
    }

    #[tokio::test]
    async fn target_is_carried_as_metadata_not_a_gate() {
        let marker = BenchMarker::new(config(10));
        // Samples all exceed the target; the item still simply records the
        // distribution: there is no pass/fail field.
        let lane = ScriptedLane::new("x", 30.0, ok_seq(10, 500.0), ok_seq(10, 500.0));
        let result = marker
            .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
            .await;
        let item = &result.benchmarks[0];
        assert_eq!(item.target_ms, 30.0);
        let json = serde_json::to_value(item).unwrap();
        assert!(json.get("pass").is_none(), "no pass field may exist");
    }
}
