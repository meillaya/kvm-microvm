//! The demo evidence report (plan todo 28).
//!
//! [`DemoReport`] is the machine-readable artifact the demo produces. It records
//! the cold first-call latency, the warm p50/p95/p99 distribution, the warmup
//! count, full restore-trial accounting, the cold-path phase durations
//! (spawn/socket/configured/guest-ready/snapshot-ready/restore-ready/request),
//! cleanup evidence, and host metadata.
//!
//! # Hard rules encoded by this type
//! - **No pass/fail gate.** There is no `pass` field at any level and no method
//!   that reduces the measurements to a verdict. `cold_first_call_ms` and the
//!   warm percentiles are reported numbers; a reviewer interprets them. The
//!   `<200 ms` figure from the wider plan is a reference target only.
//! - **Blocked carries evidence, not fabricated samples.** A blocked report sets
//!   `blocked_reason`, a null cold call, and an empty warm distribution; samples
//!   are never invented.
//! - **Every trial is accounted for.** `request_trials` equals the sample budget
//!   and `warm.samples + warm.failures == request_trials`.

use crate::measure::ColdWarmMeasurement;
use crate::restore::{DemoPhase, PhaseLog};
use microvm_bench::{BlockedReason, Distribution, HostMetadata, Workload};
use serde::{Deserialize, Serialize};

/// JSON Schema `$id` for the warm-HTTP demo artifact.
pub const DEMO_SCHEMA_ID: &str =
    "https://kvm-microvm-orchestrator.local/schemas/warm-http-demo.v1.json";

/// Evidence class discriminator. Every demo artifact sets `class` to this.
pub const DEMO_CLASS: &str = "warm_http_demo";

/// Schema/version marker for the demo evidence format.
pub const DEMO_EVIDENCE_VERSION: u32 = 1;

/// Cumulative cold-path phase durations from `spawn`, plus a representative warm
/// `restore_ready` duration. Each field is `None` when that phase was not
/// recorded (e.g. a failed cold start records nothing).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ColdPhaseDurations {
    /// `spawn -> socket_ready` (ms).
    pub socket_ready_ms: Option<f64>,
    /// `spawn -> configured` (ms).
    pub configured_ms: Option<f64>,
    /// `spawn -> guest_ready` (ms).
    pub guest_ready_ms: Option<f64>,
    /// `spawn -> snapshot_ready` (ms) — snapshot taken after readiness.
    pub snapshot_ready_ms: Option<f64>,
    /// `spawn -> restore_ready` (ms) from a representative warm restore.
    pub restore_ready_ms: Option<f64>,
    /// `spawn -> request` (ms) — the cold first call.
    pub request_ms: Option<f64>,
}

impl ColdPhaseDurations {
    /// Derive durations from the cold-path log plus an optional representative
    /// warm-restore log (for `restore_ready`).
    pub fn from_logs(cold: &PhaseLog, warm_representative: Option<&PhaseLog>) -> Self {
        Self {
            socket_ready_ms: cold.elapsed_ms(DemoPhase::SocketReady),
            configured_ms: cold.elapsed_ms(DemoPhase::Configured),
            guest_ready_ms: cold.elapsed_ms(DemoPhase::GuestReady),
            snapshot_ready_ms: cold.elapsed_ms(DemoPhase::SnapshotReady),
            restore_ready_ms: warm_representative
                .and_then(|w| w.elapsed_ms(DemoPhase::RestoreReady)),
            request_ms: cold.elapsed_ms(DemoPhase::Request),
        }
    }
}

/// Evidence that demo resources were cleaned up after the run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupEvidence {
    /// Number of pooled VMs released (dropped) at the end of the run.
    pub released_vms: usize,
    /// True when the snapshot artifact was discarded after the run.
    pub snapshot_discarded: bool,
}

/// The complete warm-HTTP demo evidence artifact.
///
/// There is intentionally **no** `pass` field and no method that computes one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DemoReport {
    /// Class discriminator; always [`DEMO_CLASS`].
    #[serde(rename = "class")]
    pub class: String,
    /// Host substrate snapshot (reused from the benchmark harness).
    pub host_metadata: HostMetadata,
    /// The single pinned function/rootfs workload (content hash).
    pub workload: Workload,
    /// Cold first-call latency (ms), or `null` when the cold start failed.
    pub cold_first_call_ms: Option<f64>,
    /// Warm p50 (ms), or `null` when no warm samples were collected.
    pub warm_p50_ms: Option<f64>,
    /// Warm p95 (ms), or `null` when no warm samples were collected.
    pub warm_p95_ms: Option<f64>,
    /// Warm p99 (ms), or `null` when no warm samples were collected.
    pub warm_p99_ms: Option<f64>,
    /// Full warm request distribution (samples, failures, percentiles, min/max).
    pub warm: Distribution,
    /// Number of VMs successfully pre-restored (warmed) into the pool.
    pub warmup_count: usize,
    /// Number of warm request attempts (successful + failed).
    pub request_trials: usize,
    /// Total restore attempts.
    pub restore_trials: usize,
    /// Restore attempts that failed.
    pub restore_failures: usize,
    /// Cold-path phase durations, or `None` when the cold start failed.
    pub cold_phases: Option<ColdPhaseDurations>,
    /// Cleanup evidence (always present).
    pub cleanup: CleanupEvidence,
    /// Stable blocked-reason token, or `null` when the demo ran.
    pub blocked_reason: Option<String>,
    /// Human-readable blocked detail, or `null` when the demo ran.
    pub blocked_detail: Option<String>,
}

impl DemoReport {
    /// A completed (ran) report. `class` is forced to [`DEMO_CLASS`].
    pub fn completed(
        host_metadata: HostMetadata,
        workload: Workload,
        measurement: ColdWarmMeasurement,
        cold_phases: Option<ColdPhaseDurations>,
        cleanup: CleanupEvidence,
    ) -> Self {
        Self {
            class: DEMO_CLASS.to_string(),
            host_metadata,
            workload,
            cold_first_call_ms: measurement.cold_first_call_ms,
            warm_p50_ms: measurement.warm_p50(),
            warm_p95_ms: measurement.warm_p95(),
            warm_p99_ms: measurement.warm_p99(),
            warm: measurement.warm,
            warmup_count: measurement.warmup_count,
            request_trials: measurement.request_trials,
            restore_trials: measurement.restore_trials,
            restore_failures: measurement.restore_failures,
            cold_phases,
            cleanup,
            blocked_reason: None,
            blocked_detail: None,
        }
    }

    /// A blocked report: null cold call, empty warm distribution, recorded
    /// reason. Samples are never fabricated.
    pub fn blocked(
        host_metadata: HostMetadata,
        workload: Workload,
        reason: BlockedReason,
        detail: impl Into<String>,
        cleanup: CleanupEvidence,
    ) -> Self {
        let m = ColdWarmMeasurement::blocked();
        Self {
            class: DEMO_CLASS.to_string(),
            host_metadata,
            workload,
            cold_first_call_ms: None,
            warm_p50_ms: None,
            warm_p95_ms: None,
            warm_p99_ms: None,
            warm: m.warm,
            warmup_count: 0,
            request_trials: 0,
            restore_trials: 0,
            restore_failures: 0,
            cold_phases: None,
            cleanup,
            blocked_reason: Some(reason.as_str().to_string()),
            blocked_detail: Some(detail.into()),
        }
    }

    /// True when the demo was blocked (no real samples).
    pub fn is_blocked(&self) -> bool {
        self.blocked_reason.is_some()
    }

    /// Serialize to pretty JSON for writing to the `--out` path.
    ///
    /// # Errors
    /// Propagates a serialization error (cannot occur for this schema-bound type
    /// in practice).
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_artifacts::Digest;
    use microvm_bench::PageCachePolicy;

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

    fn workload() -> Workload {
        Workload::new("hello-http", Digest::from_bytes([7; 32])).unwrap()
    }

    fn no_pass_field_anywhere(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key = k.to_ascii_lowercase();
                    if key == "pass" || key == "passed" || key == "meets_target" || key == "sla_met"
                    {
                        return false;
                    }
                    if !no_pass_field_anywhere(v) {
                        return false;
                    }
                }
                true
            }
            serde_json::Value::Array(items) => items.iter().all(no_pass_field_anywhere),
            _ => true,
        }
    }

    #[test]
    fn completed_report_carries_numbers_and_no_pass_gate() {
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let m = ColdWarmMeasurement::new(Some(42.0), &samples, 0, 100, 8, 8, 0);
        let report = DemoReport::completed(host(), workload(), m, None, CleanupEvidence::default());
        assert_eq!(report.class, DEMO_CLASS);
        assert_eq!(report.cold_first_call_ms, Some(42.0));
        assert_eq!(report.warm_p50_ms, Some(50.0));
        assert_eq!(report.warm_p99_ms, Some(99.0));
        assert_eq!(report.warmup_count, 8);
        assert!(!report.is_blocked());
        let json = serde_json::to_value(&report).unwrap();
        assert!(no_pass_field_anywhere(&json), "no pass field may exist");
    }

    #[test]
    fn blocked_report_has_nulls_and_reason() {
        let report = DemoReport::blocked(
            host(),
            workload(),
            BlockedReason::KvmUnavailable,
            "no /dev/kvm",
            CleanupEvidence::default(),
        );
        assert!(report.is_blocked());
        assert_eq!(report.blocked_reason.as_deref(), Some("kvm_unavailable"));
        assert!(report.cold_first_call_ms.is_none());
        assert!(report.warm_p50_ms.is_none());
        assert_eq!(report.warm.samples, 0);
        assert_eq!(report.request_trials, 0);
    }

    #[test]
    fn cold_phase_durations_derive_from_logs() {
        let cold = PhaseLog::from_deltas(&[
            (DemoPhase::Spawn, 1_000_000),
            (DemoPhase::SocketReady, 1_000_000),
            (DemoPhase::Configured, 1_000_000),
            (DemoPhase::GuestReady, 1_000_000),
            (DemoPhase::SnapshotReady, 1_000_000),
            (DemoPhase::Request, 2_000_000),
        ])
        .unwrap();
        let warm = PhaseLog::from_deltas(&[
            (DemoPhase::Spawn, 500_000),
            (DemoPhase::SocketReady, 500_000),
            (DemoPhase::Configured, 500_000),
            (DemoPhase::RestoreReady, 500_000),
        ])
        .unwrap();
        let d = ColdPhaseDurations::from_logs(&cold, Some(&warm));
        assert_eq!(d.socket_ready_ms, Some(2.0));
        assert_eq!(d.guest_ready_ms, Some(4.0));
        assert_eq!(d.snapshot_ready_ms, Some(5.0));
        assert_eq!(d.request_ms, Some(7.0));
        assert_eq!(d.restore_ready_ms, Some(2.0));
    }

    #[test]
    fn report_round_trips_through_json() {
        let m = ColdWarmMeasurement::new(Some(1.0), &[1.0, 2.0], 0, 2, 1, 1, 0);
        let report = DemoReport::completed(host(), workload(), m, None, CleanupEvidence::default());
        let json = report.to_json_pretty().unwrap();
        let back: DemoReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }
}
