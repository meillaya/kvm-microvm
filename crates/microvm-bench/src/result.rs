//! Benchmark result schema: the machine-readable artifact the harness writes.
//!
//! The serialized form conforms to `schemas/evidence-benchmark.v1.json`
//! ([`BENCHMARK_SCHEMA_ID`]). Two invariants are load-bearing:
//!
//! 1. No `pass` field anywhere (requirement 10). `target_ms` is metadata;
//!    the schema forbids a `pass` boolean at every level via
//!    `additionalProperties:false` plus an explicit `not: {required:["pass"]}`.
//!    [`BenchmarkResult`] therefore has no field, method, or accessor that
//!    reduces a distribution to a pass/fail verdict.
//! 2. Blocked lanes carry zero samples and null percentiles (requirement 11).
//!    A blocked item sets `blocked_reason`, `cold.samples = warm.samples = 0`,
//!    and null p50/p95/p99: samples are never fabricated.
//!
//! The result also carries the fields requirement 8 demands beyond the original
//! schema: [`Workload`] (workload/artifact hashes) and [`RuntimeVersions`]
//! (Firecracker/Docker versions; the kernel version is
//! [`HostMetadata::kernel`]). These are declared in the extended schema.

use crate::config::{PageCachePolicy, RuntimeVersions, Workload};
use crate::percentiles::Distribution;
use serde::{Deserialize, Serialize};

/// JSON Schema `$id` for the benchmark evidence artifact.
pub const BENCHMARK_SCHEMA_ID: &str =
    "https://kvm-microvm-orchestrator.local/schemas/evidence-benchmark.v1.json";

/// Evidence class discriminator. Every benchmark artifact sets `class` to this.
pub const BENCHMARK_CLASS: &str = "benchmark";

/// Schema/version marker for the benchmark evidence format.
pub const BENCHMARK_EVIDENCE_VERSION: u32 = 1;

/// Units for recorded percentiles and `target_ms`.
///
/// Matches the `unit` enum in the schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Unit {
    /// Milliseconds.
    #[serde(rename = "ms")]
    Ms,
    /// Microseconds.
    #[serde(rename = "us")]
    Us,
    /// Seconds.
    #[serde(rename = "s")]
    S,
    /// Requests per second.
    #[serde(rename = "rps")]
    Rps,
    /// Bytes per second.
    #[serde(rename = "B/s")]
    BytesPerSec,
    /// Kibibytes per second.
    #[serde(rename = "KiB/s")]
    KiBPerSec,
    /// Mebibytes per second.
    #[serde(rename = "MiB/s")]
    MiBPerSec,
}

impl Unit {
    /// Stable schema token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ms => "ms",
            Self::Us => "us",
            Self::S => "s",
            Self::Rps => "rps",
            Self::BytesPerSec => "B/s",
            Self::KiBPerSec => "KiB/s",
            Self::MiBPerSec => "MiB/s",
        }
    }
}

/// Snapshot of the host substrate at benchmark time.
///
/// Matches the schema `host_metadata` object exactly. Required so every
/// p50/p95/p99 is reproducible and reviewable: the same distribution on
/// different hardware means different things. `kvm_api_version` is `-1` when
/// `/dev/kvm` was inaccessible so the field is always present.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostMetadata {
    /// CPU model string (`/proc/cpuinfo` "model name").
    pub cpu: String,
    /// Kernel release (`uname -r`). Also the "kernel version" of requirement 8.
    pub kernel: String,
    /// `KVM_GET_API_VERSION` at benchmark time; `-1` when inaccessible.
    pub kvm_api_version: i64,
    /// Page-cache state at the start of each measurement.
    pub page_cache_state: PageCachePolicy,
    /// Total host RAM in MiB.
    pub memory_size_mib: u64,
    /// Logical CPU count available (`nproc`).
    pub vcpu_count: u64,
    /// True iff a unified cgroup-v2 hierarchy with cpu+memory+pids is available.
    pub cgroup_v2: bool,
    /// True iff nested virtualization is available.
    pub nested: bool,
}

/// A single named benchmark distribution record.
///
/// Matches one entry of the schema `benchmarks` array. The headline
/// `p50/p95/p99` summarise the primary condition: the warm distribution
/// when it has samples, otherwise the cold distribution, otherwise `null`
/// (blocked). This mirrors the committed schema example, where a warm-capable
/// benchmark headlines its warm latency and a cold-only benchmark headlines its
/// cold latency.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkItem {
    /// Stable benchmark identifier (e.g. `snapshot_restore`, `docker_start_cold`).
    pub name: String,
    /// Reference target in `unit`. Metadata only; never a pass/fail threshold.
    pub target_ms: f64,
    /// Unit of the percentiles and `target_ms`.
    pub unit: Unit,
    /// Headline 50th percentile, or `null` when blocked.
    pub p50: Option<f64>,
    /// Headline 95th percentile, or `null` when blocked.
    pub p95: Option<f64>,
    /// Headline 99th percentile, or `null` when blocked.
    pub p99: Option<f64>,
    /// Cold-condition distribution.
    pub cold: Distribution,
    /// Warm-condition distribution.
    pub warm: Distribution,
    /// Stable blocked-reason token, or `null` when the benchmark ran.
    pub blocked_reason: Option<String>,
}

impl BenchmarkItem {
    /// Build an item, deriving the headline p50/p95/p99 from the cold/warm
    /// distributions (warm preferred, then cold, else null).
    pub fn new(
        name: impl Into<String>,
        target_ms: f64,
        unit: Unit,
        cold: Distribution,
        warm: Distribution,
        blocked_reason: Option<String>,
    ) -> Self {
        let headline = if !warm.is_empty() {
            Some(warm)
        } else if !cold.is_empty() {
            Some(cold)
        } else {
            None
        };
        let (p50, p95, p99) = match headline {
            Some(d) => (d.p50, d.p95, d.p99),
            None => (None, None, None),
        };
        Self {
            name: name.into(),
            target_ms,
            unit,
            p50,
            p95,
            p99,
            cold,
            warm,
            blocked_reason,
        }
    }

    /// A blocked item: zero samples, null percentiles, and a recorded reason.
    /// Samples are never fabricated.
    pub fn blocked(name: impl Into<String>, target_ms: f64, unit: Unit, reason: &str) -> Self {
        Self {
            name: name.into(),
            target_ms,
            unit,
            p50: None,
            p95: None,
            p99: None,
            cold: Distribution::empty(),
            warm: Distribution::empty(),
            blocked_reason: Some(reason.to_string()),
        }
    }

    /// True when this item was blocked (no real samples).
    pub fn is_blocked(&self) -> bool {
        self.blocked_reason.is_some()
    }
}

/// The complete benchmark evidence artifact.
///
/// Serialized to the output JSON file. Conforms to [`BENCHMARK_SCHEMA_ID`].
/// There is intentionally no `pass` field and no method that computes one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Class discriminator; always [`BENCHMARK_CLASS`].
    #[serde(rename = "class")]
    pub class: String,
    /// Host substrate snapshot.
    pub host_metadata: HostMetadata,
    /// The single pinned workload (workload/artifact hashes, requirement 8/9).
    pub workload: Workload,
    /// Firecracker/Docker versions (requirement 8).
    pub runtime_versions: RuntimeVersions,
    /// Per-benchmark distribution records.
    pub benchmarks: Vec<BenchmarkItem>,
}

impl BenchmarkResult {
    /// Assemble a result. `class` is forced to [`BENCHMARK_CLASS`].
    pub fn new(
        host_metadata: HostMetadata,
        workload: Workload,
        runtime_versions: RuntimeVersions,
        benchmarks: Vec<BenchmarkItem>,
    ) -> Self {
        Self {
            class: BENCHMARK_CLASS.to_string(),
            host_metadata,
            workload,
            runtime_versions,
            benchmarks,
        }
    }

    /// Serialize to pretty JSON for writing to the `--out` path.
    ///
    /// # Errors
    /// Propagates a serialization error (cannot occur for this schema-bound type
    /// in practice).
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// True when any benchmark item was blocked.
    pub fn has_blocked_lane(&self) -> bool {
        self.benchmarks.iter().any(BenchmarkItem::is_blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Workload;
    use microvm_artifacts::Digest;

    fn host() -> HostMetadata {
        HostMetadata {
            cpu: "test-cpu".into(),
            kernel: "7.1.3-test".into(),
            kvm_api_version: 12,
            page_cache_state: PageCachePolicy::Cold,
            memory_size_mib: 65536,
            vcpu_count: 32,
            cgroup_v2: true,
            nested: false,
        }
    }

    fn workload() -> Workload {
        Workload::new("snapshot-restore", Digest::from_bytes([7; 32])).unwrap()
    }

    #[test]
    fn unit_tokens_match_schema_enum() {
        assert_eq!(Unit::Ms.as_str(), "ms");
        assert_eq!(Unit::Us.as_str(), "us");
        assert_eq!(Unit::S.as_str(), "s");
        assert_eq!(Unit::Rps.as_str(), "rps");
        assert_eq!(Unit::BytesPerSec.as_str(), "B/s");
        assert_eq!(Unit::KiBPerSec.as_str(), "KiB/s");
        assert_eq!(Unit::MiBPerSec.as_str(), "MiB/s");
        // Round-trip the awkward slash tokens through serde.
        for u in [
            Unit::Ms,
            Unit::BytesPerSec,
            Unit::KiBPerSec,
            Unit::MiBPerSec,
        ] {
            let json = serde_json::to_value(u).unwrap();
            assert_eq!(json, serde_json::json!(u.as_str()));
            let back: Unit = serde_json::from_value(json).unwrap();
            assert_eq!(back, u);
        }
    }

    #[test]
    fn headline_prefers_warm_then_cold() {
        let cold = Distribution::from_samples(&[100.0, 200.0]);
        let warm = Distribution::from_samples(&[10.0, 20.0]);
        let item = BenchmarkItem::new("x", 30.0, Unit::Ms, cold, warm, None);
        // Headline = warm. Nearest-rank p50 of [10,20] is rank ceil(0.5*2)=1 -> 10.
        assert_eq!(item.p50, Some(10.0));
        assert_eq!(item.p50, warm.p50);

        let cold_only = BenchmarkItem::new(
            "y",
            30.0,
            Unit::Ms,
            Distribution::from_samples(&[5.0]),
            Distribution::empty(),
            None,
        );
        assert_eq!(cold_only.p50, Some(5.0));
    }

    #[test]
    fn blocked_item_has_zero_samples_and_null_percentiles() {
        let item = BenchmarkItem::blocked("snapshot_restore", 30.0, Unit::Ms, "kvm_unavailable");
        assert!(item.is_blocked());
        assert_eq!(item.blocked_reason.as_deref(), Some("kvm_unavailable"));
        assert_eq!(item.cold.samples, 0);
        assert_eq!(item.warm.samples, 0);
        assert!(item.p50.is_none() && item.p95.is_none() && item.p99.is_none());
        assert!(item.cold.min_ms.is_none() && item.cold.max_ms.is_none());
    }

    #[test]
    fn result_serializes_with_class_and_no_pass_field() {
        let result = BenchmarkResult::new(
            host(),
            workload(),
            RuntimeVersions::default(),
            vec![BenchmarkItem::blocked(
                "snapshot_restore",
                30.0,
                Unit::Ms,
                "kvm_unavailable",
            )],
        );
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["class"], "benchmark");
        // No pass field at top level or in any benchmark item.
        assert!(json.get("pass").is_none());
        for item in json["benchmarks"].as_array().unwrap() {
            assert!(item.get("pass").is_none());
        }
        // Requirement 8 fields present.
        assert!(json.get("workload").is_some());
        assert!(json.get("runtime_versions").is_some());
        assert!(json["host_metadata"].get("kernel").is_some());
    }

    #[test]
    fn result_round_trips_through_json() {
        let result = BenchmarkResult::new(
            host(),
            workload(),
            RuntimeVersions {
                firecracker: Some("1.16.1".into()),
                docker: None,
            },
            vec![BenchmarkItem::new(
                "snapshot_restore",
                30.0,
                Unit::Ms,
                Distribution::from_samples(&[150.0, 160.0]),
                Distribution::from_samples(&[14.0, 16.0]),
                None,
            )],
        );
        let json = result.to_json_pretty().unwrap();
        let back: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, result);
    }
}
