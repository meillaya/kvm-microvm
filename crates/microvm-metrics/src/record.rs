//! The stable per-VM metrics record (plan todo 23).
//!
//! [`VmMetricsRecord`] is the full, wire-stable snapshot returned by the
//! collector and exposed through the UDS API. Its schema is defined by
//! `schemas/vm-metrics-record.v1.json` and includes: boot time, memory usage,
//! CPU usage/throttling, guest CPU steal *when available*, RX/TX throughput,
//! per-source timestamps, and explicit availability flags.
//!
//! # Cardinality
//! The record carries **no free-form label maps**. The only map is `errors`,
//! keyed by the fixed [`MetricErrorKind`] enum, so label cardinality is bounded
//! by construction. `vm_id` is a validated [`VmId`] (≤ 64 bytes, restricted
//! charset).

use crate::availability::{Availability, UnavailableReason};
use crate::cgroup::CgroupMetrics;
use crate::guest::GuestMetrics;
use crate::network::NetworkMetrics;
use chrono::{DateTime, Utc};
use microvm_types::VmId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Metrics record schema version. Bumped only on a breaking schema change.
pub const SCHEMA_VERSION: u32 = 1;

/// The lifecycle phase the VM was in when this record was collected.
///
/// These are the **monotonic boot/restore phases**: a VM boots once
/// (`Booting` → `Running`) or restores once (`Restoring` → `Running`), and the
/// phase only ever advances forward. `Stopped` is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricsPhase {
    /// Cold boot in progress.
    Booting,
    /// Snapshot restore in progress.
    Restoring,
    /// The VM reached service-ready and is running.
    Running,
    /// The VM has been cleaned up; sampling has stopped.
    Stopped,
}

impl MetricsPhase {
    /// Stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Booting => "booting",
            Self::Restoring => "restoring",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

impl std::fmt::Display for MetricsPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Host-monotonic phase markers (ns since an arbitrary monotonic epoch).
///
/// Each marker is `None` until that phase boundary is reached. Durations
/// ([`boot_time_ns`](Self::boot_time_ns),
/// [`restore_time_ns`](Self::restore_time_ns)) are derived from marker spans
/// and are `None` until both endpoints exist — a missing endpoint is reported
/// as "not ready yet", never as a zero duration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhaseMarkers {
    /// VMM process spawned.
    pub spawn_ns: Option<u64>,
    /// API socket became ready.
    pub socket_ready_ns: Option<u64>,
    /// Boot configuration applied.
    pub configured_ns: Option<u64>,
    /// Guest service-ready marker observed (boot complete).
    pub service_ready_ns: Option<u64>,
    /// Snapshot load issued (restore start).
    pub snapshot_load_ns: Option<u64>,
    /// Restore reached ready (restore complete).
    pub restore_ready_ns: Option<u64>,
}

/// A monotonic span `end - start`, or `None` if either endpoint is missing or
/// the endpoints are inconsistent (end before start).
fn monotonic_span(start: Option<u64>, end: Option<u64>) -> Option<u64> {
    match (start, end) {
        (Some(start), Some(end)) if end >= start => Some(end - start),
        _ => None,
    }
}

impl Serialize for PhaseMarkers {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PhaseMarkers", 8)?;
        state.serialize_field("spawn_ns", &self.spawn_ns)?;
        state.serialize_field("socket_ready_ns", &self.socket_ready_ns)?;
        state.serialize_field("configured_ns", &self.configured_ns)?;
        state.serialize_field("service_ready_ns", &self.service_ready_ns)?;
        state.serialize_field("snapshot_load_ns", &self.snapshot_load_ns)?;
        state.serialize_field("restore_ready_ns", &self.restore_ready_ns)?;
        // Derived durations are part of the stable schema (boot time / restore
        // time). They are recomputed from the raw markers above.
        state.serialize_field("boot_time_ns", &self.boot_time_ns())?;
        state.serialize_field("restore_time_ns", &self.restore_time_ns())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PhaseMarkers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Only the raw markers are read back; the derived boot_time_ns /
        // restore_time_ns fields (if present) are ignored as redundant.
        #[derive(Deserialize)]
        struct Shadow {
            spawn_ns: Option<u64>,
            socket_ready_ns: Option<u64>,
            configured_ns: Option<u64>,
            service_ready_ns: Option<u64>,
            snapshot_load_ns: Option<u64>,
            restore_ready_ns: Option<u64>,
        }
        let shadow = Shadow::deserialize(deserializer)?;
        Ok(Self {
            spawn_ns: shadow.spawn_ns,
            socket_ready_ns: shadow.socket_ready_ns,
            configured_ns: shadow.configured_ns,
            service_ready_ns: shadow.service_ready_ns,
            snapshot_load_ns: shadow.snapshot_load_ns,
            restore_ready_ns: shadow.restore_ready_ns,
        })
    }
}

impl PhaseMarkers {
    /// Total cold-boot time in ns (spawn → service-ready), or `None` until the
    /// guest reports service-ready.
    pub fn boot_time_ns(&self) -> Option<u64> {
        monotonic_span(self.spawn_ns, self.service_ready_ns)
    }

    /// Total restore time in ns (snapshot-load → restore-ready), or `None`
    /// until restore completes.
    pub fn restore_time_ns(&self) -> Option<u64> {
        monotonic_span(self.snapshot_load_ns, self.restore_ready_ns)
    }
}

/// The fixed set of collection-error categories.
///
/// Bounded and stable: error counters are keyed by this enum, never by a
/// free-form string, so the label set cannot grow (no high-cardinality
/// labels).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricErrorKind {
    /// Reading the cgroup source failed (missing/unreadable).
    CgroupRead,
    /// Reading the TAP network counters failed.
    NetworkRead,
    /// Reading the guest agent failed.
    GuestRead,
    /// A source existed but its contents could not be parsed.
    Parse,
}

impl MetricErrorKind {
    /// All error kinds. The length of this slice is the hard upper bound on
    /// error-label cardinality.
    pub fn all() -> &'static [MetricErrorKind] {
        &[
            Self::CgroupRead,
            Self::NetworkRead,
            Self::GuestRead,
            Self::Parse,
        ]
    }
}

/// A full per-VM metrics snapshot with explicit availability flags.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmMetricsRecord {
    /// The VM this record describes.
    pub vm_id: VmId,
    /// Schema version; equals [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Lifecycle phase at collection time (monotonic boot/restore phase).
    pub phase: MetricsPhase,
    /// Wall-clock source timestamp of collection (RFC 3339, UTC).
    pub collected_at: DateTime<Utc>,
    /// Host-monotonic source timestamp of collection (ns).
    pub monotonic_ns: u64,
    /// Monotonic boot/restore phase markers and derived durations.
    pub phases: PhaseMarkers,
    /// Host cgroup-v2 metrics (CPU/memory/IO/pids), availability-flagged.
    pub cgroup: Availability<CgroupMetrics>,
    /// TAP RX/TX counters and throughput, availability-flagged.
    pub network: Availability<NetworkMetrics>,
    /// Optional guest-agent metrics (steal/load/RSS), availability-flagged.
    /// Absent agent => `Unavailable`, never zero.
    pub guest: Availability<GuestMetrics>,
    /// Cumulative collection-error counters keyed by a fixed error kind.
    /// Cardinality is bounded by [`MetricErrorKind::all`].
    #[serde(default)]
    pub errors: BTreeMap<MetricErrorKind, u64>,
}

impl VmMetricsRecord {
    /// Build a record for a backend that has no host-metrics collector
    /// attached (e.g. the in-memory lifecycle service or a mock backend).
    ///
    /// Every host/guest source is marked [`UnavailableReason::NoBackend`] —
    /// honest "not collected", never a fabricated zero. The error map is empty
    /// because no collection was attempted.
    pub fn not_collected(
        vm_id: VmId,
        phase: MetricsPhase,
        collected_at: DateTime<Utc>,
        monotonic_ns: u64,
    ) -> Self {
        Self {
            vm_id,
            schema_version: SCHEMA_VERSION,
            phase,
            collected_at,
            monotonic_ns,
            phases: PhaseMarkers::default(),
            cgroup: Availability::Unavailable(UnavailableReason::NoBackend),
            network: Availability::Unavailable(UnavailableReason::NoBackend),
            guest: Availability::Unavailable(UnavailableReason::NoBackend),
            errors: BTreeMap::new(),
        }
    }

    // -- Convenience accessors for the stable schema fields -----------------

    /// Boot time in ns, if the boot completed.
    pub fn boot_time_ns(&self) -> Option<u64> {
        self.phases.boot_time_ns()
    }

    /// Current memory usage in bytes, if the cgroup source was available.
    pub fn memory_current_bytes(&self) -> Option<u64> {
        self.cgroup.value().map(|c| c.memory_current_bytes)
    }

    /// CPU usage in microseconds, if the cgroup source was available.
    pub fn cpu_usage_usec(&self) -> Option<u64> {
        self.cgroup.value().map(|c| c.cpu.usage_usec)
    }

    /// CPU throttled time in microseconds, if the cgroup source was available.
    pub fn cpu_throttled_usec(&self) -> Option<u64> {
        self.cgroup.value().map(|c| c.cpu.throttled_usec)
    }

    /// Guest CPU steal percentage, **only** if the guest agent was available.
    pub fn guest_cpu_steal_pct(&self) -> Option<f64> {
        self.guest.value().map(|g| g.cpu_steal_pct)
    }

    /// TAP RX throughput in bytes/sec, if available and a rate could be
    /// derived.
    pub fn rx_bytes_per_sec(&self) -> Option<u64> {
        self.network.value().and_then(|n| n.rx_bytes_per_sec)
    }

    /// TAP TX throughput in bytes/sec, if available and a rate could be
    /// derived.
    pub fn tx_bytes_per_sec(&self) -> Option<u64> {
        self.network.value().and_then(|n| n.tx_bytes_per_sec)
    }

    /// Total collection errors recorded for `kind`.
    pub fn error_count(&self, kind: MetricErrorKind) -> u64 {
        self.errors.get(&kind).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm() -> VmId {
        VmId::new("vm-rec").unwrap()
    }

    #[test]
    fn phase_markers_derive_durations() {
        let mut m = PhaseMarkers::default();
        assert_eq!(m.boot_time_ns(), None);
        m.spawn_ns = Some(1_000);
        // Still no service-ready => no boot time (not zero).
        assert_eq!(m.boot_time_ns(), None);
        m.service_ready_ns = Some(1_500);
        assert_eq!(m.boot_time_ns(), Some(500));

        m.snapshot_load_ns = Some(2_000);
        m.restore_ready_ns = Some(2_300);
        assert_eq!(m.restore_time_ns(), Some(300));
    }

    #[test]
    fn inconsistent_markers_yield_none_not_negative() {
        let m = PhaseMarkers {
            spawn_ns: Some(2_000),
            service_ready_ns: Some(1_000),
            ..Default::default()
        };
        assert_eq!(m.boot_time_ns(), None);
    }

    #[test]
    fn not_collected_marks_every_source_unavailable() {
        let r = VmMetricsRecord::not_collected(vm(), MetricsPhase::Running, Utc::now(), 123);
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        assert!(!r.cgroup.is_available());
        assert!(!r.network.is_available());
        assert!(!r.guest.is_available());
        assert_eq!(r.cgroup.reason(), Some(UnavailableReason::NoBackend));
        assert!(r.errors.is_empty());
        // Convenience accessors report None, never zero.
        assert_eq!(r.memory_current_bytes(), None);
        assert_eq!(r.guest_cpu_steal_pct(), None);
    }

    #[test]
    fn error_kind_cardinality_is_bounded() {
        // The label set is fixed; this test fails loudly if a new kind is
        // added without updating the cardinality contract.
        assert_eq!(MetricErrorKind::all().len(), 4);
    }

    #[test]
    fn record_serde_roundtrip_with_availability_flags() {
        let mut r = VmMetricsRecord::not_collected(vm(), MetricsPhase::Booting, Utc::now(), 5);
        r.errors.insert(MetricErrorKind::GuestRead, 2);
        let json = serde_json::to_string(&r).unwrap();
        let back: VmMetricsRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
