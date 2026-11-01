//! Pure metrics consumption and reconciliation inputs (plan todo 24).
//!
//! The scheduler consumes per-VM metrics ([`VmMetricsRecord`]) to build
//! reconciliation inputs, but it never mutates the record and never touches any
//! host resource. Crucially, observed metrics never relax hard limits:
//! admission and bin capacity are accounted against *reserved* resources, while
//! metrics only inform reconciliation (reserved-vs-observed drift detection).
//!
//! Every observed value is availability-flagged: a missing cgroup sample stays
//! [`Availability::Unavailable`]: it is never coerced to a measured `0`.

use crate::placement::Placement;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_metrics::{
    Availability, CgroupMetrics, MetricsPhase, UnavailableReason, VmMetricsRecord,
};
use microvm_types::VmId;
use serde::{Deserialize, Serialize};

const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Map an availability-flagged cgroup sample without consuming the record.
fn map_cgroup<U>(record: &VmMetricsRecord, f: impl FnOnce(&CgroupMetrics) -> U) -> Availability<U> {
    match record.cgroup.value() {
        Some(c) => Availability::available(f(c)),
        None => Availability::unavailable(
            record
                .cgroup
                .reason()
                .unwrap_or(UnavailableReason::NoBackend),
        ),
    }
}

/// Observed memory usage in MiB, availability-flagged (never zero-filled).
#[must_use]
pub fn observed_memory_mib(record: &VmMetricsRecord) -> Availability<u64> {
    map_cgroup(record, |c| c.memory_current_bytes / BYTES_PER_MIB)
}

/// Observed cumulative CPU usage in microseconds, availability-flagged.
#[must_use]
pub fn observed_cpu_usage_usec(record: &VmMetricsRecord) -> Availability<u64> {
    map_cgroup(record, |c| c.cpu.usage_usec)
}

/// A pure reconciliation input pairing a placement's reservations with the
/// latest observed metrics for the same VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationInput {
    /// The VM this input describes.
    pub vm_id: VmId,
    /// Lifecycle phase reported by the metrics record.
    pub phase: MetricsPhase,
    /// Reserved vCPUs (hard limit).
    pub reserved_vcpus: u32,
    /// Reserved memory in MiB (hard limit).
    pub reserved_memory_mib: u64,
    /// Observed memory usage in MiB, availability-flagged.
    pub observed_memory_mib: Availability<u64>,
    /// Observed cumulative CPU usage (usec), availability-flagged.
    pub observed_cpu_usage_usec: Availability<u64>,
}

impl ReconciliationInput {
    /// Whether observed memory exceeds the reservation, availability-flagged.
    ///
    /// `Unavailable` when the metrics sample is unavailable: drift is unknown,
    /// not assumed false.
    #[must_use]
    pub fn observed_exceeds_reserved_memory(&self) -> Availability<bool> {
        match self.observed_memory_mib {
            Availability::Available(obs) => Availability::available(obs > self.reserved_memory_mib),
            Availability::Unavailable(reason) => Availability::unavailable(reason),
        }
    }
}

/// Build a reconciliation input from a placement and its metrics record.
///
/// Pure: reads both inputs by reference and mutates neither.
///
/// # Errors
/// Returns [`ErrorCode::InvalidResourceSpec`] if the record describes a
/// different VM than the placement.
pub fn reconciliation_input(
    placement: &Placement,
    record: &VmMetricsRecord,
) -> Result<ReconciliationInput, MicrovmError> {
    if placement.vm_id != record.vm_id {
        return Err(MicrovmError::new(
            ErrorCode::InvalidResourceSpec,
            "metrics record vm_id mismatch",
        )
        .with_context("placement_vm", placement.vm_id.as_str())
        .with_context("record_vm", record.vm_id.as_str()));
    }
    Ok(ReconciliationInput {
        vm_id: placement.vm_id.clone(),
        phase: record.phase,
        reserved_vcpus: placement.vcpu_count,
        reserved_memory_mib: placement.memory_mib,
        observed_memory_mib: observed_memory_mib(record),
        observed_cpu_usage_usec: observed_cpu_usage_usec(record),
    })
}
