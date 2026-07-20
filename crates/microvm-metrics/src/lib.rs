//! Per-VM host and guest metrics with a stable, availability-flagged schema
//! (plan todo 23).
//!
//! This crate collects, for each microVM:
//! - **Host cgroup-v2 metrics** ([`CgroupMetrics`]): CPU usage/throttling,
//!   memory current/events, block IO, and pids.
//! - **TAP network counters** ([`NetworkMetrics`]): RX/TX byte counters plus
//!   derived RX/TX throughput.
//! - **Monotonic boot/restore phases** ([`PhaseMarkers`], [`MetricsPhase`]):
//!   host-monotonic spans for boot and restore, with derived durations.
//! - **Optional guest-agent metrics** ([`GuestMetrics`]): guest CPU steal,
//!   load, and RSS, available only when a guest agent is reachable.
//!
//! The full snapshot is [`VmMetricsRecord`], whose wire schema is
//! `schemas/vm-metrics-record.v1.json`.
//!
//! # Core invariant: never zero-fill missing data
//! Every source is wrapped in [`Availability`]: a source either produced a
//! value ([`Availability::Available`]) or it is explicitly
//! [`Availability::Unavailable`] with a bounded [`UnavailableReason`]. A
//! missing guest agent or a removed cgroup is reported as *unavailable* —
//! never as a measured `0`.
//!
//! # Bounded cardinality
//! The record carries no free-form label maps. Error counters are keyed by the
//! fixed [`MetricErrorKind`] enum, and identifiers are validated [`VmId`]s, so
//! label cardinality is bounded by construction.
//!
//! # Determinism
//! [`MetricsCollector`] reads from configurable roots (cgroup leaf dir, sysfs
//! root) plus an injectable [`GuestAgentReader`] and [`Clock`]. Tests exercise
//! it against a temporary directory and a fixed clock — no privileged host
//! capabilities required. Sampling stops after VM cleanup
//! ([`MetricsCollector::stop_sampling`]).
//!
//! [`VmId`]: microvm_types::VmId

pub mod availability;
pub mod cgroup;
pub mod collector;
pub mod guest;
pub mod network;
pub mod record;

pub use availability::{Availability, UnavailableReason};
pub use cgroup::{CgroupMetrics, CpuStat, IoMetrics, MemoryEvents};
pub use collector::{
    write_cgroup_fixture, write_tap_fixture, Clock, ManualClock, MetricsCollector, PhaseMarker,
    SystemClock,
};
pub use guest::{GuestAgentReader, GuestAgentSample, GuestMetrics, NoGuestAgent, StaticGuestAgent};
pub use network::NetworkMetrics;
pub use record::{MetricErrorKind, MetricsPhase, PhaseMarkers, VmMetricsRecord, SCHEMA_VERSION};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_surface_is_reexported() {
        // Compile-time smoke test that the documented surface is exported.
        let _ = SCHEMA_VERSION;
        let _ = MetricErrorKind::all();
        let _ = MetricsPhase::Running.as_str();
        let _: fn() -> Availability<u64> =
            || Availability::Unavailable(UnavailableReason::NoBackend);
    }
}
