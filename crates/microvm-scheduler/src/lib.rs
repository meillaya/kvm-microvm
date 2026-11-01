//! Deterministic core-aware bin-packing scheduler with admission control
//! (plan todo 24).
//!
//! This crate decides where a microVM's reserved resources land on a host:
//! which NUMA node (or flat CPU pool) and which concrete logical CPUs. It is a
//! pure decision engine, no I/O, no cgroups, no TAP, no Firecracker, so a
//! scheduling decision can never produce a host side effect.
//!
//! # Model
//! - [`HostTopology`] is the preflight-supplied host description: total CPUs,
//!   total memory, and *optional* NUMA nodes. NUMA awareness is opt-in and
//!   evidence-backed: with no NUMA topology the host is one flat bin and the
//!   scheduler makes no NUMA claim.
//! - [`PlacementRequest`] is a reservation (vCPU + memory + tenant + optional
//!   [`CpuAffinity`]). Reservations are hard limits.
//! - The [`Scheduler`] packs requests into bins (NUMA nodes, or one flat bin)
//!   using first-fit-decreasing for batches and first-fit for single
//!   requests, with per-tenant quota admission control.
//! - A [`Placement`] is the decision (host + concrete CPUs + reserved memory +
//!   owning NUMA node). Placements are recorded before lifecycle mutation.
//! - A no-fit decision is a typed [`Unschedulable`] carrying an
//!   [`UnschedulableReason`].
//!
//! # Guarantees
//! - No overcommit of hard limits: a bin accepts a request only if it has
//!   enough free CPUs *and* free memory; tenant quota is checked first.
//! - Deterministic: identical input yields identical placement (ordered
//!   bins, lowest-id-first CPUs, total FFD sort key, ordered maps; no
//!   randomness or clock).
//! - Pure metrics consumption: [`metrics`] reads [`VmMetricsRecord`]s to
//!   build reconciliation inputs without mutating resources; observed usage
//!   never relaxes hard limits.
//!
//! [`VmMetricsRecord`]: microvm_metrics::VmMetricsRecord

pub mod metrics;
pub mod placement;
pub mod quota;
pub mod request;
pub mod scheduler;
pub mod topology;
pub mod unschedulable;

pub use placement::Placement;
pub use quota::{QuotaPolicy, TenantQuota, TenantUsage};
pub use request::{CpuAffinity, PlacementRequest};
pub use scheduler::Scheduler;
pub use topology::{HostId, HostTopology, NumaNode, MAX_HOST_ID_BYTES};
pub use unschedulable::{QuotaDimension, Unschedulable, UnschedulableReason};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_surface_is_reexported() {
        // Compile-time assertion that the documented surface is re-exported.
        fn _assert<T>() {}
        _assert::<Scheduler>();
        _assert::<Placement>();
        _assert::<PlacementRequest>();
        _assert::<CpuAffinity>();
        _assert::<HostTopology>();
        _assert::<HostId>();
        _assert::<NumaNode>();
        _assert::<TenantQuota>();
        _assert::<TenantUsage>();
        _assert::<QuotaPolicy>();
        _assert::<Unschedulable>();
        _assert::<UnschedulableReason>();
        _assert::<QuotaDimension>();
        _assert::<metrics::ReconciliationInput>();
    }
}
