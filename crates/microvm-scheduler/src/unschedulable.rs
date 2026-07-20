//! Typed unschedulable reasons (plan todo 24).
//!
//! When a request cannot be placed, the scheduler returns an [`Unschedulable`]
//! carrying a typed [`UnschedulableReason`]. There are no free-form strings in
//! the reason itself — every variant is a stable, machine-readable case. The
//! scheduler is pure: returning `Unschedulable` never touches cgroups, TAP, or
//! Firecracker, so a no-fit decision has **zero** host side effects.

use microvm_types::{TenantId, VmId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The quota dimension that a placement would exceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaDimension {
    /// Total reserved vCPUs across the tenant.
    Vcpus,
    /// Total reserved memory (MiB) across the tenant.
    MemoryMib,
    /// Number of VMs owned by the tenant.
    Vms,
}

impl QuotaDimension {
    /// Stable `snake_case` string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vcpus => "vcpus",
            Self::MemoryMib => "memory_mib",
            Self::Vms => "vms",
        }
    }
}

impl fmt::Display for QuotaDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a request could not be placed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum UnschedulableReason {
    /// No bin has enough free vCPUs for the request.
    InsufficientCpu {
        /// vCPUs requested.
        requested: u32,
        /// Largest free vCPU count across all candidate bins.
        available: u32,
    },
    /// No bin has enough free memory for the request.
    InsufficientMemory {
        /// Memory requested (MiB).
        requested_mib: u64,
        /// Largest free memory across all candidate bins (MiB).
        available_mib: u64,
    },
    /// The request would exceed a tenant quota.
    QuotaExceeded {
        /// The tenant whose quota would be exceeded.
        tenant: TenantId,
        /// The quota dimension that would be exceeded.
        dimension: QuotaDimension,
        /// The quota limit.
        limit: u64,
        /// Current usage in that dimension.
        current: u64,
        /// Requested amount in that dimension.
        requested: u64,
    },
    /// No quota is configured for the tenant (fail closed).
    NoQuotaForTenant {
        /// The tenant with no configured quota.
        tenant: TenantId,
    },
    /// NUMA-aware placement was requested but the host has no preflight NUMA
    /// topology. The scheduler refuses to claim NUMA awareness in this case.
    NumaTopologyUnavailable,
    /// The requested NUMA node does not exist in the topology.
    UnknownNumaNode {
        /// The requested node id.
        requested: u32,
    },
    /// The requested CPU set references CPUs not present in the topology.
    UnknownCpus {
        /// Requested CPU ids that are not part of the host topology.
        unknown: Vec<u32>,
    },
    /// The affinity constraint cannot be satisfied (e.g. the CPU set spans
    /// multiple NUMA bins, or the pinned CPUs are not all free / not enough
    /// memory is local to their bin).
    AffinityUnsatisfiable {
        /// Human-readable detail (bounded, scheduler-generated).
        detail: String,
    },
    /// The VM already has a recorded placement.
    DuplicatePlacement {
        /// The VM that is already placed.
        vm_id: VmId,
    },
}

impl UnschedulableReason {
    /// Stable `snake_case` tag for the reason case.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InsufficientCpu { .. } => "insufficient_cpu",
            Self::InsufficientMemory { .. } => "insufficient_memory",
            Self::QuotaExceeded { .. } => "quota_exceeded",
            Self::NoQuotaForTenant { .. } => "no_quota_for_tenant",
            Self::NumaTopologyUnavailable => "numa_topology_unavailable",
            Self::UnknownNumaNode { .. } => "unknown_numa_node",
            Self::UnknownCpus { .. } => "unknown_cpus",
            Self::AffinityUnsatisfiable { .. } => "affinity_unsatisfiable",
            Self::DuplicatePlacement { .. } => "duplicate_placement",
        }
    }
}

impl fmt::Display for UnschedulableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientCpu {
                requested,
                available,
            } => write!(
                f,
                "insufficient cpu: requested {} vcpus, largest free bin has {}",
                requested, available
            ),
            Self::InsufficientMemory {
                requested_mib,
                available_mib,
            } => write!(
                f,
                "insufficient memory: requested {} MiB, largest free bin has {} MiB",
                requested_mib, available_mib
            ),
            Self::QuotaExceeded {
                tenant,
                dimension,
                limit,
                current,
                requested,
            } => write!(
                f,
                "quota exceeded for tenant {}: {} limit {} (current {}, requested {})",
                tenant, dimension, limit, current, requested
            ),
            Self::NoQuotaForTenant { tenant } => {
                write!(f, "no quota configured for tenant {}", tenant)
            }
            Self::NumaTopologyUnavailable => {
                f.write_str("numa-aware placement requested but no preflight numa topology")
            }
            Self::UnknownNumaNode { requested } => {
                write!(f, "unknown numa node {}", requested)
            }
            Self::UnknownCpus { unknown } => {
                write!(f, "cpus not present in topology: {:?}", unknown)
            }
            Self::AffinityUnsatisfiable { detail } => {
                write!(f, "affinity unsatisfiable: {}", detail)
            }
            Self::DuplicatePlacement { vm_id } => {
                write!(f, "vm {} already has a recorded placement", vm_id)
            }
        }
    }
}

/// A typed no-fit decision for one VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unschedulable {
    /// The VM that could not be placed.
    pub vm_id: VmId,
    /// The typed reason.
    pub reason: UnschedulableReason,
}

impl Unschedulable {
    /// Construct an unschedulable decision for a VM.
    #[must_use]
    pub fn new(vm_id: VmId, reason: UnschedulableReason) -> Self {
        Self { vm_id, reason }
    }
}

impl fmt::Display for Unschedulable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unschedulable vm {}: {}", self.vm_id, self.reason)
    }
}

impl std::error::Error for Unschedulable {}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    #[test]
    fn reason_tags_are_stable() {
        assert_eq!(
            UnschedulableReason::NumaTopologyUnavailable.as_str(),
            "numa_topology_unavailable"
        );
        assert_eq!(
            UnschedulableReason::InsufficientCpu {
                requested: 4,
                available: 2
            }
            .as_str(),
            "insufficient_cpu"
        );
    }

    #[test]
    fn unschedulable_display() {
        let u = Unschedulable::new(
            vm("vm-1"),
            UnschedulableReason::InsufficientMemory {
                requested_mib: 1024,
                available_mib: 512,
            },
        );
        assert!(u.to_string().contains("vm-1"));
        assert!(u.to_string().contains("insufficient memory"));
    }

    #[test]
    fn unschedulable_serde_roundtrip() {
        let u = Unschedulable::new(
            vm("vm-1"),
            UnschedulableReason::QuotaExceeded {
                tenant: TenantId::new("t-a").unwrap(),
                dimension: QuotaDimension::Vcpus,
                limit: 8,
                current: 7,
                requested: 2,
            },
        );
        let json = serde_json::to_string(&u).unwrap();
        let back: Unschedulable = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn quota_dimension_display() {
        assert_eq!(QuotaDimension::Vcpus.to_string(), "vcpus");
        assert_eq!(QuotaDimension::MemoryMib.to_string(), "memory_mib");
        assert_eq!(QuotaDimension::Vms.to_string(), "vms");
    }

    #[test]
    fn unschedulable_is_std_error() {
        let u = Unschedulable::new(vm("vm-1"), UnschedulableReason::NumaTopologyUnavailable);
        let dyn_err: &dyn std::error::Error = &u;
        assert!(dyn_err.to_string().contains("numa"));
    }
}
