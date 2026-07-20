//! A concrete resource placement (plan todo 24).
//!
//! A [`Placement`] is the scheduler's decision: which host a VM lands on, which
//! physical CPUs are reserved, how much memory is reserved, and (when the host
//! is NUMA-aware) which NUMA node owns the allocation. Placements are recorded
//! in the scheduler ledger **before** any lifecycle mutation.

use crate::topology::HostId;
use microvm_types::{TenantId, VmId};
use serde::{Deserialize, Serialize};

/// A concrete placement of one VM onto the host.
///
/// `assigned_cpus` are the exact logical CPU ids reserved for the VM; they are
/// disjoint across all recorded placements (no CPU overcommit). `memory_mib`
/// is reserved against the owning bin (no memory overcommit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    /// The VM this placement is for.
    pub vm_id: VmId,
    /// The host the VM was placed on.
    pub host_id: HostId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Reserved virtual CPUs.
    pub vcpu_count: u32,
    /// Reserved memory in MiB.
    pub memory_mib: u64,
    /// Exact logical CPU ids reserved for the VM (sorted, disjoint per host).
    pub assigned_cpus: Vec<u32>,
    /// NUMA node the allocation landed on, or `None` for a flat (non-NUMA) host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_node: Option<u32>,
}

impl Placement {
    /// The NUMA node this placement is local to, if any.
    #[must_use]
    pub fn numa_node(&self) -> Option<u32> {
        self.numa_node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_serde_roundtrip() {
        let p = Placement {
            vm_id: VmId::new("vm-1").unwrap(),
            host_id: HostId::new("host-0").unwrap(),
            tenant_id: TenantId::new("t-a").unwrap(),
            vcpu_count: 2,
            memory_mib: 512,
            assigned_cpus: vec![0, 1],
            numa_node: Some(0),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: Placement = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn placement_numa_none_omitted_in_json() {
        let p = Placement {
            vm_id: VmId::new("vm-1").unwrap(),
            host_id: HostId::new("host-0").unwrap(),
            tenant_id: TenantId::new("t-a").unwrap(),
            vcpu_count: 1,
            memory_mib: 256,
            assigned_cpus: vec![0],
            numa_node: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("numa_node"));
    }
}
