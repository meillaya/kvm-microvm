//! Placement requests and CPU-affinity constraints (plan todo 24).

use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::{TenantId, VmId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// CPU-affinity constraint attached to a [`PlacementRequest`].
///
/// Affinity is optional: [`CpuAffinity::None`] lets the scheduler place the
/// VM on any fitting bin. NUMA-node and CPU-set affinities are only honored when
/// the host topology actually carries the corresponding preflight metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CpuAffinity {
    /// No affinity; place on the first fitting bin.
    #[default]
    None,
    /// Require placement on a specific NUMA node.
    NumaNode {
        /// The required NUMA node id.
        node: u32,
    },
    /// Require the VM's vCPUs to be pinned to exactly this set of logical CPUs.
    ///
    /// The set size must equal the request's `vcpu_count` (validated at
    /// construction).
    CpuSet {
        /// The exact logical CPU ids to pin to.
        cpus: BTreeSet<u32>,
    },
}

/// A request to place one VM's reserved resources onto the host.
///
/// Reservations are hard limits: the scheduler accounts the full
/// `vcpu_count` and `memory_mib` up front and never overcommits them,
/// regardless of observed runtime usage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRequest {
    /// The VM this placement is for. Used as the ledger key.
    pub vm_id: VmId,
    /// Reserved virtual CPUs (hard limit).
    pub vcpu_count: u32,
    /// Reserved memory in MiB (hard limit).
    pub memory_mib: u64,
    /// Owning tenant; quota is enforced per tenant.
    pub tenant_id: TenantId,
    /// Optional CPU-affinity constraint.
    #[serde(default)]
    pub affinity: CpuAffinity,
}

impl PlacementRequest {
    /// Build a validated placement request.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] when `vcpu_count` or
    /// `memory_mib` is zero, or when a [`CpuAffinity::CpuSet`] size does not
    /// equal `vcpu_count`.
    pub fn new(
        vm_id: VmId,
        vcpu_count: u32,
        memory_mib: u64,
        tenant_id: TenantId,
        affinity: CpuAffinity,
    ) -> Result<Self, MicrovmError> {
        if vcpu_count == 0 {
            return Err(Self::spec_error("vcpu_count must be greater than zero"));
        }
        if memory_mib == 0 {
            return Err(Self::spec_error("memory_mib must be greater than zero"));
        }
        if let CpuAffinity::CpuSet { cpus } = &affinity {
            let cpus_len = u32::try_from(cpus.len()).unwrap_or(u32::MAX);
            if cpus_len != vcpu_count {
                return Err(Self::spec_error("cpu set size must equal vcpu_count"));
            }
        }
        Ok(Self {
            vm_id,
            vcpu_count,
            memory_mib,
            tenant_id,
            affinity,
        })
    }

    fn spec_error(reason: &'static str) -> MicrovmError {
        MicrovmError::new(ErrorCode::InvalidResourceSpec, "invalid placement request")
            .with_context("reason", reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).unwrap()
    }

    #[test]
    fn valid_request() {
        let req =
            PlacementRequest::new(vm("vm-1"), 2, 512, tenant("t-a"), CpuAffinity::None).unwrap();
        assert_eq!(req.vcpu_count, 2);
        assert_eq!(req.memory_mib, 512);
        assert_eq!(req.affinity, CpuAffinity::None);
    }

    #[test]
    fn zero_vcpu_or_memory_rejected() {
        assert!(
            PlacementRequest::new(vm("vm-1"), 0, 512, tenant("t-a"), CpuAffinity::None).is_err()
        );
        assert!(PlacementRequest::new(vm("vm-1"), 1, 0, tenant("t-a"), CpuAffinity::None).is_err());
    }

    #[test]
    fn cpuset_size_must_equal_vcpu() {
        let cpus: BTreeSet<u32> = [0, 1, 2].into_iter().collect();
        // 3 cpus but vcpu_count 2 -> rejected.
        assert!(PlacementRequest::new(
            vm("vm-1"),
            2,
            512,
            tenant("t-a"),
            CpuAffinity::CpuSet { cpus }
        )
        .is_err());
    }

    #[test]
    fn cpuset_size_matching_vcpu_ok() {
        let cpus: BTreeSet<u32> = [0, 1].into_iter().collect();
        assert!(PlacementRequest::new(
            vm("vm-1"),
            2,
            512,
            tenant("t-a"),
            CpuAffinity::CpuSet { cpus }
        )
        .is_ok());
    }

    #[test]
    fn affinity_default_is_none() {
        assert_eq!(CpuAffinity::default(), CpuAffinity::None);
    }

    #[test]
    fn request_serde_roundtrip() {
        let req =
            PlacementRequest::new(vm("vm-1"), 2, 512, tenant("t-a"), CpuAffinity::None).unwrap();
        let json = serde_json::to_string(&req).unwrap();
        let back: PlacementRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }
}
