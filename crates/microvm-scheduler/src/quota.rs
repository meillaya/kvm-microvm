//! Tenant quotas and derived usage for scheduling (plan todo 24).
//!
//! The scheduler enforces the quota dimensions it packs: vCPUs, memory, and VM
//! count. (Disk quota is an artifact/lifecycle concern, not a core-aware
//! bin-packing concern, so it is intentionally out of scope here.) Quota is
//! checked before any placement is recorded, mirroring the lifecycle
//! contract that over-quota requests are rejected without side effects.

use microvm_types::TenantId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Per-tenant scheduling quotas. All fields are upper bounds.
///
/// A value of `0` means the dimension is entirely disallowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantQuota {
    /// Maximum total reserved vCPUs across the tenant's VMs.
    pub max_vcpus: u32,
    /// Maximum total reserved memory (MiB) across the tenant's VMs.
    pub max_memory_mib: u64,
    /// Maximum number of VMs the tenant may have placed.
    pub max_vms: u32,
}

/// Current derived usage for a tenant, computed from recorded placements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantUsage {
    /// Reserved vCPUs currently allocated.
    pub vcpus_used: u32,
    /// Reserved memory (MiB) currently allocated.
    pub memory_mib_used: u64,
    /// Number of VMs currently placed.
    pub vm_count: u32,
}

/// A quota policy: a quota per tenant.
///
/// Tenants without an entry are fail-closed: a placement request for an
/// unconfigured tenant is rejected with `NoQuotaForTenant`.
pub type QuotaPolicy = BTreeMap<TenantId, TenantQuota>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_usage_default_is_zero() {
        let u = TenantUsage::default();
        assert_eq!(u.vcpus_used, 0);
        assert_eq!(u.memory_mib_used, 0);
        assert_eq!(u.vm_count, 0);
    }

    #[test]
    fn quota_serde_roundtrip() {
        let q = TenantQuota {
            max_vcpus: 16,
            max_memory_mib: 8192,
            max_vms: 10,
        };
        let json = serde_json::to_string(&q).unwrap();
        let back: TenantQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn quota_policy_is_a_btree_map() {
        let mut p = QuotaPolicy::new();
        p.insert(
            TenantId::new("t-a").unwrap(),
            TenantQuota {
                max_vcpus: 4,
                max_memory_mib: 1024,
                max_vms: 2,
            },
        );
        assert_eq!(p.len(), 1);
    }
}
