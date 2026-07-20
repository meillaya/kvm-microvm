//! The deterministic core-aware bin-packing scheduler (plan todo 24).
//!
//! The [`Scheduler`] packs VM reservations into **bins**: the host's NUMA nodes
//! when preflight NUMA topology is present, or a single flat bin covering the
//! whole host otherwise. It uses **first-fit-decreasing** (FFD) ordering for
//! batch placement and **first-fit** for single placement, with per-tenant
//! admission control.
//!
//! # Purity and the record-before-mutate contract
//! The scheduler is pure: it holds only the topology, the quota policy, and an
//! in-memory placement ledger. It performs **no I/O** and never touches
//! cgroups, TAP devices, or Firecracker. [`Scheduler::schedule`] and
//! [`Scheduler::plan_batch`] are read-only queries (`&self`) that compute a
//! placement without mutating the ledger. A placement only affects subsequent
//! decisions once it is **recorded** ([`Scheduler::record`] or
//! [`Scheduler::place`]). Callers must record a placement **before** mutating VM
//! lifecycle state, so the ledger is the single source of truth for reserved
//! resources.
//!
//! # Hard limits never overcommit
//! Reservations are accounted in full up front. A bin accepts a request only if
//! it has enough *free* CPUs **and** enough *free* memory; tenant quota is
//! checked before any placement. Observed runtime metrics never relax these
//! hard limits (see [`crate::metrics`]).
//!
//! # Determinism
//! Identical input always yields identical placement: bins are ordered by NUMA
//! node id, CPUs are assigned lowest-id-first, FFD uses a total sort key, and
//! all maps are ordered (`BTreeMap`/`BTreeSet`). There is no randomness, no
//! clock, and no ambient environment in any decision path.

use crate::placement::Placement;
use crate::quota::{QuotaPolicy, TenantQuota, TenantUsage};
use crate::request::{CpuAffinity, PlacementRequest};
use crate::topology::{HostId, HostTopology};
use crate::unschedulable::{Unschedulable, UnschedulableReason};
use microvm_types::{TenantId, VmId};
use std::collections::{BTreeMap, BTreeSet};

/// Internal per-bin capacity state.
#[derive(Clone, Debug)]
struct BinState {
    /// Owning NUMA node id, or `None` for the flat (non-NUMA) bin.
    numa_node: Option<u32>,
    /// All logical CPUs belonging to this bin (fixed at construction).
    all_cpus: BTreeSet<u32>,
    /// Currently free logical CPUs.
    free_cpus: BTreeSet<u32>,
    /// Total memory for this bin (MiB).
    total_memory_mib: u64,
    /// Currently free memory (MiB).
    free_memory_mib: u64,
}

impl BinState {
    fn free_cpu_count(&self) -> u32 {
        u32::try_from(self.free_cpus.len()).unwrap_or(u32::MAX)
    }

    fn has_capacity(&self, vcpu: u32, memory_mib: u64) -> bool {
        self.free_cpu_count() >= vcpu && self.free_memory_mib >= memory_mib
    }
}

/// Outcome of selecting a bin and CPU set for a request (no mutation yet).
///
/// The owning bin is re-derived from `cpus` at apply time ([`apply_exact`]), so
/// it is not stored here — keeping a single source of truth.
struct Selection {
    cpus: Vec<u32>,
    numa_node: Option<u32>,
}

/// Deterministic core-aware FFD bin-packing scheduler with admission control.
#[derive(Clone, Debug)]
pub struct Scheduler {
    topology: HostTopology,
    quotas: QuotaPolicy,
    bins: Vec<BinState>,
    placements: BTreeMap<VmId, Placement>,
}

impl Scheduler {
    /// Build a scheduler from a preflight topology and a per-tenant quota policy.
    ///
    /// Bins are derived from the topology: one bin per NUMA node (ordered by
    /// node id) when NUMA-aware, otherwise a single flat bin covering all CPUs.
    #[must_use]
    pub fn new(topology: HostTopology, quotas: QuotaPolicy) -> Self {
        let bins = Self::build_bins(&topology);
        Self {
            topology,
            quotas,
            bins,
            placements: BTreeMap::new(),
        }
    }

    fn build_bins(topology: &HostTopology) -> Vec<BinState> {
        match &topology.numa_nodes {
            Some(nodes) => {
                let mut nodes = nodes.clone();
                nodes.sort_by_key(|n| n.id);
                nodes
                    .into_iter()
                    .map(|n| BinState {
                        numa_node: Some(n.id),
                        free_cpus: n.cpus.clone(),
                        total_memory_mib: n.memory_mib,
                        free_memory_mib: n.memory_mib,
                        all_cpus: n.cpus,
                    })
                    .collect()
            }
            None => {
                let cpus: BTreeSet<u32> = (0..topology.cpu_count).collect();
                vec![BinState {
                    numa_node: None,
                    free_cpus: cpus.clone(),
                    total_memory_mib: topology.memory_mib,
                    free_memory_mib: topology.memory_mib,
                    all_cpus: cpus,
                }]
            }
        }
    }

    // -- read-only queries --------------------------------------------------

    /// Compute a placement for a single request against the current ledger,
    /// **without** mutating the scheduler (pure query).
    ///
    /// The returned placement does not affect subsequent scheduling until it is
    /// [`record`](Self::record)ed.
    ///
    /// # Errors
    /// Returns [`Unschedulable`] with a typed reason if the request cannot be
    /// placed (quota, capacity, affinity, or missing NUMA topology).
    pub fn schedule(&self, req: &PlacementRequest) -> Result<Placement, Unschedulable> {
        let mut bins = self.bins.clone();
        let mut placements = self.placements.clone();
        place_into(
            &mut bins,
            &mut placements,
            &self.quotas,
            self.topology.is_numa_aware(),
            &self.topology.host_id,
            req,
        )
    }

    /// Compute placements for a batch of requests using **first-fit-decreasing**
    /// ordering, without mutating the scheduler (pure query).
    ///
    /// Requests are sorted by `(vcpu desc, memory desc, vm_id asc)` and placed
    /// first-fit. The batch is all-or-nothing: on the first request that cannot
    /// be placed, the error is returned and no placement is produced.
    ///
    /// # Errors
    /// Returns the first [`Unschedulable`] encountered in FFD order.
    pub fn plan_batch(&self, reqs: &[PlacementRequest]) -> Result<Vec<Placement>, Unschedulable> {
        let mut order: Vec<&PlacementRequest> = reqs.iter().collect();
        order.sort_by(|a, b| {
            ffd_key(b)
                .cmp(&ffd_key(a))
                .then(a.vm_id.as_str().cmp(b.vm_id.as_str()))
        });

        let mut bins = self.bins.clone();
        let mut placements = self.placements.clone();
        let mut out = Vec::with_capacity(order.len());
        for req in order {
            let p = place_into(
                &mut bins,
                &mut placements,
                &self.quotas,
                self.topology.is_numa_aware(),
                &self.topology.host_id,
                req,
            )?;
            out.push(p);
        }
        // Return in the caller's original request order for stable output.
        out.sort_by(|a, b| a.vm_id.as_str().cmp(b.vm_id.as_str()));
        Ok(out)
    }

    // -- mutating operations (ledger only; never host resources) ------------

    /// Schedule **and** record a request atomically.
    ///
    /// This is the common path: the placement is committed to the ledger before
    /// the caller mutates VM lifecycle state.
    ///
    /// # Errors
    /// Returns [`Unschedulable`] if the request cannot be placed; the ledger is
    /// left unchanged on error.
    pub fn place(&mut self, req: &PlacementRequest) -> Result<Placement, Unschedulable> {
        let placement = place_into(
            &mut self.bins,
            &mut self.placements,
            &self.quotas,
            self.topology.is_numa_aware(),
            &self.topology.host_id,
            req,
        )?;
        Ok(placement)
    }

    /// Record an externally-produced placement into the ledger.
    ///
    /// Re-validates that the placement's exact CPUs are free, that memory fits,
    /// and that tenant quota is respected, so the ledger can never overcommit
    /// even if the placement was computed against a stale view.
    ///
    /// # Errors
    /// Returns [`Unschedulable`] if the VM is already placed, the placement no
    /// longer fits, or quota would be exceeded. The ledger is unchanged on error.
    pub fn record(&mut self, placement: &Placement) -> Result<(), Unschedulable> {
        let reason = record_into(
            &mut self.bins,
            &mut self.placements,
            &self.quotas,
            &self.topology.host_id,
            placement,
        );
        reason.map_err(|reason| Unschedulable::new(placement.vm_id.clone(), reason))
    }

    /// Release a VM's recorded placement, returning its resources to the host.
    ///
    /// Returns the removed placement, or `None` if the VM had no placement.
    pub fn release(&mut self, vm_id: &VmId) -> Option<Placement> {
        let placement = self.placements.remove(vm_id)?;
        if let Some(bin) = bin_for_cpus(&self.bins, &placement.assigned_cpus) {
            let b = &mut self.bins[bin];
            for cpu in &placement.assigned_cpus {
                b.free_cpus.insert(*cpu);
            }
            b.free_memory_mib = b.free_memory_mib.saturating_add(placement.memory_mib);
        }
        Some(placement)
    }

    // -- accessors ----------------------------------------------------------

    /// The host this scheduler places onto.
    #[must_use]
    pub fn host_id(&self) -> &HostId {
        &self.topology.host_id
    }

    /// Whether the scheduler is NUMA-aware (i.e. has preflight NUMA topology).
    #[must_use]
    pub fn is_numa_aware(&self) -> bool {
        self.topology.is_numa_aware()
    }

    /// The number of bins (NUMA nodes, or 1 for a flat host).
    #[must_use]
    pub fn bin_count(&self) -> usize {
        self.bins.len()
    }

    /// All recorded placements, keyed by VM id.
    #[must_use]
    pub fn placements(&self) -> &BTreeMap<VmId, Placement> {
        &self.placements
    }

    /// Derived current usage for a tenant from recorded placements.
    #[must_use]
    pub fn tenant_usage(&self, tenant: &TenantId) -> TenantUsage {
        tenant_usage_from(&self.placements, tenant)
    }

    /// Total vCPU capacity across all bins (NUMA nodes or the flat pool).
    #[must_use]
    pub fn total_vcpus(&self) -> u32 {
        self.bins.iter().fold(0u32, |acc, b| {
            acc.saturating_add(u32::try_from(b.all_cpus.len()).unwrap_or(u32::MAX))
        })
    }

    /// Total memory capacity (MiB) across all bins.
    #[must_use]
    pub fn total_memory_mib(&self) -> u64 {
        self.bins
            .iter()
            .fold(0u64, |acc, b| acc.saturating_add(b.total_memory_mib))
    }

    /// Total free vCPUs across all bins.
    #[must_use]
    pub fn available_vcpus(&self) -> u32 {
        self.bins
            .iter()
            .fold(0u32, |acc, b| acc.saturating_add(b.free_cpu_count()))
    }

    /// Total free memory (MiB) across all bins.
    #[must_use]
    pub fn available_memory_mib(&self) -> u64 {
        self.bins
            .iter()
            .fold(0u64, |acc, b| acc.saturating_add(b.free_memory_mib))
    }

    /// Free vCPUs on a specific NUMA node, or `None` if the node is unknown.
    #[must_use]
    pub fn available_vcpus_on_node(&self, node: u32) -> Option<u32> {
        self.bins
            .iter()
            .find(|b| b.numa_node == Some(node))
            .map(BinState::free_cpu_count)
    }
}

/// FFD sort weight: larger reservations first.
fn ffd_key(req: &PlacementRequest) -> (u32, u64) {
    (req.vcpu_count, req.memory_mib)
}

/// Core placement: admission control, bin/CPU selection, then commit to the
/// working bins and placements.
fn place_into(
    bins: &mut [BinState],
    placements: &mut BTreeMap<VmId, Placement>,
    quotas: &QuotaPolicy,
    numa_aware: bool,
    host_id: &HostId,
    req: &PlacementRequest,
) -> Result<Placement, Unschedulable> {
    let fail = |reason: UnschedulableReason| Unschedulable::new(req.vm_id.clone(), reason);

    if placements.contains_key(&req.vm_id) {
        return Err(fail(UnschedulableReason::DuplicatePlacement {
            vm_id: req.vm_id.clone(),
        }));
    }
    check_quota(quotas, placements, req).map_err(fail)?;

    let selection = select_bin_and_cpus(bins, numa_aware, req).map_err(fail)?;
    let placement = Placement {
        vm_id: req.vm_id.clone(),
        host_id: host_id.clone(),
        tenant_id: req.tenant_id.clone(),
        vcpu_count: req.vcpu_count,
        memory_mib: req.memory_mib,
        assigned_cpus: selection.cpus,
        numa_node: selection.numa_node,
    };
    apply_exact(bins, &placement).map_err(fail)?;
    placements.insert(req.vm_id.clone(), placement.clone());
    Ok(placement)
}

/// Commit a pre-built placement, re-validating fit and quota.
fn record_into(
    bins: &mut [BinState],
    placements: &mut BTreeMap<VmId, Placement>,
    quotas: &QuotaPolicy,
    host_id: &HostId,
    placement: &Placement,
) -> Result<(), UnschedulableReason> {
    if placement.host_id != *host_id {
        return Err(UnschedulableReason::AffinityUnsatisfiable {
            detail: "placement host does not match scheduler host".to_string(),
        });
    }
    if placements.contains_key(&placement.vm_id) {
        return Err(UnschedulableReason::DuplicatePlacement {
            vm_id: placement.vm_id.clone(),
        });
    }
    check_quota_exact(
        quotas,
        placements,
        &placement.tenant_id,
        placement.vcpu_count,
        placement.memory_mib,
    )?;
    apply_exact(bins, placement)?;
    placements.insert(placement.vm_id.clone(), placement.clone());
    Ok(())
}

/// Select the first fitting bin and concrete CPUs for a request (no mutation).
fn select_bin_and_cpus(
    bins: &[BinState],
    numa_aware: bool,
    req: &PlacementRequest,
) -> Result<Selection, UnschedulableReason> {
    match &req.affinity {
        CpuAffinity::None => select_first_fit(bins, req),
        CpuAffinity::NumaNode { node } => select_on_node(bins, numa_aware, *node, req),
        CpuAffinity::CpuSet { cpus } => select_cpu_set(bins, cpus, req),
    }
}

/// First-fit over all bins, lowest-id CPUs first.
fn select_first_fit(
    bins: &[BinState],
    req: &PlacementRequest,
) -> Result<Selection, UnschedulableReason> {
    for bin in bins.iter() {
        if bin.has_capacity(req.vcpu_count, req.memory_mib) {
            let cpus = lowest_cpus(bin, req.vcpu_count);
            return Ok(Selection {
                cpus,
                numa_node: bin.numa_node,
            });
        }
    }
    Err(no_fit_reason(
        &bins.iter().collect::<Vec<_>>(),
        req.vcpu_count,
        req.memory_mib,
    ))
}

/// First-fit restricted to a specific NUMA node.
fn select_on_node(
    bins: &[BinState],
    numa_aware: bool,
    node: u32,
    req: &PlacementRequest,
) -> Result<Selection, UnschedulableReason> {
    if !numa_aware {
        return Err(UnschedulableReason::NumaTopologyUnavailable);
    }
    let Some(idx) = bins.iter().position(|b| b.numa_node == Some(node)) else {
        return Err(UnschedulableReason::UnknownNumaNode { requested: node });
    };
    let bin = &bins[idx];
    if !bin.has_capacity(req.vcpu_count, req.memory_mib) {
        return Err(no_fit_reason(&[bin], req.vcpu_count, req.memory_mib));
    }
    Ok(Selection {
        cpus: lowest_cpus(bin, req.vcpu_count),
        numa_node: Some(node),
    })
}

/// Pin to an exact CPU set; all CPUs must exist, be in one bin, and be free.
fn select_cpu_set(
    bins: &[BinState],
    cpus: &BTreeSet<u32>,
    req: &PlacementRequest,
) -> Result<Selection, UnschedulableReason> {
    let unknown = unknown_cpus(bins, cpus);
    if !unknown.is_empty() {
        return Err(UnschedulableReason::UnknownCpus { unknown });
    }
    let Some(idx) = bin_for_cpus(bins, &cpus.iter().copied().collect::<Vec<_>>()) else {
        return Err(UnschedulableReason::AffinityUnsatisfiable {
            detail: "cpu set spans multiple numa bins".to_string(),
        });
    };
    let bin = &bins[idx];
    if !cpus.iter().all(|c| bin.free_cpus.contains(c)) {
        return Err(UnschedulableReason::AffinityUnsatisfiable {
            detail: "requested cpus are not all free".to_string(),
        });
    }
    if bin.free_memory_mib < req.memory_mib {
        return Err(no_fit_reason(&[bin], req.vcpu_count, req.memory_mib));
    }
    Ok(Selection {
        cpus: cpus.iter().copied().collect(),
        numa_node: bin.numa_node,
    })
}

/// The lowest `count` free CPUs in a bin (deterministic: ascending order).
fn lowest_cpus(bin: &BinState, count: u32) -> Vec<u32> {
    bin.free_cpus.iter().take(count as usize).copied().collect()
}

/// CPUs requested that are not present in any bin.
fn unknown_cpus(bins: &[BinState], cpus: &BTreeSet<u32>) -> Vec<u32> {
    cpus.iter()
        .copied()
        .filter(|c| !bins.iter().any(|b| b.all_cpus.contains(c)))
        .collect()
}

/// Index of the single bin whose `all_cpus` contains every CPU in `cpus`.
///
/// Returns `None` if `cpus` is empty or spans more than one bin.
fn bin_for_cpus(bins: &[BinState], cpus: &[u32]) -> Option<usize> {
    if cpus.is_empty() {
        return None;
    }
    let mut owner: Option<usize> = None;
    for c in cpus {
        let idx = bins.iter().position(|b| b.all_cpus.contains(c))?;
        match owner {
            Some(o) if o != idx => return None,
            Some(_) => {}
            None => owner = Some(idx),
        }
    }
    owner
}

/// Apply a placement's exact CPU/memory reservation to the owning bin.
fn apply_exact(bins: &mut [BinState], placement: &Placement) -> Result<(), UnschedulableReason> {
    let idx = bin_for_cpus(bins, &placement.assigned_cpus).ok_or_else(|| {
        UnschedulableReason::AffinityUnsatisfiable {
            detail: "placement cpus do not belong to a single bin".to_string(),
        }
    })?;
    let bin = &mut bins[idx];
    if !placement
        .assigned_cpus
        .iter()
        .all(|c| bin.free_cpus.contains(c))
    {
        return Err(UnschedulableReason::AffinityUnsatisfiable {
            detail: "placement cpus are no longer free".to_string(),
        });
    }
    if bin.free_memory_mib < placement.memory_mib {
        return Err(UnschedulableReason::InsufficientMemory {
            requested_mib: placement.memory_mib,
            available_mib: bin.free_memory_mib,
        });
    }
    for c in &placement.assigned_cpus {
        bin.free_cpus.remove(c);
    }
    bin.free_memory_mib -= placement.memory_mib;
    Ok(())
}

/// Build a typed no-fit reason from the candidate bins.
fn no_fit_reason(candidates: &[&BinState], vcpu: u32, memory_mib: u64) -> UnschedulableReason {
    let cpu_ok_any = candidates.iter().any(|b| b.free_cpu_count() >= vcpu);
    if !cpu_ok_any {
        let available = candidates
            .iter()
            .map(|b| b.free_cpu_count())
            .max()
            .unwrap_or(0);
        return UnschedulableReason::InsufficientCpu {
            requested: vcpu,
            available,
        };
    }
    let available_mib = candidates
        .iter()
        .filter(|b| b.free_cpu_count() >= vcpu)
        .map(|b| b.free_memory_mib)
        .max()
        .unwrap_or(0);
    UnschedulableReason::InsufficientMemory {
        requested_mib: memory_mib,
        available_mib,
    }
}

/// Quota check for a request against derived usage.
fn check_quota(
    quotas: &QuotaPolicy,
    placements: &BTreeMap<VmId, Placement>,
    req: &PlacementRequest,
) -> Result<(), UnschedulableReason> {
    check_quota_exact(
        quotas,
        placements,
        &req.tenant_id,
        req.vcpu_count,
        req.memory_mib,
    )
}

/// Quota check for explicit tenant/vcpu/memory against derived usage.
fn check_quota_exact(
    quotas: &QuotaPolicy,
    placements: &BTreeMap<VmId, Placement>,
    tenant: &TenantId,
    vcpu: u32,
    memory_mib: u64,
) -> Result<(), UnschedulableReason> {
    let usage = tenant_usage_from(placements, tenant);
    let Some(quota) = quotas.get(tenant) else {
        return Err(UnschedulableReason::NoQuotaForTenant {
            tenant: tenant.clone(),
        });
    };
    check_quota_limits(quota, usage, tenant, vcpu, memory_mib)
}

/// Pure quota-limit comparison (fail closed on any exceeded dimension).
fn check_quota_limits(
    quota: &TenantQuota,
    usage: TenantUsage,
    tenant: &TenantId,
    vcpu: u32,
    memory_mib: u64,
) -> Result<(), UnschedulableReason> {
    use crate::unschedulable::QuotaDimension;
    if usage.vm_count >= quota.max_vms {
        return Err(UnschedulableReason::QuotaExceeded {
            tenant: tenant.clone(),
            dimension: QuotaDimension::Vms,
            limit: u64::from(quota.max_vms),
            current: u64::from(usage.vm_count),
            requested: 1,
        });
    }
    let vcpus_after = usage.vcpus_used.saturating_add(vcpu);
    if vcpus_after > quota.max_vcpus {
        return Err(UnschedulableReason::QuotaExceeded {
            tenant: tenant.clone(),
            dimension: QuotaDimension::Vcpus,
            limit: u64::from(quota.max_vcpus),
            current: u64::from(usage.vcpus_used),
            requested: u64::from(vcpu),
        });
    }
    let memory_after = usage.memory_mib_used.saturating_add(memory_mib);
    if memory_after > quota.max_memory_mib {
        return Err(UnschedulableReason::QuotaExceeded {
            tenant: tenant.clone(),
            dimension: QuotaDimension::MemoryMib,
            limit: quota.max_memory_mib,
            current: usage.memory_mib_used,
            requested: memory_mib,
        });
    }
    Ok(())
}

/// Derive a tenant's current usage from recorded placements.
fn tenant_usage_from(placements: &BTreeMap<VmId, Placement>, tenant: &TenantId) -> TenantUsage {
    let mut usage = TenantUsage::default();
    for p in placements.values().filter(|p| &p.tenant_id == tenant) {
        usage.vcpus_used = usage.vcpus_used.saturating_add(p.vcpu_count);
        usage.memory_mib_used = usage.memory_mib_used.saturating_add(p.memory_mib);
        usage.vm_count = usage.vm_count.saturating_add(1);
    }
    usage
}
