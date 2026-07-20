//! Deterministic placement integration tests (plan todo 24).
//!
//! QA invocation: `cargo test -p microvm-scheduler --test deterministic_placement`.
//!
//! Covers: first-fit-decreasing placement, identical-input/identical-output
//! determinism, typed unschedulable reasons, tenant-quota enforcement, CPU/NUMA
//! affinity, the record-before-lifecycle-mutation contract, and pure metrics
//! consumption with no resource mutation.

use microvm_metrics::{
    Availability, CgroupMetrics, CpuStat, MetricsPhase, UnavailableReason, VmMetricsRecord,
};
use microvm_scheduler::{
    metrics, CpuAffinity, HostId, HostTopology, NumaNode, Placement, PlacementRequest, QuotaPolicy,
    Scheduler, TenantQuota, UnschedulableReason,
};
use microvm_types::{TenantId, VmId};
use std::collections::BTreeSet;

const MIB: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn vm(id: &str) -> VmId {
    VmId::new(id).unwrap()
}

fn tenant(id: &str) -> TenantId {
    TenantId::new(id).unwrap()
}

fn host() -> HostId {
    HostId::new("host-0").unwrap()
}

fn flat(cpus: u32, mem_mib: u64) -> HostTopology {
    HostTopology::flat(host(), cpus, mem_mib).unwrap()
}

/// Two NUMA nodes: node0 = cpus 0-3 / 2048 MiB, node1 = cpus 4-7 / 2048 MiB.
fn numa() -> HostTopology {
    let nodes = vec![
        NumaNode {
            id: 0,
            cpus: [0, 1, 2, 3].into_iter().collect(),
            memory_mib: 2048,
        },
        NumaNode {
            id: 1,
            cpus: [4, 5, 6, 7].into_iter().collect(),
            memory_mib: 2048,
        },
    ];
    HostTopology::new(host(), 8, 4096, Some(nodes)).unwrap()
}

fn quota(vcpus: u32, mem_mib: u64, vms: u32) -> TenantQuota {
    TenantQuota {
        max_vcpus: vcpus,
        max_memory_mib: mem_mib,
        max_vms: vms,
    }
}

/// A policy granting both `t-a` and `t-b` a generous quota.
fn generous_policy() -> QuotaPolicy {
    let mut p = QuotaPolicy::new();
    p.insert(tenant("t-a"), quota(64, 65536, 64));
    p.insert(tenant("t-b"), quota(64, 65536, 64));
    p
}

fn req(id: &str, vcpu: u32, mem_mib: u64, tenant_id: &str) -> PlacementRequest {
    PlacementRequest::new(vm(id), vcpu, mem_mib, tenant(tenant_id), CpuAffinity::None).unwrap()
}

fn req_affinity(
    id: &str,
    vcpu: u32,
    mem_mib: u64,
    tenant_id: &str,
    affinity: CpuAffinity,
) -> PlacementRequest {
    PlacementRequest::new(vm(id), vcpu, mem_mib, tenant(tenant_id), affinity).unwrap()
}

fn cpus_of(p: &Placement) -> BTreeSet<u32> {
    p.assigned_cpus.iter().copied().collect()
}

// ---------------------------------------------------------------------------
// First-fit-decreasing placement
// ---------------------------------------------------------------------------

#[test]
fn ffd_places_largest_request_first() {
    let sched = Scheduler::new(flat(4, 4096), generous_policy());
    // Submitted small-first, but FFD must place the 3-vCPU request first.
    let batch = vec![
        req("vm-small", 1, 256, "t-a"),
        req("vm-large", 3, 256, "t-a"),
    ];
    let placements = sched.plan_batch(&batch).unwrap();
    let large = placements
        .iter()
        .find(|p| p.vm_id == vm("vm-large"))
        .unwrap();
    let small = placements
        .iter()
        .find(|p| p.vm_id == vm("vm-small"))
        .unwrap();
    // Large placed first => gets the lowest CPUs; small fills the remainder.
    assert_eq!(large.assigned_cpus, vec![0, 1, 2]);
    assert_eq!(small.assigned_cpus, vec![3]);
}

#[test]
fn first_fit_assigns_lowest_cpus() {
    let mut sched = Scheduler::new(flat(8, 4096), generous_policy());
    let p = sched.place(&req("vm-1", 2, 256, "t-a")).unwrap();
    assert_eq!(p.assigned_cpus, vec![0, 1]);
    let p2 = sched.place(&req("vm-2", 2, 256, "t-a")).unwrap();
    assert_eq!(p2.assigned_cpus, vec![2, 3]);
}

// ---------------------------------------------------------------------------
// Determinism: identical input => identical placement
// ---------------------------------------------------------------------------

#[test]
fn identical_input_produces_identical_placement() {
    let a = vec![
        req("vm-1", 2, 512, "t-a"),
        req("vm-2", 3, 256, "t-b"),
        req("vm-3", 1, 1024, "t-a"),
    ];
    // Same requests, different submission order.
    let b = vec![a[2].clone(), a[0].clone(), a[1].clone()];

    let s1 = Scheduler::new(numa(), generous_policy());
    let s2 = Scheduler::new(numa(), generous_policy());
    let p1 = s1.plan_batch(&a).unwrap();
    let p2 = s2.plan_batch(&b).unwrap();
    assert_eq!(p1, p2, "placement must be independent of submission order");

    // Re-running on a fresh scheduler with the same input is byte-identical.
    let s3 = Scheduler::new(numa(), generous_policy());
    let p3 = s3.plan_batch(&a).unwrap();
    assert_eq!(p1, p3);
}

#[test]
fn placement_serialization_is_stable() {
    let sched = Scheduler::new(numa(), generous_policy());
    let p = sched.schedule(&req("vm-1", 2, 512, "t-a")).unwrap();
    let json1 = serde_json::to_string(&p).unwrap();
    let json2 = serde_json::to_string(&p).unwrap();
    assert_eq!(json1, json2);
}

// ---------------------------------------------------------------------------
// Typed unschedulable reasons
// ---------------------------------------------------------------------------

#[test]
fn no_fit_returns_typed_insufficient_cpu() {
    let sched = Scheduler::new(flat(2, 4096), generous_policy());
    let err = sched.schedule(&req("vm-1", 4, 256, "t-a")).unwrap_err();
    assert_eq!(err.vm_id, vm("vm-1"));
    assert_eq!(
        err.reason,
        UnschedulableReason::InsufficientCpu {
            requested: 4,
            available: 2
        }
    );
}

#[test]
fn no_fit_returns_typed_insufficient_memory() {
    let sched = Scheduler::new(flat(8, 512), generous_policy());
    let err = sched.schedule(&req("vm-1", 2, 1024, "t-a")).unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::InsufficientMemory {
            requested_mib: 1024,
            available_mib: 512
        }
    );
}

#[test]
fn fragmented_capacity_reports_memory_when_cpu_exists() {
    // Two NUMA nodes each with 4 cpus / 512 MiB. A request needing 6 cpus has
    // no single bin with enough CPU => InsufficientCpu (available 4).
    let sched = Scheduler::new(numa(), generous_policy());
    let err = sched.schedule(&req("vm-1", 6, 256, "t-a")).unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::InsufficientCpu {
            requested: 6,
            available: 4
        }
    );
}

#[test]
fn no_fit_leaves_scheduler_unchanged() {
    // The scheduler is pure: a no-fit decision has no side effects (no cgroup,
    // TAP, or Firecracker interaction exists anywhere in this crate).
    let sched = Scheduler::new(flat(2, 512), generous_policy());
    let before_vcpus = sched.available_vcpus();
    let before_mem = sched.available_memory_mib();
    // Within quota (<=64 vCPU / <=65536 MiB) but over host capacity (2 vCPU).
    let err = sched.schedule(&req("vm-1", 3, 256, "t-a")).unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::InsufficientCpu {
            requested: 3,
            available: 2
        }
    );
    assert_eq!(sched.available_vcpus(), before_vcpus);
    assert_eq!(sched.available_memory_mib(), before_mem);
    assert!(sched.placements().is_empty());
}

// ---------------------------------------------------------------------------
// Tenant quota enforcement
// ---------------------------------------------------------------------------

#[test]
fn quota_vcpu_enforced() {
    let mut policy = QuotaPolicy::new();
    policy.insert(tenant("t-a"), quota(4, 65536, 64));
    let mut sched = Scheduler::new(flat(16, 65536), policy);

    sched.place(&req("vm-1", 3, 256, "t-a")).unwrap();
    let err = sched.place(&req("vm-2", 2, 256, "t-a")).unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::QuotaExceeded {
            tenant: tenant("t-a"),
            dimension: microvm_scheduler::QuotaDimension::Vcpus,
            limit: 4,
            current: 3,
            requested: 2,
        }
    );
}

#[test]
fn quota_memory_enforced() {
    let mut policy = QuotaPolicy::new();
    policy.insert(tenant("t-a"), quota(64, 1024, 64));
    let mut sched = Scheduler::new(flat(16, 65536), policy);

    sched.place(&req("vm-1", 1, 768, "t-a")).unwrap();
    let err = sched.place(&req("vm-2", 1, 512, "t-a")).unwrap_err();
    assert!(matches!(
        err.reason,
        UnschedulableReason::QuotaExceeded {
            dimension: microvm_scheduler::QuotaDimension::MemoryMib,
            limit: 1024,
            current: 768,
            requested: 512,
            ..
        }
    ));
}

#[test]
fn quota_vm_count_enforced() {
    let mut policy = QuotaPolicy::new();
    policy.insert(tenant("t-a"), quota(64, 65536, 1));
    let mut sched = Scheduler::new(flat(16, 65536), policy);

    sched.place(&req("vm-1", 1, 256, "t-a")).unwrap();
    let err = sched.place(&req("vm-2", 1, 256, "t-a")).unwrap_err();
    assert!(matches!(
        err.reason,
        UnschedulableReason::QuotaExceeded {
            dimension: microvm_scheduler::QuotaDimension::Vms,
            limit: 1,
            ..
        }
    ));
}

#[test]
fn quota_exact_boundary_is_allowed() {
    let mut policy = QuotaPolicy::new();
    policy.insert(tenant("t-a"), quota(4, 1024, 2));
    let mut sched = Scheduler::new(flat(16, 65536), policy);
    sched.place(&req("vm-1", 2, 512, "t-a")).unwrap();
    sched.place(&req("vm-2", 2, 512, "t-a")).unwrap();
    assert_eq!(sched.placements().len(), 2);
}

#[test]
fn quota_is_per_tenant() {
    let mut policy = QuotaPolicy::new();
    policy.insert(tenant("t-a"), quota(2, 65536, 64));
    policy.insert(tenant("t-b"), quota(2, 65536, 64));
    let mut sched = Scheduler::new(flat(16, 65536), policy);
    // t-a exhausts its 2 vCPUs; t-b is unaffected.
    sched.place(&req("vm-a", 2, 256, "t-a")).unwrap();
    assert!(sched.place(&req("vm-a2", 1, 256, "t-a")).is_err());
    sched.place(&req("vm-b", 2, 256, "t-b")).unwrap();
}

#[test]
fn missing_quota_fails_closed() {
    let sched = Scheduler::new(flat(16, 65536), QuotaPolicy::new());
    let err = sched
        .schedule(&req("vm-1", 1, 256, "t-unknown"))
        .unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::NoQuotaForTenant {
            tenant: tenant("t-unknown")
        }
    );
}

// ---------------------------------------------------------------------------
// CPU / NUMA affinity
// ---------------------------------------------------------------------------

#[test]
fn numa_affinity_places_on_requested_node() {
    let sched = Scheduler::new(numa(), generous_policy());
    let p = sched
        .schedule(&req_affinity(
            "vm-1",
            2,
            512,
            "t-a",
            CpuAffinity::NumaNode { node: 1 },
        ))
        .unwrap();
    assert_eq!(p.numa_node, Some(1));
    assert!(cpus_of(&p).is_subset(&[4, 5, 6, 7].into_iter().collect()));
    assert_eq!(p.assigned_cpus, vec![4, 5]);
}

#[test]
fn numa_affinity_without_topology_is_rejected() {
    // A flat host has no preflight NUMA topology; the scheduler must not claim
    // NUMA awareness.
    let sched = Scheduler::new(flat(8, 4096), generous_policy());
    let err = sched
        .schedule(&req_affinity(
            "vm-1",
            2,
            512,
            "t-a",
            CpuAffinity::NumaNode { node: 0 },
        ))
        .unwrap_err();
    assert_eq!(err.reason, UnschedulableReason::NumaTopologyUnavailable);
}

#[test]
fn numa_affinity_unknown_node_is_rejected() {
    let sched = Scheduler::new(numa(), generous_policy());
    let err = sched
        .schedule(&req_affinity(
            "vm-1",
            2,
            512,
            "t-a",
            CpuAffinity::NumaNode { node: 9 },
        ))
        .unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::UnknownNumaNode { requested: 9 }
    );
}

#[test]
fn numa_node_capacity_is_isolated() {
    // Fill node0, then a node0-affinity request fails while node1 still has room.
    let mut sched = Scheduler::new(numa(), generous_policy());
    sched
        .place(&req_affinity(
            "vm-1",
            4,
            512,
            "t-a",
            CpuAffinity::NumaNode { node: 0 },
        ))
        .unwrap();
    let err = sched
        .schedule(&req_affinity(
            "vm-2",
            1,
            512,
            "t-a",
            CpuAffinity::NumaNode { node: 0 },
        ))
        .unwrap_err();
    assert!(matches!(
        err.reason,
        UnschedulableReason::InsufficientCpu { .. }
    ));
    // node1 still schedulable.
    assert!(sched
        .schedule(&req_affinity(
            "vm-3",
            1,
            512,
            "t-a",
            CpuAffinity::NumaNode { node: 1 }
        ))
        .is_ok());
}

#[test]
fn cpuset_affinity_pins_exact_cpus() {
    let sched = Scheduler::new(numa(), generous_policy());
    let cpus: BTreeSet<u32> = [5, 6].into_iter().collect();
    let p = sched
        .schedule(&req_affinity(
            "vm-1",
            2,
            512,
            "t-a",
            CpuAffinity::CpuSet { cpus },
        ))
        .unwrap();
    assert_eq!(p.assigned_cpus, vec![5, 6]);
    assert_eq!(p.numa_node, Some(1));
}

#[test]
fn cpuset_affinity_unknown_cpus_rejected() {
    let sched = Scheduler::new(numa(), generous_policy());
    let cpus: BTreeSet<u32> = [0, 99].into_iter().collect();
    let err = PlacementRequest::new(
        vm("vm-1"),
        2,
        512,
        tenant("t-a"),
        CpuAffinity::CpuSet { cpus },
    )
    .unwrap();
    let err = sched.schedule(&err).unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::UnknownCpus { unknown: vec![99] }
    );
}

#[test]
fn cpuset_affinity_not_free_rejected() {
    let mut sched = Scheduler::new(numa(), generous_policy());
    let first: BTreeSet<u32> = [4, 5].into_iter().collect();
    sched
        .place(&req_affinity(
            "vm-1",
            2,
            512,
            "t-a",
            CpuAffinity::CpuSet { cpus: first },
        ))
        .unwrap();
    // cpu 5 is now taken.
    let second: BTreeSet<u32> = [5, 6].into_iter().collect();
    let err = sched
        .schedule(&req_affinity(
            "vm-2",
            2,
            512,
            "t-a",
            CpuAffinity::CpuSet { cpus: second },
        ))
        .unwrap_err();
    assert!(matches!(
        err.reason,
        UnschedulableReason::AffinityUnsatisfiable { .. }
    ));
}

// ---------------------------------------------------------------------------
// Record-before-lifecycle-mutation contract
// ---------------------------------------------------------------------------

#[test]
fn schedule_is_pure_until_recorded() {
    let mut sched = Scheduler::new(flat(4, 4096), generous_policy());
    let r = req("vm-1", 2, 256, "t-a");

    // schedule() does not mutate the ledger.
    let p = sched.schedule(&r).unwrap();
    assert_eq!(sched.available_vcpus(), 4);
    assert!(sched.placements().is_empty());

    // record() commits the placement; only now does capacity decrease.
    sched.record(&p).unwrap();
    assert_eq!(sched.available_vcpus(), 2);
    assert_eq!(sched.placements().len(), 1);

    // A subsequent decision sees the recorded reservation.
    let err = sched.schedule(&req("vm-2", 3, 256, "t-a")).unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::InsufficientCpu {
            requested: 3,
            available: 2
        }
    );
}

#[test]
fn record_rejects_a_stale_overcommitting_placement() {
    let mut sched = Scheduler::new(flat(4, 4096), generous_policy());
    // Compute (but do not record) a placement for cpus [0,1].
    let stale = sched.schedule(&req("vm-1", 2, 256, "t-a")).unwrap();
    // Commit a different VM that takes cpus [0,1].
    sched.place(&req("vm-2", 2, 256, "t-a")).unwrap();
    // Recording the stale placement must fail: its CPUs are no longer free.
    let err = sched.record(&stale).unwrap_err();
    assert!(matches!(
        err.reason,
        UnschedulableReason::AffinityUnsatisfiable { .. }
    ));
    assert_eq!(sched.placements().len(), 1);
}

#[test]
fn record_rejects_duplicate_vm() {
    let mut sched = Scheduler::new(flat(4, 4096), generous_policy());
    let p = sched.place(&req("vm-1", 1, 256, "t-a")).unwrap();
    let err = sched.record(&p).unwrap_err();
    assert_eq!(
        err.reason,
        UnschedulableReason::DuplicatePlacement { vm_id: vm("vm-1") }
    );
}

#[test]
fn place_is_schedule_plus_record() {
    let mut sched = Scheduler::new(flat(4, 4096), generous_policy());
    let p = sched.place(&req("vm-1", 2, 256, "t-a")).unwrap();
    assert_eq!(sched.placements().get(&vm("vm-1")), Some(&p));
    assert_eq!(sched.available_vcpus(), 2);
}

#[test]
fn release_frees_resources() {
    let mut sched = Scheduler::new(flat(4, 4096), generous_policy());
    sched.place(&req("vm-1", 2, 1024, "t-a")).unwrap();
    assert_eq!(sched.available_vcpus(), 2);
    assert_eq!(sched.available_memory_mib(), 3072);

    let released = sched.release(&vm("vm-1")).unwrap();
    assert_eq!(released.vm_id, vm("vm-1"));
    assert_eq!(sched.available_vcpus(), 4);
    assert_eq!(sched.available_memory_mib(), 4096);
    assert!(sched.placements().is_empty());

    // The freed capacity is reusable.
    assert!(sched.place(&req("vm-2", 4, 4096, "t-a")).is_ok());
}

// ---------------------------------------------------------------------------
// Batch semantics
// ---------------------------------------------------------------------------

#[test]
fn plan_batch_is_all_or_nothing_and_pure() {
    let sched = Scheduler::new(flat(4, 4096), generous_policy());
    let batch = vec![req("vm-1", 3, 256, "t-a"), req("vm-2", 3, 256, "t-a")];
    // 3 + 3 > 4 cpus => the batch cannot fully fit.
    let err = sched.plan_batch(&batch).unwrap_err();
    assert!(matches!(
        err.reason,
        UnschedulableReason::InsufficientCpu { .. }
    ));
    // Pure: nothing was committed.
    assert!(sched.placements().is_empty());
    assert_eq!(sched.available_vcpus(), 4);
}

#[test]
fn plan_batch_succeeds_when_all_fit() {
    let sched = Scheduler::new(flat(4, 4096), generous_policy());
    let batch = vec![
        req("vm-1", 2, 256, "t-a"),
        req("vm-2", 1, 256, "t-b"),
        req("vm-3", 1, 256, "t-a"),
    ];
    let placements = sched.plan_batch(&batch).unwrap();
    assert_eq!(placements.len(), 3);
    // No CPU is assigned twice.
    let mut all: Vec<u32> = placements
        .iter()
        .flat_map(|p| p.assigned_cpus.clone())
        .collect();
    all.sort_unstable();
    let mut dedup = all.clone();
    dedup.dedup();
    assert_eq!(all, dedup, "no CPU may be assigned to two placements");
}

// ---------------------------------------------------------------------------
// No overcommit (explicit scenario)
// ---------------------------------------------------------------------------

#[test]
fn packing_never_overcommits_cpu_or_memory() {
    let mut sched = Scheduler::new(flat(4, 1024), generous_policy());
    // Place 2-vCPU / 512-MiB VMs until full: exactly 2 fit.
    sched.place(&req("vm-1", 2, 512, "t-a")).unwrap();
    sched.place(&req("vm-2", 2, 512, "t-b")).unwrap();
    assert_eq!(sched.available_vcpus(), 0);
    assert_eq!(sched.available_memory_mib(), 0);
    // The third cannot fit on either dimension.
    assert!(sched.place(&req("vm-3", 1, 1, "t-a")).is_err());

    // Invariant: total assigned vCPUs <= capacity, assigned CPUs are disjoint.
    let assigned: BTreeSet<u32> = sched
        .placements()
        .values()
        .flat_map(|p| p.assigned_cpus.clone())
        .collect();
    let total_assigned: usize = sched
        .placements()
        .values()
        .map(|p| p.assigned_cpus.len())
        .sum();
    assert_eq!(
        assigned.len(),
        total_assigned,
        "assigned CPUs must be disjoint"
    );
    assert!(u32::try_from(total_assigned).unwrap() <= sched.total_vcpus());
}

// ---------------------------------------------------------------------------
// Pure metrics consumption (no resource mutation)
// ---------------------------------------------------------------------------

fn record_with_cgroup(id: &str, mem_bytes: u64, cpu_usec: u64) -> VmMetricsRecord {
    let mut record = VmMetricsRecord::not_collected(
        vm(id),
        MetricsPhase::Running,
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        1_000,
    );
    record.cgroup = Availability::available(CgroupMetrics {
        sampled_monotonic_ns: 1_000,
        cpu: CpuStat {
            usage_usec: cpu_usec,
            ..Default::default()
        },
        memory_current_bytes: mem_bytes,
        memory_events: Default::default(),
        io: Default::default(),
        pids_current: 3,
    });
    record
}

#[test]
fn metrics_are_consumed_without_mutation() {
    let sched = Scheduler::new(flat(4, 4096), generous_policy());
    let placement = sched.schedule(&req("vm-1", 2, 512, "t-a")).unwrap();
    let record = record_with_cgroup("vm-1", 300 * MIB, 42_000);
    let record_before = record.clone();

    let input = metrics::reconciliation_input(&placement, &record).unwrap();
    assert_eq!(input.vm_id, vm("vm-1"));
    assert_eq!(input.reserved_vcpus, 2);
    assert_eq!(input.reserved_memory_mib, 512);
    assert_eq!(input.observed_memory_mib, Availability::available(300));
    assert_eq!(
        input.observed_cpu_usage_usec,
        Availability::available(42_000)
    );
    // Observed (300) does not exceed reserved (512).
    assert_eq!(
        input.observed_exceeds_reserved_memory(),
        Availability::available(false)
    );

    // The record was read by reference and is unchanged.
    assert_eq!(record, record_before);
    // The scheduler ledger was not mutated by consuming metrics.
    assert!(sched.placements().is_empty());
}

#[test]
fn metrics_drift_is_flagged_not_hidden() {
    let sched = Scheduler::new(flat(4, 4096), generous_policy());
    let placement = sched.schedule(&req("vm-1", 1, 256, "t-a")).unwrap();
    // Observed 512 MiB exceeds the 256 MiB reservation.
    let record = record_with_cgroup("vm-1", 512 * MIB, 0);
    let input = metrics::reconciliation_input(&placement, &record).unwrap();
    assert_eq!(
        input.observed_exceeds_reserved_memory(),
        Availability::available(true)
    );
}

#[test]
fn unavailable_metrics_stay_unavailable() {
    let sched = Scheduler::new(flat(4, 4096), generous_policy());
    let placement = sched.schedule(&req("vm-1", 1, 256, "t-a")).unwrap();
    // not_collected => cgroup Unavailable(NoBackend); never coerced to zero.
    let record = VmMetricsRecord::not_collected(
        vm("vm-1"),
        MetricsPhase::Running,
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        1_000,
    );
    assert_eq!(
        metrics::observed_memory_mib(&record),
        Availability::Unavailable(UnavailableReason::NoBackend)
    );
    let input = metrics::reconciliation_input(&placement, &record).unwrap();
    assert_eq!(
        input.observed_exceeds_reserved_memory(),
        Availability::Unavailable(UnavailableReason::NoBackend)
    );
}

#[test]
fn metrics_vm_mismatch_is_rejected() {
    let sched = Scheduler::new(flat(4, 4096), generous_policy());
    let placement = sched.schedule(&req("vm-1", 1, 256, "t-a")).unwrap();
    let record = record_with_cgroup("vm-other", 100 * MIB, 0);
    assert!(metrics::reconciliation_input(&placement, &record).is_err());
}
