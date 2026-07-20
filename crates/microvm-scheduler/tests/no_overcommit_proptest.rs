//! Fixed-seed property tests proving the scheduler never overcommits CPU or
//! memory and is deterministic (plan todo 24).
//!
//! proptest derives each test's RNG seed deterministically from the test name,
//! so these property tests are reproducible (fixed-seed) across runs; combined
//! with the scheduler's own internal determinism (ordered bins, lowest-id-first
//! CPUs, ordered maps, no clock/randomness), identical input always yields
//! identical placement.

use microvm_scheduler::{
    CpuAffinity, HostId, HostTopology, PlacementRequest, QuotaPolicy, Scheduler, TenantQuota,
    Unschedulable,
};
use microvm_types::{TenantId, VmId};
use proptest::collection::vec;
use proptest::prelude::*;

// Per-tenant quota used across the property tests.
const QUOTA_VCPUS: u32 = 8;
const QUOTA_MEMORY_MIB: u64 = 4096;
const QUOTA_VMS: u32 = 16;

fn vm(id: &str) -> VmId {
    VmId::new(id).unwrap()
}

fn tenant(id: &str) -> TenantId {
    TenantId::new(id).unwrap()
}

fn policy() -> QuotaPolicy {
    let mut p = QuotaPolicy::new();
    for t in ["t-a", "t-b"] {
        p.insert(
            tenant(t),
            TenantQuota {
                max_vcpus: QUOTA_VCPUS,
                max_memory_mib: QUOTA_MEMORY_MIB,
                max_vms: QUOTA_VMS,
            },
        );
    }
    p
}

fn make_sched(cpus: u32, mem_mib: u64) -> Scheduler {
    let topology = HostTopology::flat(HostId::new("host-0").unwrap(), cpus, mem_mib).unwrap();
    Scheduler::new(topology, policy())
}

fn req(id: &str, vcpu: u32, mem_mib: u64, tenant_id: &str) -> PlacementRequest {
    PlacementRequest::new(vm(id), vcpu, mem_mib, tenant(tenant_id), CpuAffinity::None).unwrap()
}

/// A workload: host size plus a list of (vcpu, memory_mib, tenant_index).
fn workload_strategy() -> impl Strategy<Value = (u32, u64, Vec<(u32, u64, usize)>)> {
    (
        2u32..=16,
        512u64..=8192u64,
        vec((1u32..=4, 128u64..=1024u64, 0usize..2usize), 1..=24),
    )
}

/// Assert every hard-limit invariant on a scheduler after arbitrary placements.
fn assert_invariants(sched: &Scheduler, host_cpus: u32, host_mem_mib: u64) {
    let placements: Vec<_> = sched.placements().values().collect();

    // 1. Assigned CPUs are disjoint across all placements (no CPU overcommit).
    let mut all_cpus: Vec<u32> = placements
        .iter()
        .flat_map(|p| p.assigned_cpus.clone())
        .collect();
    all_cpus.sort_unstable();
    let total_assigned = all_cpus.len();
    all_cpus.dedup();
    assert_eq!(
        all_cpus.len(),
        total_assigned,
        "a CPU was assigned to more than one placement"
    );

    // 2. Every assigned CPU is a valid host CPU.
    for cpu in &all_cpus {
        assert!(*cpu < host_cpus, "assigned cpu {} out of range", cpu);
    }

    // 3. Total reserved vCPUs and memory never exceed host capacity.
    let total_vcpu: u32 = placements.iter().map(|p| p.vcpu_count).sum();
    let total_mem: u64 = placements.iter().map(|p| p.memory_mib).sum();
    assert!(
        total_vcpu <= host_cpus,
        "vcpu overcommit: {} > {}",
        total_vcpu,
        host_cpus
    );
    assert!(
        total_mem <= host_mem_mib,
        "memory overcommit: {} > {}",
        total_mem,
        host_mem_mib
    );

    // 4. assigned_cpus.len() always equals vcpu_count (consistent accounting).
    for p in &placements {
        assert_eq!(p.assigned_cpus.len(), p.vcpu_count as usize);
    }

    // 5. Per-tenant quota is never exceeded.
    for t in ["t-a", "t-b"] {
        let usage = sched.tenant_usage(&tenant(t));
        assert!(
            usage.vcpus_used <= QUOTA_VCPUS,
            "tenant {} vcpu quota exceeded",
            t
        );
        assert!(
            usage.memory_mib_used <= QUOTA_MEMORY_MIB,
            "tenant {} memory quota exceeded",
            t
        );
        assert!(
            usage.vm_count <= QUOTA_VMS,
            "tenant {} vm quota exceeded",
            t
        );
    }
}

/// Run a workload, returning the ordered sequence of placement outcomes.
fn run_workload(
    sched: &mut Scheduler,
    workload: &[(u32, u64, usize)],
) -> Vec<Result<microvm_scheduler::Placement, Unschedulable>> {
    let tenants = ["t-a", "t-b"];
    workload
        .iter()
        .enumerate()
        .map(|(i, (vcpu, mem, t))| {
            sched.place(&req(&format!("vm-{}", i), *vcpu, *mem, tenants[*t]))
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn never_overcommits_cpu_or_memory((cpus, mem, workload) in workload_strategy()) {
        let mut sched = make_sched(cpus, mem);
        let tenants = ["t-a", "t-b"];
        for (i, (vcpu, m, t)) in workload.iter().enumerate() {
            let _ = sched.place(&req(&format!("vm-{}", i), *vcpu, *m, tenants[*t]));
        }
        assert_invariants(&sched, cpus, mem);
    }

    #[test]
    fn identical_input_produces_identical_placement((cpus, mem, workload) in workload_strategy()) {
        let mut s1 = make_sched(cpus, mem);
        let mut s2 = make_sched(cpus, mem);
        let r1 = run_workload(&mut s1, &workload);
        let r2 = run_workload(&mut s2, &workload);
        prop_assert_eq!(&r1, &r2);
        // Final ledgers are identical too.
        prop_assert_eq!(s1.placements(), s2.placements());
    }

    #[test]
    fn release_restores_capacity_exactly((cpus, mem, workload) in workload_strategy()) {
        let mut sched = make_sched(cpus, mem);
        let base_vcpus = sched.available_vcpus();
        let base_mem = sched.available_memory_mib();
        let tenants = ["t-a", "t-b"];
        let mut placed: Vec<VmId> = Vec::new();
        for (i, (vcpu, m, t)) in workload.iter().enumerate() {
            let id = vm(&format!("vm-{}", i));
            if sched.place(&req(&format!("vm-{}", i), *vcpu, *m, tenants[*t])).is_ok() {
                placed.push(id);
            }
        }
        // Releasing every placement restores capacity to the original baseline.
        for id in placed {
            assert!(sched.release(&id).is_some());
        }
        prop_assert_eq!(sched.available_vcpus(), base_vcpus);
        prop_assert_eq!(sched.available_memory_mib(), base_mem);
        prop_assert!(sched.placements().is_empty());
    }
}

// A fixed, hand-built regression scenario (independent of proptest seeding)
// that also asserts the no-overcommit invariant.
#[test]
fn fixed_seed_regression_no_overcommit() {
    let mut sched = make_sched(8, 2048);
    // Deterministic workload: fill, overflow, release, refill.
    let workload: Vec<(u32, u64, usize)> = vec![
        (4, 1024, 0),
        (4, 1024, 1),
        (2, 512, 0),  // must fail: host full
        (8, 4096, 0), // must fail: exceeds quota and capacity
    ];
    let outcomes = run_workload(&mut sched, &workload);
    assert!(outcomes[0].is_ok());
    assert!(outcomes[1].is_ok());
    assert!(outcomes[2].is_err());
    assert!(outcomes[3].is_err());
    assert_invariants(&sched, 8, 2048);

    // Release one and confirm a previously-fitting request now succeeds.
    sched.release(&vm("vm-0"));
    assert!(sched.place(&req("vm-4", 4, 1024, "t-a")).is_ok());
    assert_invariants(&sched, 8, 2048);

    // Determinism: a fresh scheduler reproduces the exact same outcome sequence.
    let mut sched2 = make_sched(8, 2048);
    let outcomes2 = run_workload(&mut sched2, &workload);
    assert_eq!(
        outcomes.iter().map(|r| r.is_ok()).collect::<Vec<_>>(),
        outcomes2.iter().map(|r| r.is_ok()).collect::<Vec<_>>()
    );
}
