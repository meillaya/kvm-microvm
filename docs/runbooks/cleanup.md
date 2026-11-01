# Runbook: cleanup and reconciliation

Goal: ensure the platform leaves no owned resource behind after normal use or
an unclean exit. Owned resources are cgroups, network namespaces, nft tables,
and processes.

Cleanup is idempotent and fails closed. Reconciliation detects orphans,
quarantines them, and records leaks. It does not ignore a leftover resource. See
[architecture.md](../architecture.md#34-cleanup-and-reconciliation).

## Owned resource kinds

| Kind | Identifier prefix or location | Cleaned up by |
| --- | --- | --- |
| cgroup-v2 leaf | `<root>/microvm/<vm-id>` | cgroup manager teardown |
| network namespace | `NETNS_PREFIX` plus the id | net manager teardown |
| nftables table | `NFT_TABLE_PREFIX` plus the id | net manager teardown |
| Firecracker or jailer process | supervised child | process supervision |
| quarantined orphans | `DEFAULT_QUARANTINE_DIR` | orphan reconciler |
| state records | `DEFAULT_STATE_DIR` | cleanup manager |

## Procedure

### 1. Normal teardown

Stopping a VM triggers idempotent teardown of its cgroup leaf, netns, nft table,
and supervised process:

```bash
microvm stop --vm-id <VM_ID>
```

Idempotent means a repeated stop, or a stop after a partial teardown, does not
return an error and does not double-free. It converges to the clean state.

### 2. Reconcile orphans after an unclean exit

If the orchestrator or a VM process dies, run reconciliation. The
`OrphanReconciler` compares live resources against recorded state, quarantines
orphans, and emits `OrphanRecord` and `LeakRecord` entries:

```bash
# Exercise the deterministic reconciliation logic without host privileges.
cargo test -p microvm-isolation
```

On a capable host, the privileged lane runs reconciliation against the real
cgroupfs, netns, and nftables. The lane is gated by preflight; see
[preflight.md](preflight.md).

### 3. Inspect leak records

Cleanup outcomes are typed (`CleanupOutcome`, `ReconcileOutcome`) and recorded
with the resource kind and identifier. A non-empty leak record means the
platform detected and quarantined a resource. Investigate the unclean exit that
created it.

## Verification

These tests cover cleanup idempotency and reconciliation:

```bash
cargo test -p microvm-isolation
cargo test -p microvm-security-tests --test cgroup_security
cargo test -p microvm-security-tests --test network_security
```

Privileged-gated cgroup tests verify real kernel behavior, such as the
no-internal-process `EBUSY` constraint on a populated cgroup, and skip on a
non-root host:

```bash
cargo test -p microvm-security-tests --features privileged
```

## Operator checklist

- [ ] Every stopped VM converges to a clean state with no owned cgroup, netns,
      nft table, or process.
- [ ] A repeated stop is idempotent and does not double-free.
- [ ] Reconciliation quarantines orphans and records leaks after an unclean exit.
- [ ] Leak records are investigated.
- [ ] Cleanup paths do not introduce a world-writable control socket or a
      host-network share.

See [security.md](../security.md#2-trusted-computing-base-tcb); safe cleanup is
part of the TCB. See also
[ADR-0012](../adr/0012-fail-closed-tcb.md).
