# Runbook: Cleanup and Reconciliation

Goal: ensure the platform leaves **no owned resource behind** — cgroups, network
namespaces, nft tables, and processes — even after unclean exits.

> **Invariant.** Cleanup is **idempotent** and **fail-closed**. Reconciliation
> detects orphans, quarantines them, and records leaks; it never silently
> ignores a leftover resource. See
> [../architecture.md#34-cleanup-and-reconciliation](../architecture.md#34-cleanup-and-reconciliation).

---

## Owned resource kinds

| Kind | Identifier prefix / location | Cleaned up by |
| --- | --- | --- |
| cgroup-v2 leaf | `<root>/microvm/<vm-id>` | cgroup manager teardown |
| network namespace | `NETNS_PREFIX` + id | net manager teardown |
| nftables table | `NFT_TABLE_PREFIX` + id | net manager teardown |
| Firecracker/jailer process | supervised child | process supervision |
| quarantined orphans | `DEFAULT_QUARANTINE_DIR` | orphan reconciler |
| state records | `DEFAULT_STATE_DIR` | cleanup manager |

---

## Procedure

### 1. Normal teardown (idempotent)

Stopping a VM triggers idempotent teardown of its cgroup leaf, netns, nft table,
and supervised process:

```bash
microvm stop --vm-id <VM_ID>
```

Idempotent means a repeated stop (or a stop after a partial teardown) does not
error and does not double-free; it converges to the clean state.

### 2. Reconcile orphans after an unclean exit

If the orchestrator or a VM process dies uncleanly, run reconciliation. The
`OrphanReconciler` compares live resources against recorded state, quarantines
orphans, and emits `OrphanRecord` / `LeakRecord` entries:

```bash
# Deterministic reconciliation logic is exercised without host privileges:
cargo test -p microvm-isolation
```

On a capable host, reconciliation operates against the real cgroupfs/netns/nft
under the privileged lane (gated by preflight; see
[preflight.md](preflight.md)).

### 3. Inspect leak records

Cleanup outcomes are typed (`CleanupOutcome`, `ReconcileOutcome`) and recorded with
the resource kind and identifier. A non-empty leak record means a resource was
detected and quarantined rather than silently dropped — investigate the
underlying unclean exit.

---

## Verification

Cleanup idempotency and reconciliation are covered by the isolation crate tests
and the adversarial security batteries:

```bash
cargo test -p microvm-isolation
cargo test -p microvm-security-tests --test cgroup_security
cargo test -p microvm-security-tests --test network_security
```

Privileged-gated cgroup tests verify real-kernel behavior (for example, the
no-internal-process `EBUSY` constraint on a populated cgroup) and skip
gracefully on a non-root host:

```bash
cargo test -p microvm-security-tests --features privileged
```

---

## Operator checklist

- [ ] Every stopped VM converges to a clean state (no owned cgroup/netns/nft/process).
- [ ] Repeated stop is idempotent (no error, no double-free).
- [ ] After an unclean exit, reconciliation quarantines orphans and records leaks.
- [ ] Leak records are investigated, not ignored.
- [ ] No world-writable control socket or host-network share is introduced by cleanup paths.

See [../security.md](../security.md#2-trusted-computing-base-tcb) (safe cleanup
is part of the TCB) and
[../adr/0012-fail-closed-tcb.md](../adr/0012-fail-closed-tcb.md).
