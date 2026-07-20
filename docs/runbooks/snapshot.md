# Runbook: Snapshot and Restore

Goal: create and restore versioned, local, content-addressed snapshots, and
interpret the pre-restore compatibility gate.

> **Trust boundary.** Snapshots are **local, content-addressed, and
> owner-scoped**. There is **no** cross-host transfer, signing, or encryption
> contract. Firecracker's internal CRC is only accidental-corruption detection
> and is **never** treated as authentication; the orchestrator's own SHA-256
> content hashes are the integrity boundary. See
> [../adr/0007-local-content-addressed-snapshots.md](../adr/0007-local-content-addressed-snapshots.md).

---

## When to run

- To capture a point-in-time snapshot of a running or paused VM.
- To restore a VM from an existing snapshot (creates a new VM).
- To verify that tampering or cross-tenant access is rejected before launch.

Snapshot/restore against **real KVM** is a privileged-lane operation and
requires a capable host (see [preflight.md](preflight.md)). The manifest and
compatibility-gate logic itself is pure and runs in the deterministic lane.

---

## Procedure

### 1. Preflight (privileged restore)

```bash
bash scripts/preflight.sh --json .preflight/host.json
```

A blocked host (`77`) cannot perform real snapshot/restore; record blocked
evidence instead.

### 2. Create a snapshot

Over the CLI (Unix socket only):

```bash
microvm snapshot --vm-id <VM_ID>
```

Or over REST/gRPC (`SnapshotVm`). The VM must be `running` or `paused`. The
platform writes a snapshot manifest conforming to
[`schemas/snapshot-manifest.v1.json`](../../schemas/snapshot-manifest.v1.json).

The manifest records:

- **Content hashes (SHA-256):** Firecracker binary, kernel/rootfs/block devices,
  guest memory, and VM state.
- **Compatibility metadata:** VM config, CPU/KVM API, cgroup version, owner
  tenant, quota, and the immutable-memory requirement.
- **Identity:** `snapshot_id`, `vm_id`, `version`, `created_at`.

### 3. Restore from a snapshot

```bash
microvm restore --snapshot-id <SNAPSHOT_ID>
```

Or over REST/gRPC (`RestoreVm`). Restore creates a **new** VM.

### 4. Pre-restore compatibility gate

Before any Firecracker process is spawned or `/snapshot/load` is issued, the
`CompatibilityGate` validates the manifest against:

- the current **host envelope** (CPU/KVM API, cgroup version),
- the current **binary** (Firecracker hash),
- the current **VM config**, and
- the **caller tenant** (owner check + quota).

A mismatch is a **hard rejection**, not a portability negotiation. Memory files
are treated as **immutable**; an immutable-memory violation is rejected.

---

## Interpreting rejections

| Rejection | Meaning | Operator action |
| --- | --- | --- |
| Hash mismatch (binary/kernel/rootfs/block/memory/state) | Tampering or artifact drift detected. | Treat as a security event; do not restore. Re-verify artifact provenance. |
| Host-envelope mismatch | CPU/KVM API or cgroup version differs from the snapshot's recorded host. | Restore only on a matching host; cross-host transfer is out of scope. |
| Owner / cross-tenant denial | Caller tenant does not own the snapshot. | Denied fail-closed; use the owning principal. |
| Quota exceeded | Restore would exceed the tenant quota. | Free resources or raise quota via the owning principal. |
| Immutable-memory violation | Memory file was modified after snapshot. | Rejected; recreate the snapshot from a clean source. |

---

## Tamper-rejection drill (deterministic)

The snapshot integrity and compatibility logic is pure and is exercised without
`/dev/kvm` by the security batteries:

```bash
cargo test -p microvm-security-tests --test snapshot_security
```

These tests confirm that tampered hashes and cross-tenant access fail before
launch.

---

## Scope reminders

- **No cross-host transfer.** A snapshot is bound to its host envelope; moving
  it to another host is out of scope and is rejected, not negotiated.
- **No signed/encrypted transport.** Local integrity only.
- **CRC is not auth.** Do not rely on Firecracker's CRC for integrity decisions.

See [../security.md](../security.md#54-snapshot-boundaries) and the
[architecture snapshot section](../architecture.md#41-snapshots).
