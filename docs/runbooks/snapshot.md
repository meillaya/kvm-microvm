# Runbook: snapshot and restore

Goal: create and restore versioned, local, content-addressed snapshots, and
interpret the pre-restore compatibility gate.

Snapshots are local, content-addressed, and owner-scoped. The repository defines
no cross-host transfer, signing, or encryption contract. Firecracker's internal
CRC detects accidental corruption. It is not authentication; the orchestrator's
SHA-256 content hashes are the integrity boundary. See
[ADR-0007](../adr/0007-local-content-addressed-snapshots.md).

## When to run

- To capture a point-in-time snapshot of a running or paused VM.
- To restore a VM from an existing snapshot, which creates a new VM.
- To verify that tampering or cross-tenant access is rejected before launch.

Snapshot and restore against real KVM is a privileged-lane operation and needs a
capable host. See [preflight.md](preflight.md). The manifest and compatibility
gate logic is pure and runs in the deterministic lane.

## Procedure

### 1. Preflight for a privileged restore

```bash
bash scripts/preflight.sh --json .preflight/host.json
```

A blocked host (`77`) cannot perform a real snapshot or restore. Record blocked
evidence instead.

### 2. Create a snapshot

Use the CLI over the Unix socket:

```bash
microvm snapshot --vm-id <VM_ID>
```

You can also send `SnapshotVm` over REST or gRPC. The VM must be `running` or
`paused`. The platform writes a snapshot manifest that conforms to
[`schemas/snapshot-manifest.v1.json`](../../schemas/snapshot-manifest.v1.json).

The manifest records:

- Content hashes (SHA-256) for the Firecracker binary, kernel, rootfs, block
  devices, guest memory, and VM state.
- Compatibility metadata: VM config, CPU and KVM API version, cgroup version,
  owner tenant, quota, and the immutable-memory requirement.
- Identity: `snapshot_id`, `vm_id`, `version`, and `created_at`.

### 3. Restore from a snapshot

```bash
microvm restore --snapshot-id <SNAPSHOT_ID>
```

You can also send `RestoreVm` over REST or gRPC. Restore creates a new VM.

### 4. Pass the pre-restore compatibility gate

Before the platform spawns a Firecracker process or issues `/snapshot/load`, the
`CompatibilityGate` validates the manifest against:

- The current host envelope: CPU and KVM API version, and cgroup version.
- The current binary: the Firecracker hash.
- The current VM config.
- The caller tenant: owner check and quota.

A mismatch is a hard rejection. Memory files are treated as immutable, and an
immutable-memory violation is rejected.

## Interpreting rejections

| Rejection | Meaning | Operator action |
| --- | --- | --- |
| Hash mismatch (binary, kernel, rootfs, block, memory, or state) | Tampering or artifact drift. | Treat it as a security event. Do not restore. Reverify artifact provenance. |
| Host-envelope mismatch | The CPU, KVM API, or cgroup version differs from the snapshot's recorded host. | Restore only on a matching host. Cross-host transfer is out of scope. |
| Owner or cross-tenant denial | The caller tenant does not own the snapshot. | The request is denied fail-closed. Use the owning principal. |
| Quota exceeded | The restore would exceed the tenant quota. | Free resources or raise the quota through the owning principal. |
| Immutable-memory violation | The memory file changed after the snapshot. | Rejected. Recreate the snapshot from a clean source. |

## Tamper-rejection drill

The snapshot integrity and compatibility logic is pure and runs without
`/dev/kvm`:

```bash
cargo test -p microvm-security-tests --test snapshot_security
```

These tests confirm that a tampered hash or a cross-tenant request fails before
launch.

## Scope reminders

- A snapshot is bound to its host envelope. Moving it to another host is out of
  scope and is rejected.
- The platform defines no signed or encrypted snapshot transport. Integrity is
  local.
- Do not use Firecracker's CRC for an integrity decision.

See [security.md](../security.md#55-snapshot-boundaries) and
[architecture.md](../architecture.md#41-snapshots).
