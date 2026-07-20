# ADR-0007: Local Content-Addressed Snapshots; No Cross-Host Transfer; CRC Is Not Auth

## Status

Accepted.

## Context

The owner selected **local snapshot integrity**: reproducible, auditable
snapshots whose integrity is verifiable locally. Firecracker's internal snapshot
CRC only detects accidental corruption and is not an integrity/authentication
boundary. Cross-host snapshot portability would require signing/encryption and a
compatibility negotiation the owner did not request.

## Decision

- Snapshots are **local, content-addressed, and owner-scoped**. A manifest
  (`schemas/snapshot-manifest.v1.json`) records **SHA-256** content hashes
  (Firecracker binary, kernel/rootfs/block devices, guest memory, VM state) plus
  compatibility metadata (VM config, CPU/KVM API, cgroup version, owner tenant,
  quota, immutable-memory requirement).
- A **pre-restore compatibility gate** validates the manifest against the
  current host/binary/config and the caller tenant **before** any Firecracker
  process is spawned or `/snapshot/load` is issued.
- **Memory files are immutable**; an immutable-memory violation is rejected.
- The orchestrator's SHA-256 hashes are the integrity boundary. **Firecracker's
  CRC is never treated as authentication.**
- A host-envelope mismatch is a **hard rejection**, not a portability
  negotiation.

## Consequences

- Tampering and cross-tenant access fail before launch (exercised by the
  snapshot security battery).
- Snapshots are bound to their host envelope; there is no cross-host transfer
  contract.
- Manifest validation and the compatibility gate are pure (no I/O, no host API
  calls), so they are fully testable without `/dev/kvm`.

## Scope-out

No cross-host snapshot transfer. No signed/encrypted snapshot transport. No
claim that Firecracker's CRC authenticates state. No portability negotiation on
host-envelope mismatch.

## References

- [../architecture.md](../architecture.md#41-snapshots)
- [runbooks/snapshot.md](../runbooks/snapshot.md)
- [ADR-0004](0004-peer-credential-auth.md), [ADR-0012](0012-fail-closed-tcb.md)
