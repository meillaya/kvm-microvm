# ADR-0010: Direct-KVM educational subset, feature-gated and scope-locked

## Status

Accepted.

## Context

A small in-tree KVM backend is useful as a learning path for the KVM API surface
used by the platform. The risk is scope creep into a production VMM, which the
owner explicitly does not want. The subset must stay tiny, educational, and
unable to ship in a default production binary.

## Decision

Implement a narrow, educational direct-KVM subset (`microvm-backend-directkvm`),
pinned in [../design/direct-kvm-subset.md](../design/direct-kvm-subset.md):

- One architecture: x86_64 only (KVM API version 12, 4 KiB pages,
  little-endian).
- Exactly one vCPU, 64-bit long mode.
- One 16 MiB memory slot, identity-mapped; no second slot, ballooning, or
  hotplug.
- Serial output via the 16550 UART data register (I/O port `0x3F8`).
- Four handled VM exits: `KVM_EXIT_IO` (port `0x3F8`, OUT, size 1),
  `KVM_EXIT_HLT`, `KVM_EXIT_FAIL_ENTRY`, `KVM_EXIT_INTERNAL_ERROR`. Any other
  exit is an unexpected exit → `Failed`.
- Feature-gated behind the `direct-kvm` Cargo feature (off by default), so
  it is never compiled in the default workspace build and cannot accidentally
  ship in a production binary. Contract types remain available without the
  feature for documentation and static analysis.
- Labelled educational in all documentation and CLI surfaces.

## Consequences

- The subset teaches the KVM API surface without implying production capability.
- Deterministic contract tests run without `/dev/kvm`; the privileged boot test
  requires `/dev/kvm` and the `direct-kvm,privileged` features.
- The scope is locked: expansion requires a written scope-change proposal,
  recorded approval, and a document update before implementation.

## Scope-out

No production Firecracker replacement or compatibility layer. No network devices
(TAP/virtio-net/vhost-net), block devices, vsock, multi-vCPU, live migration,
snapshot/restore, broad device emulation (PCI/ACPI/APIC/PIT/RTC beyond minimal),
multiple memory slots, memory hotplug, or any architecture other than x86_64.

## References

- [../design/direct-kvm-subset.md](../design/direct-kvm-subset.md)
- [../architecture.md](../architecture.md#53-direct-kvm-educational-subset)
- [ADR-0002](0002-firecracker-first.md)
