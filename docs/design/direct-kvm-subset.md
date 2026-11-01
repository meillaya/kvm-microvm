# Direct KVM educational subset

Status: pinned. Do not expand without a scope-change decision.

Audience: educational. This is not a production Firecracker replacement.

## Purpose

This document pins the contract for a minimal KVM backend that teaches the KVM
API surface used by kvm-microvm-orchestrator. The subset is deliberately small:
one architecture, one vCPU, one memory slot, serial output, and a small set of
VM exits.

The crate `microvm-backend-directkvm` implements this contract. It is gated
behind the `direct-kvm` Cargo feature, off by default, and labelled educational
in all documentation and CLI surfaces.

## Supported host architecture

| Property | Value |
| --- | --- |
| Architecture | `x86_64` only |
| KVM API version | 12 (stable ABI) |
| Host page size | 4 KiB |
| Endianness | Little-endian |

No other architecture (aarch64, riscv64, s390x) is supported or planned within
this subset.

## vCPU configuration

| Property | Value |
| --- | --- |
| vCPU count | Exactly 1 |
| Initial RIP | `0x0000_0000_0000_0000` (real-mode reset vector) |
| Initial RFLAGS | `0x0000_0000_0000_0002` (bit 1 always set) |
| Mode | 64-bit long mode, set through MSRs before the first `KVM_RUN` |

Multi-vCPU is explicitly excluded.

## Guest memory layout

One contiguous memory slot, identity-mapped:

| Region | Guest physical address | Size | Purpose |
| --- | --- | --- | --- |
| RAM | `0x0000_0000_0000_0000` | 16 MiB | Guest code and data |
| Serial port | `0x0000_0000_03F8` | 1 byte (port I/O) | 16550 UART data register |

- One memory slot (`slot = 0`), registered via `KVM_SET_USER_MEMORY_REGION`.
- Guest physical address 0 maps to the host virtual address of a 16 MiB
  `mmap(MAP_ANONYMOUS | MAP_PRIVATE)` region.
- No second slot, ballooning, or hotplug.

### Guest marker

A tiny local guest writes the ASCII byte `0x4B` (`'K'`) to I/O port `0x3F8`, the
serial data register, and then executes `HLT`. The host observes the port-I/O
exit, reads the marker byte, and confirms the guest ran. This is the only guest
workload used for validation.

## Allowed VM exits

The backend handles exactly these exit reasons:

| KVM exit reason | Handling |
| --- | --- |
| `KVM_EXIT_IO` (port `0x3F8`, direction OUT, size 1) | Record the byte as serial output, inject nothing, and resume. |
| `KVM_EXIT_HLT` | Stop the vCPU loop and transition to `Stopped`. |
| `KVM_EXIT_FAIL_ENTRY` | Record `hardware_entry_failure_reason` and transition to `Failed`. |
| `KVM_EXIT_INTERNAL_ERROR` | Record `internal_error_suberror` and transition to `Failed`. |

Any other exit reason is an unexpected exit. The backend transitions to
`Failed` and records the raw exit reason. It performs no device emulation beyond
the single serial port.

## Stop behavior

| Trigger | Action |
| --- | --- |
| Guest executes `HLT` | The vCPU loop exits and the state becomes `Stopped`. |
| Host calls `stop()` | A stop flag is checked between `KVM_RUN` iterations and the state becomes `Stopped`. |
| Unexpected exit or entry failure | The vCPU loop exits and the state becomes `Failed`. |

After a stop, the memory slot is deregistered and the vCPU file descriptor is
dropped. There is no snapshot, migration, or restart.

## Explicit exclusions

These features are outside the subset. Adding one requires a formal scope-change
decision:

- A production Firecracker replacement or compatibility layer.
- Network devices (TAP, virtio-net, vhost-net).
- Block devices (virtio-blk, vhost-user-blk).
- vsock (virtio-vsock, vhost-vsock).
- Multi-vCPU support.
- Live migration or snapshot/restore.
- Broad device emulation (PCI, ACPI, APIC, PIT, RTC beyond the minimum).
- Multiple memory slots or memory hotplug.
- Any architecture other than x86_64.

## Feature gate

The `direct-kvm` Cargo feature is off by default. Code behind the feature is
never compiled in the default workspace build. The feature exists so that:

1. CI can run the full workspace without `/dev/kvm` access.
2. The educational backend cannot ship in a production binary by accident.
3. The contract types remain available for documentation and static analysis
   without the feature.

## Contract types

The crate exposes these public types without the feature flag:

- `KvmContract`: top-level contract descriptor (arch, vcpu_count,
  memory_layout, allowed_exits, stop_behavior).
- `Arch`: enum pinned to `X86_64`.
- `MemoryLayout`: single-slot descriptor (guest_phys_addr, size_bytes).
- `AllowedExit`: enum of the four handled exit reasons.
- `StopBehavior`: enum (`Hlt`, `HostStop`, `Failure`).
- `EducationalLabel`: newtype asserting that the educational label is present.

Validation is deterministic and needs no host access.

## Scope lock

This document is the authoritative scope definition for the direct-KVM
educational subset. Any expansion requires:

1. A written scope-change proposal that references this document.
2. Explicit approval recorded in the plan artifacts.
3. An update to this document before implementation begins.
