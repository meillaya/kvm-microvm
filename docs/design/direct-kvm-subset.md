# Direct KVM Educational Subset

**Status:** Pinned — do not expand without a scope-change decision.
**Audience:** Educational. This is NOT a production Firecracker replacement.

---

## Purpose

This document pins the exact contract for a minimal, single-purpose KVM
backend that exists solely to teach the KVM API surface used by the
kvm-microvm-orchestrator platform. It is deliberately tiny: one architecture,
one vCPU, one memory slot, serial output, and a small set of VM exits.

The crate `microvm-backend-directkvm` implements this contract. It is gated
behind the `direct-kvm` Cargo feature (off by default) and is labelled
**educational** in all documentation and CLI surfaces.

---

## Supported Host Architecture

| Property | Value |
| ---------- | ------- |
| Architecture | `x86_64` only |
| KVM API version | 12 (stable ABI) |
| Host page size | 4 KiB |
| Endianness | Little-endian |

No other architecture (aarch64, riscv64, s390x) is supported or planned
within this subset.

---

## vCPU Configuration

| Property | Value |
| ---------- | ------- |
| vCPU count | Exactly **1** |
| Initial RIP | `0x0000_0000_0000_0000` (real-mode reset vector) |
| Initial RFLAGS | `0x0000_0000_0000_0002` (bit 1 always set) |
| Mode | 64-bit long mode (set via MSRs before first KVM_RUN) |

Multi-vCPU is explicitly excluded.

---

## Guest Memory Layout

One contiguous memory slot, identity-mapped:

| Region | Guest Physical Address | Size | Purpose |
| -------- | ---------------------- | ------ | --------- |
| RAM | `0x0000_0000_0000_0000` | 16 MiB | Guest code + data |
| Serial MMIO | `0x0000_0000_03F8` | 1 byte (port I/O) | 16550 UART data register |

- **One memory slot** (`slot = 0`), registered via `KVM_SET_USER_MEMORY_REGION`.
- Guest physical address 0 maps to host virtual address of a 16 MiB
  `mmap(MAP_ANONYMOUS | MAP_PRIVATE)` region.
- No second slot, no ballooning, no hotplug.

### Guest Marker

A tiny local guest writes the ASCII byte `0x4B` (`'K'`) to I/O port `0x3F8`
(serial data register) and then executes `HLT`. The host observes the port-I/O
exit, reads the marker byte, and confirms the guest ran. This is the sole
guest workload used for validation.

---

## Allowed VM Exits

The backend handles exactly these exit reasons and no others:

| KVM Exit Reason | Handling |
| ----------------- | ---------- |
| `KVM_EXIT_IO` (port `0x3F8`, direction OUT, size 1) | Record the byte as serial output; inject nothing; resume. |
| `KVM_EXIT_HLT` | Stop the vCPU loop; transition to `Stopped`. |
| `KVM_EXIT_FAIL_ENTRY` | Record `hardware_entry_failure_reason`; transition to `Failed`. |
| `KVM_EXIT_INTERNAL_ERROR` | Record `internal_error_suberror`; transition to `Failed`. |

Any other exit reason is treated as an **unexpected exit**: the backend
transitions to `Failed` with the raw exit reason recorded. No device emulation
beyond the single serial port is performed.

---

## Stop Behavior

| Trigger | Action |
| --------- | -------- |
| Guest executes `HLT` | vCPU loop exits; state → `Stopped`. |
| Host calls `stop()` | Sets a stop flag checked between KVM_RUN iterations; state → `Stopped`. |
| Unexpected exit / entry failure | vCPU loop exits; state → `Failed`. |

After stopping, the memory slot is deregistered and the vCPU fd is dropped.
No snapshot, no migration, no restart.

---

## Explicit Exclusions

The following are **not** part of this subset and must not be added without a
formal scope-change decision:

- Production Firecracker replacement or compatibility layer
- Network devices (TAP, virtio-net, vhost-net)
- Block devices (virtio-blk, vhost-user-blk)
- vsock (virtio-vsock, vhost-vsock)
- Multi-vCPU support
- Live migration or snapshot/restore
- Broad device emulation (PCI, ACPI, APIC, PIT, RTC beyond minimal)
- Multiple memory slots or memory hotplug
- Any architecture other than x86_64

---

## Feature Gate

The `direct-kvm` Cargo feature is **off by default**. Code behind this feature
is never compiled in the default workspace build. The feature exists so that:

1. CI can run the full workspace without `/dev/kvm` access.
2. The educational backend cannot accidentally ship in a production binary.
3. The contract types remain available for documentation and static analysis
   without the feature.

---

## Contract Types (microvm-backend-directkvm)

The crate exposes these public types (available without the feature flag):

- `KvmContract` — top-level contract descriptor (arch, vcpu_count,
  memory_layout, allowed_exits, stop_behavior).
- `Arch` — enum pinned to `X86_64`.
- `MemoryLayout` — single-slot descriptor (guest_phys_addr, size_bytes).
- `AllowedExit` — enum of the four handled exit reasons.
- `StopBehavior` — enum (`Hlt`, `HostStop`, `Failure`).
- `EducationalLabel` — newtype asserting the "educational" label is present.

Validation is deterministic and requires no host access.

---

## Scope Lock

This document is the authoritative scope definition for the direct-KVM
educational subset. Any expansion requires:

1. A written scope-change proposal referencing this document.
2. Explicit approval recorded in the plan artifacts.
3. An update to this document before implementation begins.
