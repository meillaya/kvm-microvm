# Architecture

This page describes the component topology, the transport model, the isolation
model, and the state/observability and interface layers of the
kvm-microvm-orchestrator platform.

For the decisions behind each boundary, see [adr/](adr/README.md). For the
trust model and explicit non-claims, see [security.md](security.md).

---

## 1. Component topology

The platform is organized into **five independently verifiable components**.
Each can succeed or fail independently and carries its own evidence artifact.

```text
                ┌────────────────────────────────────────────────────────┐
                │                      environment                        │
                │   devenv/Nix toolchain  +  scripts/preflight.sh         │
                └───────────────────────────────┬────────────────────────┘
                                                │ gates
        ┌───────────────────────────────────────┼────────────────────────────────┐
        │                                       │                                │
        ▼                                       ▼                                ▼
┌───────────────┐   transport-neutral    ┌───────────────┐              ┌─────────────────────┐
│   lifecycle   │◄────── service ───────►│   isolation   │              │ state-observability │
│  typed VM FSM │   (create/start/stop/  │ cgroup-v2 +   │              │ snapshots + metrics │
│  REST + gRPC  │    snapshot/restore)   │ jailer + TAP  │              │ + scheduler         │
└───────┬───────┘                        └───────────────┘              └─────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         interfaces-benchmarks                                │
│  constrained OCI import · Docker comparison · warm HTTP demo · direct-KVM    │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Component | Outcome it owns | Key crates |
| --- | --- | --- |
| **environment** | Reproducible devenv/Nix toolchain and Linux host preflight are available. | `devenv.nix`, `devenv.yaml`, `scripts/preflight.sh` |
| **lifecycle** | Typed VM/image control plane exposes create/start/stop/snapshot/restore over the selected transport. | `microvm-types`, `microvm-errors`, `microvm-lifecycle`, `microvm-transport-contract`, `microvm-service`, `microvm-rest`, `microvm-grpc`, `microvm-cli` |
| **isolation** | Per-VM jailer, cgroup-v2 limits, TAP/NAT, and cleanup enforce host boundaries. | `microvm-isolation`, `microvm-firecracker` |
| **state-observability** | Snapshot/restore, resource metrics, and core-aware bin-packing are auditable. | `microvm-snapshots`, `microvm-metrics`, `microvm-scheduler`, `microvm-artifacts` |
| **interfaces-benchmarks** | OCI-like entry point, Docker comparison, warm-function demo, and direct-KVM subset produce reproducible artifacts. | `microvm-oci`, `microvm-bench`, `microvm-demo`, `microvm-backend-directkvm` |

Cross-cutting verification crates: `microvm-contract-tests` (REST/gRPC parity,
socket hardening, request audit) and `microvm-security-tests` (adversarial
boundary batteries).

### Workspace crate map

| Crate | Role |
| --- | --- |
| `microvm-types` | Typed IDs (VM, snapshot, tenant), resource specs, VM states. |
| `microvm-errors` | Typed error model with a stable `ErrorCode` vocabulary. |
| `microvm-lifecycle` | VM lifecycle state machine and legal transitions. |
| `microvm-transport-contract` | Transport-neutral service contract shared by REST and gRPC. |
| `microvm-service` | Transport-neutral lifecycle service implementation. |
| `microvm-rest` | REST/JSON adapter over a Unix domain socket. |
| `microvm-grpc` | gRPC adapter over a Unix domain socket. |
| `microvm-cli` | `microvm` command-line client (Unix-socket only). |
| `microvm-artifacts` | Digest-addressed local artifact store and path validation. |
| `microvm-oci` | Constrained local OCI-like importer (not an OCI runtime). |
| `microvm-isolation` | cgroup-v2 hierarchy, jailer argv, TAP/netns/nftables, cleanup, binary verification. |
| `microvm-firecracker` | Firecracker-first runtime adapter and process supervision. |
| `microvm-snapshots` | Versioned snapshot manifest and pre-restore compatibility gate. |
| `microvm-metrics` | Per-VM host (cgroup/TAP) and optional guest metrics. |
| `microvm-scheduler` | Deterministic core-aware first-fit-decreasing bin-packing with admission control. |
| `microvm-contract-tests` | REST/gRPC transport parity and socket-hardening contract tests. |
| `microvm-security-tests` | Adversarial boundary tests (path/auth/cgroup/network/snapshot/OCI/binary). |
| `microvm-bench` | Reproducible snapshot/boot benchmark harness and Docker comparison. |
| `microvm-demo` | Warm HTTP-function microVM demo with cold/warm evidence. |
| `microvm-backend-directkvm` | Educational direct-KVM subset (feature-gated, not production). |

---

## 2. Transport model

Both control transports are **Unix-domain-socket only** and are backed by **one
transport-neutral service layer**, so REST and gRPC behavior is identical.

```text
   microvm CLI ──┐
                 │  REST/JSON over UDS
   REST client ──┼──────────────────►  microvm-rest  ─┐
                                                       │  transport-neutral
                                                       ▼  contract
   gRPC client ──┬──────────────────►  microvm-grpc ──┤  (microvm-transport-contract
                 │  gRPC over UDS                     │   + microvm-service)
                                                       ▼
                                               lifecycle state machine
                                               (microvm-lifecycle)
```

- **No TCP listener.** There is no public, loopback, or remote TCP endpoint
  anywhere in the platform. This is enforced by contract tests. See
  [adr/0001-unix-socket-only-transport.md](adr/0001-unix-socket-only-transport.md).
- **One service contract.** REST and gRPC are thin adapters over the same
  transport-neutral contract, so a legal state transition, idempotency rule, or
  ownership check behaves identically on both. See
  [adr/0003-transport-neutral-service.md](adr/0003-transport-neutral-service.md).
- **Documented socket paths.** The CLI `--socket` default is
  `/run/microvm/api/rest.sock`; the gRPC service is documented at
  `unix:///run/microvm/api.sock` (see
  [`api/microvm/v1/service.proto`](../api/microvm/v1/service.proto) and
  [`api/openapi.yaml`](../api/openapi.yaml)). Both are filesystem sockets owned
  and mode-protected by the platform.
- **Auth on the socket.** The owner principal is derived from Unix socket peer
  credentials, combined with filesystem mode/ownership of the socket path. See
  [security.md](security.md#authentication) and
  [adr/0004-peer-credential-auth.md](adr/0004-peer-credential-auth.md).

### Lifecycle operations

`CreateVm`, `StartVm`, `StopVm`, `SnapshotVm`, `RestoreVm`, `GetVmStatus`,
`GetVmMetrics`. VM states: `created`, `configured`, `running`, `paused`,
`snapshotting`, `restoring`, `stopped`, `failed`. Transitions are validated by
the lifecycle state machine; illegal transitions return typed errors.

---

## 3. Isolation model

Isolation is **fail-closed**: a missing capability, invalid path, unsupported
cgroup topology, or unverified artifact is a hard error *before* any process
spawn — never a silent fallback. See
[adr/0012-fail-closed-tcb.md](adr/0012-fail-closed-tcb.md).

### 3.1 cgroup-v2

The platform builds a **unified cgroup-v2** hierarchy explicitly and hands the
jailer only a pre-created leaf path. It does not rely on jailer defaults
(historically cgroup v1).

- One **parent** cgroup (`<root>/microvm`) delegates `cpu`, `memory`, `pids`,
  and `io` top-down via `cgroup.subtree_control`.
- One **leaf** cgroup per VM (`<root>/microvm/<vm-id>`) carries explicit limits
  (`cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`, optional `io.max`).
  A leaf has **no children** and an **empty** `cgroup.subtree_control`.
- The generated jailer argv **always** includes `--cgroup-version=2` and a
  `--parent-cgroup` pointing at the pre-created leaf.
- A missing cgroup root or required controller yields `CgroupUnavailable` before
  any spawn; an invalid spec or leaf-contract violation yields
  `InvalidResourceSpec`.

See [adr/0005-explicit-cgroup-v2.md](adr/0005-explicit-cgroup-v2.md) and the
[cgroup runbook](runbooks/network.md) / [cleanup runbook](runbooks/cleanup.md).

### 3.2 Firecracker + jailer

- **Firecracker-first** runtime adapter using a pinned release/static binary.
  See [adr/0002-firecracker-first.md](adr/0002-firecracker-first.md).
- **Binary provenance.** The Firecracker and jailer binaries are verified by
  SHA-256, ELF form, and seccomp mode before use. The platform does **not**
  treat release-build seccomp or trusted jailer paths as sufficient outer
  security — it owns validation itself.
- **jailer argv validation.** Subprocess arguments are validated; unrestricted
  argument passthrough is not permitted.
- **Fail-closed startup.** Readiness signaling and process supervision fail
  closed; there is no silent fallback when prerequisites are unavailable.

### 3.3 Networking (TAP + netns + nftables)

- Each VM gets a **TAP** device inside an **isolated network namespace**.
- **Controlled nftables NAT** provides egress; guest egress is enabled only by
  explicit VM network policy (`none`, `nat-only`, `egress-allowed`).
- **Inter-VM and unsolicited inbound traffic is denied.**
- Network setup is idempotent and cleaned up deterministically.

See [adr/0006-per-vm-tap-netns-nat.md](adr/0006-per-vm-tap-netns-nat.md) and the
[network runbook](runbooks/network.md).

### 3.4 Cleanup and reconciliation

Cleanup is idempotent and leaves no owned resource behind. An orphan reconciler
detects and quarantines leaked cgroups, netns, nft tables, and processes,
producing leak records. See the [cleanup runbook](runbooks/cleanup.md).

---

## 4. State and observability

### 4.1 Snapshots

- **Versioned, local, content-addressed.** A snapshot manifest records SHA-256
  content hashes (Firecracker binary, kernel/rootfs/block devices, guest memory,
  VM state) plus compatibility metadata (VM config, CPU/KVM API, cgroup version,
  owner tenant, quota, immutable-memory requirement). Serialized form:
  [`schemas/snapshot-manifest.v1.json`](../schemas/snapshot-manifest.v1.json).
- **Pre-restore compatibility gate.** The manifest is validated against the
  current host/binary/config and the caller tenant **before** any Firecracker
  process is spawned or `/snapshot/load` is issued. A host-envelope mismatch is
  a hard rejection, not a portability negotiation.
- **Local integrity only.** The SHA-256 digests are the orchestrator's own
  content hashes. Firecracker's internal snapshot CRC is only
  accidental-corruption detection and is **never** treated as authentication.
  There is **no cross-host transfer**, signing, or encryption contract.

See [adr/0007-local-content-addressed-snapshots.md](adr/0007-local-content-addressed-snapshots.md)
and the [snapshot runbook](runbooks/snapshot.md).

### 4.2 Metrics

Per-VM, availability-flagged metrics with a stable schema
([`schemas/vm-metrics-record.v1.json`](../schemas/vm-metrics-record.v1.json)):

- **Host cgroup-v2**: CPU usage/throttling, memory current/events, block IO, pids.
- **TAP network**: RX/TX byte counters plus derived throughput.
- **Boot/restore phases**: host-monotonic spans with derived durations.
- **Optional guest agent**: guest CPU steal, load, RSS — only when reachable.

**Core invariant: never zero-fill missing data.** Every source is wrapped in an
`Availability`: it is either `Available` or explicitly `Unavailable` with a
bounded reason. A missing guest agent or removed cgroup is reported as
*unavailable*, never as a measured `0`.

### 4.3 Scheduler

A **pure**, deterministic decision engine (no I/O, no cgroups, no TAP, no
Firecracker). It decides where a VM's reserved resources land: which NUMA node
(or flat CPU pool) and which concrete logical CPUs.

- **First-fit-decreasing** for batches, **first-fit** for single requests, with
  per-tenant quota admission control.
- **No overcommit of hard limits**: a bin accepts a request only if it has
  enough free CPUs *and* free memory; tenant quota is checked first. A no-fit
  decision is a typed `Unschedulable` reason.
- **Deterministic**: identical input yields identical placement (ordered bins,
  lowest-id-first CPUs, total FFD sort key; no randomness or clock).
- NUMA awareness is opt-in and evidence-backed; with no NUMA topology the host
  is one flat bin and the scheduler makes no NUMA claim.

---

## 5. Interfaces and benchmarks

### 5.1 Constrained local OCI-like import

`microvm run` imports a **constrained local OCI-like** layout (`manifest.json`
plus `blobs/sha256/<hex>`), verifies the SHA-256 of the config blob and every
layer, selects a supported platform (`linux/amd64` or `linux/arm64`), and
translates the result into a typed microVM spec.

- The reference must be a **local path or `file://` URI**. Remote and tag-only
  references (`https://`, `docker://`, `oci://`, `registry://`,
  `repo/img@sha256:…`, `nginx:latest`) are rejected **before any I/O** with
  `local_artifact_required`.
- The importer **refuses** images that request host mounts, host
  network/PID/IPC sharing, privileged mode, capability additions, or arbitrary
  host process controls. Container process metadata (Cmd/Entrypoint/Env) is
  ignored, never applied to the host.
- This is **not** an OCI runtime and makes **no** OCI runtime conformance claim.

See [adr/0008-local-digest-artifacts-constrained-oci.md](adr/0008-local-digest-artifacts-constrained-oci.md).

### 5.2 Benchmarks and demo

- **Benchmark harness** (`microvm-bench`) publishes distributions (p50/p95/p99,
  cold/warm), never a verdict. `target_ms` is metadata; there is no `pass` field.
  See [setup.md — Benchmark interpretation](setup.md#benchmark-interpretation).
- **Warm HTTP-function demo** (`microvm-demo`) shows cold first-call vs warm
  pool/request behavior with reproducible evidence — never a pass/fail gate.

### 5.3 Direct-KVM educational subset

`microvm-backend-directkvm` is an **educational** KVM backend behind the
`direct-kvm` Cargo feature (off by default). It is **not** a production
Firecracker replacement. Its contract is pinned in
[design/direct-kvm-subset.md](design/direct-kvm-subset.md): x86_64 only, exactly
one vCPU, one 16 MiB memory slot, serial output, and four handled VM exits
(`KVM_EXIT_IO` on port `0x3F8`, `KVM_EXIT_HLT`, `KVM_EXIT_FAIL_ENTRY`,
`KVM_EXIT_INTERNAL_ERROR`). Any other exit is an unexpected exit → `Failed`.
Multi-vCPU, networking, block devices, vsock, migration, snapshot/restore, and
any other architecture are explicitly excluded.

See [adr/0010-direct-kvm-educational-subset.md](adr/0010-direct-kvm-educational-subset.md).

---

## 6. Determinism boundary

A recurring design rule: **specification, validation, and decision logic are
pure**, and host I/O is pushed to a thin, injectable shell.

- Snapshot manifest checks, cgroup spec validation, jailer argv generation,
  scheduler placement, OCI reference classification, and the direct-KVM contract
  are pure functions requiring no host access.
- Real `/dev/kvm`, `/dev/net/tun`, and writable-cgroupfs runs live behind the
  `privileged` feature and degrade to `blocked` evidence when prerequisites are
  absent.

This is what lets the deterministic lane run on any host while still requiring
real evidence for privileged claims. See
[adr/0009-hybrid-test-lanes.md](adr/0009-hybrid-test-lanes.md).
