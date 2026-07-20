# kvm-microvm-orchestrator — Operator Documentation

A Rust-based, **Firecracker-first** microVM control plane that creates, starts,
stops, snapshots, and restores isolated Linux workloads through both REST/JSON
and gRPC, exposed **only** over protected Unix domain sockets.

This directory is the operator-facing documentation set. It describes how to
set up a development environment, what the host preflight means, how the
platform isolates workloads, how to operate snapshots/network/cleanup, and the
locked architecture decisions behind the design.

---

## Read this first: what this project is NOT

These boundaries are deliberate and are enforced by tests. Every page in this
set respects them.

- **Not production-ready.** This is a development and verification platform.
  Nothing here claims production readiness or a production support contract.
- **No universal latency guarantee.** The `<200 ms` snapshot/restore figure is a
  *measured reference target*, not an SLA. Benchmarks publish p50/p95/p99
  distributions with host conditions; they never reduce to a pass/fail verdict.
  See [setup.md](setup.md#benchmark-interpretation) and
  [adr/0011-benchmark-distributions-not-sla.md](adr/0011-benchmark-distributions-not-sla.md).
- **Not a general OCI runtime.** The `microvm run` interface is a *constrained
  local import* path for digest-pinned OCI-like layouts. It performs no network
  I/O, applies no host mounts/capabilities/process controls, and makes no OCI
  runtime conformance claim. See
  [adr/0008-local-digest-artifacts-constrained-oci.md](adr/0008-local-digest-artifacts-constrained-oci.md).
- **No host-security claim beyond the stated TCB.** The platform owns a defined
  trusted computing base (validation, auth, binary provenance, artifact hashes,
  safe cleanup). It does **not** treat Firecracker's unauthenticated UDS API,
  trusted jailer paths, release-build seccomp, or Firecracker's CRC as sufficient
  outer security. See [security.md](security.md).
- **Unix sockets only.** No TCP, loopback, or remote listener exists anywhere in
  the platform. See
  [adr/0001-unix-socket-only-transport.md](adr/0001-unix-socket-only-transport.md).

---

## Documentation map

| Document | What it covers |
| --- | --- |
| [setup.md](setup.md) | devenv/Nix setup, host preflight meanings, deterministic vs privileged lanes, runnable commands, benchmark interpretation. |
| [architecture.md](architecture.md) | Component topology, transport model, isolation model, state/observability, interfaces. |
| [security.md](security.md) | Threat model, TCB, Unix-socket auth, tenant ownership, isolation boundaries, explicit non-claims. |
| [runbooks/](runbooks/README.md) | Operational runbooks: preflight, snapshot, network, cleanup. |
| [adr/](adr/README.md) | Architecture Decision Records for every locked decision and scope-out rule. |
| [design/direct-kvm-subset.md](design/direct-kvm-subset.md) | Pinned contract for the educational direct-KVM subset (not a production VMM). |

Project-level references (source of truth for contracts):

| Reference | Purpose |
| --- | --- |
| [`api/openapi.yaml`](../api/openapi.yaml) | REST lifecycle API contract (Unix-socket server). |
| [`api/microvm/v1/service.proto`](../api/microvm/v1/service.proto) | gRPC lifecycle service contract (Unix-socket only). |
| [`schemas/`](../schemas/README.md) | JSON Schemas for evidence, snapshot manifest, and metrics records. |
| [`scripts/preflight.sh`](../scripts/preflight.sh) | Read-only host capability probe. |
| [`scripts/run-privileged-tests.sh`](../scripts/run-privileged-tests.sh) | Privileged-lane gate. |

---

## Five independently verifiable components

The platform is organized into five topology components. Each can succeed or
fail independently and carries its own evidence. See
[architecture.md](architecture.md) for the full topology and crate map.

1. **environment** — reproducible devenv/Nix toolchain and Linux host preflight.
2. **lifecycle** — typed VM control plane over a transport-neutral service.
3. **isolation** — per-VM cgroup-v2, jailer, TAP/netns/NAT, and cleanup.
4. **state-observability** — snapshots, metrics, and deterministic scheduling.
5. **interfaces-benchmarks** — constrained OCI import, Docker comparison, warm
   HTTP-function demo, and the educational direct-KVM subset.

---

## Quick start (orientation only)

The full, verified command sequence lives in [setup.md](setup.md). This is only
an orientation sketch — run the preflight before trusting any privileged result.

```bash
# 1. Enter the pinned development environment.
devenv shell

# 2. Probe the host (read-only). Exit 0 = capable, 2 = degraded, 77 = blocked.
bash scripts/preflight.sh --json .preflight/host.json

# 3. Run the deterministic lane (no /dev/kvm required).
cargo test --workspace

# 4. Gate the privileged lane (requires a capable host).
bash scripts/run-privileged-tests.sh
```

---

## Status

Development / verification platform. See the non-claims above and
[security.md](security.md) for the authoritative scope and trust boundaries.
