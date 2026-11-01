# Operator documentation

This directory is the operator-facing documentation for
kvm-microvm-orchestrator. Start with [setup](setup.md) to run the deterministic
lane. Read [architecture](architecture.md) and [security](security.md) before
you trust a privileged result.

## Scope

The platform creates, starts, stops, snapshots, and restores Firecracker
microVMs. It is a development and verification platform, not a production
service. These boundaries are part of the design, and tests enforce most of
them:

- The control plane listens on Unix domain sockets. There is no TCP endpoint.
- The OCI entry point imports digest-pinned local layouts. It performs no
  network I/O and applies no host mounts, capabilities, or process controls.
- Snapshots stay local and content-addressed. The compatibility gate rejects a
  manifest from a different host envelope or owner.
- Benchmarks publish distributions. The `<200 ms` target is metadata for a
  reviewer, not a release gate.
- The TCB covers input validation, authentication, binary provenance, artifact
  integrity, isolation setup, and cleanup. It does not claim host hardening
  beyond that boundary.

See [security.md](security.md) for the full threat model.

## Documentation map

| Document | Contents |
| --- | --- |
| [setup.md](setup.md) | devenv setup, host preflight meanings, deterministic and privileged lanes, benchmark interpretation. |
| [architecture.md](architecture.md) | Component topology, transport model, isolation model, state and observability, interfaces and benchmarks. |
| [security.md](security.md) | Threat model, TCB, Unix-socket auth, tenant ownership, isolation boundaries, explicit non-claims. |
| [runbooks/](runbooks/README.md) | Preflight, snapshot, network, cleanup, and CI setup procedures. |
| [adr/](adr/README.md) | Architecture decision records for each locked decision and scope-out rule. |
| [design/direct-kvm-subset.md](design/direct-kvm-subset.md) | Pinned contract for the educational direct-KVM subset. |
| [release-readiness.md](release-readiness.md) | Verification matrix across the deterministic, privileged, and benchmark lanes. |

Reference contracts live outside this directory:

| Reference | Purpose |
| --- | --- |
| [`api/openapi.yaml`](../api/openapi.yaml) | REST lifecycle API. |
| [`api/microvm/v1/service.proto`](../api/microvm/v1/service.proto) | gRPC lifecycle service. |
| [`schemas/`](../schemas/README.md) | JSON Schemas for evidence, snapshot manifests, and metrics records. |
| [`scripts/preflight.sh`](../scripts/preflight.sh) | Read-only host capability probe. |
| [`scripts/run-privileged-suite.sh`](../scripts/run-privileged-suite.sh) | Privileged test runner. |

## Five independently verifiable components

The platform has five components. Each can fail alone and carries its own
evidence. [architecture.md](architecture.md) shows how they connect and maps
every crate.

| Component | What it owns |
| --- | --- |
| environment | The devenv/Nix toolchain and the Linux host preflight. |
| lifecycle | The typed VM control plane behind REST and gRPC. |
| isolation | The jailer, cgroup v2 limits, TAP networking, and cleanup. |
| state-observability | Snapshots, metrics, and deterministic placement. |
| interfaces-benchmarks | Local OCI import, Docker comparison, the warm demo, and the direct-KVM subset. |

## Quick start

The full sequence is in [setup.md](setup.md). The short version:

```bash
devenv shell
bash scripts/preflight.sh --json .preflight/host.json
cargo test --workspace
```

Preflight exits `0` for a capable host, `2` for a degraded host, and `77` for a
blocked host. The deterministic suite runs on any Linux host. The privileged
suite requires `/dev/kvm`, `/dev/net/tun`, cgroup v2, and the pinned Firecracker
and jailer binaries.

## Status

The project is under active development. [release-readiness.md](release-readiness.md)
records which lanes passed, which blocked on host capabilities, and why.
