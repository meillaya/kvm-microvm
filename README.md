# kvm-microvm-orchestrator

A Rust control plane for Firecracker microVMs. It creates, starts, stops,
snapshots, and restores Linux workloads through REST/JSON and gRPC. Both
transports listen only on protected Unix domain sockets.

The project is a development and verification platform. It targets engineers who
want a small, auditable control plane and a test suite that separates pure
contract checks from host-dependent KVM checks.

## Run it

You need Nix and devenv. From the repository root:

```bash
devenv shell
cargo test --workspace
```

The deterministic suite runs on Linux. The workspace uses Linux-only `libc`
constants and paths, so it does not build on macOS. The suite needs no
`/dev/kvm`, `/dev/net/tun`, or writable cgroupfs. On a Linux host with KVM,
probe the host and run the privileged suite:

```bash
bash scripts/preflight.sh --json .preflight/host.json
sudo -E bash scripts/run-privileged-suite.sh
```

The preflight exits `0` when the host is capable, `2` when it is degraded, and
`77` when it is blocked. A blocked host still runs the deterministic lane. See
[setup](docs/setup.md) for the full sequence and for the guest image pipeline.

## What it does

| Area | Code | Behavior |
| --- | --- | --- |
| Lifecycle | `microvm-lifecycle`, `microvm-service` | Validates every VM state transition and applies it through one transport-neutral contract. |
| Transports | `microvm-rest`, `microvm-grpc`, `microvm-cli` | Expose the same lifecycle operations over Unix sockets, with REST and gRPC parity tests. |
| Isolation | `microvm-isolation`, `microvm-firecracker` | Builds a cgroup v2 leaf, a jailer argv, and a TAP device in a network namespace before the VM starts. |
| Snapshots | `microvm-snapshots`, `microvm-artifacts` | Records SHA-256 content hashes and rejects a manifest whose host envelope or owner does not match. |
| Observability | `microvm-metrics`, `microvm-scheduler` | Reports host and guest metrics with explicit availability, and places VMs on cores without overcommitting. |
| Guest image | `microvm-guest-health`, `scripts/build-guest-image.sh` | Builds a 64 MiB rootfs around a static health server that acts as init for snapshot and benchmark runs. |
| Interfaces | `microvm-oci`, `microvm-bench`, `microvm-demo` | Imports digest-pinned local OCI layouts, compares Firecracker with Docker, and runs a warm HTTP-function demo. |

## Measured result

A July 2026 run on an AMD Ryzen 7 5700X measured 100 samples per workload with
Firecracker v1.16.1 and Docker 29.6.0:

| Workload | Condition | p50 | p95 | p99 | n |
| --- | --- | --- | --- | --- | --- |
| Firecracker snapshot/restore | Warm | 6.88 ms | 8.58 ms | 9.35 ms | 100 |
| Docker cold-start | Warm | 315.7 ms | n/a | n/a | 100 |

The p50 ratio is about 46x. The raw artifacts from that run are local-only and
are not committed here, so treat the table as a record of one run. The `<200 ms`
figure is a reference target, not an SLA. See
[ADR-0011](docs/adr/0011-benchmark-distributions-not-sla.md).

## Documentation

| Document | Contents |
| --- | --- |
| [docs/README.md](docs/README.md) | Documentation map and scope boundaries. |
| [docs/setup.md](docs/setup.md) | devenv setup, preflight meanings, deterministic and privileged lanes. |
| [docs/architecture.md](docs/architecture.md) | Component topology, transport, isolation, state, and interfaces, with figures. |
| [docs/security.md](docs/security.md) | Threat model, TCB, Unix-socket auth, tenant ownership, and non-claims. |
| [docs/runbooks/](docs/runbooks/README.md) | Preflight, snapshot, network, cleanup, and CI setup procedures. |
| [docs/adr/](docs/adr/README.md) | Twelve accepted architecture decisions and scope-out rules. |
| [docs/design/direct-kvm-subset.md](docs/design/direct-kvm-subset.md) | Pinned contract for the educational direct-KVM backend. |
| [docs/release-readiness.md](docs/release-readiness.md) | Verification matrix and release-gate status. |

## Scope

The control plane has no TCP listener. Remote registry pulls, tag-only image
references, host mounts, host namespaces, and privileged container flags are
rejected before use. Snapshots stay local and are checked against the host
envelope before load.

This repository does not claim production readiness, a universal latency
guarantee, general OCI runtime compatibility, or host security beyond the TCB.
The [security model](docs/security.md) states each boundary.

## Verification status

The verification matrix covers 34 items. The July 20 baseline recorded 16
deterministic passes, 1 privileged pass and 11 blocked, and 1 published
benchmark and 1 blocked. The July 2026 run reported 7 privileged passes and 7
blocked, and measured the benchmark table above; its raw artifacts are
local-only. The committed reducer baseline reports 0 semantic violations and
34/34 coverage. See [release-readiness](docs/release-readiness.md) for both
snapshots and the blocked reasons.

## Development

Run the same gates as CI before you send a change:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The privileged workflow is described in
[the CI runbook](docs/runbooks/ci-setup.md).
