# Verification status

This page records the verification matrix for the 34 items and explains
what each lane proves. It is a status report. Benchmark numbers are evidence,
not release gates.

## Current status

The current status combines the July 21 privileged run with the July 20
baseline:

| Lane | Result |
| --- | --- |
| Deterministic | 16 pass, 0 fail |
| Privileged | 7 pass, 7 blocked, 0 fail |
| Benchmark | 1 published, 1 blocked in the matrix |
| Scope fidelity | Clean |
| Coverage | 34/34 items, 0 semantic violations |

The raw evidence lives under `.omo/evidence/kvm-microvm-orchestrator/`, which
is git-ignored, and the artifacts from that run are not in this checkout. The
privileged count comes from the July 21 run and is repeated in the project
README. The deterministic count, matrix benchmark status, and coverage come from
the committed July 20 baseline below, because the reducer output was not
regenerated after July 21. A fresh checkout cannot reproduce those counts
without running the lanes again.

## Baseline: release reconciliation, 2026-07-20

The last committed evidence summary ran at commit `6a74671` and reported
`pass=19 blocked=14 published=1 fail=0 missing=0 invalid=0`, with
`semantic_violations=0` and coverage `34/34`.

| Lane | Result | Detail |
| --- | --- | --- |
| Deterministic | pass | `cargo test --workspace` reported 1317 passed and 0 failed. `cargo fmt` and `cargo clippy` were clean. The reducer validated every artifact. |
| Privileged | pass or blocked | One real pass, the direct-KVM boot, and 11 blocked items with host reasons. |
| Benchmark | published or blocked | The warm HTTP-function demo published distributions. The Docker and Firecracker comparison blocked on missing binaries. |
| Scope fidelity | clean | The product code binds Unix sockets only, keeps the OCI importer local, and contains no rootless, VFIO, live-migration, or general-OCI path. |

The July 21 changes added the guest image pipeline, end-to-end lifecycle tests,
Firecracker snapshot/restore benchmark wiring, and the Docker comparison. The
privileged count moved from 1 pass and 11 blocked at the baseline to 7 pass and
7 blocked. Blocked items fall into three classes: Firecracker or jailer binaries
missing, cgroup delegation unavailable, and privileged behavior not demonstrated
on the host.

## Deterministic lane

The deterministic lane covers unit tests, property tests, transport contract
parity, scheduler logic, the OCI importer, the snapshot manifest and
compatibility gate, and the adversarial security batteries. It needs no
`/dev/kvm`, `/dev/net/tun`, or writable cgroupfs.

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Deterministic evidence does not carry `host_preflight` or `target_ms` fields.
Per-host metadata would make a reproducible result depend on the host. See
[`schemas/evidence-deterministic.v1.json`](../schemas/evidence-deterministic.v1.json).

## Privileged lane

The privileged lane exercises Firecracker boot, cgroup-v2 enforcement,
TAP/netns, jailer launch, lifecycle cleanup, and snapshot/restore against real
KVM. It is gated by `scripts/preflight.sh --strict`. When prerequisites are
absent, the lane emits `blocked` evidence instead of a mocked pass.

The one real pass at the baseline was the direct-KVM boot: KVM API
version 12 on a nested AMD host, a guest marker byte `75` (`'K'`) written in
64-bit long mode to I/O port `0x3F8`, and a halt stop. The evidence schema
encodes the anti-mock rule: when `host_preflight.kvm_ok` is `false`, no run may
record `pass: true`.

## Benchmark lane

The baseline published the warm HTTP-function demo. The Docker and
Firecracker comparison was blocked with the reason
`docker_missing,firecracker_missing`.

The July 21 run produced the measurements in the README:

| Workload | Condition | p50 | p95 | p99 | n |
| --- | --- | --- | --- | --- | --- |
| Firecracker snapshot/restore | Warm | 6.88 ms | 8.58 ms | 9.35 ms | 100 |
| Docker cold-start | Warm | 315.7 ms | n/a | n/a | 100 |

The matrix still marks the comparison blocked because the committed reducer
output predates the July 21 run. The distributions are recorded in the README
from that run, and the schema forbids a `pass` field at the top level and on
every item. The `<200 ms` figure is a measured reference target recorded as
`target_ms`, not an SLA. See
[ADR-0011](adr/0011-benchmark-distributions-not-sla.md).

## Scope fidelity

| Boundary | Verdict | Evidence |
| --- | --- | --- |
| No TCP control-plane listener | clean | REST and gRPC bind `tokio::net::UnixListener` only. The only TCP code is the outbound guest readiness probe and detector fixtures. A scan for `0.0.0.0`, `tcp://`, `[::]`, and `localhost:` found no product matches. |
| No remote pull | clean | The OCI importer is local-only and rejects remote or tag-only references with `ImportError::RemoteReference` before any I/O. |
| No rootless, VFIO, or live migration | clean | A scan across `crates/` found no non-comment, non-test matches. |
| No general OCI behavior | clean | `microvm-oci` rejects host mounts, capabilities, privileged mode, host namespaces, and host process controls. |
| No framework metadata changes | clean | `git status --porcelain -- .codegraph .omo/run-continuation` was empty at the baseline. |

## Five components

The reducer covers each topology component. The per-component status is in the
local evidence tree, and the lane totals above aggregate it.

| Component | Evidence |
| --- | --- |
| environment | Toolchain and preflight artifacts. |
| lifecycle | Types, state machine, auth, transport parity, direct-KVM contract, and the real KVM boot. |
| isolation | cgroup, jailer, network, and cleanup evidence. |
| state-observability | Artifact paths, images, snapshots, scheduler, and metrics. |
| interfaces-benchmarks | OCI import, CLI, benchmark, and warm demo. |

## Release gate policy

- Benchmark targets are not release gates. Distributions are published with
  host metadata and never reduce to pass or fail.
- Blocked evidence is preserved with its host reason. No blocked item is erased
  or promoted to pass.
- The reducer is fail-closed. The deterministic lane has no blocked state, a
  privileged pass requires real-substrate proof, and a benchmark never records
  `pass`.

## Reproduce

```bash
devenv shell
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
scripts/aggregate-evidence.sh --require-complete
```

The reducer reads the local evidence tree. On a fresh checkout it reports
missing artifacts until a lane writes them, so run the lane before you run the
reducer. The privileged and benchmark lanes need the host capabilities listed in
[setup.md](setup.md#4-the-two-verification-lanes).
