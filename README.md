# kvm-microvm-orchestrator

A Rust-based, **Firecracker-first** microVM control plane that creates, starts,
stops, snapshots, and restores isolated Linux workloads through REST/JSON and
gRPC — exposed **only** over protected Unix domain sockets.

## Documentation

Operator documentation lives in [`docs/`](docs/README.md):

- [`docs/README.md`](docs/README.md) — overview and navigation (start here).
- [`docs/setup.md`](docs/setup.md) — devenv setup, preflight meanings, deterministic/privileged lanes.
- [`docs/architecture.md`](docs/architecture.md) — component topology, transport, and isolation model.
- [`docs/security.md`](docs/security.md) — threat model, TCB, auth, and isolation boundaries.
- [`docs/runbooks/`](docs/runbooks/README.md) — operational runbooks (preflight, snapshot, network, cleanup).
- [`docs/adr/`](docs/adr/README.md) — architecture decision records.
- [`docs/design/direct-kvm-subset.md`](docs/design/direct-kvm-subset.md) — pinned educational direct-KVM contract.

## Quick orientation

```bash
devenv shell                                   # enter the pinned toolchain
bash scripts/preflight.sh --json .preflight/host.json   # read-only host probe
cargo test --workspace                         # deterministic lane (no /dev/kvm needed)
bash scripts/run-privileged-tests.sh           # privileged lane gate (capable host only)
```

## What this is NOT

This is a development/verification platform. It does **not** claim production
readiness, a universal `<200 ms` latency SLA, general OCI runtime compatibility,
or host security beyond the stated TCB. See
[`docs/README.md`](docs/README.md#read-this-first-what-this-project-is-not) and
[`docs/security.md`](docs/security.md#7-what-this-platform-does-not-claim).
