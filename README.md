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
- [`docs/release-readiness.md`](docs/release-readiness.md) — verification matrix and release-readiness report.

## Quick orientation

```bash
devenv shell                                   # enter the pinned toolchain (firecracker, jailer, docker, rust)
bash scripts/preflight.sh --json .preflight/host.json   # read-only host probe
cargo test --workspace                         # deterministic lane (no /dev/kvm needed)
sudo -E bash scripts/run-privileged-suite.sh   # privileged lane (cgroup, jailer, KVM, security)
sudo env "PATH=$PATH" bash scripts/prepare-bench-artifacts.sh  # full benchmark pipeline
```

## Toolchain (via devenv)

`devenv shell` provides all required tools reproducibly via Nix:

| Tool | Version | Purpose |
|------|---------|---------|
| Firecracker | v1.16.1 (static musl) | microVM runtime |
| Jailer | v1.16.1 (static musl) | Firecracker process jailer |
| Docker | 29.6.x | Benchmark comparison |
| Rust | stable (1.95.0 via rust-toolchain.toml) | Build toolchain |
| nftables | — | Per-VM network policy |
| e2fsprogs | — | Guest rootfs creation |

## Benchmark results

Docker cold-start latency measured on this host (AMD Ryzen 7, 100 samples):

| Condition | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| Cold | 1436 ms | 1467 ms | 1498 ms |
| Warm | 1440 ms | 1503 ms | 1543 ms |

Firecracker snapshot/restore measurements require a prepared guest kernel +
rootfs + snapshot (run `scripts/prepare-bench-artifacts.sh`). The `<200 ms`
figure is a reference target, **not** an SLA. See
[`docs/adr/0011-benchmark-distributions-not-sla.md`](docs/adr/0011-benchmark-distributions-not-sla.md).

## Verification matrix

34/34 todos have evidence. Deterministic lane: 16 pass, 0 fail. Privileged
lane: 1 pass (direct-KVM real boot), 11 blocked (host-gated). Benchmark:
1 published, 1 blocked. 0 semantic violations. See
[`docs/release-readiness.md`](docs/release-readiness.md).

## What this is NOT

This is a development/verification platform. It does **not** claim production
readiness, a universal `<200 ms` latency SLA, general OCI runtime compatibility,
or host security beyond the stated TCB. See
[`docs/README.md`](docs/README.md#read-this-first-what-this-project-is-not) and
[`docs/security.md`](docs/security.md#7-what-this-platform-does-not-claim).
