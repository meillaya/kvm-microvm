# Setup, Preflight, and Test Lanes

This page explains how to set up the development environment, what the host
preflight result means, and how to run the two verification lanes
(**deterministic** and **privileged**). Every command here is runnable as
written from the repository root.

> **Scope reminder.** This is a development/verification platform, not a
> production deployment guide. No command here claims to make a host
> production-ready. See [security.md](security.md) for the trust boundaries.

---

## 1. Prerequisites

| Requirement | Why | Notes |
| --- | --- | --- |
| Linux x86_64 host | KVM target architecture | aarch64 is a documented secondary/future target, not the primary. |
| [Nix](https://nixos.org/) + [devenv](https://devenv.sh/) | Reproducible toolchain | `devenv.yaml` requires devenv `>=2.1`. |
| `/dev/kvm` (privileged lane only) | Real virtualization | Deterministic lane does **not** need it. |
| `/dev/net/tun` (privileged lane only) | TAP networking | Deterministic lane does **not** need it. |
| cgroup v2 unified hierarchy (privileged lane only) | Resource limits | Needs `cpu`, `memory`, `pids` controllers. |
| Pinned Firecracker + jailer (privileged lane only) | Runtime adapter | Verified by SHA-256 before use. |

The deterministic lane runs on **any** host (including macOS for development and
ordinary CI containers) because it never touches `/dev/kvm`, `/dev/net/tun`, or
a writable cgroupfs.

---

## 2. Enter the development environment

The toolchain is pinned through devenv/Nix. `devenv.yaml` pins the inputs
(`nixpkgs`, `git-hooks`) and `devenv.nix` pins the Rust toolchain (`1.95.0`)
plus the Linux-only VM hosting tools (QEMU/KVM, nftables, cpio, util-linux,
kmod, e2fsprogs, pciutils).

```bash
# From the repository root:
devenv shell
```

Inside the shell the pinned Rust toolchain and Linux tooling are on `PATH`.
Confirm the environment resolved:

```bash
devenv shell -- rustc --version
devenv shell -- cargo --version
```

> **No KVM/QEMU daemon module.** devenv 2.x has no built-in KVM/QEMU service
> module, and `devenv.nix` deliberately does not declare one (it would error at
> evaluation). The orchestrator owns the VM host stack through its own Rust
> crates and host-side scripts, not through devenv-managed services.

---

## 3. Host preflight: what it means

`scripts/preflight.sh` is a **read-only** host capability probe. It never
mutates sysctls, never creates namespaces, never loads kernel modules, and never
opens `/dev/kvm` with write intent. It parses `/etc/os-release` with `grep`/`sed`
(never `source`).

### Run it

```bash
# Human-readable JSON to stdout, plus a convenience copy in .preflight/host.json
bash scripts/preflight.sh

# Atomic write to an explicit path (required for CI evidence):
bash scripts/preflight.sh --json .preflight/host.json

# Treat warnings (degraded conditions) as blockers:
bash scripts/preflight.sh --strict --json .preflight/host.json
```

### Exit codes

| Exit | Meaning | Lane consequence |
| --- | --- | --- |
| `0` | **Capable** — no blockers, no degraded warnings. | Privileged lane may proceed. |
| `2` | **Degraded** — warnings present, no hard blockers. | Privileged lane may proceed *with caveat*; blocked under `--strict`. |
| `77` | **Blocked** — one or more blockers. | Privileged lane must NOT run; emit blocked evidence instead of mocking a pass. |

`--strict` promotes the degraded (`2`) condition to blocked (`77`).

### What the JSON records

The output conforms to
[`schemas/evidence-host-preflight.v1.json`](../schemas/evidence-host-preflight.v1.json)
(`class: "host_preflight"`). Top-level fields:

| Field | Meaning |
| --- | --- |
| `host` | OS / arch / kernel / Nix version. |
| `cpu` | Vendor, virtualization flag (`virt`), nested-virt flag (`nested`). |
| `kvm` | `/dev/kvm` mode/uid/gid, `accessible`, `api_version`. |
| `tap` | `/dev/net/tun` mode and `accessible`. |
| `cgroup_v2` | `unified` flag and the list of available `controllers`. |
| `tools` | Firecracker + jailer presence, version, and `sha256`. |
| `mitigations` | CPU vulnerability status from `/sys/devices/system/cpu/vulnerabilities/*`. |
| `blockers` | Array of hard-blocking condition tokens. |
| `warnings` | Array of degraded-condition tokens. |
| `blocked_reason` | Human-readable summary when blocked. |

### Documented toolchain limitation

Pure Bash cannot issue `ioctl(2)`, so the script cannot run `KVM_GET_API_VERSION`
or `TUNGETFEATURES` directly. When `/dev/kvm` is openable the probe reports
`kvm.api_version = -1` and emits the warning token
`kvm_api_version_unprobed_in_bash`. A future privileged-host runner may ship a
small `kvm-probe` companion binary to refine `api_version` to the schema's strict
`O_RDWR + ioctl` semantics. This gap is recorded explicitly rather than papered
over.

---

## 4. The two verification lanes

The platform uses a **hybrid** test strategy: deterministic contracts first,
privileged host behavior gated behind preflight. This keeps deterministic
feedback fast and reproducible while still requiring real evidence for any host
claim.

### 4.1 Deterministic lane (no host capabilities required)

Runs on any host. Covers unit tests, property tests, API/transport contract
parity, scheduler pure logic, the OCI importer, the snapshot manifest and
compatibility gate, and the adversarial security batteries — all without
`/dev/kvm`, `/dev/net/tun`, or a writable cgroupfs.

```bash
# Whole-workspace deterministic suite:
cargo test --workspace

# Formatting and lint gates:
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Dependency policy gate:
cargo deny check
```

Deterministic evidence artifacts MUST NOT carry `host_preflight` or `target_ms`
fields — per-host metadata would only confuse a reproducible result. See
[`schemas/evidence-deterministic.v1.json`](../schemas/evidence-deterministic.v1.json).

### 4.2 Privileged lane (requires a capable host)

Exercises real Firecracker boot, cgroup-v2 enforcement, TAP/netns, jailer launch,
lifecycle cleanup, and snapshot/restore against real KVM. The privileged lane is
**gated**: it refuses to run unless strict preflight passes, and it emits
`blocked` evidence (never a mocked pass) when prerequisites are absent.

```bash
# Gate the privileged lane. Runs preflight --strict first; exits 77 if blocked.
bash scripts/run-privileged-tests.sh
```

Feature-gated privileged test targets (run only on a capable host):

```bash
# Direct-KVM educational subset privileged boot (requires /dev/kvm):
cargo test -p microvm-backend-directkvm --features direct-kvm,privileged

# Adversarial security batteries that need a real kernel (skip gracefully otherwise):
cargo test -p microvm-security-tests --features privileged
```

Privileged evidence embeds the `host_preflight` snapshot and is governed by
[`schemas/evidence-privileged.v1.json`](../schemas/evidence-privileged.v1.json).
That schema carries an anti-mock rule: when `host_preflight.kvm_ok` is `false`,
no run may record `pass: true`. A blocked lane emits `pass: false`,
`blocked: true`, and a `blocked_reason` token.

### Lane selection summary

| Lane | Substrate | Gate | On an incapable host |
| --- | --- | --- | --- |
| deterministic | none | `cargo test --workspace` | Runs unchanged. |
| privileged | `/dev/kvm` (API ≥ 12), `/dev/net/tun`, unified cgroup-v2 (`cpu`+`memory`+`pids`), pinned Firecracker+jailer | `bash scripts/run-privileged-tests.sh` (preflight `--strict`) | Emits `blocked` evidence; never mocks a pass. |
| benchmark | same as privileged, plus page-cache control and N ≥ 100 samples | benchmark harness binary | Records a stable blocked reason, zero samples, null percentiles; exits `77`. |

---

## Benchmark interpretation

Benchmark artifacts are governed by
[`schemas/evidence-benchmark.v1.json`](../schemas/evidence-benchmark.v1.json)
and follow strict interpretation rules. Read these before quoting any number.

- **Target, not SLA.** The `<200 ms` snapshot/restore figure is a *measured
  reference target* recorded as `target_ms` metadata. Firecracker publishes no
  universal restore-latency SLA, and this project makes no universal guarantee
  that every host achieves it. Restore latency depends on memory size, vCPU
  count, device count, and storage/page-cache state.
- **No pass/fail gate.** The benchmark schema forbids a `pass` field at the top
  level and on every benchmark item. Reviewers compare the recorded p50/p95/p99
  against `target_ms`; the harness never reduces that comparison to a boolean.
- **Distributions, not verdicts.** Each lane records p50/p95/p99 under cold and
  warm page-cache conditions, with full host metadata, pinned workload/artifact
  hashes, and runtime versions.
- **Like-for-like content.** A single pinned `payload_sha256` is shared by the
  Docker and VM comparison lanes. Comparing different image contents is
  explicitly not proof of superiority.
- **Blocked lanes carry evidence.** An unavailable Docker/KVM/Firecracker lane
  records a stable blocked reason, zero samples, and null percentiles — never
  fabricated samples. Sample failures are recorded and excluded from statistics,
  never zero-filled.

See [adr/0011-benchmark-distributions-not-sla.md](adr/0011-benchmark-distributions-not-sla.md)
for the decision rationale.

---

## Direct-KVM educational subset

The `microvm-backend-directkvm` crate is an **educational** KVM backend gated
behind the `direct-kvm` Cargo feature (off by default). It is **not** a
production Firecracker replacement. Its contract is pinned in
[design/direct-kvm-subset.md](design/direct-kvm-subset.md): one architecture
(x86_64), one vCPU, one 16 MiB memory slot, serial output, and four handled VM
exits. Deterministic contract tests run without `/dev/kvm`:

```bash
cargo test -p microvm-backend-directkvm --no-default-features
```

The privileged boot test requires `/dev/kvm` and the `direct-kvm,privileged`
features (see §4.2).

---

## Troubleshooting orientation

| Symptom | First check |
| --- | --- |
| Preflight exits `77` | Read `blockers` / `blocked_reason` in `.preflight/host.json`. Privileged work is not possible on this host; deterministic work still is. |
| Preflight exits `2` | Read `warnings`. The host is degraded; `--strict` will treat this as blocked. |
| `kvm_api_version_unprobed_in_bash` warning | Expected Bash limitation (§3). The device is openable but the API version was not probed via ioctl. |
| Firecracker/jailer `accessible: false` | The pinned binaries are not on `PATH`; the privileged lane will block rather than fall back. |
| Privileged test skips | Expected on a non-capable/non-root host; privileged-gated tests skip gracefully instead of failing. |
