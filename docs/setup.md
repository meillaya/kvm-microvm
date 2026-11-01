# Setup, preflight, and test lanes

This page explains how to set up the development environment, what the host
preflight result means, and how to run the deterministic and privileged lanes.
Run every command from the repository root.

This is a development and verification platform. The commands below do not make
a host production-ready. See [security.md](security.md) for the trust
boundaries.

## 1. Prerequisites

| Requirement | Why | Notes |
| --- | --- | --- |
| Linux x86_64 host | KVM target architecture | aarch64 is a documented secondary target. |
| [Nix](https://nixos.org/) and [devenv](https://devenv.sh/) | Reproducible toolchain | `devenv.yaml` requires devenv `>=2.1`. |
| `/dev/kvm` (privileged lane) | Real virtualization | The deterministic lane does not need it. |
| `/dev/net/tun` (privileged lane) | TAP networking | The deterministic lane does not need it. |
| cgroup v2 unified hierarchy (privileged lane) | Resource limits | Needs the `cpu`, `memory`, and `pids` controllers. |
| Pinned Firecracker and jailer (privileged lane) | Runtime adapter | Verified by SHA-256 before use. |

The deterministic lane runs on Linux, including ordinary CI containers. It
never touches `/dev/kvm`, `/dev/net/tun`, or a writable cgroupfs. Several crates
use Linux-only `libc` constants and paths (`openat2`, cgroupfs), so the
workspace does not build on macOS.

## 2. Enter the development environment

`devenv.yaml` pins the inputs (`nixpkgs`, `git-hooks`). `devenv.nix` enables
Rust on the stable channel and adds the Linux VM tools: QEMU/KVM, nftables,
cpio, util-linux, kmod, e2fsprogs, and pciutils. `rust-toolchain.toml` pins Rust
1.95.0.

```bash
devenv shell
```

Confirm the toolchain resolved:

```bash
devenv shell -- rustc --version
devenv shell -- cargo --version
```

devenv 2.x has no built-in KVM/QEMU service module, and `devenv.nix` does not
declare one. The orchestrator owns the VM host stack through its Rust crates and
host scripts, not through devenv-managed services.

## 3. Host preflight: what it means

`scripts/preflight.sh` reads host capabilities. It never mutates sysctls,
creates namespaces, loads kernel modules, or opens `/dev/kvm` for writing. It
parses `/etc/os-release` with `grep` and `sed` and does not source the file.

### Run it

```bash
# Print JSON to stdout and write a convenience copy in .preflight/host.json.
bash scripts/preflight.sh

# Write atomically to an explicit path, as CI evidence expects.
bash scripts/preflight.sh --json .preflight/host.json

# Treat degraded warnings as blockers.
bash scripts/preflight.sh --strict --json .preflight/host.json
```

### Exit codes

| Exit | Meaning | Lane consequence |
| --- | --- | --- |
| `0` | Capable. No blockers and no warnings. | The privileged lane may proceed. |
| `2` | Degraded. Warnings are present and no hard blocker exists. | Proceed with a caveat, or block under `--strict`. |
| `77` | Blocked. One or more blockers are present. | Do not run the privileged lane. Record blocked evidence. |

`--strict` promotes the degraded (`2`) result to blocked (`77`).

### What the JSON records

The output conforms to
[`schemas/evidence-host-preflight.v1.json`](../schemas/evidence-host-preflight.v1.json)
with `class: "host_preflight"`. The fields are:

| Field | Meaning |
| --- | --- |
| `host` | OS, architecture, kernel, and Nix version. |
| `cpu` | Vendor, virtualization flag (`virt`), and nested-virtualization flag (`nested`). |
| `kvm` | `/dev/kvm` mode, uid, gid, accessibility, and API version. |
| `tap` | `/dev/net/tun` mode and accessibility. |
| `cgroup_v2` | Unified flag and available controllers. |
| `tools` | Firecracker and jailer presence, version, and SHA-256. |
| `mitigations` | CPU vulnerability status from `/sys/devices/system/cpu/vulnerabilities/*`. |
| `blockers` | Hard-blocking condition tokens. |
| `warnings` | Degraded-condition tokens. |
| `blocked_reason` | A human-readable summary when the host is blocked. |

### Documented toolchain limitation

Pure Bash cannot issue `ioctl(2)`, so the script cannot run
`KVM_GET_API_VERSION` or `TUNGETFEATURES`. When `/dev/kvm` is openable, the
probe reports `kvm.api_version = -1` and emits the warning token
`kvm_api_version_unprobed_in_bash`. A privileged runner can refine the value
with a small companion binary. The gap is recorded instead of hidden.

## 4. The two verification lanes

The platform uses a hybrid test strategy: deterministic contracts first, with
privileged host behavior gated behind preflight. This keeps feedback fast and
reproducible while still requiring real evidence for host claims.

### 4.1 Deterministic lane (no host capabilities required)

The deterministic lane covers unit tests, property tests, API and transport
contract parity, scheduler logic, the OCI importer, the snapshot manifest and
compatibility gate, and the adversarial security batteries. It needs no
`/dev/kvm`, `/dev/net/tun`, or writable cgroupfs.

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Dependency policy is configured in `deny.toml`. CI does not run it, so run
`nix run nixpkgs#cargo-deny -- check` when you change a dependency.

Deterministic evidence does not carry `host_preflight` or `target_ms` fields.
Per-host metadata would make a reproducible result depend on the host. See
[`schemas/evidence-deterministic.v1.json`](../schemas/evidence-deterministic.v1.json).

### 4.2 Privileged lane (requires a capable host)

The privileged lane exercises Firecracker boot, cgroup-v2 enforcement,
TAP/netns, jailer launch, lifecycle cleanup, and snapshot/restore against real
KVM. Two scripts split the work. `scripts/run-privileged-tests.sh` runs strict
preflight and refuses a blocked host. `scripts/run-privileged-suite.sh` runs the
tests and needs `sudo` for cgroup, netns, and jailer setup.

```bash
# Strict preflight gate. Exits 77 when the host is blocked.
bash scripts/run-privileged-tests.sh

# Run the suite after the gate passes.
sudo -E bash scripts/run-privileged-suite.sh
```

Privileged test targets:

```bash
# Direct-KVM educational subset, requires /dev/kvm.
cargo test -p microvm-backend-directkvm --features direct-kvm,privileged

# Adversarial security batteries that need a real kernel.
cargo test -p microvm-security-tests --features privileged
```

Privileged evidence embeds the `host_preflight` snapshot and conforms to
[`schemas/evidence-privileged.v1.json`](../schemas/evidence-privileged.v1.json).
The schema carries an anti-mock rule: when `host_preflight.kvm_ok` is `false`,
no run may record `pass: true`. A blocked lane emits `pass: false`,
`blocked: true`, and a `blocked_reason` token.

### Lane selection summary

| Lane | Substrate | Gate | On an incapable host |
| --- | --- | --- | --- |
| deterministic | None | `cargo test --workspace` | Runs unchanged. |
| privileged | `/dev/kvm` (API 12 or later), `/dev/net/tun`, unified cgroup v2 with `cpu`, `memory`, and `pids`, pinned Firecracker and jailer | `bash scripts/run-privileged-tests.sh`, then `sudo -E bash scripts/run-privileged-suite.sh` | The gate exits `77` and the suite is not run. |
| benchmark | The privileged substrate, plus page-cache control and at least 100 samples | Benchmark harness binary | Records a stable blocked reason, zero samples, and null percentiles, then exits `77`. |

## Benchmark interpretation

Benchmark artifacts conform to
[`schemas/evidence-benchmark.v1.json`](../schemas/evidence-benchmark.v1.json).
Read these rules before you quote a number.

- The `<200 ms` snapshot/restore figure is a measured reference target recorded
  as `target_ms`. Firecracker publishes no universal restore-latency SLA, and
  this project does not guarantee that every host reaches the target. Restore
  latency depends on memory size, vCPU count, device count, and page-cache
  state.
- The harness publishes p50, p95, and p99 under cold and warm page-cache
  conditions, with host metadata, pinned workload and artifact hashes, and
  runtime versions. It does not reduce a comparison to a boolean, and the
  schema forbids a `pass` field.
- The Docker and VM lanes share one pinned `payload_sha256`. A comparison across
  different image contents is not evidence of superiority.
- A blocked lane records a stable reason, zero samples, and null percentiles.
  Failed samples are recorded and excluded from the statistics, not zero-filled.

See [ADR-0011](adr/0011-benchmark-distributions-not-sla.md) for the rationale.

## Direct-KVM educational subset

The `microvm-backend-directkvm` crate is an educational KVM backend behind the
`direct-kvm` Cargo feature, off by default. It is not a production Firecracker
replacement. Its contract is pinned in
[design/direct-kvm-subset.md](design/direct-kvm-subset.md): x86_64 only, one
vCPU, one 16 MiB memory slot, serial output, and four handled VM exits.

The deterministic contract tests run without `/dev/kvm`:

```bash
cargo test -p microvm-backend-directkvm --no-default-features
```

The privileged boot test requires `/dev/kvm` and the `direct-kvm,privileged`
features. See section 4.2.

## Guest image pipeline

The snapshot and benchmark lanes need a Firecracker-compatible kernel and
rootfs. `scripts/build-guest-image.sh` builds three artifacts under `guest/`:

- `vmlinux`: the Firecracker CI guest kernel, or the URL in `KERNEL_URL`.
- `rootfs.ext4`: a 64 MiB ext4 image with static busybox and the health server
  from `crates/microvm-guest-health`.
- `payload.sha256`: SHA-256 checksums for the kernel and rootfs.

```bash
bash scripts/build-guest-image.sh
```

The script needs the Rust `x86_64-unknown-linux-musl` target, `mkfs.ext4`,
`curl`, a static busybox, `sha256sum`, and `sudo` for the loop mount. The
`guest/` directory is git-ignored. `scripts/prepare-bench-artifacts.sh` builds
the image when it is absent, takes a snapshot, and runs the Firecracker and
Docker lanes against the same payload bytes.

## Troubleshooting orientation

| Symptom | First check |
| --- | --- |
| Preflight exits `77` | Read `blockers` and `blocked_reason` in `.preflight/host.json`. Privileged work is not possible on this host; deterministic work still is. |
| Preflight exits `2` | Read `warnings`. `--strict` treats the same result as blocked. |
| `kvm_api_version_unprobed_in_bash` warning | This is the Bash limitation in section 3. The device is openable, but the API version was not probed. |
| Firecracker or jailer reports `accessible: false` | The pinned binaries are not on `PATH`. The privileged lane blocks instead of falling back. |
| Privileged tests skip | The host is not capable or the process is not root. Privileged-gated tests skip and record blocked evidence. |
