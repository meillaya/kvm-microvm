# Release-Readiness Report — kvm-microvm-orchestrator

**Plan todo 34 — release-readiness integration matrix.**
Generated: 2026-07-20 (America/Toronto) · Verification base commit: `6a74671` ·
Reducer: [`scripts/aggregate-evidence.sh`](../scripts/aggregate-evidence.sh) ·
Machine-readable evidence:
[`.omo/evidence/kvm-microvm-orchestrator/task-34-kvm-microvm-orchestrator.json`](../.omo/evidence/kvm-microvm-orchestrator/task-34-kvm-microvm-orchestrator.json)
and [`summary.json`](../.omo/evidence/kvm-microvm-orchestrator/summary.json).

This report reconciles the full verification matrix across the project's five
topology components and records the release gate decision. It is **fail-closed**:
blocked evidence is preserved verbatim, benchmark targets are never release
gates, and no privileged result is mocked into a pass.

---

## 1. Headline verdict

| Lane | Result | Detail |
| --- | --- | --- |
| Deterministic suite/lint/schema/docs | **PASS** | `cargo test --workspace` 1317 passed / 0 failed; `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; reducer schema validation `all_valid=true`, `arithmetic_reconciled=true`. |
| Privileged suite | **PASS-or-BLOCKED** | 1 real pass (todo 30 direct-KVM real boot) + 11 explicitly blocked with preflight/host reasons; 0 fail; 0 mocked pass. |
| Benchmark artifacts | **PUBLISHED-or-BLOCKED** | 1 published (warm HTTP-function demo distributions) + 1 blocked (Docker/Firecracker binaries missing). **Not a release gate; no `pass` field.** |
| Scope fidelity | **CLEAN** | No TCP control-plane listener, no remote pull, no rootless/VFIO/live-migration, no general-OCI; no `.codegraph/` or `.omo/run-continuation/` changes. |
| Topology coverage | **COMPLETE** | All five components have evidence files and a final status. |

**Overall:** release-ready for the deterministic contract and scope-fidelity
boundaries on this host. Privileged host-mutation lanes and the Docker/Firecracker
benchmark comparison are **honestly blocked** pending a capable host with
Firecracker/jailer/docker installed and cgroup delegation enabled. No benchmark
target is asserted as a gate and no blocked evidence is erased.

Reducer totals (strict `--require-complete`, exit 0):
`pass=19 blocked=14 published=1 fail=0 missing=0 invalid=0`,
`semantic_violations=0`, coverage `34/34`.

---

## 2. Deterministic lane (requirement 1)

| Gate | Command | Exit | Result |
| --- | --- | --- | --- |
| Tests | `cargo test --workspace` | 0 | 1317 passed, 0 failed, 0 ignored |
| Format | `cargo fmt --all --check` | 0 | no diffs (rustfmt `format_strings` nightly-config warnings are not format violations) |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | zero warnings |
| Schema/docs | reducer schema validation | 0 | `all_valid=true`, `arithmetic_reconciled=true`; docs tree present |

Toolchain: pinned `rustc`/`cargo` 1.95.0 via `rust-toolchain.toml`. The
deterministic lane requires no `/dev/kvm`, `/dev/net/tun`, or cgroup mutation.

---

## 3. Privileged lane (requirement 2)

The privileged suite is **pass or explicitly blocked with preflight** — never
mocked to pass.

**Real pass (1):**

- **Todo 30 — feature-gated direct-KVM subset.** Real KVM boot on this host:
  `kvm_api_version 12`, nested AMD KVM, marker guest wrote byte `75` (`'K'`) in
  64-bit long mode to I/O port `0x3F8` and halted (`stop=hlt`). Anti-mock check
  satisfied (real-substrate proof present).

**Explicitly blocked (11), each with a host reason:**

| Todo | Blocked reason |
| --- | --- |
| 4 | preflight lane verdict blocked (Firecracker binary not installed) |
| 10 | `cgroup_delegate_failed` |
| 11 | `privileged_not_demonstrated_on_host` |
| 12 | `firecracker_binary_missing,jailer_binary_missing,no_pinned_binary_verified` |
| 13 | `privileged_not_demonstrated_on_host` |
| 14 | `privileged_not_demonstrated_on_host` |
| 15 | `privileged_not_demonstrated_on_host` |
| 19 | `firecracker_binary_missing` |
| 22 | `privileged_not_demonstrated_on_host` |
| 23 | `privileged_not_demonstrated_on_host` |
| 31 | `privileged_not_demonstrated_on_host` |

Host preflight (`.preflight/host.json`): CachyOS x86_64, kernel 7.1.3-2-cachyos,
AuthenticAMD with `svm`/nested virt; `/dev/kvm` and `/dev/net/tun` accessible
(mode 0666); cgroup v2 unified with `cpuset,cpu,io,memory,hugetlb,pids,rdma,misc,dmem`.
Missing host prerequisites for the blocked lanes: Firecracker binary, jailer
binary, docker binary, and unprivileged cgroup delegation.

---

## 4. Benchmark lane (requirement 3 + 7)

Benchmark artifacts are **published distributions or blocked with a host reason**.
They are **never release gates** and **never carry a `pass` field** (the reducer
enforces this anti-boolean invariant; `benchmark.pass_forbidden=true`).

- **Published — todo 28 (warm HTTP-function demo).** `task-28-warm.json`
  validates against `warm-http-demo.v1.json`; cold/warm distributions recorded
  with host metadata; cleanup evidenced.
- **Blocked — todo 27 (snapshot/boot benchmark + Docker comparison).**
  `task-27-benchmark.json` validates against `evidence-benchmark.v1.json`;
  blocked reason `docker_missing,firecracker_missing`.

The `<200 ms` snapshot/restore figure is a measured reference target, not an SLA
or gate (see [adr/0011-benchmark-distributions-not-sla.md](adr/0011-benchmark-distributions-not-sla.md)).

---

## 5. Scope fidelity (requirement 4 + 5)

| Boundary | Verdict | Evidence |
| --- | --- | --- |
| No TCP control-plane listener | clean | REST (`microvm-rest`) and gRPC (`microvm-grpc`) bind **only** `tokio::net::UnixListener` (mode 0660, peer-credential auth). The only TCP code is the outbound guest-readiness `TcpHealthProbe` (connects to the guest for the warm demo) and the `transport-contract` scope guard `scan_for_tcp_patterns` plus its detector test fixtures. Config/manifest/schema scan for `0.0.0.0`/`tcp://`/`[::]`/`localhost:` returned zero matches outside the detector tests. |
| No remote pull | clean | OCI importer is local-only; remote/tag-only refs (`https://`, `docker://`, `registry:`) rejected with `ImportError::RemoteReference` before any I/O; no network I/O performed. |
| No rootless / VFIO / live-migration | clean | grep across `crates/` returned zero non-comment/non-test matches. |
| No general-OCI behavior | clean | `microvm-oci` rejects host mounts, capabilities, privileged mode, host namespaces, and host process controls (`ForbiddenField`); help/tests assert it disclaims "OCI runtime compatible". |
| No `.codegraph/` or `.omo/run-continuation/` changes | clean | `git status --porcelain -- .codegraph .omo/run-continuation` is empty. The only working-tree change from this run is the reducer output `summary.json`. |

---

## 6. Five topology components (requirement 6)

Each component (topology ledger locked in the approved draft) has evidence files
and a final status. No component has a `fail`; blocked components are host-gated,
not failed.

| Component | Todos | Final status | Evidence summary |
| --- | --- | --- | --- |
| **environment** | 1,2,3,4 | pass-deterministic / blocked-privileged | Evidence schema green (3); pinned Rust 1.95.0 workspace builds/tests/fmt/clippy clean in this run. devenv-shell verdict (1,2) blocked by container Nix trust-user restriction; privileged preflight (4) blocked: Firecracker missing. |
| **lifecycle** | 5,6,7,8,14,15,16,17,18,19,29,30 | **pass** | 9 deterministic todos green (types, state machine, auth/ownership, REST/gRPC contract+parity, direct-KVM contract) **plus a real privileged KVM boot (todo 30)**. Firecracker adapter/service/integration (14,15,19) blocked: binary missing. |
| **isolation** | 10,11,12,13,31 | blocked-host-gated | All 5 are privileged host-mutation todos, blocked with explicit reasons (cgroup delegation, Firecracker/jailer binaries, not demonstrated on host). Deterministic policy/invocation unit logic is green within the 1317; no silent isolation fallback; no fabricated pass. |
| **state-observability** | 9,20,21,22,23,24 | pass-deterministic / blocked-privileged | 4 deterministic green (artifact path/digest, images+manifests, snapshot manifest+compat gate, scheduler). Privileged snapshot create/load (22) and live metrics (23) blocked: not demonstrated on host. |
| **interfaces-benchmarks** | 25,26,27,28 | pass-deterministic / published-benchmark | 2 deterministic green (constrained OCI importer + `microvm run`, CLI). Benchmark published (warm demo, 28) + blocked (Docker/Firecracker comparison, 27). |

Cross-cutting meta todos (32 docs, 33 aggregation, 34 this release) support all
five components and are not themselves topology components.

---

## 7. Release gate policy (requirement 7)

- **Benchmark targets are not release gates.** Distributions are published with
  host metadata; they never reduce to pass/fail and never gate release.
- **Blocked evidence is preserved.** Every blocked privileged/benchmark todo
  retains its explicit host reason in `summary.json` and in its task artifact;
  none is erased or promoted to pass.
- **Fail-closed reducer.** Deterministic lane has no blocked state; privileged
  pass requires real-substrate proof (anti-mock); benchmark never records `pass`
  (anti-boolean). `semantic_violations=0`.

## 8. Reproduce

```bash
export PATH="/nix/store/cxx967kpb69s62f8xh97qq1r2lhj6i3s-rustup-1.29.0/bin:$PATH"
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
scripts/aggregate-evidence.sh --require-complete      # exit 0 at 34/34
git diff --exit-code -- .codegraph .omo/run-continuation   # no changes
```
