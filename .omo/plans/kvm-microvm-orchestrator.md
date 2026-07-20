# kvm-microvm-orchestrator - Work Plan

## TL;DR (For humans)
<!-- Fill this LAST, after the detailed plan below is written, so it summarizes the REAL plan. -->
<!-- Plain English for a non-engineer: NO file paths, NO todo numbers, NO wave/agent/tool names. -->

**What you'll get:** A Rust-based, Firecracker-first microVM platform that can create, run, stop, snapshot, and restore isolated Linux workloads through both REST and gRPC, with local image building, resource limits, networking, metrics, scheduling, benchmarks, and a warm-function demonstration.

**Why this approach:** One transport-neutral lifecycle service keeps REST and gRPC behavior identical, while explicit cgroup-v2, jailer, path, and network gates prevent the upstream runtime's trusted-input assumptions from becoming tenant escapes. Local digest-addressed artifacts and compatibility manifests make snapshots reproducible and auditable.

**What it will NOT do:** It will not expose a TCP control API, pull remote tags, or claim general OCI runtime compatibility. It will not implement live migration, VFIO/GPU passthrough, rootless mode, multi-host scheduling, or a production-complete custom VMM.

**Effort:** XL
**Risk:** High - privileged KVM, namespaces, cgroup-v2, networking, and multi-tenant cleanup must be proven on a capable Linux host.
**Decisions to sanity-check:** The owner has selected Rust, Firecracker-first, dual Unix-socket transports, multi-tenant isolation, controlled NAT, pinned local artifacts, and local-integrity snapshots; no unresolved owner fork remains.

Your next move: choose whether to start execution now or run the optional high-accuracy plan review first. Full execution detail follows below.

---

> TL;DR (machine): XL/high-risk greenfield Rust microVM platform plan covering Firecracker lifecycle, Unix-socket REST+gRPC, cgroup-v2/TAP isolation, local images/snapshots, metrics/scheduler, direct-KVM subset, benchmarks, and warm-function demo.

## Scope
### Must have
- Reproducible devenv.sh/Nix environment with pinned Rust toolchain, explicit `git-hooks` input, lockfiles, Linux-only KVM/TAP tooling, and deterministic/privileged CI lanes.
- Rust workspace with typed IDs, VM lifecycle state machine, resource specifications, tenant ownership, typed errors, and transport-neutral lifecycle service.
- REST/JSON and gRPC lifecycle APIs over protected Unix sockets only: create, start, stop, snapshot, restore, status, and per-VM metrics; peer-credential authorization and cross-tenant denial.
- Firecracker-first runtime adapter using a pinned release/static binary, explicit `--cgroup-version=2`, jailer argv validation, process supervision, readiness signaling, and fail-closed startup.
- Descriptor-relative local artifact paths, deterministic kernel/rootfs image builder, digest-addressed artifact store, and constrained local OCI-like `microvm run` interface.
- Per-VM cgroup-v2 CPU/memory/pids/IO limits, TAP networking in a network namespace, controlled nftables NAT, egress policy, quotas, and idempotent cleanup/reconciliation.
- Versioned local snapshots with state/memory/block-device hashes, compatibility metadata, quotas, paused-create and fresh-process-load protocol, and immutable memory-file handling.
- Per-VM metrics for boot phases, memory, CPU usage/guest steal, CPU throttling, and network throughput; deterministic scheduler with resource-aware bin-packing.
- Snapshot/restore latency evidence, Docker-style cold/warm comparison, and a warm HTTP-function microVM demo with reproducible p50/p95/p99 artifacts.
- Narrow direct-KVM educational subset with an explicit one-architecture, one-vCPU, serial/device contract and separate privileged verification.

### Must NOT have (guardrails, anti-slop, scope boundaries)
- No product code may touch `.codegraph/`, `.omo/run-continuation/`, or the approved draft artifact.
- No public, unauthenticated, loopback, or remote TCP listener; both control transports remain Unix-socket-only.
- No arbitrary host paths, unrestricted subprocess arguments, host-network sharing, world-writable control sockets, or silent fallback when `/dev/kvm`, TAP, cgroup v2, jailer, seccomp, or artifact validation is unavailable.
- No remote registry pulls or tag-based `nginx:latest` behavior; OCI-like input is local and digest-addressed only.
- No general OCI runtime compatibility, host mounts, host capabilities, privileged container flags, live migration, GPU/VFIO passthrough, multi-host clustering, rootless mode, Windows/non-Linux guest support, or production-grade custom VMM beyond the documented subset.
- No cross-host snapshot transfer, signed/encrypted snapshot transport, or claim that Firecracker CRC authenticates state.
- No universal `<200 ms` performance guarantee; benchmarks publish conditions and distributions, while correctness/isolation/cleanup are hard gates.


## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: Hybrid — tests-first for deterministic types, state, API, policy, artifact, scheduler, and adapter-replay contracts; tests-after for privileged KVM/TAP/cgroup/jailer/Firecracker and benchmark harnesses. Framework: Rust `cargo test`/`cargo nextest`, property tests for pure policies, JSON-schema validation, and explicit host preflight with `pass`, `blocked`, or `failed` outcomes.
- Evidence: each todo writes its exact artifact under `.omo/evidence/kvm-microvm-orchestrator/`; privileged evidence must include host preflight and never report a mock as a real KVM pass; benchmark evidence must include p50/p95/p99, cold/warm conditions, sample count, and host metadata.


## Execution strategy
### Parallel execution waves
> Target 5-8 todos per wave. Fewer than 3 (except the final) means you under-split.

Wave 0 establishes the devenv, Rust workspace, evidence schema, and host preflight. Wave 1 defines domain/API/policy contracts. Wave 2 builds artifact-path, cgroup-v2, TAP/netns, jailer, and cleanup primitives. Wave 3 integrates Firecracker lifecycle and both Unix-socket transports. Wave 4 adds image building, snapshots, metrics, scheduler, and audit/reconciliation. Wave 5 adds the constrained OCI-like interface, CLI, direct-KVM subset, Docker comparison, and warm-function demo. Wave 6 runs adversarial verification and final evidence aggregation.

### Dependency matrix
When the matrix and a todo's `Blocked by`/`Blocks` disagree, the todo wins; F1 audits the matrix against the per-todo text and reports any remaining drift. The `Can parallelize with` column is implicit: any two todos whose `Blocks` sets do not intersect and whose `Blocked by` is fully satisfied can be worked in parallel.

| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1-4 | none | 5-34 | each other after workspace bootstrap, except shared lock edits |
| 5 | 1-4 | 6-9, 14-30 | 6-8 |
| 6 | 5 | 14-18 | 5, 7-8 |
| 7 | 5 | 8, 15-18, 20-24, 31-34 | 5-6, 8 |
| 8 | 5-7 | 15-18, 31-34 | 5-7 |
| 9 | 5, 7 | 10-13, 14, 20, 25-26 | 10-13 |
| 10 | 4, 7 | 13-15, 23-24, 31 | 11-13 |
| 11 | 4, 7, 9 | 13-15, 28, 30 | 10, 12-13 |
| 12 | 4, 9-10 | 15, 24 | 11, 13 |
| 13 | 9-12 | 14-24, 28-31 | none |
| 14 | 5-13 | 15-19, 21-24, 28-30 | 20-24 after lifecycle ports are stable |
| 15 | 6-7, 10-14 | 16-19, 21-30 | 20-24 |
| 16 | 6-8, 15 | 18, 27-30 | 17, 20-24 |
| 17 | 6-8, 15 | 18, 27-30 | 16, 20-24 |
| 18 | 7-8, 15-17 | 19, 25-34 | 20-24 |
| 19 | 10-15 | 20-24, 27-30 | none |
| 20 | 5, 9, 14 | 21, 25-30 | 21-24 |
| 21 | 5, 7, 9, 14 | 22, 27-30 | 22-24 |
| 22 | 14-15, 21 | 27-30 | 23-24 |
| 23 | 10-15, 19 | 24, 27-30 | 24 |
| 24 | 7, 10, 13, 23 | 27-30 | none |
| 25 | 8-9, 20-24 | 26-30 | 26 |
| 26 | 8, 15-18, 25 | 27-30 | 27-30 |
| 27 | 14-15, 20-24, 26 | 31-34 | 28-30 |
| 28 | 20-23, 26-27 | 31-34 | 29-30 |
| 29 | 5, 6, 20 | 30-31 | 30 |
| 30 | 4-6, 29 | 31-34 | 31-34 |
| 31 | 1-30 | 32-34 | 32-34 |
| 32 | 1-31 | 33-34 | 33-34 |
| 33 | 3, 4, 19, 21-24, 27-32 | 34 | 34 |
| 34 | 31-33 | F1-F4 | none |

## Todos
> Implementation + Test = ONE todo. Never separate.
<!-- APPEND TASK BATCHES BELOW THIS LINE WITH edit/apply_patch - never rewrite the headers above. -->
- [x] 1. Bootstrap `devenv.yaml`, `devenv.nix`, and committed lockfiles for a reproducible Rust/Linux environment
  What to do / Must NOT do: Add explicit devenv 2.x inputs for pinned nixpkgs and `git-hooks`, `devenv.lock`, Linux-only packages via `lib.mkMerge`/`lib.mkIf`, and a thin flake entry if required. Must not add a KVM service, remote secrets, or platform-specific package evaluation outside Linux.
  Parallelization: Wave 0 | Blocked by: none | Blocks: 2-4, 5-34
  References (executor has NO interview context - be exhaustive): `/home/mei/projects/kernels/kernel-v4/.omo/drafts/kvm-microvm-orchestrator.md:42-54,64-79`; official devenv docs `https://devenv.sh/files-and-variables/`, `https://devenv.sh/recipes/cross-platform/`, `https://devenv.sh/pinning/`; current finding that no KVM/QEMU service exists in devenv.
  Acceptance criteria (agent-executable): `devenv shell -- true` exits 0; `devenv.lock` exists and is referenced by `devenv.yaml`; Linux-only package branches evaluate with `nix flake check`; `grep -R 'services.*kvm\|services.*qemu' devenv.nix` returns no match; `git-hooks` is declared explicitly.
  QA scenarios (name the exact tool + invocation): happy `devenv shell -- bash -lc 'rustc --version && cargo --version'`; failure `devenv shell --strict-ports -- true` with a deliberately invalid input returns non-zero and leaves no generated lock outside approved paths. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-1-kvm-microvm-orchestrator.json`.
  Commit: Y | `chore(env): pin devenv inputs and Linux toolchain`

- [x] 2. Create the Rust workspace, toolchain pin, formatting, lint, and dependency policy
  What to do / Must NOT do: Add `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` pinned to Rust `1.95.0` with edition 2021 and `rustfmt`, `clippy`, `rust-analyzer`, `rust-src` components, `rustfmt.toml`, `deny.toml`, and empty crate manifests for the planned workspace. Must not add runtime behavior or choose an unpinned compiler through system Rust.
  Parallelization: Wave 0 | Blocked by: 1 | Blocks: 5-34
  References (executor has NO interview context - be exhaustive): Draft decisions Rust and hybrid tests at `.omo/drafts/kvm-microvm-orchestrator.md:24-31,56-61`; `https://doc.rust-lang.org/cargo/guide/`; `https://rust-lang.github.io/rustup/overrides.html`; `https://github.com/EmbarkStudios/cargo-deny`.
  Acceptance criteria (agent-executable): `cargo metadata --locked --no-deps` succeeds; `rustup show active-toolchain` reports `1.95.0`; `cargo fmt --all -- --check` succeeds; `cargo clippy --workspace --all-targets -- -D warnings` succeeds; `cargo deny check` succeeds; default build has no privileged feature enabled.
  QA scenarios (name the exact tool + invocation): happy `cargo test --workspace --locked`; failure temporarily selecting an unavailable toolchain causes `rustup show active-toolchain`/devenv command to fail with the pinned-toolchain error rather than silently selecting system Rust. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-2-kvm-microvm-orchestrator.json`.
  Commit: Y | `chore(env): scaffold Rust workspace and quality gates`

- [x] 3. Define the evidence schema and outcome vocabulary for deterministic, privileged, and benchmark lanes
  What to do / Must NOT do: Add JSON Schemas and a validator for `deterministic`, `privileged`, `benchmark`, and host-preflight artifacts. Must not allow a mocked privileged result to be encoded as a real pass or a benchmark target as a boolean gate.
  Parallelization: Wave 0 | Blocked by: 1-2 | Blocks: 4, 31-34
  References (executor has NO interview context - be exhaustive): Draft test strategy and evidence requirement at `.omo/drafts/kvm-microvm-orchestrator.md:25,48,54,71`; `https://json-schema.org/specification`; Firecracker metrics/snapshot constraints at `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/metrics.md` and `.../docs/snapshotting/snapshot-support.md`.
  Acceptance criteria (agent-executable): schema validation rejects privileged `pass:true` when `host_preflight.ok` is false; benchmark schema contains sample count, cold/warm conditions, p50/p95/p99, and host metadata but no `pass` field; `cargo run --bin evidence-validate -- --all examples` exits 0.
  QA scenarios (name the exact tool + invocation): happy `jq -e '.class=="deterministic"' examples/deterministic.json`; failure remove `blocked_reason` from a blocked privileged artifact and assert `evidence-validate` exits 1. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-3-kvm-microvm-orchestrator.json`.
  Commit: Y | `chore(evidence): add lane evidence schemas`

- [x] 4. Implement host preflight and deterministic/privileged CI lane separation
  What to do / Must NOT do: Add read-only preflight for Linux arch, SVM/VMX, `/dev/kvm`, `/dev/net/tun`, cgroup v2/controllers, nft, Firecracker/jailer versions and hashes, and mitigation metadata; add deterministic CI and self-hosted privileged workflow definitions plus a 60-second drift watcher that blocks new creates after capability/binary permission changes. Must not mutate sysctls, load modules, create namespaces, or pass mocked KVM results.
  Parallelization: Wave 0 | Blocked by: 1-3 | Blocks: 5-34
  References (executor has NO interview context - be exhaustive): Draft host findings `.omo/drafts/kvm-microvm-orchestrator.md:34-54`; Linux KVM `https://docs.kernel.org/virt/kvm/api.html`; cgroup v2 `https://docs.kernel.org/admin-guide/cgroup-v2.html`; TAP `https://www.kernel.org/doc/Documentation/networking/tuntap.txt`; Firecracker getting started `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/getting-started.md`.
  Acceptance criteria (agent-executable): `scripts/preflight.sh --json .omo/evidence/kvm-microvm-orchestrator/task-4-preflight.json` always emits JSON; deterministic CI runs without `/dev/kvm`; privileged runner refuses to run real tests unless KVM API version 12, TUN, cgroup v2, nft, and pinned binaries pass; blocked output uses `blocked`, not `passed`; a changed `/dev/kvm` permission or binary hash is observed by the next drift tick and causes a new create to return `PreflightDrift`.
  QA scenarios (name the exact tool + invocation): happy `bash scripts/preflight.sh --json /tmp/preflight.json && jq -e '.host.arch and .cgroup_v2' /tmp/preflight.json`; failure run with an unreadable fake device path and assert exit 77 plus `.blocked_reason`, with no namespace or cgroup mutation. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-4-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(env): add host preflight and CI lane gates`

- [~] 5. Define typed identifiers, resource specifications, tenancy, and stable error codes
  What to do / Must NOT do: Add `crates/microvm-types` and `crates/microvm-errors` with VM/image/snapshot/tenant IDs, vCPU/memory/disk/network policy, principal roles, and stable machine-readable error codes. Must not perform I/O or call host APIs from these crates.
  Parallelization: Wave 1 | Blocked by: 1-4 | Blocks: 6-9, 14-30
  References (executor has NO interview context - be exhaustive): Draft tenancy/isolation assumptions `.omo/drafts/kvm-microvm-orchestrator.md:26-31,61-67`; Rust serde/cargo docs; Firecracker ID constraint `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/jailer.md`.
  Acceptance criteria (agent-executable): serde round-trip tests pass for every public type; property test finds no duplicate error code; invalid IDs containing `/`, `..`, uppercase where forbidden, or >64 bytes are rejected; `cargo test -p microvm-types -p microvm-errors --locked` exits 0 without Linux-only features.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-types --test roundtrip`; failure feed a duplicate error code fixture and assert the test names both variants; feed a negative memory limit and assert `InvalidResourceSpec`. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-5-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(types): add typed VM resources tenancy and errors`

- [~] 6. Define the lifecycle state machine and transport-neutral service contract
  What to do / Must NOT do: Add `crates/microvm-lifecycle` state transitions and a backend-neutral service trait for create, start, stop, snapshot, restore, status, and metrics. Must not embed REST/gRPC or Firecracker-specific JSON in the service contract.
  Parallelization: Wave 1 | Blocked by: 5 | Blocks: 14-18
  References (executor has NO interview context - be exhaustive): Draft lifecycle scope `.omo/drafts/kvm-microvm-orchestrator.md:16,45,52-61`; Firecracker lifecycle/swagger `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/firecracker/swagger/firecracker.yaml`; state-machine testing requirement in Metis review.
  Acceptance criteria (agent-executable): every legal transition in `Created → Configured → Running → Paused → Snapshotting/Restoring → Stopped/Failed` has a test; illegal transitions return typed errors; REST/gRPC crates can depend on the trait without the trait depending on either transport; mock backend contract suite passes.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-lifecycle --test state_machine`; failure call snapshot from `Created` and assert `InvalidTransition` with no backend call recorded. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-6-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(lifecycle): add typed state machine and service ports`

- [~] 7. Implement tenant authorization, ownership policy, quotas, and audit event types
  What to do / Must NOT do: Add policy checks for tenant ownership of VMs, images, snapshots, and metrics; define per-tenant vCPU/memory/disk/snapshot quotas and structured audit events. Must not authorize by mutable path strings or allow cross-tenant reads.
  Parallelization: Wave 1 | Blocked by: 5 | Blocks: 8, 15-18, 20-24, 31-34
  References (executor has NO interview context - be exhaustive): Draft multi-tenant decision `.omo/drafts/kvm-microvm-orchestrator.md:26,55-61`; Scope OUT `.omo/drafts/kvm-microvm-orchestrator.md:74-79`; Firecracker jailer trusted-input model `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/jailer.md`.
  Acceptance criteria (agent-executable): cross-tenant get/list/start/stop/snapshot/restore returns `PermissionDenied`; over-quota create returns `QuotaExceeded` before any Firecracker process or cgroup is created; every mutating request yields exactly one structured audit event with principal, tenant, resource, operation, result.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-lifecycle policy::tests::owner_can_start`; failure `cargo test -p microvm-lifecycle policy::tests::cross_tenant_snapshot_denied` and assert zero backend calls. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-7-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(policy): enforce tenant ownership quotas and audit events`

- [~] 8. Define REST OpenAPI and gRPC proto parity over Unix-socket-only transports
  What to do / Must NOT do: Add `api/openapi.yaml` and `api/microvm/v1/service.proto` for lifecycle/status/metrics methods, with one canonical operation model. Must not define TCP addresses, loopback fallback, or transport-specific business rules.
  Parallelization: Wave 1 | Blocked by: 5-7 | Blocks: 15-18, 31-34
  References (executor has NO interview context - be exhaustive): Draft REST+gRPC and Unix-only decisions `.omo/drafts/kvm-microvm-orchestrator.md:7,29,55,74`; Firecracker API swagger `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/firecracker/swagger/firecracker.yaml`; OpenAPI `https://spec.openapis.org/oas/latest.html`; protobuf `https://protobuf.dev/overview/`.
  Acceptance criteria (agent-executable): schemas define create/start/stop/snapshot/restore/status/metrics and error mappings; generated clients compile; parity test proves every OpenAPI operation has a proto service equivalent; static scan rejects `0.0.0.0`, `127.0.0.1`, and TCP listen configuration.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-transport-contract --test schema_parity`; failure remove a proto method and assert `cargo test --test schema_parity` exits 1. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-8-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(api): define REST and gRPC lifecycle contracts`

- [~] 9. Implement descriptor-relative artifact path validation and local digest store
  What to do / Must NOT do: Add `crates/microvm-artifacts` path resolver using `openat2` where available or a no-symlink `openat` fallback, per-tenant roots, owner/mode checks, and SHA-256/BLAKE3 manifest verification. Must not use unchecked absolute `open`, follow symlinks, or allow `..` escapes.
  Parallelization: Wave 2 | Blocked by: 5, 7 | Blocks: 10-13, 14, 20, 25-26
  References (executor has NO interview context - be exhaustive): Draft path/security findings `.omo/drafts/kvm-microvm-orchestrator.md:34,49-50,61-79`; Firecracker v1.16.1 PR #5959 context; `openat2(2)` `https://man7.org/linux/man-pages/man2/openat2.2.html`; Linux path resolution `https://docs.kernel.org/filesystems/path-lookup.html`.
  Acceptance criteria (agent-executable): fixtures for `/etc/passwd`, `../`, symlink component, magic link, world-writable file, foreign-owner file, and digest mismatch all return typed errors; valid digest-addressed local file opens through a held fd; no remote URI is accepted.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-artifacts path::tests::valid_digest_addressed_file`; failure `cargo test -p microvm-artifacts path::tests::rejects_symlink_escape` and assert no file outside the tenant root was opened. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-9-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(artifacts): add descriptor-relative path and digest validation`

- [~] 10. Build and verify the explicit cgroup-v2 hierarchy and resource limits
  What to do / Must NOT do: Add cgroup-v2 parent/leaf creation with top-down controller checks, `cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`, and optional `io.max`; pass only pre-created leaf paths to jailer. Must not rely on jailer’s v1 default, put domain controllers in a leaf subtree, or silently continue without the leaf.
  Parallelization: Wave 2 | Blocked by: 4, 7 | Blocks: 13-15, 23-24, 31
  References (executor has NO interview context - be exhaustive): Draft cgroup findings `.omo/drafts/kvm-microvm-orchestrator.md:40,49-50,56,68`; Linux cgroup v2 `https://docs.kernel.org/admin-guide/cgroup-v2.html`; Firecracker jailer `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/jailer.md`.
  Acceptance criteria (agent-executable): parent exposes required controllers; leaf has no children and empty `cgroup.subtree_control`; configured values round-trip from files; missing cgroup or controller returns `CgroupUnavailable` before spawn; generated jailer argv always includes `--cgroup-version=2` and an existing parent-cgroup.
  QA scenarios (name the exact tool + invocation): happy privileged `cargo test --features privileged --test cgroup_v2 -- --nocapture`; failure run with a synthetic missing controller and assert `blocked`/`CgroupUnavailable`, zero Firecracker children, and evidence of the missing controller. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-10-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(isolation): add explicit cgroup-v2 limits`

- [~] 11. Create per-VM network namespaces, TAP devices, and controlled nftables NAT
  What to do / Must NOT do: Add per-VM netns/TAP allocation, unique /30 addressing, nftables postrouting masquerade, default-deny forwarding/inter-VM rules, and explicit egress policy. Must not use host-network mode, a global permissive table, or silent shared NAT.
  Parallelization: Wave 2 | Blocked by: 4, 7, 9 | Blocks: 13-15, 28, 30
  References (executor has NO interview context - be exhaustive): Draft network policy `.omo/drafts/kvm-microvm-orchestrator.md:30,41,56,62`; Firecracker networking `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/network-setup.md`; TAP driver `https://www.kernel.org/doc/Documentation/networking/tuntap.txt`; nftables `https://wiki.nftables.org/`.
  Acceptance criteria (agent-executable): each VM receives a unique netns/TAP/CIDR; egress rule is present only when policy enables it; two VMs cannot reach each other by default; cleanup removes TAP/netns/nft table; all network setup errors roll back already-created resources.
  QA scenarios (name the exact tool + invocation): happy privileged `cargo test --features privileged --test tap_netns`; failure deny `CAP_NET_ADMIN`/missing TUN and assert `blocked` with no lingering `ip netns`, TAP, or nft table. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-11-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(isolation): add per-VM netns TAP and nftables NAT`

- [~] 12. Build the pinned Firecracker/jailer process specification and binary provenance gate
  What to do / Must NOT do: Add binary version/hash verification, static/release build checks, validated jailer argv, UID/GID assignment, resource limits, chroot/API socket paths, and post-exec seccomp verification. Must not accept debug/GNU/non-pinned binaries or claim jailer itself installs seccomp.
  Parallelization: Wave 2 | Blocked by: 4, 9-10 | Blocks: 13-15, 20-21, 29-31
  References (executor has NO interview context - be exhaustive): Draft Firecracker corrections `.omo/drafts/kvm-microvm-orchestrator.md:37-39,49-52`; Firecracker jailer `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/jailer.md`; seccomp `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/seccomp.md`; release `v1.16.1`.
  Acceptance criteria (agent-executable): binary hash/version matches the pinned manifest; ELF is the required release/static form; argv contains `--cgroup-version=2`, `--parent-cgroup`, `--netns`, non-root UID/GID, and bounded `--resource-limit`; after API readiness `/proc/<pid>/status` reports `Seccomp: 2`; missing checks reject before spawn.
  QA scenarios (name the exact tool + invocation): happy privileged `cargo test --features privileged --test jailer_invocation`; failure substitute a debug or wrong-hash binary and assert `BinaryProvenanceError`, no child process, and audit evidence. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-12-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(isolation): pin Firecracker and validate jailer launch`

- [~] 13. Implement idempotent VM resource cleanup and orphan reconciliation
  What to do / Must NOT do: Add resource ownership records and reverse-order cleanup for Firecracker/jailer, cgroups, netns, TAP/veth, nftables, sockets, chroot, artifact handles, and snapshots; add startup/periodic reconciliation. Must not leave orphan VMM processes or delete resources still owned by another tenant.
  Parallelization: Wave 2 | Blocked by: 9-12 | Blocks: 14-24, 28-31
  References (executor has NO interview context - be exhaustive): Draft cleanup scope `.omo/drafts/kvm-microvm-orchestrator.md:54-62,69`; cgroup `cgroup.events` and process lifecycle `https://docs.kernel.org/admin-guide/cgroup-v2.html`; Firecracker jailer cleanup notes `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/jailer.md`.
  Acceptance criteria (agent-executable): stop removes all owned resources within 5 seconds on a capable host; repeated cleanup is a no-op; orphan process/resource fixtures are detected and quarantined; cross-tenant resources are never removed; reconciler emits a leak record when cleanup cannot complete.
  QA scenarios (name the exact tool + invocation): happy privileged 50 create/stop cycles then assert no matching `pgrep`, `ip netns`, `ip link`, cgroup leaf, socket, or chroot remains; failure kill supervisor mid-start and assert reconciliation reports and cleans the orphan without touching another tenant’s fixture. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-13-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(isolation): add idempotent cleanup and reconciliation`

- [~] 14. Integrate the Firecracker boot/configure/start/stop adapter
  What to do / Must NOT do: Add a backend implementation that launches one Firecracker process per VM, configures kernel/rootfs/machine/network through its UDS API, waits for guest readiness, and maps process/API errors into lifecycle errors. Must not add QEMU as an equal runtime or expose Firecracker’s unauthenticated socket to tenants.
  Parallelization: Wave 3 | Blocked by: 5-13 | Blocks: 15-19, 21-24, 28-30
  References (executor has NO interview context - be exhaustive): Draft Firecracker-first decision `.omo/drafts/kvm-microvm-orchestrator.md:7,37-39,55-61`; Firecracker swagger `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/firecracker/swagger/firecracker.yaml`; design `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/design.md`.
  Acceptance criteria (agent-executable): a capable host can create, configure, start, observe guest readiness, stop, and clean one VM; all configuration paths are digest-validated; launcher records phase timestamps; missing host prerequisites fail before child creation; process exit and API errors become typed states.
  QA scenarios (name the exact tool + invocation): happy `cargo test --features privileged --test firecracker_boot`; failure use a malformed kernel/rootfs and assert no `InstanceStart`, `Failed` state, audit error, and cleanup evidence. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-14-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(lifecycle): integrate Firecracker boot adapter`

- [~] 15. Implement the lifecycle service with ownership, idempotency, readiness, and process supervision
  What to do / Must NOT do: Compose typed state, policy, isolation, Firecracker backend, quotas, readiness markers, and cleanup behind the service trait. Must not advance state before the backend confirms it or allow duplicate concurrent operations.
  Parallelization: Wave 3 | Blocked by: 6-7, 10-14 | Blocks: 16-19, 21-30
  References (executor has NO interview context - be exhaustive): Draft lifecycle/metrics findings `.omo/drafts/kvm-microvm-orchestrator.md:45-48,52-61`; Firecracker one-process model `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/design.md`; KVM process/thread restrictions `https://docs.kernel.org/virt/kvm/api.html`.
  Acceptance criteria (agent-executable): legal create/start/stop requests are idempotent by request key; readiness requires guest marker/service health, not only Firecracker process/socket readiness; duplicate operations serialize; owner and quota checks run before mutation; supervisor death is reconciled.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-lifecycle --test service_contract`; failure send two concurrent starts and assert one backend start, stable final state, and one audit decision per request; guest never sends readiness and assert typed `GuestNotReady`. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-15-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(lifecycle): compose supervised VM lifecycle service`

- [~] 16. Implement REST/JSON over a protected Unix socket
  What to do / Must NOT do: Add the OpenAPI routes over a filesystem Unix socket with mode/owner validation and peer credentials; map service errors to stable HTTP status/body. Must not bind TCP, accept anonymous sockets, or duplicate business policy.
  Parallelization: Wave 3 | Blocked by: 6-8, 15 | Blocks: 18, 27-30
  References (executor has NO interview context - be exhaustive): Draft API decisions `.omo/drafts/kvm-microvm-orchestrator.md:29,55,74`; OpenAPI spec from todo 8; Linux `SO_PEERCRED` `https://man7.org/linux/man-pages/man7/unix.7.html`.
  Acceptance criteria (agent-executable): REST happy paths call the shared service; socket is `0660` and expected owner/group; peer UID/GID is captured before authorization; cross-tenant maps to 403; malformed JSON maps to 400; no TCP listener is created.
  QA scenarios (name the exact tool + invocation): happy `curl --unix-socket runtime/api/rest.sock -sS -X POST http://localhost/v1/vms ... | jq -e '.id'`; failure connect using a socket with insecure mode or wrong peer and assert startup/request denial, no service mutation, and audit log. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-16-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(api): add authenticated REST Unix socket`

- [~] 17. Implement gRPC over a protected Unix socket with REST parity
  What to do / Must NOT do: Add generated protobuf server over a separate Unix socket using the same lifecycle service, auth middleware, error codes, and ownership policy. Must not enable reflection in the production socket or listen on TCP.
  Parallelization: Wave 3 | Blocked by: 6-8, 15 | Blocks: 18, 27-30
  References (executor has NO interview context - be exhaustive): Todo 8 proto contract; draft dual transport decision `.omo/drafts/kvm-microvm-orchestrator.md:7,55`; Unix socket credentials `https://man7.org/linux/man-pages/man7/unix.7.html`.
  Acceptance criteria (agent-executable): generated gRPC methods cover every lifecycle operation; same request through REST/gRPC reaches the same service result; unauthorized peer returns `PERMISSION_DENIED`; reflection is disabled; `ss -ltnp` has no orchestrator TCP listener.
  QA scenarios (name the exact tool + invocation): happy `grpcurl -unix runtime/api/grpc.sock -proto api/microvm/v1/service.proto list` returns only when test reflection mode is explicitly enabled; failure `grpcurl -plaintext 127.0.0.1:50051 list` fails because no TCP endpoint exists; cross-tenant restore returns `PermissionDenied`. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-17-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(api): add authenticated gRPC Unix socket`

- [~] 18. Add REST/gRPC parity, socket hardening, and request audit tests
  What to do / Must NOT do: Add contract tests that exercise both transports against shared fixtures and assert operation/error parity, socket mode, no-TCP policy, and audit emission. Must not duplicate or weaken authorization in either adapter.
  Parallelization: Wave 3 | Blocked by: 7-8, 15-17 | Blocks: 19, 25-34
  References (executor has NO interview context - be exhaustive): Draft multi-tenant and transport decisions `.omo/drafts/kvm-microvm-orchestrator.md:26-31,55-62`; OpenAPI/proto from todo 8; REST/gRPC from todos 16-17.
  Acceptance criteria (agent-executable): each operation has one REST and one gRPC happy fixture plus invalid/unauthorized fixture; results and error codes match; insecure socket mode and TCP config fail; denied requests write exactly one audit event.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-contract-tests --test transport_parity`; failure mutate REST schema/status or gRPC code and assert parity test exits 1. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-18-kvm-microvm-orchestrator.json`.
  Commit: Y | `test(api): enforce transport parity and socket policy`

- [x] 19. Add readiness, process, and cgroup/netns lifecycle integration tests
  What to do / Must NOT do: Add capable-host tests that prove a VM is not `Running` until guest readiness, child processes die with the supervisor, and all per-VM resources disappear on stop. Must not use QEMU TCG or mocks as KVM/Firecracker passes.
  Parallelization: Wave 3 | Blocked by: 10-15 | Blocks: 20-24, 27-30
  References (executor has NO interview context - be exhaustive): Draft readiness/cleanup findings `.omo/drafts/kvm-microvm-orchestrator.md:45-48,54,69-71`; Firecracker metrics/design docs; evidence schema todo 3.
  Acceptance criteria (agent-executable): successful test records spawn/socket/configured/guest-ready/stop timestamps; failed readiness ends in `GuestNotReady`; supervisor termination leaves no Firecracker, jailer, cgroup, TAP, netns, or socket; evidence class is privileged.
  QA scenarios (name the exact tool + invocation): happy `cargo test --features privileged --test lifecycle_cleanup`; failure kill daemon during boot and assert `preflight`/reconciler marks blocked or cleans all owned resources within 5 seconds. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-19-kvm-microvm-orchestrator.json`.
  Commit: Y | `test(lifecycle): verify readiness and resource lifecycle`

- [x] 20. Build local kernel/rootfs images and digest-addressed artifact manifests
  What to do / Must NOT do: Add a deterministic builder from local kernel/rootfs inputs to uncompressed kernel and ext4/rootfs artifacts, with manifest version, SHA-256, sizes, guest arch, boot args, and source provenance. Must not download remote registries or accept tag-only input.
  Parallelization: Wave 4 | Blocked by: 5, 9, 14 | Blocks: 21, 25-30
  References (executor has NO interview context - be exhaustive): Draft image scope `.omo/drafts/kvm-microvm-orchestrator.md:53,61,67,76`; Firecracker getting started `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/getting-started.md`; OCI image spec `https://github.com/opencontainers/image-spec`.
  Acceptance criteria (agent-executable): two builds from identical local inputs produce identical manifest/file hashes; all files have SHA-256 and size; non-`file://`/local digest source is rejected; malformed rootfs/kernel path is rejected before output; generated artifact opens only through todo 9.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-artifacts --test reproducible_builder`; failure pass a remote/tag URI and assert `LocalArtifactRequired`, no network call, and no partial artifact directory. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-20-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(artifacts): build pinned local kernel and rootfs images`

- [x] 21. Define and enforce the local snapshot manifest and compatibility gate
  What to do / Must NOT do: Add `schemas/snapshot-manifest.v1.json` and typed manifest with Firecracker version/hash, kernel/rootfs/block-device hashes, VM config, CPU/KVM API, cgroup version, owner tenant, memory/state hashes, quota, and immutable-memory requirement. Must not treat Firecracker CRC as authentication or invent cross-host compatibility.
  Parallelization: Wave 4 | Blocked by: 5, 7, 9, 14 | Blocks: 22, 27-30
  References (executor has NO interview context - be exhaustive): Draft snapshot findings `.omo/drafts/kvm-microvm-orchestrator.md:28,31,39,47-52,65,77`; Firecracker snapshot support `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/snapshot-support.md`; JSON Schema `https://json-schema.org/specification`.
  Acceptance criteria (agent-executable): required fields cannot be omitted; manifest owner must equal caller tenant; hash mismatch, unsupported schema, CPU/KVM/API/binary incompatibility, quota overflow, and foreign snapshot owner each fail before Firecracker load; memory file is required immutable and retained while restored VM runs.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-snapshots --test manifest_compat`; failure flip one byte in memory/state/block device and assert typed `SnapshotIntegrityError` before a child process is spawned. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-21-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(snapshot): add versioned local integrity manifest`

- [x] 22. Implement Firecracker snapshot create/load ordering and restore rebinding
  What to do / Must NOT do: Add pause → full snapshot create and fresh-process snapshot load using `mem_backend.backend_path`, network/vsock overrides, local resource rebinding, and explicit resume. Must not configure boot source/drives as if restore were fresh, use deprecated `mem_file_path`, or claim network/vsock connection continuity.
  Parallelization: Wave 4 | Blocked by: 14-15, 21 | Blocks: 27-30
  References (executor has NO interview context - be exhaustive): Draft QA correction `.omo/drafts/kvm-microvm-orchestrator.md:49-52`; Firecracker snapshot API `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/snapshot-support.md`; swagger snapshot routes `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/firecracker/swagger/firecracker.yaml`.
  Acceptance criteria (agent-executable): recorded request sequence includes `PATCH /vm` Paused before create; restore calls `PUT /snapshot/load` on a fresh process before ordinary configuration; deprecated field is rejected; loaded VM reaches Paused/Resumed only through the supported backend contract; network/vsock disconnect semantics are documented and tested.
  QA scenarios (name the exact tool + invocation): happy privileged snapshot create/load round trip with guest canary and restored service readiness; failure mock rejects post-load `PUT /boot-source`/drive reconfiguration and asserts `LoadPreConfig`, no corrupted state. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-22-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(snapshot): implement Firecracker create and restore protocol`

- [x] 23. Collect per-VM host and guest metrics with a stable schema
  What to do / Must NOT do: Add host cgroup metrics (CPU usage/throttling, memory/current/events, IO, pids), TAP byte counters, monotonic boot/restore phases, and optional guest agent/vsock fields for guest steal/load/RSS. Missing guest data must be marked unavailable, never zero-filled.
  Parallelization: Wave 4 | Blocked by: 10-15, 19 | Blocks: 24, 27-30
  References (executor has NO interview context - be exhaustive): Draft metrics requirement `.omo/drafts/kvm-microvm-orchestrator.md:18,46,57,69`; cgroup v2 `https://docs.kernel.org/admin-guide/cgroup-v2.html`; Firecracker metrics `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/metrics.md`.
  Acceptance criteria (agent-executable): schema includes boot time, memory usage, CPU usage/throttling, guest CPU steal when available, RX/TX throughput, source timestamps, and availability flags; metrics are exposed via the UDS API; sampling stops after VM cleanup; no high-cardinality unbounded labels.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-metrics --test schema_and_counters`; failure remove cgroup/guest agent during sampling and assert an unavailable field plus bounded error metric, not zero or panic. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-23-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(metrics): add per-VM host and guest measurements`

- [x] 24. Implement deterministic core-aware bin-packing scheduler and reconciliation inputs
  What to do / Must NOT do: Add pure first-fit-decreasing/admission logic over vCPU, memory, CPU topology/NUMA metadata, and tenant quotas; emit explicit unschedulable reasons and consume metrics without mutating resources in the pure scheduler. Must not overcommit hard limits or claim NUMA awareness without a preflight topology.
  Parallelization: Wave 4 | Blocked by: 7, 10, 13, 23 | Blocks: 27-30
  References (executor has NO interview context - be exhaustive): Draft scheduler scope `.omo/drafts/kvm-microvm-orchestrator.md:18,57,69`; cgroup CPU/memory docs; host topology `/sys/devices/system/node/node*/cpulist`.
  Acceptance criteria (agent-executable): fixed-seed property tests prove no CPU/memory overcommit; identical input produces identical placement; no-fit returns typed `Unschedulable` reason; scheduler respects tenant quota and CPU affinity when requested; placement is recorded before lifecycle mutation.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-scheduler --test deterministic_placement`; failure feed a request exceeding all hosts and assert no cgroup/TAP/Firecracker side effect and `Unschedulable{reason}`. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-24-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(scheduler): add deterministic resource bin packing`

- [x] 25. Implement the constrained local OCI-like importer and `microvm run` interface
  What to do / Must NOT do: Add local OCI manifest/layer parsing, digest verification, platform selection, and translation to the typed kernel/rootfs/resource spec. Reject remote/tag-only references, host mounts, host network, privileged/capability additions, and arbitrary host process controls. Must not claim OCI runtime compatibility.
  Parallelization: Wave 5 | Blocked by: 8-9, 20-24 | Blocks: 26-30
  References (executor has NO interview context - be exhaustive): Draft OCI scope `.omo/drafts/kvm-microvm-orchestrator.md:27,53,64,67,76`; OCI image spec `https://github.com/opencontainers/image-spec`; OCI runtime spec `https://github.com/opencontainers/runtime-spec`.
  Acceptance criteria (agent-executable): local digest-pinned manifest imports to a typed microVM spec; every layer hash is verified; unsupported mounts/capabilities/host-network/remote URI return typed errors; `microvm run` help/documentation says constrained import, not OCI runtime; no remote client dependency is required.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-oci --test local_import`; failure import a manifest containing `mounts`, `capabilities`, `privileged`, or `https://` and assert rejection with no artifact/VM side effect. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-25-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(interfaces): add constrained local OCI importer`

- [x] 26. Add the `microvm` CLI and client-side lifecycle commands
  What to do / Must NOT do: Add `microvm create/start/stop/snapshot/restore/status/metrics/run` commands using the REST or gRPC Unix sockets and stable exit codes. Must not add `--tcp`, `--rootless`, `--mount`, `--cap-add`, or remote registry convenience flags.
  Parallelization: Wave 5 | Blocked by: 8, 15-18, 25 | Blocks: 27-30
  References (executor has NO interview context - be exhaustive): Draft scope `.omo/drafts/kvm-microvm-orchestrator.md:52-71,74-79`; OpenAPI/proto todo 8; CLI local OCI todo 25.
  Acceptance criteria (agent-executable): every command maps to a service operation and returns documented exit codes; no TCP/rootless/mount/capability flags exist; wrong-owner and missing-artifact errors are surfaced without leaking host paths; CLI can execute a mocked complete lifecycle.
  QA scenarios (name the exact tool + invocation): happy `cargo run -p microvm-cli -- create --image sha256:<digest> --socket runtime/api/rest.sock`; failure `microvm run --image nginx:latest` returns `LocalArtifactRequired` and exit 4 without network activity. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-26-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(cli): add Unix-socket lifecycle and run commands`

- [~] 27. Build the reproducible snapshot/boot benchmark harness and Docker comparison
  What to do / Must NOT do: Add a harness with identical workload/artifact content for Firecracker and Docker, cold/warm/page-cache conditions, monotonic phases, N≥100 measurements per condition, p50/p95/p99, sample failures, and host metadata. Must not treat a single number or different image contents as proof of superiority.
  Parallelization: Wave 5 | Blocked by: 14-15, 20-24, 26 | Blocks: 31-34
  References (executor has NO interview context - be exhaustive): Draft benchmark scope `.omo/drafts/kvm-microvm-orchestrator.md:28,46-48,58,70,77`; Firecracker performance caveat `https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/snapshot-support.md`; Docker comparison requirements from user prompt.
  Acceptance criteria (agent-executable): benchmark JSON contains workload/artifact hashes, kernel/Firecracker/Docker versions, cgroup/nested/page-cache conditions, N, p50/p95/p99, and blocked reasons; Docker and VM use the same pinned payload hash; `<200 ms` is represented as target metadata, never a pass field; unavailable Docker/KVM lane is blocked with evidence.
  QA scenarios (name the exact tool + invocation): happy `cargo run -p microvm-bench -- snapshot-restore --samples 100 --out .omo/evidence/kvm-microvm-orchestrator/task-27-benchmark.json`; failure run without Docker or `/dev/kvm` and assert `blocked_reason`, no fabricated samples, and exit 77 for the privileged lane. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-27-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(bench): add reproducible snapshot and Docker comparison`

- [~] 28. Build the warm HTTP-function microVM demo with cold/warm evidence
  What to do / Must NOT do: Add one minimal static Rust HTTP function in a pinned local rootfs, snapshot after service readiness, restore through the orchestrator, and report cold first-call versus warm pool/request latency. Must not add autoscaling, multi-function routing, persistent external data, or another language runtime.
  Parallelization: Wave 5 | Blocked by: 20-23, 26-27 | Blocks: 31-34
  References (executor has NO interview context - be exhaustive): Draft warm/demo scope `.omo/drafts/kvm-microvm-orchestrator.md:18,53,58,70,76-79`; Firecracker snapshot restore contract; user “Lambda clone” requirement.
  Acceptance criteria (agent-executable): demo records spawn/socket/configured/guest-ready/restore-ready/request timestamps; N≥100 restore trials are accounted for including failures; report contains `cold_first_call`, `warm_p50`, `warm_p99`, warmup count, and host metadata; no benchmark boolean gate is emitted.
  QA scenarios (name the exact tool + invocation): happy `cargo run -p microvm-bench -- warm-http --samples 100 --out .omo/evidence/kvm-microvm-orchestrator/task-28-warm.json`; failure make guest health never ready and assert every timed-out trial is recorded, no request is counted as warm, and cleanup evidence is present. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-28-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(bench): add warm HTTP microVM demo`

- [~] 29. Define the direct-KVM educational guest/device contract
  What to do / Must NOT do: Document one supported host architecture, one vCPU, one memory slot, serial output, minimal exit handling, and a tiny local guest marker; explicitly exclude production Firecracker replacement, network, block, vsock, multi-vCPU, migration, and broad device emulation. Must not expand the subset without a scope change.
  Parallelization: Wave 5 | Blocked by: 5, 6, 20 | Blocks: 30-31
  References (executor has NO interview context - be exhaustive): Draft direct-KVM scope `.omo/drafts/kvm-microvm-orchestrator.md:44-48,53,60,66,78`; Linux KVM API `https://docs.kernel.org/virt/kvm/api.html`; `kvm-ioctls` docs `https://docs.rs/kvm-ioctls/latest/kvm_ioctls/`.
  Acceptance criteria (agent-executable): `docs/design/direct-kvm-subset.md` names exact arch, guest memory layout, vCPU setup, allowed exits, and stop behavior; build feature is off by default; docs and CLI label it educational; no network/block/vsock device modules are included in the subset.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-backend-directkvm --no-default-features`; failure enable an unsupported device fixture and assert compile/test guard rejects it or returns `UnsupportedDevice`. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-29-kvm-microvm-orchestrator.json`.
  Commit: Y | `docs(vmm): pin direct KVM educational contract`

- [~] 30. Implement and verify the feature-gated direct-KVM subset
  What to do / Must NOT do: Add `kvm-ioctls`-backed API-version/capability probe, VM memory slot, one vCPU `KVM_RUN` loop, serial/exit dispatcher, and clean shutdown behind `direct-kvm`. Must not make it the default backend or report TCG as KVM evidence.
  Parallelization: Wave 5 | Blocked by: 4-6, 29 | Blocks: 31-34
  References (executor has NO interview context - be exhaustive): KVM API fd/thread restrictions `https://docs.kernel.org/virt/kvm/api.html`; `kvm-ioctls` 0.25.x docs; Draft KVM subset guardrails `.omo/drafts/kvm-microvm-orchestrator.md:38,44-48,66`.
  Acceptance criteria (agent-executable): capability probe requires API version 12; direct subset boots the documented guest and observes the serial marker on a capable x86_64 host; missing `/dev/kvm` produces `blocked`, not pass; default build does not link or launch direct-KVM backend; vCPU operations remain on the creating thread.
  QA scenarios (name the exact tool + invocation): happy `cargo test -p microvm-backend-directkvm --features direct-kvm,privileged`; failure run on a host without KVM and assert structured `blocked_reason` plus no fallback to Firecracker/QEMU for the subset test. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-30-kvm-microvm-orchestrator.json`.
  Commit: Y | `feat(vmm): add feature-gated direct KVM subset`

- [~] 31. Add adversarial security tests for paths, auth, cgroups, snapshots, OCI input, and isolation
  What to do / Must NOT do: Add deterministic mutation/property suites and privileged isolation probes covering every known Firecracker/jailer/cgroup/network/snapshot trap. Must not use grep-only checks as the sole security proof or modify host policy without a disposable test namespace.
  Parallelization: Wave 6 | Blocked by: 1-30 | Blocks: 32-34
  References (executor has NO interview context - be exhaustive): Metis review findings; Draft corrections `.omo/drafts/kvm-microvm-orchestrator.md:49-54,73-79`; Firecracker jailer/seccomp/snapshot docs; cgroup v2 docs; OCI specs.
  Acceptance criteria (agent-executable): tests cover `--cgroup-version=2`, release/static binary hash, jailer path symlink rejection, peer-credential denial, cgroup no-internal-process, inter-VM network denial, snapshot tamper/compatibility, local-only OCI, no TCP/rootless/VFIO/live-migration flags; every failure has a typed error and evidence artifact.
  QA scenarios (name the exact tool + invocation): happy `cargo nextest run --workspace --test adversarial --locked`; failure run the mutation corpus with one deliberate bypass fixture and assert the suite fails before any privileged side effect. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-31-kvm-microvm-orchestrator.json`.
  Commit: Y | `test(security): add adversarial boundary coverage`

- [~] 32. Add operator documentation, runbooks, and architecture decision records
  What to do / Must NOT do: Document setup, preflight meanings, Unix-socket auth, tenant ownership, cgroup-v2 requirements, network policy, snapshot compatibility, benchmark interpretation, and direct-KVM scope. Must not claim production readiness, universal latency, general OCI compatibility, or host security beyond the stated TCB.
  Parallelization: Wave 6 | Blocked by: 1-31 | Blocks: 33-34
  References (executor has NO interview context - be exhaustive): Draft findings/decisions/scope `.omo/drafts/kvm-microvm-orchestrator.md:29-54,56-79`; Firecracker design/jailer/snapshot docs; devenv docs; plan Must NOT have.
  Acceptance criteria (agent-executable): docs contain runnable commands for deterministic and privileged preflight; all locked decisions and scope-out rules are represented; markdown/link/schema checks pass; benchmark docs state target-not-SLA language; no unresolved template markers remain outside generated examples.
  QA scenarios (name the exact tool + invocation): happy `devenv shell -- markdownlint-cli2 README.md docs/**/*.md`; failure inject a broken source link or unresolved decision marker and assert the docs gate exits 1. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-32-kvm-microvm-orchestrator.json`.
  Commit: Y | `docs(project): add architecture and operator runbooks`

- [~] 33. Aggregate evidence and enforce deterministic/privileged/benchmark outcome semantics
  What to do / Must NOT do: Add the evidence reducer that reads all task artifacts, validates schemas, counts deterministic failures, reports privileged blocks separately, and publishes benchmark distributions without boolean pass/fail. Must not promote blocked host tests to pass or fail solely because a target was missed.
  Parallelization: Wave 6 | Blocked by: 3, 4, 19, 21-24, 27-32 | Blocks: 34
  References (executor has NO interview context - be exhaustive): Evidence schema todo 3; Draft evidence/benchmark requirements `.omo/drafts/kvm-microvm-orchestrator.md:25,28,48,71,77`; JSON Schema spec.
  Acceptance criteria (agent-executable): reducer emits `.omo/evidence/kvm-microvm-orchestrator/final.json` with deterministic `pass/fail`, privileged `pass/blocked/fail`, and benchmark `published/blocked` sections; missing artifact is a failure; benchmark has no `pass` field; all task artifacts validate before reduction.
  QA scenarios (name the exact tool + invocation): happy `cargo run --bin evidence-reduce -- --root .omo/evidence/kvm-microvm-orchestrator --out .omo/evidence/kvm-microvm-orchestrator/final.json`; failure delete one required artifact and assert reducer exits 1 with the task number and missing path. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-33-kvm-microvm-orchestrator.json`.
  Commit: Y | `chore(evidence): aggregate and classify verification results`

- [~] 34. Run the release-readiness integration matrix and preserve clean scope boundaries
  What to do / Must NOT do: Execute all deterministic tests, run privileged lanes where preflight permits, run benchmarks/demo where dependencies exist, verify no forbidden files changed, and reconcile success criteria for all five components. Must not declare benchmark targets as release gates or erase blocked evidence.
  Parallelization: Wave 6 | Blocked by: 31-33 | Blocks: F1-F4
  References (executor has NO interview context - be exhaustive): Draft topology `.omo/drafts/kvm-microvm-orchestrator.md:12-19`; draft scope IN/OUT `.omo/drafts/kvm-microvm-orchestrator.md:63-79`; all prior todo evidence and dependency matrix.
  Acceptance criteria (agent-executable): deterministic suite/lint/schema/docs pass; privileged suite is pass or explicitly blocked with preflight; benchmark artifacts are published or blocked with host reason; no TCP/remote-pull/rootless/VFIO/live-migration/general-OCI behavior is present; no `.codegraph/` or `.omo/run-continuation/` file changed; five topology components each have evidence and a final status.
  QA scenarios (name the exact tool + invocation): happy `devenv shell -- just verify-all` followed by `git diff --exit-code -- .codegraph .omo/run-continuation`; failure run with one forbidden TCP config fixture and assert `verify-all` exits 1 while preserving prior evidence. Evidence `.omo/evidence/kvm-microvm-orchestrator/task-34-kvm-microvm-orchestrator.json`.
  Commit: Y | `chore(release): reconcile full verification matrix`

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [~] F1. Plan compliance audit — run a structural parser over this plan; every implementation row is column-zero `- [ ] N.`, every final row is `- [ ] F<number>.`, all 34 todos contain references, acceptance, happy/failure QA, evidence path, and commit; verify headers remain in template order; verify the dependency matrix in this file exactly matches each todo's `Blocked by`/`Blocks` text.
- [~] F2. Code quality review — run `devenv shell -- cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo deny check`; review typed errors, no unchecked path/process/privilege operations, no product file over the project’s documented module-size limit.
- [~] F3. Real manual QA — on a capable Linux host run `devenv shell -- just verify-all`, execute REST and gRPC lifecycle flows over Unix sockets, inspect `ss -ltnp`, `/dev/kvm` API probe, cgroup/TAP/nft cleanup, snapshot tamper rejection, and warm-demo evidence; on an incapable host verify explicit blocked artifacts instead of mocks.
- [~] F4. Scope fidelity — scan manifests/config/routes for TCP listeners, remote registry clients, rootless/VFIO/live-migration/general-OCI flags; verify no `.codegraph/` or `.omo/run-continuation/` changes; verify the five topology components and every requested capability have evidence.

## Commit strategy
Each implementation todo is one atomic commit with the exact `type(scope): summary` shown on its `Commit` line and a body footer `Refs plan todo N`. Keep environment, lifecycle, isolation, state/observability, interfaces, benchmarks, evidence, and docs changes separated. Never combine product code with a plan artifact or modify `.codegraph/`/`.omo/run-continuation/`. A commit is acceptable only when its happy and failure QA both ran, its evidence file exists, and `cargo fmt`, targeted tests, and relevant schema validation pass. Lockfile updates occur only through the environment dependency-update todo and must include the corresponding toolchain/config rationale.

## Success criteria
- **Environment:** the pinned devenv/Rust workspace and preflight produce reproducible deterministic evidence, and capable/ incapable hosts are distinguished without false privileged passes.
- **Lifecycle:** REST and gRPC clients can create, start, status, snapshot, restore, and stop through one service contract with legal state transitions, idempotency, ownership checks, and no leaked child process.
- **Isolation:** every VM uses explicit cgroup v2, validated jailer inputs, Firecracker release/seccomp checks, per-VM TAP/netns/nftables policy, and cleanup that leaves no owned resource behind.
- **State/observability:** local image and snapshot manifests are digest/compatibility checked; tampering and cross-tenant access fail before launch; metrics expose requested boot, memory, CPU/steal, and network fields; scheduler rejects overcommit deterministically.
- **Interfaces/benchmarks:** constrained local OCI-like execution, Docker comparison, snapshot/restore distribution, and warm HTTP demo produce machine-readable artifacts with host conditions and no universal performance claim.
- **Direct KVM:** the documented educational subset boots its narrow guest/device contract only when KVM is available, remains feature-gated, and is never presented as a production VMM replacement.
- **Scope/security:** no TCP listener, remote pull, host path escape, rootless/VFIO/live-migration/general OCI behavior, or silent isolation fallback is present; all five topology components receive final verification evidence.
