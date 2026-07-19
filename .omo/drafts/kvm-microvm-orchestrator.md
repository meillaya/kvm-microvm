---
slug: kvm-microvm-orchestrator
status: reviewed-approved
intent: clear
review_required: false
pending-action: write .omo/plans/kvm-microvm-orchestrator.md
approach: Rust control plane with a shared lifecycle service exposed through both REST/JSON and gRPC over protected Unix-socket endpoints, Firecracker-first runtime integration, cgroup-v2/TAP+jail integration, versioned snapshot/image artifacts, and a narrowly scoped in-tree KVM VMM learning path
---

# Draft: kvm-microvm-orchestrator

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->
| environment | Reproducible devenv.sh/Nix toolchain and Linux host preflight are available | active | empty repository inventory; devenv Context7 docs; `/proc/mounts:7`, `/sys/fs/cgroup/cgroup.controllers:1` |
| lifecycle | Typed VM/image control plane exposes create/start/stop lifecycle over the selected transport | active | user request; Firecracker API/swagger contract |
| isolation | Per-VM jailer, cgroup-v2 CPU/memory limits, TAP/NAT, and cleanup enforce host boundaries | active | Firecracker `docs/design.md`, `docs/jailer.md`; Linux cgroup/TAP docs |
| state-observability | Snapshot/restore, resource metrics, and core-aware bin-packing scheduler are auditable | active | Firecracker snapshot support; user request |
| interfaces-benchmarks | OCI-like image entry point, Docker comparison, and warm-function demo produce reproducible artifacts | active | user request; QA matrix research |

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it. -->
<!-- assumption | adopted default | rationale | reversible? -->
| host target | Linux x86_64 with cgroup v2; aarch64 is a documented future/secondary target | Current request is KVM/Linux and host evidence shows x86_64 AMD plus cgroup v2; reversible at API boundary, not in low-level VMM | yes at control-plane boundary; no for first low-level guest contract |
| test strategy | Hybrid: deterministic contracts first; privileged KVM/TAP/jailer and benchmark harnesses tests-after with explicit preflight gating | Privileged host behavior cannot be fully exercised in ordinary CI; keeps deterministic feedback fast while requiring real evidence for host claims | yes |
| threat model | Untrusted multi-tenant workloads and artifacts; authenticated ownership, per-VM isolation, fail-closed setup | User selected the stronger security contract; this makes auth, ownership, quotas, and artifact boundaries first-class | no without scope change |
| image provenance | Pinned local/base artifacts and digest-addressed imports; no immediate remote tag pulls | User selected reproducibility and avoids treating `nginx:latest` as a secure artifact source; OCI-like entry point remains local/import-oriented | yes |
| isolation trust model | Fail closed on missing capabilities, invalid paths, unsupported cgroup topology, unsigned/invalid artifacts, or unavailable host prerequisites | Security dossier identifies these as safety-critical boundaries; Firecracker jailer itself treats operator inputs as trusted | yes, only by explicit owner policy |
| snapshot claim | Treat `<200 ms` as a measured target, not a hard universal guarantee; publish p50/p95/p99 and host metadata | Firecracker restore depends on memory, vCPU, device count and storage/page-cache state | yes |
| api exposure | REST and gRPC are Unix-socket-only by default; use filesystem ownership/mode plus peer-credential authorization; no TCP listener in this plan | Firecracker's own API is unauthenticated over UDS, so the orchestrator must own the authenticated boundary | yes, but any TCP exposure is a scope change |
| network policy | Per-VM TAP inside an isolated netns with controlled nftables NAT; guest egress is enabled only by explicit VM network policy; inter-VM and unsolicited inbound traffic denied | Preserves requested NAT while retaining multi-tenant isolation and deterministic cleanup | yes |
| snapshot trust | Local content-addressed/versioned snapshots with owner checks, hashes, compatibility metadata, and immutable memory files; no cross-host transfer contract | User selected local integrity; Firecracker CRC is only accidental-corruption detection | yes, cross-host signing/encryption would be a scope change |

## Findings (cited - path:lines)
- Repository is greenfield: no source, build manifest, tests, docs, Git metadata, or conventions; only framework `.codegraph` and `.omo` state (`/home/mei/projects/kernels/kernel-v4/.codegraph/source.json:1-4`; inventory agent result). Do not infer architecture from existing code.
- Host is Linux x86_64 AMD with `svm` visible (`/proc/cpuinfo:1-20`), cgroup v2 mounted (`/proc/mounts:7`, `/sys/fs/cgroup/cgroup.controllers:1`), nested AMD virtualization enabled (`/sys/module/kvm_amd/parameters/nested:1`), and kernel mitigation status available (`/sys/devices/system/cpu/vulnerabilities/spectre_v2:1`, `meltdown:1`). Device-node access to `/dev/kvm` and `/dev/net/tun` is not readable through this tool surface and must be proven by a worker preflight, not assumed.
- KVM is fd/ioctl scoped: open `/dev/kvm`, create VM, then vCPU/device fds; VM ioctls remain tied to the creating address space; runtime capabilities must be probed (`https://docs.kernel.org/virt/kvm/api.html`, General description, restrictions, `KVM_CHECK_EXTENSION`).
- Firecracker is one microVM per process and expects Linux/KVM guests, TAP-backed network, block-file backing, seccomp/cgroups/namespaces/jailer defense in depth (`https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/design.md`). Its API is HTTP/JSON over a Unix socket (`https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/src/firecracker/swagger/firecracker.yaml`).
- Firecracker jailer validates IDs/paths, builds a chroot, creates/owns `/dev/kvm` and `/dev/net/tun`, configures cgroups/netns, drops UID/GID, and execs the VMM; its inputs and host resources are trusted and must be constrained by the orchestrator (`https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/jailer.md`).
- Firecracker snapshot create requires a paused booted VM; restore is before configuration, uses separate state/memory artifacts, requires backing disks/TAP/vsock resources, can lose network/vsock continuity, and requires snapshot disk quotas and trust management (`https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md`).
- cgroup v2 is hierarchical/top-down; controllers must be enabled by the parent and non-root domain groups obey the no-internal-process constraint (`https://docs.kernel.org/admin-guide/cgroup-v2.html`).
- TAP uses `/dev/net/tun` plus `TUNSETIFF`; TAP carries Ethernet frames and requires host networking privileges for setup (`https://www.kernel.org/doc/Documentation/networking/tuntap.txt`). Firecracker's NAT guide uses per-VM TAP addresses, forwarding, and nftables/iptables masquerade (`https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/network-setup.md`).
- devenv provides `devenv.nix` packages/languages/scripts/tests and supports pinned inputs; current official Context7 result is `/cachix/devenv` with README/docs. Use Linux-only conditionals for KVM packages and separate privileged tests from deterministic `devenv test`.
- Research claims requiring independent verification before being treated as facts: host package availability (`cargo`, `go`, Docker/Podman, Firecracker/QEMU), exact `/dev/kvm` mode, and current devenv release/package attribute names. The plan must use version probes and recorded preflight JSON rather than hard-code unverified local observations.
- KVM low-level lifecycle should be explicit: API version 12/capability probe, VM fd, guest memory slots, vCPU mmap/run loop, exit dispatcher, and per-vCPU thread affinity; `kvm-ioctls` 0.25.0 offers typed wrappers for Kvm/VmFd/VcpuFd/DeviceFd and supports x86_64 with experimental arm64/riscv64 (`https://docs.rs/kvm-ioctls/latest/kvm_ioctls/`; research commit `b4c9ed8d...`).
- The strongest architecture recommendation is a backend-neutral lifecycle service with Firecracker and QEMU adapters plus a later direct-KVM subset. QEMU TCG/qtest can cover process/QMP/device behavior without `/dev/kvm`, but must never be reported as KVM validation; Firecracker full boot uses KVM and must be host-gated.
- Boot metrics must use host monotonic spans (spawn, socket-ready, configured, guest marker/service-ready, snapshot-load, restore-ready); Firecracker’s boot-timer/log output is useful evidence but not the sole readiness or attestation signal. Snapshot restore wall-clock can retain guest snapshot time.
- Firecracker snapshot artifacts are backend-specific and compatibility-sensitive: guest memory/state plus externally managed disks/TAP/vsock resources; restore is fresh-process/pre-configuration, and CPU/kernel/device/binary compatibility must be recorded. CRC is not authentication; external snapshot manifests need integrity/authentication and quota policy.
- Adversarial Firecracker verification: the jailer performs path/ID validation, fd/env cleanup, chroot/cgroup/netns/resource setup, UID/GID drop, and exec, but **does not install seccomp**; Firecracker installs per-thread seccomp after exec and before guest code. The orchestrator must require a same-version statically linked release/musl Firecracker binary and treat jailer inputs as trusted operator paths (`https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/jailer.md`, `docs/seccomp.md`).
- Firecracker jailer defaults `--cgroup-version` to v1; cgroup v2 must be explicit and must be preflighted. Current Firecracker v1.16.1 also reverted `O_NOFOLLOW` for cgroup/netns path operations, so the orchestrator must do its own descriptor-relative path validation and not claim the jailer provides it (PR #5959 / release docs).
- Adversarial QA correction: pause uses `PATCH /vm` with `{"state":"Paused"}`; snapshot create requires paused state; snapshot load is `PUT /snapshot/load` on a fresh process before ordinary configuration, with `mem_backend.backend_path` preferred over deprecated `mem_file_path`. A successful load restores VM state; do not blindly configure boot source/drives after load as if it were a fresh VM. Rebind network/vsock through load overrides and reconfigure only what the backend contract permits.
- Firecracker does not publish a universal snapshot restore latency SLA; its own docs say performance depends on memory/vCPU/devices and warn about cgroup-v1 latency. `<200 ms` is a benchmark target only, with cold/warm/page-cache conditions and p50/p95/p99 evidence.
- OCI verification: OCI image/runtime specs describe container manifests, layers, process args/env/capabilities/mounts; the microVM interface must define a typed transformation into kernel/rootfs/device metadata and must not claim general OCI runtime compatibility.
- devenv verification: current 2.x docs require explicit `git-hooks` input when using git hooks; `devenv.yaml` inputs/lock and `devenv.nix` module config must be pinned together; no built-in KVM/QEMU/Firecracker service exists, so Linux packages and runtime `/dev/kvm` checks are explicit. Use `lib.mkMerge` + `lib.mkIf`, and use `devenv test`/`devenv up --mode all` for setup-dependent test tasks.

## Decisions (with rationale)
- Topology locked to five independently verifiable components listed above.
- Plan must preserve the full requested scope; it must not silently reduce the image builder, snapshots, networking, metrics, scheduler, OCI-like interface, benchmark, or warm-function demo.
- The low-level VMM subset is an educational/verification path with an explicit narrow guest/device contract; it must not be presented as a production-complete replacement for Firecracker.
- Deterministic tests must remain runnable without `/dev/kvm`; privileged tests must be explicitly gated and must emit `skipped`/`blocked` evidence when host prerequisites are absent rather than passing through mocks.
- Owner-selected defaults: Rust; Firecracker-first; both REST/JSON and gRPC over protected Unix-socket endpoints backed by one transport-neutral service layer; hybrid testing; untrusted multi-tenant security contract; pinned local/digest-addressed image artifacts; Unix sockets only; controlled per-VM NAT; local content-addressed snapshot integrity.
- Adopt peer credentials plus filesystem mode/ownership as the local Unix-socket auth mechanism; unknown principals and cross-VM ownership operations fail closed. Any TCP/loopback listener, remote registry pull, cross-host snapshot transfer, or signed/encrypted snapshot exchange is a scope change.
- Pass `--cgroup-version=2` explicitly to every Firecracker jailer invocation; pre-create and validate the cgroup-v2 hierarchy rather than relying on jailer defaults.
- Do not treat Firecracker's own unauthenticated UDS API, trusted jailer paths, release-build seccomp, or Firecracker CRC as sufficient outer-platform security; the orchestrator owns validation, auth, binary provenance, artifact hashes, and safe cleanup.

## Scope IN
- devenv.sh/Nix flake or devenv inputs, pinned toolchain, Linux host preflight, and developer/CI commands.
- Rust control plane with typed VM states and create/start/stop/snapshot/restore lifecycle, exposed through both REST and gRPC over protected Unix sockets.
- Firecracker-first runtime adapter, plus a small KVM/ioctl VMM subset with a documented guest kernel/rootfs/device contract.
- Kernel/rootfs/image builder, artifact hashing/version metadata, path validation, and optional OCI-like `microvm run` interface.
- cgroup v2 CPU/memory limits, per-VM process jail/seccomp integration, TAP networking with per-VM namespace/NAT cleanup.
- Per-VM boot/memory/CPU/network metrics, scheduler bin-packing policy, and operational cleanup/reconciliation.
- Snapshot/restore benchmark target, Docker-style startup comparison, and warm microVM HTTP-function demo.
- Deterministic unit/API tests, privileged host integration tests, and machine-readable benchmark/evidence artifacts.

## Scope OUT (Must NOT have)
- No arbitrary host path access, unrestricted subprocess arguments, public unauthenticated TCP API, host-network sharing, or silent fallback from isolation setup.
- No live migration, GPU/VFIO passthrough, multi-host cluster control plane, Windows/non-Linux guest support, or rootless mode unless explicitly added as a scope change.
- No claim of general-purpose OCI runtime compatibility: OCI input is a constrained image/import interface and must not apply host mounts, host process args, or host capabilities.
- No universal guarantee that every host achieves the `<200 ms` snapshot/restore target; publish measured distributions and preflight metadata.
- No full Firecracker rewrite or production-grade custom VMM device model beyond the explicitly documented subset.
- Do not modify existing `.codegraph/` or `.omo/run-continuation/` framework metadata.

## Open questions
<!-- All previously surfaced owner decisions were answered: Rust, Firecracker-first, REST+gRPC, hybrid tests, multi-tenant threat model, pinned local artifacts, Unix-only exposure, controlled NAT, and local snapshot integrity. -->
None blocking. The approval gate below is the next action.

## Approval gate
status: reviewed-approved
approach: Rust control plane with shared REST+gRPC service over Unix sockets, Firecracker-first adapter, explicit cgroup-v2/jailer/TAP/netns integration, pinned local image artifacts, content-addressed local snapshots, direct-KVM educational subset, and benchmark/QA evidence split into deterministic and privileged lanes.
next-action: plan written at `.omo/plans/kvm-microvm-orchestrator.md`; optional high-accuracy review may run before execution; do not implement product code in this planning session.
