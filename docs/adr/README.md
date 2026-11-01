# Architecture decision records (ADRs)

This directory records the locked architecture decisions and scope-out rules for
the kvm-microvm-orchestrator platform. Each ADR captures the context, the
decision, its consequences, and, where relevant, the explicit scope boundary it
establishes.

These decisions are locked. Changing one requires a written scope-change
proposal and an update to the relevant ADR before implementation.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-unix-socket-only-transport.md) | Unix-socket-only transport (no TCP) | Accepted |
| [0002](0002-firecracker-first.md) | Firecracker-first runtime adapter | Accepted |
| [0003](0003-transport-neutral-service.md) | One transport-neutral service behind REST and gRPC | Accepted |
| [0004](0004-peer-credential-auth.md) | Peer-credential + filesystem auth; tenant ownership fail-closed | Accepted |
| [0005](0005-explicit-cgroup-v2.md) | Explicit unified cgroup-v2 hierarchy (`--cgroup-version=2`) | Accepted |
| [0006](0006-per-vm-tap-netns-nat.md) | Per-VM TAP in isolated netns with controlled nftables NAT | Accepted |
| [0007](0007-local-content-addressed-snapshots.md) | Local content-addressed snapshots; no cross-host transfer; CRC is not auth | Accepted |
| [0008](0008-local-digest-artifacts-constrained-oci.md) | Pinned local digest-addressed artifacts; constrained OCI import; no remote pulls | Accepted |
| [0009](0009-hybrid-test-lanes.md) | Hybrid deterministic/privileged test lanes with preflight gating | Accepted |
| [0010](0010-direct-kvm-educational-subset.md) | Direct-KVM educational subset, feature-gated and scope-locked | Accepted |
| [0011](0011-benchmark-distributions-not-sla.md) | Benchmarks publish distributions; target-not-SLA; no pass/fail gate | Accepted |
| [0012](0012-fail-closed-tcb.md) | Fail-closed trust model; orchestrator-owned TCB | Accepted |

## Global scope-out rules

These rules are enforced across the platform (many by tests) and are binding
regardless of which ADR is being read:

- No TCP/loopback/remote listener anywhere (ADR-0001).
- No remote registry pulls or tag-based `nginx:latest` behavior; OCI-like
  input is local and digest-addressed only (ADR-0008).
- No general OCI runtime compatibility, host mounts, host capabilities,
  privileged container flags, or host process controls (ADR-0008).
- No cross-host snapshot transfer, signed/encrypted snapshot transport, or
  claim that Firecracker's CRC authenticates state (ADR-0007).
- No live migration, GPU/VFIO passthrough, multi-host clustering, rootless
  mode, or Windows/non-Linux guest support (ADR-0002, ADR-0010).
- No production-grade custom VMM beyond the documented educational subset
  (ADR-0010).
- No universal `<200 ms` performance guarantee; benchmarks publish
  conditions and distributions (ADR-0011).
- No silent isolation fallback when `/dev/kvm`, TAP, cgroup v2, jailer,
  seccomp, or artifact validation is unavailable (ADR-0012).
- No modification of `.codegraph/` or `.omo/run-continuation/` framework
  metadata by product code.
- No arbitrary host paths, unrestricted subprocess arguments, host-network
  sharing, or world-writable control sockets (ADR-0004, ADR-0006, ADR-0012).

## ADR format

Each ADR follows: Status, Context, Decision, Consequences, and
(optional) Scope-out and References.
