# ADR-0005: Explicit Unified cgroup-v2 Hierarchy (`--cgroup-version=2`)

## Status

Accepted.

## Context

Firecracker's jailer historically defaulted to cgroup v1 and is willing to
create cgroups itself. Relying on jailer defaults would make the isolation
topology implicit and version-ambiguous. The owner requires explicit, auditable
resource limits on a unified cgroup-v2 host.

## Decision

The orchestrator builds a **unified cgroup-v2** hierarchy explicitly and hands
the jailer only a pre-created leaf path:

- One **parent** cgroup (`<root>/microvm`) delegates `cpu`, `memory`, `pids`,
  and `io` top-down via `cgroup.subtree_control`.
- One **leaf** cgroup per VM (`<root>/microvm/<vm-id>`) carries explicit limits
  (`cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`, optional `io.max`).
  A leaf has **no children** and an **empty** `cgroup.subtree_control`.
- The generated jailer argv **always** includes `--cgroup-version=2` and a
  `--parent-cgroup` pointing at the pre-created leaf.
- A missing cgroup root or required controller yields `CgroupUnavailable`
  **before** any process spawn; an invalid spec or leaf-contract violation
  yields `InvalidResourceSpec`.

## Consequences

- Resource limits are explicit, version-pinned, and auditable.
- The platform never relies on jailer cgroup-version defaults.
- cgroup spec validation, controller checks, leaf-constraint validation, and
  argv generation are pure and testable without a writable cgroupfs; the real
  run is behind the `privileged` feature.

## Scope-out

No silent fallback when cgroup v2 or a required controller is unavailable. No
reliance on jailer defaults for the cgroup version.

## References

- [../architecture.md](../architecture.md#31-cgroup-v2)
- [runbooks/network.md](../runbooks/network.md), [runbooks/cleanup.md](../runbooks/cleanup.md)
- [ADR-0012](0012-fail-closed-tcb.md)
