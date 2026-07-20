# ADR-0002: Firecracker-First Runtime Adapter

## Status

Accepted.

## Context

The platform needs a microVM runtime with a small footprint, a seccomp-jailered
process model, and snapshot support. Firecracker provides these and is the
owner-selected runtime. A custom VMM is desirable only as a narrow educational
path, never as a production replacement (see ADR-0010).

## Decision

The primary runtime adapter is **Firecracker-first**:

- Use a **pinned release / static binary**, verified by SHA-256, ELF form, and
  seccomp mode before use (binary provenance is owned by the orchestrator).
- Validate **jailer argv**; unrestricted subprocess argument passthrough is not
  permitted.
- Provide **process supervision** and **readiness signaling** that **fail
  closed** on startup.
- Always pass `--cgroup-version=2` explicitly (see ADR-0005).

## Consequences

- The platform inherits Firecracker's microVM model, snapshot protocol, and
  jailer process jail, while owning the outer validation/auth/provenance/cleanup
  boundary (see ADR-0012).
- The orchestrator does **not** treat Firecracker's unauthenticated UDS API,
  trusted jailer paths, release-build seccomp, or snapshot CRC as sufficient
  outer security.
- Runtime behavior depends on a pinned binary being present; an absent or
  unverified binary is a hard error, not a fallback.

## Scope-out

No full Firecracker rewrite. No production-grade custom VMM device model beyond
the documented educational subset (ADR-0010). No live migration, GPU/VFIO
passthrough, multi-host clustering, rootless mode, or Windows/non-Linux guest
support.

## References

- [../architecture.md](../architecture.md#32-firecracker--jailer)
- [ADR-0005](0005-explicit-cgroup-v2.md), [ADR-0010](0010-direct-kvm-educational-subset.md), [ADR-0012](0012-fail-closed-tcb.md)
