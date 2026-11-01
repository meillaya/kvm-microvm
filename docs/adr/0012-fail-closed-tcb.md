# ADR-0012: Fail-closed trust model; orchestrator-owned TCB

## Status

Accepted.

## Context

The owner selected the stronger security contract: untrusted multi-tenant
workloads and artifacts, authenticated ownership, per-VM isolation, and
fail-closed setup. Firecracker's own properties (unauthenticated UDS API, trusted
jailer paths, release-build seccomp, snapshot CRC) are not sufficient as the
outer-platform security boundary. Safety-critical setup must never silently
degrade.

## Decision

- The orchestrator owns the outer-platform TCB: input validation,
  authentication, authorization and tenant ownership, binary provenance,
  artifact integrity, isolation setup, and safe cleanup (see
  [../security.md](../security.md#2-trusted-computing-base-tcb)).
- The orchestrator does not treat Firecracker's unauthenticated UDS API,
  trusted jailer paths, release-build seccomp, or snapshot CRC as sufficient
  outer security. It validates around them.
- Missing `/dev/kvm`, TAP, cgroup v2, jailer, or seccomp; invalid paths;
  unrestricted subprocess arguments; unsupported cgroup topology; and
  unverified or invalid artifacts are all hard errors before any process spawn.
  The platform does not fall back silently.
- Cleanup is idempotent and leaves no owned resource behind; orphan
  reconciliation quarantines and records leaks rather than ignoring them.

## Consequences

- A missing prerequisite produces a typed error or blocked evidence, never a
  silently degraded VM.
- The privileged lane cannot mock a pass on an incapable host (ADR-0009).
- The security posture is explicit and testable: adversarial batteries exercise
  each boundary (path/auth/cgroup/network/snapshot/OCI/binary/scope-fidelity).

## Scope-out

No silent isolation fallback. No arbitrary host path access. No unrestricted
subprocess arguments. No host-network sharing. No world-writable control socket.
No host-security claim beyond the stated TCB; no production-readiness claim.

## References

- [../security.md](../security.md)
- [../architecture.md](../architecture.md#3-isolation-model)
- [ADR-0002](0002-firecracker-first.md), [ADR-0005](0005-explicit-cgroup-v2.md), [ADR-0006](0006-per-vm-tap-netns-nat.md), [ADR-0007](0007-local-content-addressed-snapshots.md), [ADR-0009](0009-hybrid-test-lanes.md)
