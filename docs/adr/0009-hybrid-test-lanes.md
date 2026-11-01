# ADR-0009: Hybrid deterministic/privileged test lanes with preflight gating

## Status

Accepted.

## Context

Privileged host behavior (real KVM boot, cgroup-v2 enforcement, TAP/netns,
jailer launch, snapshot/restore) cannot be fully exercised in ordinary CI, which
usually lacks `/dev/kvm`, `/dev/net/tun`, and a writable cgroupfs. But the
platform still needs fast, reproducible feedback for its contracts, and it must
never fabricate a privileged pass on an incapable host.

## Decision

Use a hybrid test strategy with two lanes:

- The deterministic lane runs on any Linux host without `/dev/kvm`,
  `/dev/net/tun`, or a writable cgroupfs. It covers unit, property, API and transport parity,
  scheduler logic, the OCI importer, the snapshot manifest and gate, and the
  adversarial security batteries. Deterministic evidence does not carry
  `host_preflight` or `target_ms` fields.
- The privileged lane is gated behind `scripts/preflight.sh --strict`. It
  requires `/dev/kvm` (API 12 or later), `/dev/net/tun`, unified cgroup v2 with
  `cpu`, `memory`, and `pids`, and pinned Firecracker and jailer. Privileged
  tests live behind a `privileged` Cargo feature and skip on an incapable or
  non-root host.
- A blocked lane records evidence. When prerequisites are absent, the
  privileged lane emits `blocked` evidence (`pass: false`, `blocked: true`,
  `blocked_reason`) rather than passing through mocks. The privileged evidence
  schema encodes an anti-mock rule: when `host_preflight.kvm_ok` is `false`, no
  run may record `pass: true`.
- The benchmark lane builds on the privileged substrate plus page-cache control
  and at least 100 samples (ADR-0011).

## Consequences

- Deterministic feedback is fast and reproducible across Linux hosts and
  ordinary CI.
- Privileged claims require real evidence; an incapable host produces blocked
  evidence, not a false pass.
- Correctness, isolation, and cleanup remain hard gates; benchmark numbers are
  not gates (ADR-0011).

## Scope-out

A privileged pass requires real evidence. A missing prerequisite is recorded as
blocked evidence with a reason, not hidden in a skip.

## References

- [../setup.md](../setup.md#4-the-two-verification-lanes)
- [runbooks/preflight.md](../runbooks/preflight.md)
- [ADR-0011](0011-benchmark-distributions-not-sla.md), [ADR-0012](0012-fail-closed-tcb.md)
