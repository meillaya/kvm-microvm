# ADR-0009: Hybrid Deterministic/Privileged Test Lanes with Preflight Gating

## Status

Accepted.

## Context

Privileged host behavior (real KVM boot, cgroup-v2 enforcement, TAP/netns,
jailer launch, snapshot/restore) cannot be fully exercised in ordinary CI, which
usually lacks `/dev/kvm`, `/dev/net/tun`, and a writable cgroupfs. But the
platform still needs fast, reproducible feedback for its contracts, and it must
never fabricate a privileged pass on an incapable host.

## Decision

Use a **hybrid** test strategy with two lanes:

- **Deterministic lane** — runs on any host without `/dev/kvm`, `/dev/net/tun`,
  or a writable cgroupfs. Covers unit, property, API/transport parity, scheduler
  pure logic, OCI importer, snapshot manifest/gate, and adversarial security
  batteries. Deterministic evidence MUST NOT carry `host_preflight` or
  `target_ms` fields.
- **Privileged lane** — gated behind `scripts/preflight.sh --strict`. Requires
  `/dev/kvm` (API ≥ 12), `/dev/net/tun`, unified cgroup-v2 (`cpu`+`memory`+`pids`),
  and pinned Firecracker+jailer. Privileged tests live behind a `privileged`
  Cargo feature and **skip gracefully** on an incapable/non-root host.
- **Blocked, never mocked.** When prerequisites are absent, the privileged lane
  emits `blocked` evidence (`pass: false`, `blocked: true`, `blocked_reason`)
  rather than passing through mocks. The privileged evidence schema encodes an
  anti-mock rule: when `host_preflight.kvm_ok` is `false`, no run may record
  `pass: true`.
- A **benchmark lane** builds on the privileged substrate plus page-cache
  control and N ≥ 100 samples (ADR-0011).

## Consequences

- Deterministic feedback is fast and reproducible across hosts (including macOS
  development and ordinary CI).
- Privileged claims require real evidence; an incapable host produces blocked
  evidence, not a false pass.
- Correctness, isolation, and cleanup remain hard gates; benchmark numbers are
  not gates (ADR-0011).

## Scope-out

No mocked privileged pass. No silent skip that hides a missing prerequisite —
skips are recorded as blocked evidence with a reason.

## References

- [../setup.md](../setup.md#4-the-two-verification-lanes)
- [runbooks/preflight.md](../runbooks/preflight.md)
- [ADR-0011](0011-benchmark-distributions-not-sla.md), [ADR-0012](0012-fail-closed-tcb.md)
