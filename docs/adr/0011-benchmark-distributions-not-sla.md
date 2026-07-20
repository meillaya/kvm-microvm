# ADR-0011: Benchmarks Publish Distributions; Target-Not-SLA; No Pass/Fail Gate

## Status

Accepted.

## Context

Firecracker restore latency depends on memory size, vCPU count, device count,
and storage/page-cache state. Firecracker publishes **no universal
restore-latency SLA**, so the platform cannot honestly guarantee that every host
achieves a `<200 ms` figure. Reducing a measured distribution to a boolean
pass/fail would misrepresent the result and create a false release gate.

## Decision

- The `<200 ms` snapshot/restore figure is a **measured reference target**,
  recorded as `target_ms` metadata — **not** an SLA and **not** a universal
  guarantee.
- Benchmark artifacts publish **distributions** (p50/p95/p99) under cold and
  warm page-cache conditions, with full host metadata, pinned workload/artifact
  hashes, and runtime versions.
- **No pass/fail gate.** The benchmark schema
  (`schemas/evidence-benchmark.v1.json`) forbids a `pass` field at the top level
  and on every benchmark item. Reviewers compare recorded percentiles against
  `target_ms`; the harness never reduces that comparison to a boolean.
- **Like-for-like content.** A single pinned `payload_sha256` is shared by the
  Docker and VM comparison lanes; comparing different image contents is
  explicitly not proof of superiority.
- **Blocked lanes carry evidence.** An unavailable Docker/KVM/Firecracker lane
  records a stable blocked reason, zero samples, and null percentiles — never
  fabricated samples. Sample failures are recorded and excluded from statistics,
  never zero-filled. The binary exits `77` for a blocked privileged lane.
- **Monotonic timing.** Every sample is timed with a host-monotonic clock.

## Consequences

- Benchmark numbers are evidence, not release gates. Correctness, isolation, and
  cleanup remain the hard gates.
- A reviewer can reproduce and contextualize a result (host + conditions +
  hashes), but cannot encode a benchmark as a boolean.
- The statistical core is pure and testable without `/dev/kvm` or a Docker
  daemon; real lanes degrade to blocked-with-evidence when prerequisites are
  absent.

## Scope-out

No universal `<200 ms` performance guarantee. No benchmark pass/fail gate. No
fabricated or zero-filled samples. No comparison across different image contents.

## References

- [../setup.md](../setup.md#benchmark-interpretation)
- [../architecture.md](../architecture.md#52-benchmarks-and-demo)
- [ADR-0009](0009-hybrid-test-lanes.md)
