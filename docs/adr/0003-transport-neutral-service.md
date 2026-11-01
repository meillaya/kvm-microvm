# ADR-0003: One transport-neutral service behind REST and gRPC

## Status

Accepted.

## Context

The owner requires both a REST/JSON API and a gRPC API. Implementing lifecycle
logic twice (once per transport) risks divergence: a legal state transition,
idempotency rule, or ownership check could behave differently on REST vs gRPC.

## Decision

Implement the lifecycle logic once in a transport-neutral service layer
(`microvm-transport-contract` + `microvm-service`). REST (`microvm-rest`) and
gRPC (`microvm-grpc`) are thin adapters over that single contract.

- Operations: `CreateVm`, `StartVm`, `StopVm`, `SnapshotVm`, `RestoreVm`,
  `GetVmStatus`, `GetVmMetrics`.
- Both adapters share the same typed error model (`microvm-errors`) and the same
  lifecycle state machine (`microvm-lifecycle`).
- Transport parity is enforced by `microvm-contract-tests`.

## Consequences

- REST and gRPC behavior is identical by construction; a rule change lands in
  one place.
- Adding a future transport (still Unix-socket-only per ADR-0001) is an adapter,
  not a re-implementation.
- Contract tests must keep both adapters honest; divergence is a test failure.

## Scope-out

No transport that violates the Unix-socket-only rule (ADR-0001).

## References

- [../architecture.md](../architecture.md#2-transport-model)
- [ADR-0001](0001-unix-socket-only-transport.md)
