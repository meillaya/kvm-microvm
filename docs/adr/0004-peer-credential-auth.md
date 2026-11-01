# ADR-0004: Peer-credential and filesystem auth; tenant ownership fail-closed

## Status

Accepted.

## Context

Because the control plane is Unix-socket-only (ADR-0001), the natural local
authentication mechanism is Unix socket peer credentials combined with
filesystem protection of the socket path. The owner selected an untrusted
multi-tenant threat model, so authorization must be owner-scoped and fail
closed.

## Decision

- Authentication combines Unix socket peer credentials (`SO_PEERCRED`:
  PID/UID/GID of the connecting process) with filesystem mode/ownership of
  the socket path. The owner principal is derived from peer credentials.
- Tenant ownership. Every VM and snapshot is owned by the principal derived
  at creation. Status/stop/snapshot/restore/metrics are authorized against the
  owning principal.
- Fail-closed denial. Unknown principals and cross-VM / cross-tenant
  ownership operations are denied, never silently ignored.
- Snapshot owner checks run in the compatibility gate before any Firecracker
  spawn (ADR-0007).

## Consequences

- Auth requires no external identity service; it is intrinsic to the local Unix
  socket. This matches the local-only posture.
- Cross-tenant isolation is enforced at the service layer and exercised by the
  adversarial auth battery (`microvm-security-tests`).
- A world-writable control socket would defeat filesystem protection and is
  forbidden.

## Scope-out

No arbitrary host path access. No world-writable control socket. No
unrestricted subprocess arguments. Any TCP exposure (which would bypass the
peer-credential model) is a scope change (ADR-0001).

## References

- [../security.md](../security.md#3-authentication), [../security.md](../security.md#4-tenant-ownership)
- [ADR-0001](0001-unix-socket-only-transport.md)
