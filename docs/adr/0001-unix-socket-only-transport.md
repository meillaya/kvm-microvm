# ADR-0001: Unix-Socket-Only Transport (No TCP)

## Status

Accepted.

## Context

Firecracker's own API is unauthenticated over its Unix domain socket (UDS). The
orchestrator must own an authenticated control boundary in front of the runtime.
The owner selected the stronger security contract: untrusted multi-tenant
workloads with authenticated ownership and fail-closed setup. Exposing the
control plane over TCP (public, loopback, or remote) would enlarge the attack
surface and contradict that contract.

## Decision

Both control transports — REST/JSON and gRPC — are served **exclusively over
protected Unix domain sockets**. There is **no** TCP, loopback, or remote
listener anywhere in the platform.

- Documented socket paths: CLI `--socket` default `/run/microvm/api/rest.sock`;
  gRPC `unix:///run/microvm/api.sock` (see
  [`api/microvm/v1/service.proto`](../../api/microvm/v1/service.proto),
  [`api/openapi.yaml`](../../api/openapi.yaml)).
- The socket is created with protective filesystem mode/ownership; a
  world-writable control socket is not permitted.
- Authentication is derived from Unix socket peer credentials (see ADR-0004).

## Consequences

- The control plane is reachable only by local principals with filesystem access
  to the socket, which is the intended local-only posture.
- Any TCP exposure is a **scope change** and is enforced absent by contract
  tests (`microvm-contract-tests` socket-hardening battery).
- Remote administration requires a separate, explicitly-designed front door
  (out of scope here), not a TCP listener on the lifecycle API.

## Scope-out

No public, unauthenticated, loopback, or remote TCP listener. No host-network
sharing. No world-writable control socket.

## References

- [../security.md](../security.md#3-authentication)
- [ADR-0003](0003-transport-neutral-service.md), [ADR-0004](0004-peer-credential-auth.md)
