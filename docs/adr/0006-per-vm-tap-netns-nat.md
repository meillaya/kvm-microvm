# ADR-0006: Per-VM TAP in isolated netns with controlled nftables NAT

## Status

Accepted.

## Context

The owner requires controlled NAT for guest egress while preserving multi-tenant
isolation and deterministic cleanup. Sharing the host network or allowing
unrestricted egress would break the untrusted multi-tenant contract.

## Decision

- Each VM gets a TAP device inside an isolated network namespace.
- Controlled nftables NAT (a dedicated table) provides egress under a
  per-VM ruleset generated as a pure function of the VM's network config.
- Guest egress is enabled only by explicit VM network policy (`none`,
  `nat-only`, `egress-allowed`).
- Inter-VM traffic and unsolicited inbound traffic are denied.
- An address allocator assigns per-VM addresses from a bounded slot range;
  interface names and slots are bounded (`IFNAMSIZ`, `MAX_SLOTS`).
- Network setup is idempotent; teardown is deterministic and leaves no owned
  netns, TAP, or nft table behind.

## Consequences

- Egress is opt-in and policy-bounded; the default (`none`) is no egress.
- Multi-tenant network isolation holds: tenants cannot reach each other or
  receive unsolicited inbound traffic.
- nft ruleset generation and address allocation are pure and testable without a
  host; loading a real ruleset is behind the `privileged` feature.

## Scope-out

No host-network sharing. No unrestricted egress. No world-writable network
config. Inter-VM and unsolicited inbound traffic remain denied.

## References

- [../architecture.md](../architecture.md#33-networking-tap--netns--nftables)
- [runbooks/network.md](../runbooks/network.md)
- [ADR-0012](0012-fail-closed-tcb.md)
