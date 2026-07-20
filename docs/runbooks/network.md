# Runbook: Network Policy (TAP / netns / nftables)

Goal: understand and operate per-VM networking — isolated TAP devices, network
namespaces, controlled nftables NAT, egress policy, and deterministic cleanup.

> **Boundary.** Guest egress is enabled **only** by explicit VM network policy.
> Inter-VM traffic and unsolicited inbound traffic are **denied**. Host-network
> sharing is **not** permitted. See
> [../adr/0006-per-vm-tap-netns-nat.md](../adr/0006-per-vm-tap-netns-nat.md).

---

## Model

- Each VM gets a **TAP** device inside an **isolated network namespace**
  (netns names use a fixed prefix; see `NETNS_PREFIX`).
- **Controlled nftables NAT** (a dedicated table; see `NFT_TABLE`) provides
  egress under a per-VM ruleset.
- An **address allocator** assigns per-VM addresses from a bounded slot range
  (`MAX_SLOTS`), keeping cardinality bounded.
- Network setup is **idempotent**; teardown is deterministic and leaves no owned
  netns, TAP, or nft table behind.

### Egress policies

Set at create time (`microvm create --network-policy <POLICY>`):

| Policy | Meaning |
| --- | --- |
| `none` | No guest egress. Default. |
| `nat-only` | Egress via controlled NAT only. |
| `egress-allowed` | Explicit egress permitted by VM network policy. |

The gRPC enum maps to `NETWORK_POLICY_NONE`, `NETWORK_POLICY_NAT_ONLY`, and
`NETWORK_POLICY_FULL_EGRESS`.

---

## Procedure

### 1. Preflight (privileged networking)

```bash
bash scripts/preflight.sh --json .preflight/host.json
jq '.tap, .cgroup_v2' .preflight/host.json
```

Real TAP/netns/nftables work requires `/dev/net/tun` and a capable host. The
nft ruleset generation and address allocation logic is pure and runs in the
deterministic lane.

### 2. Create a VM with an egress policy

```bash
# No egress (default):
microvm create --image sha256:<64-hex-digest> --network-policy none

# Controlled NAT egress:
microvm create --image sha256:<64-hex-digest> --network-policy nat-only
```

Remote and tag-only image references are rejected before any I/O (see
[../adr/0008-local-digest-artifacts-constrained-oci.md](../adr/0008-local-digest-artifacts-constrained-oci.md)).

### 3. Inspect generated policy (deterministic)

The nft ruleset is a pure function of the VM's `NetConfig`. Contract and
security tests render and assert it without touching a host:

```bash
cargo test -p microvm-security-tests --test network_security
cargo test -p microvm-isolation
```

A privileged-gated test loads a real nft ruleset on a capable host and skips
gracefully otherwise:

```bash
cargo test -p microvm-security-tests --features privileged
```

### 4. Verify isolation expectations

- Inter-VM traffic is denied.
- Unsolicited inbound traffic is denied.
- Egress matches the selected policy and nothing more.

---

## Cleanup

Network resources are cleaned up deterministically when a VM stops. If a
process dies uncleanly, the orphan reconciler detects and removes leaked netns
and nft tables (prefixed for identification). See
[cleanup.md](cleanup.md) and
[../architecture.md#34-cleanup-and-reconciliation](../architecture.md#34-cleanup-and-reconciliation).

```bash
# Stop a VM (triggers idempotent network teardown):
microvm stop --vm-id <VM_ID>
```

---

## Scope reminders

- **No host-network sharing.** A VM never shares the host network namespace.
- **No unrestricted egress.** Egress exists only under an explicit policy and
  controlled NAT.
- **Bounded cardinality.** Address slots and interface names are bounded
  (`MAX_SLOTS`, `IFNAMSIZ`), preventing unbounded resource growth.
