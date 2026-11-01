# Runbook: network policy (TAP, netns, nftables)

Goal: understand and operate per-VM networking: isolated TAP devices, network
namespaces, controlled nftables NAT, egress policy, and deterministic cleanup.

Guest egress is enabled only by explicit VM network policy. Inter-VM traffic and
unsolicited inbound traffic are denied, and host-network sharing is not
permitted. See [ADR-0006](../adr/0006-per-vm-tap-netns-nat.md).

## Model

- Each VM gets a TAP device inside an isolated network namespace. Netns names
  use a fixed prefix, `NETNS_PREFIX`.
- Controlled nftables NAT in a dedicated table, `NFT_TABLE`, provides egress
  under a per-VM ruleset.
- An address allocator assigns per-VM addresses from a bounded slot range,
  `MAX_SLOTS`, which keeps cardinality bounded.
- Network setup is idempotent. Teardown is deterministic and leaves no owned
  netns, TAP device, or nft table behind.

### Egress policies

Set the policy at create time with `microvm create --network-policy <POLICY>`:

| Policy | Meaning |
| --- | --- |
| `none` | No guest egress. This is the default. |
| `nat-only` | Egress through controlled NAT only. |
| `egress-allowed` | Egress permitted by the explicit VM network policy. |

The gRPC enum maps to `NETWORK_POLICY_NONE`, `NETWORK_POLICY_NAT_ONLY`, and
`NETWORK_POLICY_FULL_EGRESS`.

## Procedure

### 1. Preflight

```bash
bash scripts/preflight.sh --json .preflight/host.json
jq '.tap, .cgroup_v2' .preflight/host.json
```

Real TAP, netns, and nftables work needs `/dev/net/tun` and a capable host. The
nft ruleset generation and address allocation logic is pure and runs in the
deterministic lane.

### 2. Create a VM with an egress policy

```bash
# No egress, the default:
microvm create --image sha256:<64-hex-digest> --network-policy none

# Controlled NAT egress:
microvm create --image sha256:<64-hex-digest> --network-policy nat-only
```

Remote and tag-only image references are rejected before any I/O. See
[ADR-0008](../adr/0008-local-digest-artifacts-constrained-oci.md).

### 3. Inspect the generated policy

The nft ruleset is a pure function of the VM's `NetConfig`. Contract and
security tests render and assert it without touching a host:

```bash
cargo test -p microvm-security-tests --test network_security
cargo test -p microvm-isolation
```

A privileged-gated test loads a real nft ruleset on a capable host and skips
otherwise:

```bash
cargo test -p microvm-security-tests --features privileged
```

### 4. Verify isolation expectations

- Inter-VM traffic is denied.
- Unsolicited inbound traffic is denied.
- Egress matches the selected policy.

## Cleanup

Network resources are cleaned up when a VM stops. If a process dies uncleanly,
the orphan reconciler detects and removes leaked netns and nft tables by their
prefix. See [cleanup.md](cleanup.md) and
[architecture.md](../architecture.md#34-cleanup-and-reconciliation).

```bash
# Stop a VM and trigger idempotent network teardown.
microvm stop --vm-id <VM_ID>
```

## Scope reminders

- A VM never shares the host network namespace.
- Egress exists only under an explicit policy and controlled NAT.
- Address slots and interface names are bounded by `MAX_SLOTS` and `IFNAMSIZ`,
  which prevents unbounded resource growth.
