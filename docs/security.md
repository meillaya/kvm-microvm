# Security Model, Threat Model, and TCB

This page states the threat model, the trusted computing base (TCB), the
authentication and tenant-ownership model, the isolation boundaries, and —
critically — what this platform **does not** claim.

> **Read the non-claims first.** This platform is a development/verification
> platform. It does **not** claim production readiness, and it does **not**
> claim to secure the host beyond the TCB described here.

---

## 1. Threat model

The platform is designed against **untrusted multi-tenant workloads and
artifacts**. Concretely, the design assumes:

- **Workloads are untrusted.** Guest code may be hostile. The platform must keep
  one tenant's workload from reading or interfering with another's, and from
  escaping to the host control plane.
- **Artifacts are untrusted.** Image and snapshot inputs may be tampered with.
  Integrity must be verified before use, and tampering must fail closed.
- **Setup is safety-critical.** Missing capabilities, invalid paths, unsupported
  cgroup topology, or unverified artifacts must be hard errors — never silent
  fallbacks.

This is the stronger security contract selected by the project owner. It makes
authentication, ownership, quotas, and artifact boundaries first-class rather
than bolted on.

---

## 2. Trusted computing base (TCB)

The orchestrator **owns** the following outer-platform security functions and
does not delegate them to the upstream runtime:

| TCB function | Owner | Notes |
| --- | --- | --- |
| **Input validation** | orchestrator | Paths, resource specs, image references, jailer argv are validated before use. |
| **Authentication** | orchestrator | Unix socket peer credentials + filesystem mode/ownership. |
| **Authorization / tenant ownership** | orchestrator | Owner principal derived from peer creds; cross-tenant and unknown-principal operations fail closed. |
| **Binary provenance** | orchestrator | Firecracker + jailer verified by SHA-256, ELF form, and seccomp mode before use. |
| **Artifact integrity** | orchestrator | Digest-addressed images and snapshot content hashes (SHA-256). |
| **Isolation setup** | orchestrator | Explicit cgroup-v2 hierarchy, per-VM netns/TAP/nftables, fail-closed on missing prerequisites. |
| **Safe cleanup** | orchestrator | Idempotent cleanup + orphan reconciliation; no owned resource left behind. |

### What the TCB deliberately does NOT treat as sufficient

The platform does **not** treat the following as sufficient outer-platform
security. Each is a property of the upstream Firecracker runtime that the
orchestrator validates around, rather than relying on:

- **Firecracker's own unauthenticated UDS API.** Firecracker's API is
  unauthenticated over its Unix socket, so the orchestrator owns the
  authenticated boundary in front of it.
- **Trusted jailer paths.** The jailer treats operator inputs as trusted; the
  orchestrator validates those inputs itself.
- **Release-build seccomp.** A release Firecracker build's seccomp filter is
  verified as one signal, not accepted as a complete boundary.
- **Firecracker's snapshot CRC.** The CRC is only accidental-corruption
  detection. It is **never** treated as authentication or integrity proof; the
  orchestrator's own SHA-256 content hashes are the integrity boundary.

See [adr/0012-fail-closed-tcb.md](adr/0012-fail-closed-tcb.md).

---

## 3. Authentication

Both control transports are **Unix-domain-socket only**. There is no TCP,
loopback, or remote listener anywhere in the platform.

### Mechanism

Authentication combines two filesystem-level mechanisms:

1. **Unix socket peer credentials.** The owner principal is derived from the
   connecting process's peer credentials (PID/UID/GID via `SO_PEERCRED`).
2. **Filesystem mode and ownership** of the socket path. The socket is created
   with protective mode/ownership; a world-writable control socket is not
   permitted.

### Fail-closed rules

- **Unknown principals fail closed.** A connection whose principal cannot be
  resolved is denied.
- **No TCP exposure.** Any TCP/loopback listener is a scope change and is
  enforced absent by contract tests.

See [adr/0001-unix-socket-only-transport.md](adr/0001-unix-socket-only-transport.md)
and [adr/0004-peer-credential-auth.md](adr/0004-peer-credential-auth.md).

---

## 4. Tenant ownership

Every VM and snapshot is owned by the tenant principal derived at creation time.

- **Owner-scoped operations.** Status, stop, snapshot, restore, and metrics are
  authorized against the owning principal.
- **Cross-tenant denial.** A cross-tenant ownership operation is denied (fail
  closed), not silently ignored.
- **Snapshot owner checks.** The snapshot compatibility gate verifies the caller
  tenant against the manifest's owner **before** any Firecracker process is
  spawned or `/snapshot/load` is issued.
- **Quota admission.** The scheduler enforces per-tenant quota before placement;
  overcommit of hard limits is rejected deterministically.

---

## 5. Isolation boundaries

### 5.1 cgroup-v2

A unified cgroup-v2 hierarchy is built explicitly (not via jailer defaults). One
parent cgroup delegates `cpu`, `memory`, `pids`, `io`; one leaf per VM carries
explicit limits and has no children and an empty `cgroup.subtree_control`. The
jailer argv always includes `--cgroup-version=2`. A missing cgroup root or
required controller is a hard error before any spawn.

### 5.2 Process jail / seccomp

Firecracker runs under the jailer with validated argv. The platform verifies the
binary's ELF form and seccomp mode as part of provenance, while owning the outer
validation itself (see §2).

### 5.3 Network

Each VM has a TAP device in an isolated network namespace with controlled
nftables NAT. Guest egress is enabled only by explicit VM network policy;
inter-VM and unsolicited inbound traffic is denied. Host-network sharing is not
permitted. See the [network runbook](runbooks/network.md).

### 5.4 Artifact and path boundaries

- **Descriptor-relative local artifact paths** only; arbitrary host path access
  is not permitted.
- **Digest-addressed imports.** Image references must be local and
  digest-pinned; remote and tag-only references are rejected before any I/O.
- **Constrained OCI import.** The importer refuses host mounts, host
  network/PID/IPC sharing, privileged mode, capability additions, and arbitrary
  host process controls. Container process metadata is ignored, never applied to
  the host.

### 5.5 Snapshot boundaries

Snapshots are local, content-addressed, and owner-scoped. SHA-256 content hashes
cover the Firecracker binary, kernel/rootfs/block devices, guest memory, and VM
state. Tampering and cross-tenant access fail before launch. There is **no**
cross-host transfer, signing, or encryption contract. See the
[snapshot runbook](runbooks/snapshot.md).

---

## 6. Fail-closed posture

Across every boundary, the rule is the same: **fail closed, never fall back.**

| Condition | Behavior |
| --- | --- |
| `/dev/kvm`, TAP, cgroup v2, jailer, or seccomp unavailable | Hard error / blocked evidence — no silent fallback. |
| Invalid path or unrestricted subprocess argument | Rejected before spawn. |
| Unverified binary or artifact hash mismatch | Rejected before use. |
| Unknown principal or cross-tenant operation | Denied. |
| Unsupported cgroup topology / leaf-contract violation | `CgroupUnavailable` / `InvalidResourceSpec` before spawn. |
| Incapable host in the privileged lane | `blocked` evidence — never a mocked pass. |

The privileged evidence schema encodes an anti-mock rule: when
`host_preflight.kvm_ok` is `false`, no run may record `pass: true`.

---

## 7. What this platform does NOT claim

These non-claims are part of the security contract, not omissions.

- **No production readiness.** This is a development/verification platform with
  no production support contract.
- **No host security beyond the stated TCB.** The platform secures the boundary
  it owns (§2). It does not claim to harden the host kernel, the upstream
  Firecracker internals, or the broader deployment.
- **No universal latency guarantee.** The `<200 ms` figure is a measured
  reference target, not an SLA. See
  [adr/0011-benchmark-distributions-not-sla.md](adr/0011-benchmark-distributions-not-sla.md).
- **No general OCI runtime compatibility.** OCI input is a constrained local
  import format only. See
  [adr/0008-local-digest-artifacts-constrained-oci.md](adr/0008-local-digest-artifacts-constrained-oci.md).
- **No snapshot authentication via Firecracker CRC.** The CRC detects accidental
  corruption only; orchestrator SHA-256 hashes are the integrity boundary.
- **No cross-host snapshot transfer**, signed/encrypted snapshot transport, live
  migration, GPU/VFIO passthrough, multi-host clustering, rootless mode, or
  Windows/non-Linux guest support. Each is an explicit scope-out (see
  [adr/README.md](adr/README.md)).
- **No production-grade custom VMM.** The direct-KVM subset is educational and
  feature-gated. See
  [adr/0010-direct-kvm-educational-subset.md](adr/0010-direct-kvm-educational-subset.md).

---

## 8. Verification evidence

Security boundaries are exercised by the adversarial batteries in
`microvm-security-tests` (path, auth, cgroup, network, snapshot, OCI, binary,
scope-fidelity). Deterministic batteries run without root, `/dev/kvm`,
`/dev/net/tun`, a writable cgroupfs, or a pinned binary; privileged-gated tests
(real-kernel cgroup `EBUSY`, real nft ruleset load) skip gracefully on a
non-root host. Evidence conforms to
[`schemas/evidence-security.v1.json`](../schemas/evidence-security.v1.json).
