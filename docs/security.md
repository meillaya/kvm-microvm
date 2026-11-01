# Security model, threat model, and TCB

This page states the threat model, the trusted computing base (TCB), the
authentication and tenant-ownership model, the isolation boundaries, and the
claims this platform does not make.

The platform is a development and verification platform. It does not claim
production readiness, and it does not claim to secure the host beyond the TCB
described here.

## 1. Threat model

The design assumes untrusted multi-tenant workloads and artifacts:

- Guest code may be hostile. The platform must keep one tenant's workload from
  reading or interfering with another's, and from escaping to the host control
  plane.
- Image and snapshot inputs may be tampered with. Integrity is verified before
  use, and tampering fails closed.
- Setup is safety-critical. A missing capability, invalid path, unsupported
  cgroup topology, or unverified artifact is a hard error.

The project owner selected this stronger security contract. Authentication,
ownership, quotas, and artifact boundaries are part of the design rather than
additions bolted onto a runtime.

## 2. Trusted computing base (TCB)

The orchestrator owns these outer-platform security functions and does not
delegate them to the upstream runtime:

| TCB function | Owner | Notes |
| --- | --- | --- |
| Input validation | orchestrator | Paths, resource specs, image references, and jailer argv are validated before use. |
| Authentication | orchestrator | Unix socket peer credentials plus filesystem mode and ownership. |
| Authorization and tenant ownership | orchestrator | The owner principal comes from peer credentials. Cross-tenant and unknown-principal operations fail closed. |
| Binary provenance | orchestrator | Firecracker and jailer are verified by SHA-256, ELF form, and seccomp mode before use. |
| Artifact integrity | orchestrator | Images are digest-addressed, and snapshot content is hashed with SHA-256. |
| Isolation setup | orchestrator | Explicit cgroup-v2 hierarchy, per-VM netns/TAP/nftables, and a hard error on missing prerequisites. |
| Safe cleanup | orchestrator | Idempotent cleanup and orphan reconciliation leave no owned resource behind. |

### What the TCB does not treat as sufficient

The platform validates around these Firecracker properties instead of relying
on them as the outer security boundary:

- Firecracker's own unauthenticated UDS API. The orchestrator owns the
  authenticated boundary in front of it.
- Trusted jailer paths. The jailer treats operator inputs as trusted, so the
  orchestrator validates those inputs itself.
- Release-build seccomp. The seccomp filter is one provenance signal, not a
  complete boundary.
- Firecracker's snapshot CRC. The CRC detects accidental corruption. The
  orchestrator's SHA-256 content hashes are the integrity boundary.

See [ADR-0012](adr/0012-fail-closed-tcb.md).

## 3. Authentication

Both control transports are Unix-domain-socket only. There is no TCP, loopback,
or remote listener in the platform.

### Mechanism

Authentication combines two filesystem-level mechanisms:

1. Unix socket peer credentials. The owner principal is derived from the
   connecting process's PID, UID, and GID via `SO_PEERCRED`.
2. Filesystem mode and ownership of the socket path. The socket is created with
   a protective mode and owner, and a world-writable control socket is not
   permitted.

### Fail-closed rules

- A connection whose principal cannot be resolved is denied.
- A TCP or loopback listener would change the scope. Contract tests enforce its
  absence.

See [ADR-0001](adr/0001-unix-socket-only-transport.md) and
[ADR-0004](adr/0004-peer-credential-auth.md).

## 4. Tenant ownership

Every VM and snapshot is owned by the tenant principal derived at creation time.

- Status, stop, snapshot, restore, and metrics operations are authorized against
  the owning principal.
- A cross-tenant operation is denied fail-closed.
- The snapshot compatibility gate verifies the caller tenant against the
  manifest owner before any Firecracker process is spawned or `/snapshot/load`
  is issued.
- The scheduler enforces per-tenant quota before placement and rejects an
  overcommit of hard limits.

## 5. Isolation boundaries

### 5.1 cgroup-v2

The platform builds a unified cgroup-v2 hierarchy explicitly. One parent cgroup
delegates `cpu`, `memory`, `pids`, and `io`. One leaf per VM carries explicit
limits and has no children and an empty `cgroup.subtree_control`. The jailer
argv always includes `--cgroup-version=2`. A missing cgroup root or required
controller is a hard error before any spawn.

### 5.2 Process jail and seccomp

Firecracker runs under the jailer with validated argv. The platform verifies the
binary's ELF form and seccomp mode as part of provenance and owns the outer
validation itself. See section 2.

### 5.3 Network

Each VM has a TAP device in an isolated network namespace with controlled
nftables NAT. Guest egress is enabled only by explicit VM network policy.
Inter-VM and unsolicited inbound traffic is denied, and host-network sharing is
not permitted. See the [network runbook](runbooks/network.md).

### 5.4 Artifact and path boundaries

- The importer uses descriptor-relative local artifact paths. Arbitrary host
  path access is not permitted.
- Image references must be local and digest-pinned. Remote and tag-only
  references are rejected before any I/O.
- The constrained OCI import refuses host mounts, host network, PID or IPC
  sharing, privileged mode, capability additions, and arbitrary host process
  controls. Container process metadata is ignored and never applied to the
  host.

### 5.5 Snapshot boundaries

Snapshots are local, content-addressed, and owner-scoped. SHA-256 content hashes
cover the Firecracker binary, kernel, rootfs, block devices, guest memory, and
VM state. Tampering and cross-tenant access fail before launch. The repository
defines no cross-host transfer, signing, or encryption contract. See the
[snapshot runbook](runbooks/snapshot.md).

## 6. Fail-closed posture

Across every boundary, a missing prerequisite or failed check stops the
operation.

| Condition | Behavior |
| --- | --- |
| `/dev/kvm`, TAP, cgroup v2, jailer, or seccomp unavailable | Hard error or blocked evidence. |
| Invalid path or unrestricted subprocess argument | Rejected before spawn. |
| Unverified binary or artifact hash mismatch | Rejected before use. |
| Unknown principal or cross-tenant operation | Denied. |
| Unsupported cgroup topology or leaf-contract violation | `CgroupUnavailable` or `InvalidResourceSpec` before spawn. |
| Incapable host in the privileged lane | `blocked` evidence, never a mocked pass. |

The privileged evidence schema encodes an anti-mock rule: when
`host_preflight.kvm_ok` is `false`, no run may record `pass: true`.

## 7. What this platform does not claim

These non-claims are part of the security contract, not omissions.

- Production readiness. This is a development and verification platform with no
  production support contract.
- Host security beyond the stated TCB. The platform secures the boundary it
  owns. It does not claim to harden the host kernel, Firecracker internals, or
  the broader deployment.
- A universal latency guarantee. The `<200 ms` figure is a measured reference
  target, not an SLA. See
  [ADR-0011](adr/0011-benchmark-distributions-not-sla.md).
- General OCI runtime compatibility. OCI input is a constrained local import
  format. See
  [ADR-0008](adr/0008-local-digest-artifacts-constrained-oci.md).
- Snapshot authentication via the Firecracker CRC. The CRC detects accidental
  corruption, and the orchestrator's SHA-256 hashes are the integrity boundary.
- Cross-host snapshot transfer, signed or encrypted snapshot transport, live
  migration, GPU or VFIO passthrough, multi-host clustering, rootless mode, or
  Windows and non-Linux guests. Each is an explicit scope-out. See
  [adr/README.md](adr/README.md).
- A production-grade custom VMM. The direct-KVM subset is educational and
  feature-gated. See
  [ADR-0010](adr/0010-direct-kvm-educational-subset.md).

## 8. Verification evidence

The adversarial batteries in `microvm-security-tests` exercise the boundaries:
paths, auth, cgroups, networks, snapshots, OCI input, binaries, and scope
fidelity. Deterministic batteries run without root, `/dev/kvm`, `/dev/net/tun`,
a writable cgroupfs, or a pinned binary. Privileged-gated tests such as the real
kernel cgroup `EBUSY` check and the real nft ruleset load skip on a non-root
host. Evidence conforms to
[`schemas/evidence-security.v1.json`](../schemas/evidence-security.v1.json).
