# Decisions

Each decision below is settled for this version. The rejected alternative is
recorded so a later change does not relitigate it by accident.

| Decision | Why | Rejected alternative |
| --- | --- | --- |
| Control over Unix sockets only | The tool is local. Peer credentials name the caller, and no network listener exists. | A TCP or loopback listener with tokens. It adds a remote attack surface the tool does not need. |
| One daemon with REST and gRPC adapters over one service | The two protocols stay in parity because both call the same lifecycle service. | Two independent servers. Validation and error codes would drift apart. |
| Firecracker as the real backend | Firecracker is small, runs on KVM, and supports snapshot and restore through its API. | QEMU or a container runtime. Both are heavier, and neither matches the snapshot path. |
| Host-owned cgroup v2 leaves | The daemon creates one parent and one leaf per VM, so limits are explicit and visible in the filesystem. | Jailer defaults. They hide the hierarchy and the limits. |
| Serial readiness for no-network VMs | A VM with no network cannot answer a probe. The readiness marker on the serial console is a direct signal. | TCP readiness for every VM. It stays available for networked VMs. A fixed sleep is rejected because it races the boot. |
| Snapshots local and content-hashed, v1 only for `network_policy = none` | The tested path keeps snapshots on the host and validates the manifest before load. Networked snapshots have no acceptance evidence yet. | Cross-host transfer and a shared snapshot store. Neither is signed, encrypted, or tested. |
| Explicit `backend = "sim"` | Deterministic tests and CLI exploration need a backend that touches no host resource. Naming it makes the choice visible. | A silent fallback to simulation when KVM is missing. That would mask a real failure. |
| Single configured principal | The tool has one operator. `allowed_uids`, `tenant`, and `role` state that principal plainly. | A multi-tenant model with quotas. It is unbuilt and unclaimed. |
| Lab scope, no production claim | Verification covers a development path and a real KVM acceptance path on one host. That is the evidence. | A production-readiness or SLA claim. There is no evidence for it. |
| Development scratch under `.work/` with a delegated cgroup | The dev path needs no sudo, and one scratch directory plus the wrapper trap removes what it created. | Writes to `/var`, `/run`, and system cgroups during development. That pollutes the host. |
