# Security

kvm-microvm is a lab tool for one operator on one host. The daemon trusts its
config file and the local user who starts it. It isolates guest code with KVM and
Firecracker, and it does not claim to harden the host beyond its own inputs and
local paths.

## Trust model

The program runs one configured principal. The daemon derives the connecting
principal from the Unix socket peer credentials and checks the peer UID against
`server.allowed_uids`. The socket file mode and owner control filesystem access.
`server.tenant` and `server.role` label the configured principal and are recorded
with each VM.

There is no multi-tenancy. The config sets one tenant and one role, the daemon
does not implement quotas across tenants, and every allowed UID acts as that
principal. Keep `server.allowed_uids` narrow.

## Authentication and transport

Both control transports are Unix domain sockets. The filesystem is the boundary,
so there is no token or password layer. A client that can open the socket with
the matching mode and UID passes the check.

- Run the daemon as a dedicated user.
- Keep the socket directory writable only by that user.
- Prefer `server.socket_mode = "0600"` and set the socket uid and gid to the
  daemon user.
- Do not expose the socket directory over a network filesystem or a proxy.

A peer whose UID is not listed in `server.allowed_uids` is rejected. The daemon
does not fall back to an unauthenticated mode.

## Guest and host boundaries

KVM and Firecracker form the isolation boundary for guest code. The daemon
places each Firecracker process in a cgroup v2 leaf with the VM's cpu and memory
limits and `isolation.pids_max`. A networked VM also launches under the jailer
when `runtime.use_jailer` is set. The v1 no-network path launches Firecracker
directly and attaches its PID to the leaf. The guest image comes from local
paths in the config; the daemon pulls no image over the network.

The simulation backend (`backend = "sim"`) is an explicit in-memory mode for
tests and CLI exploration. It provides no isolation and must not be used to run
untrusted code.

## Snapshot integrity

A snapshot manifest records SHA-256 content hashes and the host envelope. Restore
checks the manifest before it starts a process, and a mismatch is a hard
rejection. The hashes catch tampering and accidental corruption after the
snapshot is written.

The design does not sign or encrypt a snapshot. A snapshot contains guest memory,
so treat the snapshot directory as sensitive as the guest itself and keep its
permissions restricted. The manifest and the files stay local; there is no
cross-host transfer.

## Non-claims

- No production-readiness claim. The daemon is a lab tool.
- No multi-tenant isolation or quota model.
- No host hardening beyond input validation, path validation, and the cgroup
  boundary.
- No protection against a KVM or Firecracker vulnerability.
- No remote registry, TCP control plane, or cross-host snapshot transfer.
- No claim that the guest kernel or guest userland is secure.

## Hardening checklist

- Set a narrow `allowed_uids` list and a socket mode of `0600`.
- Run the daemon as a dedicated user with ownership of its state, snapshot, and
  log directories.
- Pin the Firecracker and jailer paths in the config and keep those binaries
  writable only by an administrator.
- Keep `isolation.pids_max` and the per-VM cpu and memory limits realistic for
  the host.
- Restrict the snapshot directory. Snapshots contain guest memory.
- Run `microvmd --check` before every start.
