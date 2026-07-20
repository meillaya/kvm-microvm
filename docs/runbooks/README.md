# Operational Runbooks

Step-by-step operational procedures for the kvm-microvm-orchestrator platform.
Each runbook contains runnable commands and explains how to interpret results.

| Runbook | Purpose |
| --- | --- |
| [preflight.md](preflight.md) | Probe host capability, interpret exit codes and JSON, select the deterministic or privileged lane. |
| [snapshot.md](snapshot.md) | Create and restore snapshots, read the compatibility gate, respond to tamper/owner rejection. |
| [network.md](network.md) | Per-VM TAP/netns/nftables policy, egress policies, and network cleanup. |
| [cleanup.md](cleanup.md) | Idempotent resource cleanup, orphan reconciliation, and leak records. |

> **Scope reminder.** These runbooks operate a development/verification
> platform. They do not claim to make a host production-ready. Privileged
> procedures require a capable host and refuse to run (with `blocked` evidence)
> when prerequisites are absent. See [../security.md](../security.md).

## Conventions

- Commands run from the repository root inside `devenv shell` unless noted.
- The read-only host probe is `scripts/preflight.sh`; the privileged gate is
  `scripts/run-privileged-tests.sh`.
- Exit code `77` always means **blocked**; `2` means **degraded**; `0` means
  **capable**. See [preflight.md](preflight.md).
