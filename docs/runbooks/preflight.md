# Runbook: host preflight

Goal: decide whether a host can run the privileged lane and produce a
machine-readable capability record for evidence.

The preflight probe is read-only. It never mutates sysctls, creates namespaces,
loads kernel modules, or opens `/dev/kvm` for writing.

## When to run

- Before privileged work: Firecracker boot, cgroup-v2 enforcement, TAP/netns,
  or snapshot/restore against real KVM.
- Before recording privileged or benchmark evidence, so the host substrate is
  documented.
- Whenever the host changes: kernel upgrade, new machine, or CI runner rotation.

The deterministic lane (`cargo test --workspace`) does not need a preflight
pass. It runs on any Linux host.

## Procedure

### 1. Probe the host

```bash
# Read-only probe. Prints JSON and writes .preflight/host.json.
bash scripts/preflight.sh

# CI and evidence form: atomic write to an explicit path.
bash scripts/preflight.sh --json .preflight/host.json
```

### 2. Read the exit code

```bash
bash scripts/preflight.sh --json .preflight/host.json
echo "preflight exit: $?"
```

| Exit | Meaning | Action |
| --- | --- | --- |
| `0` | Capable. No blockers and no warnings. | The privileged lane may proceed. |
| `2` | Degraded. Warnings are present and no hard blocker exists. | Proceed with a caveat, or use `--strict` to block. |
| `77` | Blocked. One or more blockers are present. | Do not run the privileged lane. Record blocked evidence. |

### 3. Inspect the JSON

```bash
jq '{blockers, warnings, blocked_reason}' .preflight/host.json
jq '.kvm, .tap, .cgroup_v2, .tools' .preflight/host.json
```

Key fields, defined by
[`schemas/evidence-host-preflight.v1.json`](../../schemas/evidence-host-preflight.v1.json):

- `kvm.accessible`: can the process open `/dev/kvm`? The `kvm.api_version` value
  is `-1` under the documented Bash limitation.
- `tap.accessible`: can the process open `/dev/net/tun`?
- `cgroup_v2.unified` and `cgroup_v2.controllers`: is the hierarchy unified, and
  does it expose `cpu`, `memory`, and `pids`? The `io` controller is preferred.
- `tools.firecracker.accessible` and `tools.jailer.accessible`: are the pinned
  binaries present, with a version and SHA-256?
- `blockers`, `warnings`, and `blocked_reason`: the derived verdict.

### 4. Strict mode

```bash
bash scripts/preflight.sh --strict --json .preflight/host.json
```

`--strict` promotes a degraded (`2`) result to blocked (`77`). The privileged
gate (`scripts/run-privileged-tests.sh`) always runs preflight in strict mode.

## Documented limitation: `kvm_api_version_unprobed_in_bash`

Pure Bash cannot issue `ioctl(2)`, so the probe cannot run
`KVM_GET_API_VERSION` or `TUNGETFEATURES`. When `/dev/kvm` is openable, the
probe records `kvm.api_version = -1` and emits the warning token
`kvm_api_version_unprobed_in_bash`.

The privileged lane still requires a real KVM API version of at least 12. The
privileged test code issues the ioctl and checks the value. A future runner may
ship a small `kvm-probe` companion binary to refine `api_version` to the
schema's strict `O_RDWR + ioctl` semantics.

## Gate the privileged lane

`scripts/run-privileged-tests.sh` runs preflight in strict mode. It exits `0`
when the host may run the suite and `77` when the host is blocked or degraded.
It does not run the tests.

```bash
bash scripts/run-privileged-tests.sh
```

After the gate passes, run the suite:

```bash
sudo -E bash scripts/run-privileged-suite.sh
```

If the gate blocks, do not work around it. Record `blocked` evidence with the
`blocked_reason` from `.preflight/host.json`, then run the deterministic lane.

## Decide which lane to run

| Preflight result | Next step |
| --- | --- |
| `0` | Run `sudo -E bash scripts/run-privileged-suite.sh`. |
| `2` | Continue with a caveat, or rerun with `--strict` to block. |
| `77` | Run the deterministic lane only: `cargo test --workspace`. |

See [setup.md](../setup.md#4-the-two-verification-lanes) for the full lane
reference and [ADR-0009](../adr/0009-hybrid-test-lanes.md) for the rationale.
