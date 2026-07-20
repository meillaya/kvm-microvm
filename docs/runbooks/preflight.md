# Runbook: Host Preflight

Goal: determine whether a host can run the privileged lane, and produce a
machine-readable capability record for evidence.

The preflight probe is **read-only**. It never mutates sysctls, creates
namespaces, loads kernel modules, or opens `/dev/kvm` with write intent.

---

## When to run

- Before any privileged-lane work (Firecracker boot, cgroup-v2 enforcement,
  TAP/netns, snapshot/restore against real KVM).
- Before recording privileged or benchmark evidence, so the host substrate is
  documented.
- Whenever a host changes (kernel upgrade, new machine, CI runner rotation).

The deterministic lane (`cargo test --workspace`) does **not** require a
preflight pass; it runs on any host.

---

## Procedure

### 1. Probe the host

```bash
# Read-only probe; prints JSON to stdout and writes .preflight/host.json.
bash scripts/preflight.sh

# CI/evidence form: atomic write to an explicit path.
bash scripts/preflight.sh --json .preflight/host.json
```

### 2. Read the exit code

```bash
bash scripts/preflight.sh --json .preflight/host.json
echo "preflight exit: $?"
```

| Exit | Meaning | Action |
| --- | --- | --- |
| `0` | Capable (no blockers, no warnings). | Privileged lane may proceed. |
| `2` | Degraded (warnings, no hard blockers). | Proceed with caveat, or use `--strict` to block. |
| `77` | Blocked (one or more blockers). | Do NOT run the privileged lane; record blocked evidence. |

### 3. Inspect the JSON

```bash
jq '{blockers, warnings, blocked_reason}' .preflight/host.json
jq '.kvm, .tap, .cgroup_v2, .tools' .preflight/host.json
```

Key fields (schema:
[`schemas/evidence-host-preflight.v1.json`](../../schemas/evidence-host-preflight.v1.json)):

- `kvm.accessible` — is `/dev/kvm` openable? `kvm.api_version` is `-1` under the
  documented Bash limitation (no ioctl from Bash); see below.
- `tap.accessible` — is `/dev/net/tun` openable?
- `cgroup_v2.unified` and `cgroup_v2.controllers` — unified hierarchy with
  `cpu`, `memory`, `pids` (and ideally `io`).
- `tools.firecracker.accessible` / `tools.jailer.accessible` — pinned binaries
  present, with `version` and `sha256`.
- `blockers` / `warnings` / `blocked_reason` — the derived verdict.

### 4. Strict mode (treat warnings as blockers)

```bash
bash scripts/preflight.sh --strict --json .preflight/host.json
```

`--strict` promotes a degraded (`2`) result to blocked (`77`). The privileged
gate (`scripts/run-privileged-tests.sh`) always runs preflight in strict mode.

---

## Documented limitation: `kvm_api_version_unprobed_in_bash`

Pure Bash cannot issue `ioctl(2)`, so the probe cannot run `KVM_GET_API_VERSION`
or `TUNGETFEATURES`. When `/dev/kvm` is openable the probe sets
`kvm.api_version = -1` and emits the warning token
`kvm_api_version_unprobed_in_bash`. This is a recorded gap, not a failure:

- The privileged lane still requires a real KVM API version ≥ 12, verified by
  the privileged test code (which can ioctl), not by the Bash probe.
- A future privileged-host runner may ship a small `kvm-probe` companion binary
  to refine `api_version` to the schema's strict `O_RDWR + ioctl` semantics.

---

## Gate the privileged lane

```bash
# Runs preflight --strict first; exits 77 if the host is not capable.
bash scripts/run-privileged-tests.sh
```

If the gate blocks, **do not** work around it. Record `blocked` evidence with
the `blocked_reason` from `.preflight/host.json` and run the deterministic lane
instead.

---

## Decision: which lane?

```text
preflight exit 0  ──► privileged lane OK  ──► bash scripts/run-privileged-tests.sh
preflight exit 2  ──► degraded; caveat or --strict
preflight exit 77 ──► deterministic lane only ──► cargo test --workspace
```

See [../setup.md](../setup.md#4-the-two-verification-lanes) for the full lane
reference and [../adr/0009-hybrid-test-lanes.md](../adr/0009-hybrid-test-lanes.md)
for the rationale.
