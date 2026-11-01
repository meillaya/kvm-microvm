# Evidence schemas

This directory holds the JSON Schemas (draft 2020-12) for the evidence artifacts
that the project writes under `.omo/evidence/kvm-microvm-orchestrator/`, plus
the schemas for snapshot manifests, per-VM metrics, and warm demo records.

## Evidence schemas

| Schema | Class | Purpose | Host substrate |
| --- | --- | --- | --- |
| `evidence-deterministic.v1.json` | `deterministic` | Unit, property, API contract, scheduler, OCI importer, snapshot manifest, and transport parity results. | None. The lane must run without `/dev/kvm`, `/dev/net/tun`, or cgroup-v2 mutation. |
| `evidence-privileged.v1.json` | `privileged` | Firecracker boot, cgroup-v2 enforcement, TAP and netns, jailer launch, lifecycle cleanup, and snapshot/restore against real KVM. | `/dev/kvm` (API 12 or later), `/dev/net/tun`, unified cgroup v2 with `cpu`, `memory`, and `pids`, and pinned Firecracker and jailer. |
| `evidence-benchmark.v1.json` | `benchmark` | Snapshot and restore latency, the Docker cold and warm comparison, and warm HTTP function percentiles. | The privileged substrate, plus page-cache control and at least 100 samples. |
| `evidence-host-preflight.v1.json` | `host_preflight` | A standalone read-only capability snapshot. Privileged artifacts embed it as `host_preflight`. | None. The probe is read-only. |
| `evidence-security.v1.json` | `security` | Adversarial probes against production security boundaries, with the typed error code each probe produced. | None. The probes are deterministic and do not need root or `/dev/kvm`. |

## Fail-closed rules

Three rules apply across the evidence schemas. They make a mocked privileged
pass impossible to encode and a benchmark impossible to encode as a boolean
gate.

### The class discriminator is constant

Every schema fixes `class` to one value: `deterministic`, `privileged`,
`benchmark`, `host_preflight`, or `security`. A reviewer can branch on the lane
without parsing the file name, and tooling can reject an artifact whose `class`
does not match the lane that produced it.

### The privileged lane cannot mock a pass

`evidence-privileged.v1.json` carries an `if`/`then` rule: when
`host_preflight.kvm_ok` is `false`, the artifact cannot record `pass: true`. A
blocked lane records `pass: false`, `blocked: true`, and a `blocked_reason`
token. The fixture `examples/privileged-blocked.json` exercises the blocked
shape.

### The benchmark lane cannot record a pass

`evidence-benchmark.v1.json` rejects a `pass` field at the top level and on every
benchmark item. It combines `additionalProperties: false` with an explicit
`not: { required: ["pass"] }` rule. Benchmark artifacts publish distributions
and `target_ms` metadata. A reviewer compares the recorded p50, p95, and p99
against `target_ms` rather than reading a boolean.

## Determinism

Deterministic artifacts do not carry `host_preflight` or `target_ms` fields.
Per-host metadata would make a reproducible result depend on the host. The
schema enforces this with `additionalProperties: false` at the top level.

## Summary arithmetic

A schema cannot count, so it does not enforce
`summary.total == items.length` or
`summary.pass + summary.fail == summary.total`. A reviewer rejects an artifact
whose arithmetic does not reconcile. The evidence reducer
(`scripts/aggregate-evidence.sh`) performs that check for the release matrix.

## Supporting schemas

| Schema | Purpose |
| --- | --- |
| `snapshot-manifest.v1.json` | Content hashes and compatibility metadata for a local snapshot. |
| `vm-metrics-record.v1.json` | Per-VM host and guest metrics with availability flags. |
| `warm-http-demo.v1.json` | Cold and warm evidence for the HTTP-function demo. |

## Usage

```python
import json
from jsonschema import Draft202012Validator

schema = json.load(open("schemas/evidence-deterministic.v1.json"))
example = json.load(open("schemas/examples/deterministic-ok.json"))
Draft202012Validator.check_schema(schema)
Draft202012Validator(schema).validate(example)
```

The files in `schemas/examples/` are positive fixtures. A fixture must validate
against the schema named by its content. When a schema changes, update the
fixture in the same change.
