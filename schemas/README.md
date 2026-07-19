# kvm-microvm-orchestrator — evidence schemas

This directory holds the JSON Schemas (draft 2020-12) that define the outcome vocabulary for every evidence artifact the project writes to `.omo/evidence/kvm-microvm-orchestrator/`. Four lanes, four schemas, one fail-closed posture.

## Lanes

| Lane | Schema | Purpose | Host substrate |
| --- | --- | --- | --- |
| deterministic | `evidence-deterministic.v1.json` | Unit, property, API contract, scheduler pure logic, OCI importer, snapshot manifest, transport parity. Reproducible across hosts. | None — must run without `/dev/kvm`, `/dev/net/tun`, cgroup-v2 mutation. |
| privileged | `evidence-privileged.v1.json` | Firecracker boot, cgroup-v2 enforcement, TAP/netns, jailer launch, lifecycle cleanup, snapshot/restore against real KVM. | Real `/dev/kvm` (API >= 12), `/dev/net/tun`, unified cgroup-v2 with cpu+memory+pids, pinned Firecracker + jailer. |
| benchmark | `evidence-benchmark.v1.json` | Snapshot create/restore latency, Docker cold/warm comparison, warm HTTP function p50/p95/p99. | Same as privileged, plus page-cache control and N>=100 samples. |
| host_preflight | `evidence-host-preflight.v1.json` | Standalone read-only capability snapshot. Embedded as `host_preflight` inside every privileged artifact. | None — read-only. |

## Fail-closed semantics

Three rules govern every schema in this directory. Together they make a mocked privileged run impossible to encode as a real pass and a benchmark impossible to encode as a boolean gate.

### 1. `class` discriminator is a constant

Every schema sets `class` to a single allowed string (`deterministic`, `privileged`, `benchmark`, `host_preflight`). A reviewer can branch on lane without parsing the file name, and tooling can refuse to accept an artifact whose `class` does not match the expected lane for the directory it lives in.

### 2. Anti-mock rule for the privileged lane

`evidence-privileged.v1.json` carries an explicit `if`/`then` rule: when `host_preflight.kvm_ok` is `false`, no run may record `pass: true`. The privileged lane cannot claim a real success against a host that lacks KVM. A blocked lane emits `pass: false`, `blocked: true`, and `blocked_reason: "<token>"`. The same rule is exercised by the negative fixture `examples/privileged-blocked.json` and the negative probe `/tmp/negative-privileged.json`.

### 3. Anti-boolean for the benchmark lane

`evidence-benchmark.v1.json` forbids a `pass` field at every level it could be added: the top-level object (via `additionalProperties: false` plus an explicit `not: { required: ["pass"] }`) and each benchmark item (same pair of rules). Benchmark artifacts publish distributions and `target_ms` metadata; reviewers compare the recorded p50/p95/p99 against `target_ms`, not against a boolean. The negative fixture `examples/benchmark-ok.json` confirms the schema accepts a well-formed benchmark; the negative probe `/tmp/negative-benchmark.json` confirms the schema rejects a benchmark that smuggles a `pass` field back in.

## Determinism guarantee

Deterministic lane artifacts MUST NOT carry `host_preflight` or `target_ms` fields. Deterministic tests are reproducible across hosts; per-host metadata would only confuse the result. The schema enforces this with `additionalProperties: false` at the top level.

## Summary arithmetic

Schemas cannot count, so they do not enforce `summary.total == items.length` or `summary.pass + summary.fail == summary.total`. Reviewers MUST reject artifacts where the math does not reconcile. The validator tooling (planned for the `evidence-validate` binary in plan todo 3's follow-up work) is responsible for the arithmetic check.

## Usage

```python
import json, jsonschema
from jsonschema import Draft202012Validator

schema = json.load(open("schemas/evidence-deterministic.v1.json"))
example = json.load(open("schemas/examples/deterministic-ok.json"))
Draft202012Validator.check_schema(schema)
Draft202012Validator(schema).validate(example)
```

The schemas are intentionally compatible with the upcoming `evidence-validate` Rust binary (`cargo run --bin evidence-validate -- --all schemas/examples`) referenced in plan todo 3's acceptance criteria. Each example in `schemas/examples/` is a positive fixture that must validate; each negative probe in `/tmp/negative-*.json` is a hand-crafted counter-example that must be rejected.