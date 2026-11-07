# JSON Schemas

The schemas in this directory describe the JSON the project writes or accepts:

| Schema | Purpose |
| --- | --- |
| `snapshot-manifest.v1.json` | Snapshot metadata, content hashes, host envelope, owner, and quota. |
| `vm-metrics-record.v1.json` | Per-VM cgroup, network, phase, and guest metrics with availability flags. |
| `evidence-benchmark.v1.json` | Benchmark result document written by `microvm-bench`. It has no pass field. |
| `evidence-host-preflight.v1.json` | Read-only host capability report written by `scripts/preflight.sh`. |

The files under `examples/` are valid positive fixtures. Validate a fixture with
a draft 2020-12 validator, or check that it parses and matches the Rust types
that produce it:

```bash
python3 - <<'PY'
import json
for path in ["schemas/examples/benchmark-ok.json",
             "schemas/examples/host-preflight-ok.json",
             "schemas/examples/snapshot-manifest-ok.json",
             "schemas/examples/vm-metrics-record-ok.json"]:
    json.load(open(path))
    print(path, "parses")
PY
```

The canonical Rust types are `microvm_bench::result::BenchmarkResult`,
`microvm_snapshots::SnapshotManifest`, and
`microvm_metrics::VmMetricsRecord`. Keep the schema and the Rust type in the
same change.
