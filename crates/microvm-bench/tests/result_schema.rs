//! Result-schema conformance for the benchmark artifact (plan todo 27).
//!
//! Named QA scenario: `cargo test -p microvm-bench --test result_schema`.
//!
//! Following the platform convention (see `microvm-metrics`), no `jsonschema`
//! crate is used; instead [`assert_benchmark_satisfies_schema`] hand-encodes the
//! invariants of `schemas/evidence-benchmark.v1.json` and is applied to (a) the
//! committed example fixture, (b) a harness-produced result, and (c) a blocked
//! result. A separate test asserts the committed JSON-schema document itself is
//! well-formed and declares the no-`pass` rule.

use microvm_artifacts::Digest;
use microvm_bench::config::{
    BenchmarkConfig, Conditions, PageCachePolicy, RuntimeVersions, Workload,
};
use microvm_bench::marker::BenchMarker;
use microvm_bench::percentiles::Distribution;
use microvm_bench::result::{
    BenchmarkItem, HostMetadata, Unit, BENCHMARK_CLASS, BENCHMARK_SCHEMA_ID,
};
use microvm_bench::{BlockedReason, ScriptedLane};
use serde_json::Value;

const ALLOWED_UNIT: &[&str] = &["ms", "us", "s", "rps", "B/s", "KiB/s", "MiB/s"];
const ALLOWED_PAGE_CACHE: &[&str] = &["cold", "warm", "mixed"];

fn is_hex64(v: &Value) -> bool {
    match v.as_str() {
        Some(s) => {
            s.len() == 64
                && s.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        }
        None => false,
    }
}

fn assert_object_keys(value: &Value, allowed: &[&str], required: &[&str], ctx: &str) {
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("{ctx}: expected object"));
    for key in obj.keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "{ctx}: unexpected key '{key}' (additionalProperties:false)"
        );
    }
    for key in required {
        assert!(
            obj.contains_key(*key),
            "{ctx}: missing required key '{key}'"
        );
    }
}

fn assert_no_pass(value: &Value, ctx: &str) {
    if let Some(obj) = value.as_object() {
        assert!(
            !obj.contains_key("pass"),
            "{ctx}: forbidden 'pass' field present"
        );
    }
}

fn assert_distribution(value: &Value, ctx: &str) {
    assert_object_keys(
        value,
        &[
            "samples", "failures", "p50", "p95", "p99", "min_ms", "max_ms",
        ],
        &["samples", "p50", "p95", "p99", "min_ms", "max_ms"],
        ctx,
    );
    let samples = value["samples"]
        .as_u64()
        .unwrap_or_else(|| panic!("{ctx}: samples must be u64"));
    if samples == 0 {
        // Blocked/skipped condition: percentiles and min/max must be null.
        for k in ["p50", "p95", "p99", "min_ms", "max_ms"] {
            assert!(value[k].is_null(), "{ctx}: {k} must be null when samples=0");
        }
    } else {
        for k in ["p50", "p95", "p99", "min_ms", "max_ms"] {
            assert!(
                value[k].is_number(),
                "{ctx}: {k} must be a number when samples>0"
            );
        }
    }
    if let Some(f) = value.get("failures") {
        assert!(f.is_u64(), "{ctx}: failures must be a non-negative integer");
    }
}

/// Hand-encoded invariants of `schemas/evidence-benchmark.v1.json`.
pub fn assert_benchmark_satisfies_schema(json: &Value) {
    // Top level.
    assert_object_keys(
        json,
        &[
            "class",
            "host_metadata",
            "workload",
            "runtime_versions",
            "benchmarks",
        ],
        &[
            "class",
            "host_metadata",
            "workload",
            "runtime_versions",
            "benchmarks",
        ],
        "top-level",
    );
    assert_no_pass(json, "top-level");
    assert_eq!(json["class"], Value::from(BENCHMARK_CLASS));

    // host_metadata.
    let host = &json["host_metadata"];
    assert_object_keys(
        host,
        &[
            "cpu",
            "kernel",
            "kvm_api_version",
            "page_cache_state",
            "memory_size_mib",
            "vcpu_count",
            "cgroup_v2",
            "nested",
        ],
        &[
            "cpu",
            "kernel",
            "kvm_api_version",
            "page_cache_state",
            "memory_size_mib",
            "vcpu_count",
            "cgroup_v2",
            "nested",
        ],
        "host_metadata",
    );
    assert!(host["cpu"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(host["kernel"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(host["kvm_api_version"].is_i64());
    assert!(
        ALLOWED_PAGE_CACHE.contains(&host["page_cache_state"].as_str().unwrap_or("")),
        "host_metadata.page_cache_state must be one of {ALLOWED_PAGE_CACHE:?}"
    );
    assert!(host["memory_size_mib"].as_u64().is_some_and(|v| v >= 1));
    assert!(host["vcpu_count"].as_u64().is_some_and(|v| v >= 1));
    assert!(host["cgroup_v2"].is_boolean());
    assert!(host["nested"].is_boolean());

    // workload.
    let workload = &json["workload"];
    assert_object_keys(
        workload,
        &[
            "name",
            "payload_sha256",
            "kernel_sha256",
            "rootfs_sha256",
            "image_sha256",
        ],
        &["name", "payload_sha256"],
        "workload",
    );
    assert!(workload["name"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        is_hex64(&workload["payload_sha256"]),
        "workload.payload_sha256 must be lowercase 64-hex"
    );
    for k in ["kernel_sha256", "rootfs_sha256", "image_sha256"] {
        if let Some(v) = workload.get(k) {
            assert!(is_hex64(v), "workload.{k} must be lowercase 64-hex");
        }
    }

    // runtime_versions.
    let versions = &json["runtime_versions"];
    assert_object_keys(
        versions,
        &["firecracker", "docker"],
        &[],
        "runtime_versions",
    );
    for k in ["firecracker", "docker"] {
        if let Some(v) = versions.get(k) {
            assert!(v.as_str().is_some_and(|s| !s.is_empty()));
        }
    }

    // benchmarks.
    let benchmarks = json["benchmarks"]
        .as_array()
        .expect("benchmarks must be an array");
    for (i, item) in benchmarks.iter().enumerate() {
        let ctx = format!("benchmarks[{i}]");
        assert_object_keys(
            item,
            &[
                "name",
                "target_ms",
                "unit",
                "p50",
                "p95",
                "p99",
                "cold",
                "warm",
                "blocked_reason",
            ],
            &[
                "name",
                "target_ms",
                "unit",
                "p50",
                "p95",
                "p99",
                "cold",
                "warm",
                "blocked_reason",
            ],
            &ctx,
        );
        assert_no_pass(item, &ctx);
        assert!(item["name"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(
            item["target_ms"].is_number(),
            "{ctx}: target_ms must be a number"
        );
        assert!(
            item["target_ms"].as_f64().is_some_and(|v| v >= 0.0),
            "{ctx}: target_ms must be >= 0"
        );
        assert!(
            ALLOWED_UNIT.contains(&item["unit"].as_str().unwrap_or("")),
            "{ctx}: unit must be one of {ALLOWED_UNIT:?}"
        );
        assert_distribution(&item["cold"], &format!("{ctx}.cold"));
        assert_distribution(&item["warm"], &format!("{ctx}.warm"));

        // Blocked invariant: a blocked item has zero samples and null percentiles.
        if let Some(reason) = item["blocked_reason"].as_str() {
            assert!(
                !reason.is_empty(),
                "{ctx}: blocked_reason must be non-empty"
            );
            assert_eq!(item["cold"]["samples"], Value::from(0));
            assert_eq!(item["warm"]["samples"], Value::from(0));
            for k in ["p50", "p95", "p99"] {
                assert!(item[k].is_null(), "{ctx}: {k} must be null when blocked");
            }
        }
    }
}

fn host() -> HostMetadata {
    HostMetadata {
        cpu: "AMD Ryzen 7 5700X 8-Core Processor".into(),
        kernel: "7.1.3-2-cachyos".into(),
        kvm_api_version: 12,
        page_cache_state: PageCachePolicy::Mixed,
        memory_size_mib: 64215,
        vcpu_count: 16,
        cgroup_v2: true,
        nested: true,
    }
}

fn workload() -> Workload {
    Workload::new("snapshot-restore", Digest::from_bytes([0xde; 32])).unwrap()
}

#[test]
fn committed_example_fixture_satisfies_the_schema() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest.join("../../schemas/examples/benchmark-ok.json");
    let raw = std::fs::read_to_string(&path).expect("example fixture exists");
    let json: Value = serde_json::from_str(&raw).expect("example is valid JSON");
    assert_benchmark_satisfies_schema(&json);
}

#[test]
fn committed_json_schema_document_is_well_formed() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest.join("../../schemas/evidence-benchmark.v1.json");
    let raw = std::fs::read_to_string(&path).expect("schema document exists");
    let schema: Value = serde_json::from_str(&raw).expect("schema is valid JSON");

    assert_eq!(schema["$id"], Value::from(BENCHMARK_SCHEMA_ID));
    // The schema must require the new fields and forbid a top-level 'pass'.
    let required = schema["required"].as_array().expect("required is an array");
    let required: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
    for field in [
        "class",
        "host_metadata",
        "benchmarks",
        "workload",
        "runtime_versions",
    ] {
        assert!(required.contains(&field), "schema must require '{field}'");
    }
    // The explicit no-pass rule must be present at the top level.
    assert_eq!(schema["not"]["required"][0], Value::from("pass"));
    // workload + runtime_versions must be declared properties.
    assert!(schema["properties"]["workload"].is_object());
    assert!(schema["properties"]["runtime_versions"].is_object());
    // cold/warm declare an optional failures counter.
    let item = &schema["properties"]["benchmarks"]["items"]["properties"];
    assert!(item["cold"]["properties"]["failures"].is_object());
    assert!(item["warm"]["properties"]["failures"].is_object());
}

#[tokio::test]
async fn harness_produced_result_satisfies_the_schema() {
    let config = BenchmarkConfig::new(workload(), 100, Conditions::default()).unwrap();
    let marker = BenchMarker::new(config);
    let cold: Vec<Result<f64, String>> = (0..100).map(|i| Ok(150.0 + i as f64)).collect();
    let warm: Vec<Result<f64, String>> = (0..100).map(|i| Ok(10.0 + i as f64 * 0.1)).collect();
    let lane = ScriptedLane::new("snapshot_restore", 200.0, cold, warm);
    let result = marker
        .run(
            host(),
            RuntimeVersions {
                firecracker: Some("1.16.1".into()),
                docker: Some("27.0.0".into()),
            },
            vec![Box::new(lane)],
        )
        .await;

    let json: Value = serde_json::from_str(&result.to_json_pretty().unwrap()).unwrap();
    assert_benchmark_satisfies_schema(&json);
    // N>=100 per condition is recorded.
    assert_eq!(json["benchmarks"][0]["cold"]["samples"], Value::from(100));
    assert_eq!(json["benchmarks"][0]["warm"]["samples"], Value::from(100));
}

#[tokio::test]
async fn blocked_result_satisfies_the_schema() {
    let config = BenchmarkConfig::new(workload(), 100, Conditions::default()).unwrap();
    let marker = BenchMarker::new(config);
    let lane = ScriptedLane::blocked(
        "snapshot_restore",
        200.0,
        BlockedReason::KvmUnavailable,
        "/dev/kvm missing",
    );
    let result = marker
        .run(host(), RuntimeVersions::default(), vec![Box::new(lane)])
        .await;
    let json: Value = serde_json::from_str(&result.to_json_pretty().unwrap()).unwrap();
    assert_benchmark_satisfies_schema(&json);
    assert_eq!(
        json["benchmarks"][0]["blocked_reason"],
        Value::from("kvm_unavailable")
    );
}

#[test]
fn distribution_with_failures_satisfies_schema() {
    let d = Distribution::from_samples_with_failures(&[1.0, 2.0, 3.0], 2);
    let json = serde_json::to_value(d).unwrap();
    assert_distribution(&json, "distribution");
    assert_eq!(json["failures"], Value::from(2));
    assert_eq!(json["samples"], Value::from(3));
}

#[test]
fn benchmark_item_unit_round_trips_all_schema_units() {
    for unit in [
        Unit::Ms,
        Unit::Us,
        Unit::S,
        Unit::Rps,
        Unit::BytesPerSec,
        Unit::KiBPerSec,
        Unit::MiBPerSec,
    ] {
        let item = BenchmarkItem::blocked("x", 1.0, unit, "kvm_unavailable");
        let json = serde_json::to_value(&item).unwrap();
        assert!(ALLOWED_UNIT.contains(&json["unit"].as_str().unwrap()));
    }
}
