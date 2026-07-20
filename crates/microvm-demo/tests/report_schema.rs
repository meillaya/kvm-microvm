//! Demo report invariants (plan todo 28).
//!
//! The report carries cold first-call, warm p50/p95/p99, warmup count, restore
//! accounting, host metadata, and cleanup evidence. It has **no** pass/fail gate
//! at any depth, and a blocked report carries nulls + a recorded reason rather
//! than fabricated samples.

use microvm_artifacts::Digest;
use microvm_bench::{BlockedReason, HostMetadata, PageCachePolicy};
use microvm_demo::{
    CleanupEvidence, ColdWarmMeasurement, DemoConfig, DemoReport, DemoRunner, HttpFunction, Rootfs,
    ScriptedRestore, ScriptedRestorer, DEMO_CLASS,
};

fn host() -> HostMetadata {
    HostMetadata {
        cpu: "test-cpu".into(),
        kernel: "7.1.3-test".into(),
        kvm_api_version: 12,
        page_cache_state: PageCachePolicy::Mixed,
        memory_size_mib: 65536,
        vcpu_count: 32,
        cgroup_v2: true,
        nested: false,
    }
}

fn function() -> HttpFunction {
    let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
    HttpFunction::new("hello-http", rootfs).unwrap()
}

fn no_pass_field_anywhere(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = k.to_ascii_lowercase();
                if matches!(key.as_str(), "pass" | "passed" | "meets_target" | "sla_met") {
                    return false;
                }
                if !no_pass_field_anywhere(v) {
                    return false;
                }
            }
            true
        }
        serde_json::Value::Array(items) => items.iter().all(no_pass_field_anywhere),
        _ => true,
    }
}

#[tokio::test]
async fn completed_report_has_required_fields_and_no_pass_gate() {
    let restores: Vec<Result<ScriptedRestore, String>> = (0..4)
        .map(|i| Ok(ScriptedRestore::new(1.0, i as f64 + 1.0)))
        .collect();
    let mut restorer = ScriptedRestorer::ok("s", 2.0, 3.0, restores);
    let runner = DemoRunner::new(DemoConfig::new(function(), 100, 4).unwrap());
    let report = runner.run(host(), &mut restorer).await;

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["class"], DEMO_CLASS);
    for field in [
        "host_metadata",
        "workload",
        "cold_first_call_ms",
        "warm_p50_ms",
        "warm_p95_ms",
        "warm_p99_ms",
        "warm",
        "warmup_count",
        "request_trials",
        "restore_trials",
        "restore_failures",
        "cleanup",
    ] {
        assert!(json.get(field).is_some(), "missing field {field}");
    }
    assert!(json["blocked_reason"].is_null());
    assert!(
        no_pass_field_anywhere(&json),
        "no pass field may exist at any depth"
    );
}

#[tokio::test]
async fn blocked_report_serializes_nulls_and_reason() {
    let mut restorer = ScriptedRestorer::blocked("s", BlockedReason::KvmUnavailable, "no /dev/kvm");
    let runner = DemoRunner::new(DemoConfig::new(function(), 100, 4).unwrap());
    let report = runner.run(host(), &mut restorer).await;

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["blocked_reason"], "kvm_unavailable");
    assert!(json["cold_first_call_ms"].is_null());
    assert!(json["warm_p50_ms"].is_null());
    assert_eq!(json["warm"]["samples"], 0);
    assert!(json["warm"]["p50"].is_null());
    assert_eq!(json["request_trials"], 0);
    assert!(no_pass_field_anywhere(&json));
}

#[test]
fn report_round_trips_and_preserves_cleanup() {
    let m = ColdWarmMeasurement::new(Some(11.0), &[1.0, 2.0, 3.0], 0, 3, 2, 2, 0);
    let cleanup = CleanupEvidence {
        released_vms: 2,
        snapshot_discarded: true,
    };
    let workload = microvm_bench::Workload::new("hello-http", Digest::from_bytes([7; 32])).unwrap();
    let report = DemoReport::completed(host(), workload, m, None, cleanup);
    let json = report.to_json_pretty().unwrap();
    let back: DemoReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
    assert_eq!(back.cleanup.released_vms, 2);
    assert!(back.cleanup.snapshot_discarded);
}

#[test]
fn committed_example_and_schema_are_consistent() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().unwrap().parent().unwrap();
    let example_path = root.join("schemas/examples/warm-http-demo-ok.json");
    let schema_path = root.join("schemas/warm-http-demo.v1.json");

    let example: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&example_path).unwrap()).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&schema_path).unwrap()).unwrap();

    // The schema document is well-formed and keeps the no-pass rule.
    assert_eq!(
        schema["$id"],
        "https://kvm-microvm-orchestrator.local/schemas/warm-http-demo.v1.json"
    );
    assert_eq!(schema["not"]["required"][0], "pass");
    let required = schema["required"].as_array().unwrap();
    for field in [
        "class",
        "host_metadata",
        "workload",
        "cold_first_call_ms",
        "warm",
        "cleanup",
    ] {
        assert!(
            required.iter().any(|v| v == field),
            "schema must require {field}"
        );
    }

    // The committed example satisfies the schema's load-bearing invariants.
    assert_eq!(example["class"], DEMO_CLASS);
    assert!(no_pass_field_anywhere(&example));
    assert!(example["blocked_reason"].is_null());
    assert_eq!(example["warm"]["samples"], 100);
    assert_eq!(example["request_trials"], 100);
    let hash = example["workload"]["payload_sha256"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

    // The example round-trips into the strongly-typed report.
    let report: DemoReport = serde_json::from_value(example.clone()).unwrap();
    assert!(!report.is_blocked());
    assert_eq!(report.cold_first_call_ms, Some(12.4));
    assert_eq!(report.warm_p99_ms, Some(1.4));
    assert_eq!(report.warmup_count, 8);
    assert_eq!(report.cleanup.released_vms, 8);
}
