//! Schema and counter contract tests for `microvm-metrics`.
//!
//! Named QA scenario: `cargo test -p microvm-metrics --test schema_and_counters`.
//!
//! These tests are fully deterministic: they drive the [`MetricsCollector`]
//! against a `tempfile` directory and a [`ManualClock`], requiring no
//! privileged host capabilities (no `/dev/kvm`, no real cgroup mutation, no
//! vsock).
//!
//! Coverage:
//! - Schema validation: the serialized [`VmMetricsRecord`] carries every
//!   stable field (boot time, memory usage, CPU usage/throttling, guest CPU
//!   steal when available, RX/TX throughput, source timestamps, availability
//!   flags) and round-trips losslessly.
//! - cgroup file parsing: real cgroup-v2 file contents are parsed into
//!   [`CgroupMetrics`].
//! - Availability flags: an available source serializes `{available:true,
//!   value}`; a missing source serializes `{available:false, reason}` and is
//!   *never* zero-filled.
//! - Missing data handling: removing the cgroup and the guest agent
//!   mid-sampling yields unavailable fields plus bounded error counters: not
//!   zeros, not panics.
//! - Cleanup stops sampling: after [`MetricsCollector::stop_sampling`],
//!   sampling returns `artifact_not_found` and reads nothing.

use chrono::{TimeZone, Utc};
use microvm_errors::ErrorCode;
use microvm_metrics::{
    write_cgroup_fixture, write_tap_fixture, Availability, GuestAgentReader, GuestAgentSample,
    ManualClock, MetricErrorKind, MetricsCollector, MetricsPhase, PhaseMarker, StaticGuestAgent,
    UnavailableReason, VmMetricsRecord, SCHEMA_VERSION,
};
use microvm_types::VmId;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

fn vm() -> VmId {
    VmId::new("vm-schema").unwrap()
}

fn wall() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 20, 12, 0, 0).unwrap()
}

/// A guest agent whose behaviour can be flipped mid-test to simulate the agent
/// disappearing (e.g. the guest crashed or vsock was torn down).
#[derive(Clone, Default)]
struct ToggleAgent {
    sample: Arc<Mutex<Option<GuestAgentSample>>>,
}

impl ToggleAgent {
    fn set(&self, sample: Option<GuestAgentSample>) {
        *self.sample.lock().unwrap() = sample;
    }
}

impl GuestAgentReader for ToggleAgent {
    fn read(&self, _vm_id: &VmId) -> Result<GuestAgentSample, UnavailableReason> {
        self.sample
            .lock()
            .unwrap()
            .ok_or(UnavailableReason::AgentUnreachable)
    }
}

struct Rig {
    _tmp: TempDir,
    cgroup_root: PathBuf,
    sysfs_root: PathBuf,
    collector: MetricsCollector,
    clock: Arc<ManualClock>,
    agent: ToggleAgent,
}

impl Rig {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let sysfs_root = tmp.path().join("sysfs");
        let clock = Arc::new(ManualClock::new(wall()));
        let agent = ToggleAgent::default();
        let collector = MetricsCollector::new(
            cgroup_root.clone(),
            sysfs_root.clone(),
            Box::new(agent.clone()),
            Box::new(clock.clone()),
        );
        Self {
            _tmp: tmp,
            cgroup_root,
            sysfs_root,
            collector,
            clock,
            agent,
        }
    }

    fn cgroup_dir(&self) -> PathBuf {
        self.cgroup_root.join("microvm").join(vm().as_str())
    }
}

// ===========================================================================
// Schema validation
// ===========================================================================

#[test]
fn record_schema_contains_all_stable_fields() {
    let rig = Rig::new();
    write_cgroup_fixture(
        &rig.cgroup_dir(),
        "usage_usec 5000\nnr_periods 100\nnr_throttled 4\nthrottled_usec 250\n",
        8 * (1 << 20),
        5,
    );
    write_tap_fixture(&rig.sysfs_root, "tap0", 10_000, 20_000);
    rig.agent.set(Some(GuestAgentSample {
        cpu_steal_pct: 7.5,
        load1: 1.25,
        rss_bytes: 4 * (1 << 20),
    }));

    rig.collector.register_vm(
        vm(),
        MetricsPhase::Booting,
        Some(PathBuf::from(format!("microvm/{}", vm().as_str()))),
        Some("tap0".to_string()),
    );
    // Record monotonic boot phase markers: spawn at 0.
    rig.collector.record_marker(&vm(), PhaseMarker::Spawn, 0);

    // First sample at monotonic 0 establishes the network baseline (no rate
    // yet).
    let _baseline = rig.collector.sample(&vm()).unwrap();

    // Advance 250ms, mark service-ready, transition to running, and bump the
    // TAP counters by 1000 RX / 2000 TX bytes.
    rig.clock.advance(250_000_000);
    rig.collector
        .record_marker(&vm(), PhaseMarker::ServiceReady, 250_000_000);
    rig.collector.set_phase(&vm(), MetricsPhase::Running);
    write_tap_fixture(&rig.sysfs_root, "tap0", 11_000, 22_000);

    // Second sample: a throughput rate is now derivable.
    let record = rig.collector.sample(&vm()).unwrap();

    let json: Value = serde_json::to_value(&record).unwrap();
    let obj = json.as_object().unwrap();

    // Identity / versioning / phase.
    assert_eq!(obj["vm_id"], Value::from(vm().as_str()));
    assert_eq!(obj["schema_version"], Value::from(SCHEMA_VERSION));
    assert_eq!(obj["phase"], Value::from("running"));

    // Source timestamps: wall (RFC 3339) + host-monotonic ns.
    assert!(obj["collected_at"].is_string());
    assert!(obj["monotonic_ns"].is_number());

    // Boot time derived from monotonic phase markers.
    assert_eq!(obj["phases"]["boot_time_ns"], Value::from(250_000_000u64));
    assert_eq!(record.boot_time_ns(), Some(250_000_000));

    // Memory usage + CPU usage/throttling, each behind an availability flag.
    assert_eq!(obj["cgroup"]["available"], Value::from(true));
    assert_eq!(
        obj["cgroup"]["value"]["memory_current_bytes"],
        Value::from(8u64 * (1 << 20))
    );
    assert_eq!(
        obj["cgroup"]["value"]["cpu"]["usage_usec"],
        Value::from(5000u64)
    );
    assert_eq!(
        obj["cgroup"]["value"]["cpu"]["throttled_usec"],
        Value::from(250u64)
    );
    assert_eq!(record.memory_current_bytes(), Some(8 * (1 << 20)));
    assert_eq!(record.cpu_usage_usec(), Some(5000));
    assert_eq!(record.cpu_throttled_usec(), Some(250));

    // RX/TX throughput present once a prior sample exists.
    assert_eq!(obj["network"]["available"], Value::from(true));
    assert!(obj["network"]["value"]["rx_bytes_per_sec"].is_number());
    assert!(obj["network"]["value"]["tx_bytes_per_sec"].is_number());
    // 1000 RX bytes / 0.25s => 4000 B/s; 2000 TX bytes / 0.25s => 8000 B/s.
    assert_eq!(record.rx_bytes_per_sec(), Some(4000));
    assert_eq!(record.tx_bytes_per_sec(), Some(8000));

    // Guest CPU steal present when the agent is available.
    assert_eq!(obj["guest"]["available"], Value::from(true));
    assert_eq!(obj["guest"]["value"]["cpu_steal_pct"], Value::from(7.5));
    assert_eq!(record.guest_cpu_steal_pct(), Some(7.5));

    // Per-source timestamps.
    assert!(obj["cgroup"]["value"]["sampled_monotonic_ns"].is_number());
    assert!(obj["network"]["value"]["sampled_monotonic_ns"].is_number());
    assert!(obj["guest"]["value"]["sampled_monotonic_ns"].is_number());

    // Lossless round-trip of the full record.
    let back: VmMetricsRecord = serde_json::from_value(json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn throughput_rate_matches_monotonic_delta() {
    let rig = Rig::new();
    write_tap_fixture(&rig.sysfs_root, "tap0", 0, 0);
    rig.collector
        .register_vm(vm(), MetricsPhase::Running, None, Some("tap0".to_string()));

    // First sample: counters only, no rate yet (not a fabricated zero).
    let r1 = rig.collector.sample(&vm()).unwrap();
    let net1 = r1.network.value().unwrap();
    assert_eq!(net1.rx_bytes_per_sec, None);
    assert_eq!(net1.tx_bytes_per_sec, None);

    // Advance exactly 1s and add 2000 RX / 4000 TX bytes.
    rig.clock.advance(1_000_000_000);
    write_tap_fixture(&rig.sysfs_root, "tap0", 2000, 4000);
    let r2 = rig.collector.sample(&vm()).unwrap();
    assert_eq!(r2.rx_bytes_per_sec(), Some(2000));
    assert_eq!(r2.tx_bytes_per_sec(), Some(4000));
}

// ===========================================================================
// cgroup file parsing (end-to-end through the collector)
// ===========================================================================

#[test]
fn parses_cgroup_v2_files_into_metrics() {
    let rig = Rig::new();
    let dir = rig.cgroup_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("cpu.stat"),
        "usage_usec 999\nnr_periods 10\nnr_throttled 1\nthrottled_usec 20\n",
    )
    .unwrap();
    std::fs::write(dir.join("memory.current"), "1048576").unwrap();
    std::fs::write(dir.join("pids.current"), "7").unwrap();
    std::fs::write(
        dir.join("memory.events"),
        "low 0\nhigh 1\nmax 2\noom 0\noom_kill 0\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("io.stat"),
        "8:0 rbytes=512 wbytes=1024 rios=5 wios=6\n",
    )
    .unwrap();

    rig.collector.register_vm(
        vm(),
        MetricsPhase::Running,
        Some(PathBuf::from(format!("microvm/{}", vm().as_str()))),
        None,
    );
    let record = rig.collector.sample(&vm()).unwrap();
    let cg = record.cgroup.value().expect("cgroup must be available");

    assert_eq!(cg.cpu.usage_usec, 999);
    assert_eq!(cg.cpu.nr_throttled, 1);
    assert_eq!(cg.cpu.throttled_usec, 20);
    assert_eq!(cg.memory_current_bytes, 1_048_576);
    assert_eq!(cg.pids_current, 7);
    assert_eq!(cg.memory_events.high, 1);
    assert_eq!(cg.memory_events.max, 2);
    assert_eq!(cg.io.read_bytes, 512);
    assert_eq!(cg.io.write_bytes, 1024);
    // No network configured => network is NoBackend, not zero.
    assert_eq!(record.network.reason(), Some(UnavailableReason::NoBackend));
}

// ===========================================================================
// Availability flags
// ===========================================================================

#[test]
fn availability_flags_serialize_with_explicit_boolean() {
    let avail: Availability<u64> = Availability::Available(42);
    let json = serde_json::to_value(avail).unwrap();
    assert_eq!(json["available"], Value::from(true));
    assert_eq!(json["value"], Value::from(42));
    assert!(json.get("reason").is_none());

    let unavail: Availability<u64> = Availability::Unavailable(UnavailableReason::SourceMissing);
    let json = serde_json::to_value(unavail).unwrap();
    assert_eq!(json["available"], Value::from(false));
    assert_eq!(json["reason"], Value::from("source_missing"));
    assert!(json.get("value").is_none());
}

#[test]
fn not_collected_record_marks_all_sources_unavailable_never_zero() {
    let record = VmMetricsRecord::not_collected(vm(), MetricsPhase::Running, wall(), 0);
    let json = serde_json::to_value(&record).unwrap();

    for source in ["cgroup", "network", "guest"] {
        assert_eq!(json[source]["available"], Value::from(false));
        assert_eq!(json[source]["reason"], Value::from("no_backend"));
        assert!(
            json[source].get("value").is_none(),
            "{source} must have no value"
        );
    }
    // Convenience accessors report None; never a fabricated zero.
    assert_eq!(record.memory_current_bytes(), None);
    assert_eq!(record.cpu_usage_usec(), None);
    assert_eq!(record.guest_cpu_steal_pct(), None);
    assert_eq!(record.rx_bytes_per_sec(), None);
}

// ===========================================================================
// Missing data handling (failure QA scenario)
// ===========================================================================

#[test]
fn removing_cgroup_and_agent_mid_sampling_yields_unavailable_plus_bounded_error() {
    let rig = Rig::new();
    // Start healthy: cgroup present, guest agent responding.
    write_cgroup_fixture(&rig.cgroup_dir(), "usage_usec 100\n", 4096, 1);
    rig.agent.set(Some(GuestAgentSample {
        cpu_steal_pct: 1.0,
        load1: 0.5,
        rss_bytes: 2048,
    }));
    rig.collector.register_vm(
        vm(),
        MetricsPhase::Running,
        Some(PathBuf::from(format!("microvm/{}", vm().as_str()))),
        None,
    );

    let healthy = rig.collector.sample(&vm()).unwrap();
    assert!(healthy.cgroup.is_available());
    assert!(healthy.guest.is_available());
    assert_eq!(healthy.guest_cpu_steal_pct(), Some(1.0));
    assert!(healthy.errors.is_empty());

    // Now the cgroup leaf is removed (VM torn down out-of-band) and the guest
    // agent disappears.
    std::fs::remove_dir_all(rig.cgroup_dir()).unwrap();
    rig.agent.set(None);

    // Sampling must not panic and must not zero-fill.
    let degraded = rig.collector.sample(&vm()).unwrap();
    assert_eq!(
        degraded.cgroup.reason(),
        Some(UnavailableReason::SourceMissing)
    );
    assert_eq!(
        degraded.guest.reason(),
        Some(UnavailableReason::AgentUnreachable)
    );
    // Bounded error counters incremented (not zero, not unbounded labels).
    assert_eq!(degraded.error_count(MetricErrorKind::CgroupRead), 1);
    assert_eq!(degraded.error_count(MetricErrorKind::GuestRead), 1);
    // The error map only ever uses the fixed MetricErrorKind label set.
    for kind in degraded.errors.keys() {
        assert!(MetricErrorKind::all().contains(kind));
    }
    // Values are absent, not zero.
    assert_eq!(degraded.memory_current_bytes(), None);
    assert_eq!(degraded.guest_cpu_steal_pct(), None);

    // Errors accumulate across samples while the source stays broken.
    let again = rig.collector.sample(&vm()).unwrap();
    assert_eq!(again.error_count(MetricErrorKind::CgroupRead), 2);
    assert_eq!(again.error_count(MetricErrorKind::GuestRead), 2);
}

#[test]
fn malformed_cgroup_content_is_parse_error_not_panic() {
    let rig = Rig::new();
    let dir = rig.cgroup_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cpu.stat"), "usage_usec not_a_number\n").unwrap();
    std::fs::write(dir.join("memory.current"), "4096").unwrap();
    std::fs::write(dir.join("pids.current"), "1").unwrap();

    rig.collector.register_vm(
        vm(),
        MetricsPhase::Running,
        Some(PathBuf::from(format!("microvm/{}", vm().as_str()))),
        None,
    );
    let record = rig.collector.sample(&vm()).unwrap();
    assert_eq!(record.cgroup.reason(), Some(UnavailableReason::ParseError));
    assert_eq!(record.error_count(MetricErrorKind::Parse), 1);
}

// ===========================================================================
// Cleanup stops sampling
// ===========================================================================

#[test]
fn cleanup_stops_sampling_and_reads_nothing() {
    let rig = Rig::new();
    write_cgroup_fixture(&rig.cgroup_dir(), "usage_usec 1\n", 1, 1);
    // A healthy guest agent so the happy path records no error counters.
    rig.agent.set(Some(GuestAgentSample {
        cpu_steal_pct: 0.0,
        load1: 0.0,
        rss_bytes: 0,
    }));
    rig.collector.register_vm(
        vm(),
        MetricsPhase::Running,
        Some(PathBuf::from(format!("microvm/{}", vm().as_str()))),
        None,
    );
    assert!(rig.collector.is_sampling(&vm()));
    assert!(rig.collector.sample(&vm()).is_ok());

    // VM cleanup stops sampling.
    rig.collector.stop_sampling(&vm());
    assert!(!rig.collector.is_sampling(&vm()));
    assert_eq!(rig.collector.sampling_count(), 0);

    // Even though the cgroup files still exist on disk, sampling refuses and
    // returns artifact_not_found (no read is performed).
    let err = rig.collector.sample(&vm()).unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);

    // Re-registering resumes sampling with fresh state (counters reset).
    rig.collector.register_vm(
        vm(),
        MetricsPhase::Booting,
        Some(PathBuf::from(format!("microvm/{}", vm().as_str()))),
        None,
    );
    let record = rig.collector.sample(&vm()).unwrap();
    assert!(record.cgroup.is_available());
    assert!(record.errors.is_empty());
}

#[test]
fn static_guest_agent_helpers_are_deterministic() {
    let sample = GuestAgentSample {
        cpu_steal_pct: 0.0,
        load1: 0.0,
        rss_bytes: 0,
    };
    let ok = StaticGuestAgent::returning(sample);
    assert_eq!(ok.read(&vm()), Ok(sample));
    let gone = StaticGuestAgent::failing(UnavailableReason::AgentUnreachable);
    assert_eq!(gone.read(&vm()), Err(UnavailableReason::AgentUnreachable));
}

// ===========================================================================
// Committed fixtures satisfy the schema invariants
// ===========================================================================

/// Validate a serialized record against the invariants that
/// `schemas/vm-metrics-record.v1.json` expresses (no jsonschema crate is used;
/// the structural invariants are checked directly so the committed fixtures
/// cannot silently drift from the contract).
fn assert_record_satisfies_schema(json: &Value) {
    let obj = json.as_object().expect("record must be an object");

    // Required top-level fields.
    for field in [
        "vm_id",
        "schema_version",
        "phase",
        "collected_at",
        "monotonic_ns",
        "phases",
        "cgroup",
        "network",
        "guest",
        "errors",
    ] {
        assert!(obj.contains_key(field), "missing required field {field}");
    }
    assert_eq!(obj["schema_version"], Value::from(SCHEMA_VERSION));
    assert!(
        ["booting", "restoring", "running", "stopped"].contains(&obj["phase"].as_str().unwrap())
    );

    // Phase durations are present (possibly null) and consistent.
    let phases = obj["phases"].as_object().unwrap();
    for field in [
        "spawn_ns",
        "socket_ready_ns",
        "configured_ns",
        "service_ready_ns",
        "snapshot_load_ns",
        "restore_ready_ns",
        "boot_time_ns",
        "restore_time_ns",
    ] {
        assert!(phases.contains_key(field), "phases missing {field}");
    }

    // Availability invariant on every source slot: available => value & no
    // reason; unavailable => reason & no value (never zero-filled).
    for source in ["cgroup", "network", "guest"] {
        let slot = obj[source].as_object().unwrap();
        let available = slot["available"].as_bool().unwrap();
        if available {
            assert!(
                slot.contains_key("value"),
                "{source} available but no value"
            );
            assert!(
                !slot.contains_key("reason"),
                "{source} has both value and reason"
            );
        } else {
            let reason = slot["reason"].as_str().unwrap();
            assert!(
                [
                    "no_backend",
                    "source_missing",
                    "parse_error",
                    "read_error",
                    "agent_unreachable",
                    "not_yet_sampled"
                ]
                .contains(&reason),
                "{source} has unbounded reason {reason}"
            );
            assert!(
                !slot.contains_key("value"),
                "{source} unavailable but has value"
            );
        }
    }

    // Error counters use only the bounded label set.
    for key in obj["errors"].as_object().unwrap().keys() {
        assert!(
            ["cgroup_read", "network_read", "guest_read", "parse"].contains(&key.as_str()),
            "unbounded error label {key}"
        );
    }
}

#[test]
fn committed_example_fixtures_satisfy_the_schema() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for example in [
        "vm-metrics-record-ok.json",
        "vm-metrics-record-guest-unavailable.json",
    ] {
        let path = manifest.join("../../schemas/examples").join(example);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()));
        let json: Value = serde_json::from_str(&raw).unwrap();
        assert_record_satisfies_schema(&json);
    }

    // The guest-unavailable fixture must mark the guest slot unavailable
    // (never zero-filled).
    let raw = std::fs::read_to_string(
        manifest.join("../../schemas/examples/vm-metrics-record-guest-unavailable.json"),
    )
    .unwrap();
    let json: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(json["guest"]["available"], Value::from(false));
    assert_eq!(json["guest"]["reason"], Value::from("agent_unreachable"));
}

#[test]
fn committed_json_schema_document_is_well_formed() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest.join("../../schemas/vm-metrics-record.v1.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let schema: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(schema["title"], Value::from("per-VM metrics record (v1)"));
    // The schema must require the stable field set.
    let required = schema["required"].as_array().unwrap();
    for field in [
        "vm_id",
        "schema_version",
        "phase",
        "cgroup",
        "network",
        "guest",
    ] {
        assert!(
            required.iter().any(|v| v == &Value::from(field)),
            "schema must require {field}"
        );
    }
}
