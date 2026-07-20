//! Emits two example [`VmMetricsRecord`] documents (plan todo 23):
//! - a fully-available record (cgroup + network + guest), and
//! - a degraded record where the guest agent is unavailable (never zero-filled).
//!
//! Run with: `cargo run -p microvm-metrics --example sample_record`.

use chrono::{TimeZone, Utc};
use microvm_metrics::{
    write_cgroup_fixture, write_tap_fixture, GuestAgentSample, ManualClock, MetricsCollector,
    MetricsPhase, PhaseMarker, StaticGuestAgent, UnavailableReason,
};
use microvm_types::VmId;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

fn main() {
    let tmp = TempDir::new().unwrap();
    let cgroup_root = tmp.path().join("cgroup");
    let sysfs_root = tmp.path().join("sysfs");
    let vm = VmId::new("vm-example").unwrap();
    let wall = Utc.with_ymd_and_hms(2026, 7, 20, 12, 0, 0).unwrap();
    let clock = Arc::new(ManualClock::new(wall));

    // -- fully-available record --------------------------------------------
    write_cgroup_fixture(
        &cgroup_root.join("microvm/vm-example"),
        "usage_usec 5000\nnr_periods 100\nnr_throttled 4\nthrottled_usec 250\n",
        8 * (1 << 20),
        5,
    );
    write_tap_fixture(&sysfs_root, "tap0", 10_000, 20_000);
    let collector = MetricsCollector::new(
        cgroup_root.clone(),
        sysfs_root.clone(),
        Box::new(StaticGuestAgent::returning(GuestAgentSample {
            cpu_steal_pct: 7.5,
            load1: 1.25,
            rss_bytes: 4 * (1 << 20),
        })),
        Box::new(clock.clone()),
    );
    collector.register_vm(
        vm.clone(),
        MetricsPhase::Booting,
        Some(PathBuf::from("microvm/vm-example")),
        Some("tap0".to_string()),
    );
    collector.record_marker(&vm, PhaseMarker::Spawn, 0);
    let _ = collector.sample(&vm).unwrap();
    clock.advance(250_000_000);
    collector.record_marker(&vm, PhaseMarker::ServiceReady, 250_000_000);
    collector.set_phase(&vm, MetricsPhase::Running);
    write_tap_fixture(&sysfs_root, "tap0", 11_000, 22_000);
    let full = collector.sample(&vm).unwrap();
    println!("=== full ===");
    println!("{}", serde_json::to_string_pretty(&full).unwrap());

    // -- degraded record: guest agent unreachable --------------------------
    let clock2 = Arc::new(ManualClock::new(wall));
    let collector2 = MetricsCollector::new(
        cgroup_root.clone(),
        sysfs_root.clone(),
        Box::new(StaticGuestAgent::failing(
            UnavailableReason::AgentUnreachable,
        )),
        Box::new(clock2.clone()),
    );
    collector2.register_vm(
        vm.clone(),
        MetricsPhase::Running,
        Some(PathBuf::from("microvm/vm-example")),
        Some("tap0".to_string()),
    );
    let degraded = collector2.sample(&vm).unwrap();
    println!("=== degraded ===");
    println!("{}", serde_json::to_string_pretty(&degraded).unwrap());
}
