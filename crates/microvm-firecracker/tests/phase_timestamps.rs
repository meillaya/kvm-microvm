//! Deterministic phase-timestamp recording tests (public API).

use chrono::{DateTime, Duration, Utc};
use microvm_errors::ErrorCode;
use microvm_firecracker::phase::{Phase, PhaseTimestamps};

fn t(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
}

#[test]
fn records_full_boot_then_stop() {
    let mut p = PhaseTimestamps::new();
    p.record(Phase::Spawn, t(100)).unwrap();
    p.record(Phase::SocketReady, t(100) + Duration::milliseconds(50))
        .unwrap();
    p.record(Phase::Configured, t(100) + Duration::milliseconds(120))
        .unwrap();
    p.record(Phase::GuestReady, t(100) + Duration::milliseconds(300))
        .unwrap();
    p.record(Phase::Stopped, t(100) + Duration::seconds(30))
        .unwrap();

    assert_eq!(p.recorded_count(), 5);
    assert!(p.is_guest_ready());
    assert!(p.stopped().is_some());
    // Monotonic non-decreasing across the whole sequence.
    let ordered = [
        p.spawn(),
        p.socket_ready(),
        p.configured(),
        p.guest_ready(),
        p.stopped(),
    ];
    for w in ordered.windows(2) {
        assert!(w[0].unwrap() <= w[1].unwrap());
    }
}

#[test]
fn enforces_ordering_and_uniqueness() {
    let mut p = PhaseTimestamps::new();
    // configured before socket_ready is rejected.
    assert_eq!(
        p.record(Phase::Configured, t(10)).unwrap_err().code,
        ErrorCode::InternalError
    );
    p.record(Phase::Spawn, t(10)).unwrap();
    // duplicate spawn rejected.
    assert_eq!(
        p.record(Phase::Spawn, t(11)).unwrap_err().code,
        ErrorCode::InternalError
    );
    // backwards timestamp rejected.
    p.record(Phase::SocketReady, t(11)).unwrap();
    assert_eq!(
        p.record(Phase::Configured, t(5)).unwrap_err().code,
        ErrorCode::InternalError
    );
}

#[test]
fn stopped_only_requires_spawn() {
    let mut p = PhaseTimestamps::new();
    assert!(p.record(Phase::Stopped, t(10)).is_err());
    p.record(Phase::Spawn, t(10)).unwrap();
    assert!(p.record(Phase::Stopped, t(11)).is_ok());
}

#[test]
fn serde_roundtrip() {
    let mut p = PhaseTimestamps::new();
    p.record(Phase::Spawn, t(100)).unwrap();
    p.record(Phase::SocketReady, t(101)).unwrap();
    let json = serde_json::to_string(&p).unwrap();
    let back: PhaseTimestamps = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}
