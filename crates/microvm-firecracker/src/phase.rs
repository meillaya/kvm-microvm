//! Phase timestamp recording for the Firecracker boot pipeline.
//!
//! A boot proceeds through a fixed sequence of phases:
//! `spawn -> socket_ready -> configured -> guest_ready`, with `stopped` as a
//! terminal phase reachable from any running point. [`PhaseTimestamps`] records
//! the wall-clock time each phase completed and enforces two invariants:
//!
//! 1. Ordering: a phase may only be recorded after its predecessor.
//! 2. Monotonicity: a recorded timestamp must not precede the previous
//!    phase's timestamp.
//!
//! Each phase is recorded at most once. Violating any invariant yields a typed
//! [`MicrovmError`] with [`ErrorCode::InternalError`]; the recorder never
//! panics. Recording is pure given the supplied timestamp, so tests drive it
//! with fixed clocks.

use chrono::{DateTime, Utc};
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};

/// The ordered boot/stop phases a Firecracker VM passes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The Firecracker child process has been spawned.
    Spawn,
    /// The API socket accepts connections.
    SocketReady,
    /// Machine/kernel/rootfs/network configuration has been accepted by the API.
    Configured,
    /// The guest has signalled readiness (not merely the VMM process/socket).
    GuestReady,
    /// The VM has stopped and its process has exited.
    Stopped,
}

impl Phase {
    /// Stable `snake_case` representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::SocketReady => "socket_ready",
            Self::Configured => "configured",
            Self::GuestReady => "guest_ready",
            Self::Stopped => "stopped",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Wall-clock timestamps for each completed boot/stop phase.
///
/// All fields start as `None` and are filled in order by the recorder methods.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTimestamps {
    spawn: Option<DateTime<Utc>>,
    socket_ready: Option<DateTime<Utc>>,
    configured: Option<DateTime<Utc>>,
    guest_ready: Option<DateTime<Utc>>,
    stopped: Option<DateTime<Utc>>,
}

impl PhaseTimestamps {
    /// An empty recorder with no phases completed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a phase at `at`, enforcing ordering, uniqueness, and monotonicity.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InternalError`] if the phase was already recorded,
    /// if a required predecessor phase has not been recorded, or if `at`
    /// precedes the most recently recorded phase.
    pub fn record(&mut self, phase: Phase, at: DateTime<Utc>) -> Result<(), MicrovmError> {
        if self.slot(phase).is_some() {
            return Err(MicrovmError::new(
                ErrorCode::InternalError,
                format!("phase {} already recorded", phase),
            )
            .with_context("phase", phase.as_str()));
        }

        // Every phase except the first (Spawn) requires its predecessor.
        // Stopped requires at least Spawn to have happened.
        if let Some(required) = predecessor(phase) {
            if self.slot(required).is_none() {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    format!("phase {} recorded before {}", phase, required),
                )
                .with_context("phase", phase.as_str())
                .with_context("missing", required.as_str()));
            }
        }

        // Monotonicity: `at` must not precede the latest recorded timestamp.
        if let Some((last_phase, last_at)) = self.latest() {
            if at < last_at {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    format!("phase {} timestamp precedes {}", phase, last_phase),
                )
                .with_context("phase", phase.as_str())
                .with_context("previous", last_phase.as_str()));
            }
        }

        *self.slot_mut(phase) = Some(at);
        Ok(())
    }

    /// The timestamp for `phase`, if recorded.
    pub fn get(&self, phase: Phase) -> Option<DateTime<Utc>> {
        self.slot(phase)
    }

    /// Spawn phase timestamp.
    pub fn spawn(&self) -> Option<DateTime<Utc>> {
        self.spawn
    }

    /// Socket-ready phase timestamp.
    pub fn socket_ready(&self) -> Option<DateTime<Utc>> {
        self.socket_ready
    }

    /// Configured phase timestamp.
    pub fn configured(&self) -> Option<DateTime<Utc>> {
        self.configured
    }

    /// Guest-ready phase timestamp.
    pub fn guest_ready(&self) -> Option<DateTime<Utc>> {
        self.guest_ready
    }

    /// Stopped phase timestamp.
    pub fn stopped(&self) -> Option<DateTime<Utc>> {
        self.stopped
    }

    /// True once the guest-ready phase has been recorded.
    pub fn is_guest_ready(&self) -> bool {
        self.guest_ready.is_some()
    }

    /// The most recently recorded phase and its timestamp, by ordinal order.
    pub fn latest(&self) -> Option<(Phase, DateTime<Utc>)> {
        const ORDER: [Phase; 5] = [
            Phase::Spawn,
            Phase::SocketReady,
            Phase::Configured,
            Phase::GuestReady,
            Phase::Stopped,
        ];
        ORDER
            .iter()
            .rev()
            .find_map(|&p| self.slot(p).map(|at| (p, at)))
    }

    /// The number of phases recorded so far.
    pub fn recorded_count(&self) -> usize {
        [
            self.spawn,
            self.socket_ready,
            self.configured,
            self.guest_ready,
            self.stopped,
        ]
        .iter()
        .filter(|s| s.is_some())
        .count()
    }

    fn slot(&self, phase: Phase) -> Option<DateTime<Utc>> {
        match phase {
            Phase::Spawn => self.spawn,
            Phase::SocketReady => self.socket_ready,
            Phase::Configured => self.configured,
            Phase::GuestReady => self.guest_ready,
            Phase::Stopped => self.stopped,
        }
    }

    fn slot_mut(&mut self, phase: Phase) -> &mut Option<DateTime<Utc>> {
        match phase {
            Phase::Spawn => &mut self.spawn,
            Phase::SocketReady => &mut self.socket_ready,
            Phase::Configured => &mut self.configured,
            Phase::GuestReady => &mut self.guest_ready,
            Phase::Stopped => &mut self.stopped,
        }
    }
}

/// The phase that must be recorded immediately before `phase`, if any.
fn predecessor(phase: Phase) -> Option<Phase> {
    match phase {
        Phase::Spawn => None,
        Phase::SocketReady => Some(Phase::Spawn),
        Phase::Configured => Some(Phase::SocketReady),
        Phase::GuestReady => Some(Phase::Configured),
        // Stopping only requires that a process was spawned.
        Phase::Stopped => Some(Phase::Spawn),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn full_boot_sequence_records_in_order() {
        let mut p = PhaseTimestamps::new();
        assert_eq!(p.recorded_count(), 0);
        p.record(Phase::Spawn, t(100)).unwrap();
        p.record(Phase::SocketReady, t(101)).unwrap();
        p.record(Phase::Configured, t(102)).unwrap();
        p.record(Phase::GuestReady, t(103)).unwrap();
        assert_eq!(p.recorded_count(), 4);
        assert!(p.is_guest_ready());
        assert_eq!(p.spawn(), Some(t(100)));
        assert_eq!(p.socket_ready(), Some(t(101)));
        assert_eq!(p.configured(), Some(t(102)));
        assert_eq!(p.guest_ready(), Some(t(103)));
        assert_eq!(p.stopped(), None);
    }

    #[test]
    fn stopped_requires_spawn() {
        let mut p = PhaseTimestamps::new();
        let err = p.record(Phase::Stopped, t(10)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("missing").map(String::as_str),
            Some("spawn")
        );

        p.record(Phase::Spawn, t(10)).unwrap();
        p.record(Phase::Stopped, t(11)).unwrap();
        assert_eq!(p.stopped(), Some(t(11)));
    }

    #[test]
    fn out_of_order_phase_rejected() {
        let mut p = PhaseTimestamps::new();
        // Cannot configure before the socket is ready.
        let err = p.record(Phase::Configured, t(10)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("missing").map(String::as_str),
            Some("socket_ready")
        );
    }

    #[test]
    fn duplicate_phase_rejected() {
        let mut p = PhaseTimestamps::new();
        p.record(Phase::Spawn, t(10)).unwrap();
        let err = p.record(Phase::Spawn, t(11)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert!(err.message.contains("already recorded"));
    }

    #[test]
    fn non_monotonic_timestamp_rejected() {
        let mut p = PhaseTimestamps::new();
        p.record(Phase::Spawn, t(100)).unwrap();
        let err = p.record(Phase::SocketReady, t(99)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("previous").map(String::as_str),
            Some("spawn")
        );
    }

    #[test]
    fn equal_timestamps_allowed() {
        let mut p = PhaseTimestamps::new();
        p.record(Phase::Spawn, t(100)).unwrap();
        // Same instant is permitted (monotonic non-decreasing).
        p.record(Phase::SocketReady, t(100)).unwrap();
        assert_eq!(p.socket_ready(), Some(t(100)));
    }

    #[test]
    fn latest_tracks_highest_ordinal() {
        let mut p = PhaseTimestamps::new();
        assert_eq!(p.latest(), None);
        p.record(Phase::Spawn, t(10)).unwrap();
        assert_eq!(p.latest(), Some((Phase::Spawn, t(10))));
        p.record(Phase::SocketReady, t(11)).unwrap();
        assert_eq!(p.latest(), Some((Phase::SocketReady, t(11))));
        // Stopped has the highest ordinal even though guest_ready is absent.
        p.record(Phase::Stopped, t(12)).unwrap();
        assert_eq!(p.latest(), Some((Phase::Stopped, t(12))));
    }

    #[test]
    fn phase_display_matches_as_str() {
        for (phase, s) in [
            (Phase::Spawn, "spawn"),
            (Phase::SocketReady, "socket_ready"),
            (Phase::Configured, "configured"),
            (Phase::GuestReady, "guest_ready"),
            (Phase::Stopped, "stopped"),
        ] {
            assert_eq!(phase.as_str(), s);
            assert_eq!(phase.to_string(), s);
        }
    }

    #[test]
    fn serde_roundtrip() {
        let mut p = PhaseTimestamps::new();
        p.record(Phase::Spawn, t(100)).unwrap();
        p.record(Phase::SocketReady, t(100) + Duration::milliseconds(250))
            .unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: PhaseTimestamps = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
