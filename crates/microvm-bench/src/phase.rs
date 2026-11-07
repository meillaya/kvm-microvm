//! Monotonic phase recording for benchmark measurements.
//!
//! Every benchmark sample is timed with a host-monotonic clock so durations
//! are immune to wall-clock jumps (NTP, suspend/resume). [`PhaseRecorder`]
//! records an ordered sequence of named phase boundaries and enforces one
//! invariant: a phase timestamp must never precede the previous one. Violating
//! it yields a typed [`MicrovmError`] rather than a silently negative duration.
//!
//! Timestamps come from an injectable [`microvm_metrics::Clock`] (reused from
//! the metrics crate so the whole platform shares one monotonic source). The
//! recorder itself is pure given the supplied timestamps, so deterministic tests
//! drive it with fixed values and no real clock.

use microvm_errors::{ErrorCode, MicrovmError};
use microvm_metrics::Clock;

/// Nanoseconds per millisecond.
const NS_PER_MS: f64 = 1_000_000.0;

/// Convert a nanosecond count to milliseconds.
pub fn ns_to_ms(ns: u64) -> f64 {
    ns as f64 / NS_PER_MS
}

/// An ordered, monotonic sequence of named phase boundaries.
///
/// Each [`PhaseRecorder::record_at`] appends a `(name, monotonic_ns)` pair and
/// rejects any timestamp that would move backwards. Durations between two
/// recorded phases are always non-negative by construction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PhaseRecorder {
    phases: Vec<(String, u64)>,
}

impl PhaseRecorder {
    /// Create an empty recorder.
    pub fn new() -> Self {
        Self { phases: Vec::new() }
    }

    /// Record a phase boundary at the clock's current monotonic reading.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InternalError`] if the reading precedes the previous
    /// phase (a monotonicity violation).
    pub fn record<C: Clock>(
        &mut self,
        name: impl Into<String>,
        clock: &C,
    ) -> Result<u64, MicrovmError> {
        self.record_at(name, clock.now_monotonic_ns())?;
        Ok(self.phases.last().map(|(_, ns)| *ns).unwrap_or(0))
    }

    /// Record a phase boundary at an explicit monotonic timestamp (pure).
    ///
    /// # Errors
    /// Returns [`ErrorCode::InternalError`] when `monotonic_ns` is less than the
    /// previously recorded timestamp.
    pub fn record_at(
        &mut self,
        name: impl Into<String>,
        monotonic_ns: u64,
    ) -> Result<(), MicrovmError> {
        if let Some((prev_name, prev_ns)) = self.phases.last() {
            if monotonic_ns < *prev_ns {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    "benchmark phase timestamps must be monotonic",
                )
                .with_context("phase", name.into())
                .with_context("prev_phase", prev_name.clone())
                .with_context("monotonic_ns", monotonic_ns.to_string())
                .with_context("prev_monotonic_ns", prev_ns.to_string()));
            }
        }
        self.phases.push((name.into(), monotonic_ns));
        Ok(())
    }

    /// The recorded phases in order.
    pub fn phases(&self) -> &[(String, u64)] {
        &self.phases
    }

    /// Duration in milliseconds between two recorded phases, or `None` if either
    /// phase is absent. Always non-negative when present.
    pub fn duration_ms(&self, from: &str, to: &str) -> Option<f64> {
        let start = self.phases.iter().find(|(n, _)| n == from)?.1;
        let end = self.phases.iter().find(|(n, _)| n == to)?.1;
        Some(ns_to_ms(end.saturating_sub(start)))
    }

    /// Duration in milliseconds from the first to the last recorded phase, or
    /// `None` when fewer than one phase is recorded.
    pub fn total_ms(&self) -> Option<f64> {
        if self.phases.len() < 2 {
            return None;
        }
        let start = self.phases.first().unwrap().1;
        let end = self.phases.last().unwrap().1;
        Some(ns_to_ms(end.saturating_sub(start)))
    }
}

/// Measure the monotonic wall-time of a blocking closure in milliseconds.
///
/// Returns the closure's result alongside the elapsed milliseconds. Used by the
/// synchronous runners (e.g. the Docker lane) to time one sample.
pub fn measure_blocking<C: Clock, R>(clock: &C, f: impl FnOnce() -> R) -> (R, f64) {
    let start = clock.now_monotonic_ns();
    let out = f();
    let end = clock.now_monotonic_ns();
    (out, ns_to_ms(end.saturating_sub(start)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ns_to_ms_conversion() {
        assert_eq!(ns_to_ms(0), 0.0);
        assert_eq!(ns_to_ms(1_000_000), 1.0);
        assert_eq!(ns_to_ms(1_500_000), 1.5);
    }

    #[test]
    fn monotonic_sequence_records_and_computes_duration() {
        let mut r = PhaseRecorder::new();
        r.record_at("spawn", 1_000_000).unwrap();
        r.record_at("load", 16_000_000).unwrap();
        r.record_at("resume", 31_000_000).unwrap();
        assert_eq!(r.duration_ms("spawn", "resume"), Some(30.0));
        assert_eq!(r.duration_ms("spawn", "load"), Some(15.0));
        assert_eq!(r.total_ms(), Some(30.0));
    }

    #[test]
    fn backwards_timestamp_is_rejected() {
        let mut r = PhaseRecorder::new();
        r.record_at("spawn", 10_000_000).unwrap();
        let err = r.record_at("load", 5_000_000).unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(err.context.get("phase").map(String::as_str), Some("load"));
    }

    #[test]
    fn equal_timestamp_is_allowed() {
        let mut r = PhaseRecorder::new();
        r.record_at("a", 100).unwrap();
        // Equal (not less) is monotonic-non-decreasing and permitted.
        assert!(r.record_at("b", 100).is_ok());
        assert_eq!(r.duration_ms("a", "b"), Some(0.0));
    }

    #[test]
    fn duration_for_missing_phase_is_none() {
        let mut r = PhaseRecorder::new();
        r.record_at("spawn", 1).unwrap();
        assert_eq!(r.duration_ms("spawn", "nope"), None);
        assert_eq!(r.total_ms(), None); // only one phase
    }

    #[test]
    fn measure_blocking_times_a_closure() {
        use microvm_metrics::ManualClock;
        let clock = ManualClock::new(chrono::Utc::now());
        let (out, ms) = measure_blocking(&clock, || {
            clock.advance(2_000_000); // 2 ms
            42
        });
        assert_eq!(out, 42);
        assert_eq!(ms, 2.0);
    }
}
