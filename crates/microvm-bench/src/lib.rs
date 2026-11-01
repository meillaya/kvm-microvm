//! Reproducible snapshot/boot benchmark harness and Docker comparison
//! (plan todo 27).
//!
//! This crate publishes distributions, never a verdict. For each benchmark
//! lane (Firecracker snapshot/restore and Docker start) it records p50/p95/p99
//! under cold and warm page-cache conditions, with full host metadata, the
//! pinned workload/artifact hashes, and runtime versions. The output conforms to
//! `schemas/evidence-benchmark.v1.json` ([`result::BENCHMARK_SCHEMA_ID`]).
//!
//! # Hard rules encoded by this crate
//! - No pass/fail gate (requirement 10). `target_ms` is metadata; there is no
//!   `pass` field anywhere in the output and no method that computes one. The
//!   `<200 ms` figure is a reference target only. Firecracker publishes no
//!   universal restore-latency SLA.
//! - Identical content across runtimes (requirements 1, 7, 9). A single
//!   [`config::Workload`] pins one `payload_sha256` shared by the Docker and VM
//!   lanes; comparing different image contents is explicitly not proof of
//!   superiority.
//! - Blocked lanes carry evidence, not fabricated samples (requirement 11).
//!   An unavailable Docker/KVM/firecracker lane records a stable
//!   [`outcome::BlockedReason`], zero samples, and null percentiles; the binary
//!   exits `77` for a blocked privileged lane.
//! - Sample failures are recorded (requirement 6), excluded from statistics,
//!   and never zero-filled.
//! - Monotonic timing (requirement 3): every sample is timed with a
//!   host-monotonic clock via [`phase`].
//!
//! # Determinism
//! The statistical core ([`percentiles`], [`result`], [`marker`], [`phase`],
//! [`outcome`], [`config`]) is pure and fully tested without `/dev/kvm` or a
//! Docker daemon. The I/O shell ([`host`]) and real lanes
//! ([`runner::firecracker`], [`runner::docker`]) degrade to blocked-with-evidence
//! when prerequisites are absent, so `cargo test -p microvm-bench` is
//! deterministic on any host.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod host;
pub mod marker;
pub mod outcome;
pub mod percentiles;
pub mod phase;
pub mod result;
pub mod runner;

pub use config::{
    BenchmarkConfig, Conditions, PageCachePolicy, RuntimeVersions, Workload, MIN_SAMPLES,
};
pub use host::HostProbe;
pub use marker::BenchMarker;
pub use outcome::{BenchExitCode, BlockedReason, LaneOutcome};
pub use percentiles::{Distribution, Percentiles};
pub use phase::{measure_blocking, ns_to_ms, PhaseRecorder};
pub use result::{
    BenchmarkItem, BenchmarkResult, HostMetadata, Unit, BENCHMARK_CLASS,
    BENCHMARK_EVIDENCE_VERSION, BENCHMARK_SCHEMA_ID,
};
pub use runner::{LaneRunner, SampleCondition, ScriptedLane};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_surface_is_reexported() {
        // Compile-time smoke test that the documented surface is exported.
        let _ = BENCHMARK_SCHEMA_ID;
        let _ = BENCHMARK_CLASS;
        let _ = BENCHMARK_EVIDENCE_VERSION;
        let _ = MIN_SAMPLES;
        let _ = Unit::Ms.as_str();
        let _ = BlockedReason::all();
        let _ = BenchExitCode::Blocked.code();
        let _: fn(&[f64]) -> Option<Percentiles> = Percentiles::compute;
    }
}
