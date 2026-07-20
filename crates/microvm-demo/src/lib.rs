//! Warm HTTP-function microVM demo with cold/warm evidence (plan todo 28).
//!
//! This crate demonstrates the "Lambda clone" warm-function model: **one**
//! minimal static Rust HTTP function packaged in a pinned local rootfs is
//! snapshotted after service readiness, then restored through the orchestrator
//! into a warm pool. The demo reports the **cold first-call** latency versus the
//! **warm pool/request** latency distribution.
//!
//! # Scope (what this crate deliberately does NOT do)
//! - No autoscaling: the warm pool is filled to a fixed size and reused.
//! - No multi-function routing: exactly one [`function::HttpFunction`].
//! - No persistent external data and no second language runtime.
//! - No pass/fail gate: the report carries numbers and counts, never a verdict.
//!   The `<200 ms` figure from the wider plan is a reference target only.
//!
//! # Measurement reuse (requirement 6)
//! Warm statistics are computed with the microvm-bench harness
//! ([`microvm_bench::Distribution`] / [`microvm_bench::Percentiles`]); phase
//! timing reuses [`microvm_bench::ns_to_ms`]; host metadata, blocked-reason
//! tokens, and the pinned [`microvm_bench::Workload`] all come from the harness.
//!
//! # Determinism
//! The statistical and protocol core ([`function`], [`restore`], [`pool`],
//! [`measure`], [`report`], [`runner`]) is pure and fully tested without
//! `/dev/kvm` via [`restore::ScriptedRestorer`]. The in-process
//! [`local::LocalFunctionRestorer`] lets the binary produce a concrete report on
//! any host. `cargo test -p microvm-demo` is deterministic everywhere.

#![forbid(unsafe_code)]

pub mod function;
pub mod local;
pub mod measure;
pub mod pool;
pub mod report;
pub mod restore;
pub mod runner;

pub use function::{HttpFunction, HttpRequest, HttpResponse, Method, Rootfs};
pub use local::LocalFunctionRestorer;
pub use measure::ColdWarmMeasurement;
pub use pool::FunctionPool;
pub use report::{
    CleanupEvidence, ColdPhaseDurations, DemoReport, DEMO_CLASS, DEMO_EVIDENCE_VERSION,
    DEMO_SCHEMA_ID,
};
pub use restore::{
    ColdStart, DemoPhase, Invocation, PhaseLog, RestoredVm, ScriptedRestore, ScriptedRestorer,
    SnapshotArtifact, VmRestorer,
};
pub use runner::{DemoConfig, DemoOutcome, DemoRunner};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_surface_is_reexported() {
        // Compile-time smoke test that the documented surface is exported.
        let _ = DEMO_SCHEMA_ID;
        let _ = DEMO_CLASS;
        let _ = DEMO_EVIDENCE_VERSION;
        let _ = DemoConfig::MIN_SAMPLES;
        let _ = DemoPhase::all();
        let _: fn(&[f64]) -> Option<microvm_bench::Percentiles> =
            microvm_bench::Percentiles::compute;
    }
}
