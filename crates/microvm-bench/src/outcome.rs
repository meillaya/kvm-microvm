//! Lane execution outcomes and process exit codes.
//!
//! # This is NOT a performance pass/fail (requirement 10)
//! [`LaneOutcome`] describes **whether a benchmark lane could run**, not whether
//! a latency target was met. The harness deliberately has no notion of a
//! benchmark "passing" or "failing" against `<200 ms`: `target_ms` is metadata
//! only, and the serialized benchmark JSON carries **no `pass` field at any
//! level** (enforced by `schemas/evidence-benchmark.v1.json`). A reviewer
//! compares the recorded p50/p95/p99 distribution against the declared
//! `target_ms`; the harness never reduces that comparison to a boolean.
//!
//! Mapping to the serialized form:
//! - [`LaneOutcome::Completed`] -> `blocked_reason: null`, real samples.
//! - [`LaneOutcome::Blocked`]   -> `blocked_reason: <token>`, zero samples,
//!   null percentiles (never fabricated).
//! - [`LaneOutcome::Failed`]    -> a runtime error surfaced through the error
//!   contract; partial samples are discarded rather than reported as measured.

use serde::{Deserialize, Serialize};

/// Stable tokens explaining why a lane could not produce real samples.
///
/// Recorded verbatim in the benchmark item's `blocked_reason` field so
/// downstream tooling can branch without parsing prose. The token vocabulary is
/// a stable contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReason {
    /// `/dev/kvm` is absent or inaccessible.
    KvmUnavailable,
    /// The Docker daemon is unreachable or the `docker` binary is missing.
    DockerMissing,
    /// The `firecracker` (or `jailer`) binary is not installed.
    FirecrackerMissing,
    /// Dropping the page cache (`drop_caches`) is not permitted, so the cold
    /// condition cannot be measured honestly.
    PageCacheDropUnsupported,
    /// The required cgroup-v2 hierarchy is unavailable.
    CgroupUnavailable,
    /// Nested virtualization is required but unavailable.
    NestedUnavailable,
    /// A pinned workload artifact (kernel/rootfs/snapshot/image) is missing.
    ArtifactMissing,
}

impl BlockedReason {
    /// Stable `snake_case` token written to `blocked_reason`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KvmUnavailable => "kvm_unavailable",
            Self::DockerMissing => "docker_missing",
            Self::FirecrackerMissing => "firecracker_missing",
            Self::PageCacheDropUnsupported => "page_cache_drop_unsupported",
            Self::CgroupUnavailable => "cgroup_unavailable",
            Self::NestedUnavailable => "nested_unavailable",
            Self::ArtifactMissing => "artifact_missing",
        }
    }

    /// All tokens, for exhaustive matching and tests.
    pub fn all() -> &'static [BlockedReason] {
        &[
            Self::KvmUnavailable,
            Self::DockerMissing,
            Self::FirecrackerMissing,
            Self::PageCacheDropUnsupported,
            Self::CgroupUnavailable,
            Self::NestedUnavailable,
            Self::ArtifactMissing,
        ]
    }
}

impl std::fmt::Display for BlockedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a benchmark lane ran, was blocked, or failed.
///
/// See the module docs: this is an *execution* outcome, never a performance
/// verdict, and it is never serialized as a `pass` boolean.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneOutcome {
    /// The lane ran and produced valid samples.
    Completed,
    /// The lane could not run because a prerequisite is unavailable. Carries the
    /// stable [`BlockedReason`] token plus human-readable evidence.
    Blocked {
        /// Stable token recorded in `blocked_reason`.
        reason: BlockedReason,
        /// Human-readable evidence (paths probed, daemon error, …).
        detail: String,
    },
    /// The lane attempted to run but errored; no samples are reported.
    Failed {
        /// Human-readable failure detail.
        detail: String,
    },
}

impl LaneOutcome {
    /// True when the lane was blocked (no samples, recorded reason).
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// True when the lane completed with valid samples.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// The stable blocked-reason token, if blocked.
    pub fn blocked_reason(&self) -> Option<BlockedReason> {
        match self {
            Self::Blocked { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// Build a blocked outcome with evidence detail.
    pub fn blocked(reason: BlockedReason, detail: impl Into<String>) -> Self {
        Self::Blocked {
            reason,
            detail: detail.into(),
        }
    }

    /// Build a failed outcome with detail.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::Failed {
            detail: detail.into(),
        }
    }
}

/// Stable process exit codes for the `microvm-bench` binary.
///
/// The numeric values are a stable contract. `77` follows the automake
/// "skipped test" convention: a blocked privileged lane is a *skip*, not a
/// failure, so CI can distinguish "could not run" from "ran and errored".
///
/// | Code | Meaning |
/// |------|---------|
/// | 0 | Success — every requested lane ran and produced samples |
/// | 1 | General error — a lane attempted and failed, or I/O error |
/// | 2 | Usage error — bad flags or malformed arguments |
/// | 77 | Blocked — a privileged lane could not run (missing KVM/Docker/…) |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BenchExitCode {
    /// Every requested lane ran and produced samples.
    Success = 0,
    /// A lane attempted and failed, or a general I/O error occurred.
    GeneralError = 1,
    /// The command-line arguments were invalid.
    UsageError = 2,
    /// A privileged lane was blocked (missing KVM/Docker/firecracker/…).
    Blocked = 77,
}

impl BenchExitCode {
    /// The stable numeric exit code.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Convert to a [`std::process::ExitCode`].
    pub fn to_process_exit_code(self) -> std::process::ExitCode {
        // process::ExitCode::from takes u8; 77 fits.
        std::process::ExitCode::from(self.code() as u8)
    }
}

impl std::fmt::Display for BenchExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Success => "success",
            Self::GeneralError => "general_error",
            Self::UsageError => "usage_error",
            Self::Blocked => "blocked",
        };
        write!(f, "{} ({})", label, self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_reason_tokens_are_stable() {
        assert_eq!(BlockedReason::KvmUnavailable.as_str(), "kvm_unavailable");
        assert_eq!(BlockedReason::DockerMissing.as_str(), "docker_missing");
        assert_eq!(
            BlockedReason::FirecrackerMissing.as_str(),
            "firecracker_missing"
        );
        assert_eq!(
            BlockedReason::PageCacheDropUnsupported.as_str(),
            "page_cache_drop_unsupported"
        );
        assert_eq!(
            BlockedReason::CgroupUnavailable.as_str(),
            "cgroup_unavailable"
        );
        assert_eq!(
            BlockedReason::NestedUnavailable.as_str(),
            "nested_unavailable"
        );
        assert_eq!(BlockedReason::ArtifactMissing.as_str(), "artifact_missing");
    }

    #[test]
    fn all_blocked_reasons_have_unique_tokens() {
        let all = BlockedReason::all();
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.as_str(), b.as_str(), "tokens must be unique");
            }
        }
    }

    #[test]
    fn lane_outcome_classification() {
        let done = LaneOutcome::Completed;
        assert!(done.is_completed());
        assert!(!done.is_blocked());
        assert_eq!(done.blocked_reason(), None);

        let blocked = LaneOutcome::blocked(BlockedReason::DockerMissing, "no socket");
        assert!(blocked.is_blocked());
        assert!(!blocked.is_completed());
        assert_eq!(blocked.blocked_reason(), Some(BlockedReason::DockerMissing));

        let failed = LaneOutcome::failed("boom");
        assert!(!failed.is_blocked());
        assert!(!failed.is_completed());
    }

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(BenchExitCode::Success.code(), 0);
        assert_eq!(BenchExitCode::GeneralError.code(), 1);
        assert_eq!(BenchExitCode::UsageError.code(), 2);
        assert_eq!(BenchExitCode::Blocked.code(), 77);
    }

    #[test]
    fn exit_code_display() {
        assert_eq!(BenchExitCode::Blocked.to_string(), "blocked (77)");
        assert_eq!(BenchExitCode::Success.to_string(), "success (0)");
    }

    #[test]
    fn process_exit_code_conversion_does_not_panic() {
        for code in [
            BenchExitCode::Success,
            BenchExitCode::GeneralError,
            BenchExitCode::UsageError,
            BenchExitCode::Blocked,
        ] {
            let _ = code.to_process_exit_code();
        }
    }
}
