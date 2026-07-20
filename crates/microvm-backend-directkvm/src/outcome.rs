//! Terminal outcome types for one educational direct-KVM subset boot.
//!
//! The outcome model encodes the central safety contract of the subset:
//!
//! - A host without a usable KVM produces [`RunOutcome::Blocked`] with a
//!   structured [`BlockedReason`] — **never** a pass.
//! - There is **no fallback** to Firecracker, QEMU, or TCG: a blocked or failed
//!   subset boot never becomes a [`RunOutcome::Completed`] through another
//!   backend. TCG (software emulation) is never reported as KVM evidence.
//! - A boot that reaches KVM but faults is [`RunOutcome::Failed`] with the
//!   reason and any partial serial output recorded.
//!
//! These types are pure and always compiled; the privileged runner constructs
//! them from real KVM events.

use crate::serial::SerialOutput;
use serde::{Deserialize, Serialize};

/// Stable, snake_case reasons a privileged direct-KVM boot cannot run on this
/// host. Each maps to a host-capability prerequisite, never to a guest bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReason {
    /// `/dev/kvm` is missing or cannot be opened.
    KvmUnavailable,
    /// `KVM_GET_API_VERSION` did not return the stable ABI version 12.
    BadApiVersion,
    /// A required KVM capability (e.g. `KVM_CAP_USER_MEMORY`) is absent.
    MissingCapability,
}

impl BlockedReason {
    /// The stable token written to evidence `blocked_reason` fields.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockedReason::KvmUnavailable => "kvm_unavailable",
            BlockedReason::BadApiVersion => "bad_api_version",
            BlockedReason::MissingCapability => "missing_capability",
        }
    }
}

/// Why a completed educational boot stopped cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The guest executed `HLT`.
    Hlt,
    /// The host requested stop between `KVM_RUN` iterations.
    HostStop,
}

/// Why a boot failed after KVM was available and the VM was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// `KVM_EXIT_FAIL_ENTRY`: `hardware_entry_failure_reason` recorded.
    EntryFailure,
    /// `KVM_EXIT_INTERNAL_ERROR`: `internal_error_suberror` recorded.
    InternalError,
    /// A VM exit reason outside the pinned allowed set.
    UnexpectedExit,
    /// A KVM ioctl (VM/vCPU setup or `KVM_RUN`) returned an error.
    KvmIoctl,
    /// The vCPU loop exceeded its bounded iteration guard.
    RunawayLoop,
}

/// Terminal outcome of one educational direct-KVM subset boot.
///
/// This enum deliberately has **no** fallback variant: the subset either
/// completes on real KVM, blocks on a missing prerequisite, or fails. It can
/// never report success via Firecracker/QEMU/TCG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RunOutcome {
    /// The guest ran on real KVM, the serial marker was observed, and the vCPU
    /// stopped cleanly.
    Completed {
        /// Captured serial output (contains the guest marker byte).
        serial: SerialOutput,
        /// Why the vCPU loop stopped.
        stop: StopReason,
    },
    /// The host cannot run KVM; structured reason, no fallback, not a pass.
    Blocked {
        /// Structured blocked reason (stable token).
        reason: BlockedReason,
        /// Human-readable detail (errno, observed version, capability name).
        detail: String,
    },
    /// KVM was available but the boot failed; reason and partial serial kept.
    Failed {
        /// Structured failure reason.
        reason: FailureReason,
        /// Human-readable detail (errno, exit reason, suberror).
        detail: String,
        /// Serial output captured before the failure (may be empty).
        serial: SerialOutput,
    },
}

impl RunOutcome {
    /// The subset has no fallback backend; a blocked/failed outcome is never
    /// laundered into a pass through Firecracker/QEMU/TCG.
    pub const HAS_FALLBACK: bool = false;

    /// True iff the boot completed on real KVM.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, RunOutcome::Completed { .. })
    }

    /// True iff the boot was blocked by a missing host prerequisite.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, RunOutcome::Blocked { .. })
    }

    /// True iff the boot reached KVM but failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, RunOutcome::Failed { .. })
    }

    /// The captured serial output, if any (empty for blocked outcomes).
    #[must_use]
    pub fn serial(&self) -> Option<&SerialOutput> {
        match self {
            RunOutcome::Completed { serial, .. } | RunOutcome::Failed { serial, .. } => {
                Some(serial)
            }
            RunOutcome::Blocked { .. } => None,
        }
    }
}

// Compile-time guarantee: the educational subset has no fallback backend. A
// blocked or failed boot can never become a pass through Firecracker/QEMU/TCG.
const _: () = assert!(!RunOutcome::HAS_FALLBACK);

#[cfg(test)]
mod tests {
    use super::*;

    fn completed() -> RunOutcome {
        let mut serial = SerialOutput::new();
        serial.record(crate::SERIAL_PORT, 0x4B);
        RunOutcome::Completed {
            serial,
            stop: StopReason::Hlt,
        }
    }

    #[test]
    fn blocked_is_not_completed_and_has_no_fallback() {
        let outcome = RunOutcome::Blocked {
            reason: BlockedReason::KvmUnavailable,
            detail: "open /dev/kvm: errno 2".to_string(),
        };
        assert!(outcome.is_blocked());
        assert!(!outcome.is_completed());
        assert!(!outcome.is_failed());
        assert!(outcome.serial().is_none());
    }

    #[test]
    fn completed_carries_serial_and_stop() {
        let outcome = completed();
        assert!(outcome.is_completed());
        let serial = outcome.serial().unwrap();
        assert!(serial.contains_marker());
    }

    #[test]
    fn blocked_reason_tokens_are_stable() {
        assert_eq!(BlockedReason::KvmUnavailable.as_str(), "kvm_unavailable");
        assert_eq!(BlockedReason::BadApiVersion.as_str(), "bad_api_version");
        assert_eq!(
            BlockedReason::MissingCapability.as_str(),
            "missing_capability"
        );
    }

    #[test]
    fn outcome_serializes_with_a_tag_and_stable_reason() {
        let outcome = RunOutcome::Blocked {
            reason: BlockedReason::KvmUnavailable,
            detail: "errno 2".to_string(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("\"outcome\":\"blocked\""));
        assert!(json.contains("\"reason\":\"kvm_unavailable\""));
    }

    #[test]
    fn outcome_round_trips() {
        let outcome = completed();
        let json = serde_json::to_string(&outcome).unwrap();
        let back: RunOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}
