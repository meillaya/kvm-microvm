//! KVM API-version / capability probe for the educational direct-KVM subset.
//!
//! The probe answers one question deterministically: *is this host able to run
//! the direct-KVM subset?* It requires `KVM_GET_API_VERSION == 12` (the stable
//! KVM ABI) and the `KVM_CAP_USER_MEMORY` capability.
//!
//! The validation logic is pure (`validate_api_version`,
//! `validate_capabilities`, [`ProbeError::blocked_reason`]) and is tested in the
//! default no-feature lane without `/dev/kvm`. The actual ioctl-backed probe
//! ([`open_and_probe`]) is behind the `direct-kvm` feature and is the only part
//! that opens `/dev/kvm`.
//!
//! A failed probe maps 1:1 to a structured [`BlockedReason`]: a missing or
//! incompatible `/dev/kvm` blocks the subset; it never passes and never
//! falls back to another backend.

use crate::outcome::{BlockedReason, RunOutcome};
use crate::KVM_API_VERSION;
use serde::{Deserialize, Serialize};

/// Default KVM device path.
pub const DEFAULT_KVM_DEVICE: &str = "/dev/kvm";

/// Why a probe could not establish a usable KVM host. Maps 1:1 to
/// [`BlockedReason`]: a probe failure blocks the subset, it never passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// `/dev/kvm` is missing or cannot be opened (detail carries errno).
    DeviceMissing(String),
    /// `KVM_GET_API_VERSION` returned something other than 12.
    BadApiVersion {
        /// The observed (wrong) API version.
        got: i32,
    },
    /// A required KVM capability is absent.
    MissingCapability(&'static str),
}

impl ProbeError {
    /// Maps the probe error to its structured blocked reason.
    #[must_use]
    pub fn blocked_reason(&self) -> BlockedReason {
        match self {
            ProbeError::DeviceMissing(_) => BlockedReason::KvmUnavailable,
            ProbeError::BadApiVersion { .. } => BlockedReason::BadApiVersion,
            ProbeError::MissingCapability(_) => BlockedReason::MissingCapability,
        }
    }

    /// Human-readable detail for evidence.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            ProbeError::DeviceMissing(detail) => detail.clone(),
            ProbeError::BadApiVersion { got } => {
                format!("KVM_GET_API_VERSION returned {got}, expected {KVM_API_VERSION}")
            }
            ProbeError::MissingCapability(cap) => format!("missing KVM capability: {cap}"),
        }
    }

    /// Converts the probe error into a structured blocked outcome.
    #[must_use]
    pub fn into_blocked(self) -> RunOutcome {
        RunOutcome::Blocked {
            reason: self.blocked_reason(),
            detail: self.detail(),
        }
    }
}

/// A successful probe report: the host KVM ABI facts the subset relies on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    /// The KVM API version (always 12 for a successful probe).
    pub api_version: i32,
    /// Whether `KVM_CAP_USER_MEMORY` is present (required for the memory slot).
    pub user_memory: bool,
    /// The device path that was probed.
    pub device_path: String,
}

/// Pure validation of a KVM API version against the pinned stable ABI (12).
///
/// # Errors
///
/// Returns [`ProbeError::BadApiVersion`] when `version` is not exactly
/// [`KVM_API_VERSION`] (12).
pub fn validate_api_version(version: i32) -> Result<(), ProbeError> {
    if version == KVM_API_VERSION {
        Ok(())
    } else {
        Err(ProbeError::BadApiVersion { got: version })
    }
}

/// Pure validation of required capability presence.
///
/// # Errors
///
/// Returns [`ProbeError::MissingCapability`] when `user_memory` is false.
pub fn validate_capabilities(user_memory: bool) -> Result<(), ProbeError> {
    if user_memory {
        Ok(())
    } else {
        Err(ProbeError::MissingCapability("user_memory"))
    }
}

/// Pure classifier: turn a probe result into a blocked outcome when it failed.
///
/// Returns `None` when the probe succeeded (the boot may proceed) and
/// `Some(RunOutcome::Blocked { .. })` when it failed. This is the deterministic
/// "missing `/dev/kvm` ⇒ blocked, not pass" decision, testable without KVM.
#[must_use]
pub fn probe_blocked_outcome(result: &Result<ProbeReport, ProbeError>) -> Option<RunOutcome> {
    match result {
        Ok(_) => None,
        Err(e) => Some(RunOutcome::Blocked {
            reason: e.blocked_reason(),
            detail: e.detail(),
        }),
    }
}

/// Opens `/dev/kvm` at `device` and probes the API version and capabilities.
///
/// This is the only probe path that performs I/O; it is behind the
/// `direct-kvm` feature. On success it returns the live [`kvm_ioctls::Kvm`]
/// handle together with the [`ProbeReport`], so the caller opens the device
/// exactly once.
///
/// # Errors
///
/// Returns [`ProbeError::DeviceMissing`] when the device cannot be opened,
/// [`ProbeError::BadApiVersion`] when the API version is not 12, or
/// [`ProbeError::MissingCapability`] when `KVM_CAP_USER_MEMORY` is absent.
#[cfg(feature = "direct-kvm")]
pub fn open_and_probe(device: &str) -> Result<(kvm_ioctls::Kvm, ProbeReport), ProbeError> {
    use kvm_ioctls::Cap;
    use std::ffi::CString;

    let path = CString::new(device)
        .map_err(|_| ProbeError::DeviceMissing(format!("invalid device path: {device:?}")))?;
    let kvm = kvm_ioctls::Kvm::new_with_path(path)
        .map_err(|e| ProbeError::DeviceMissing(format!("open {device}: errno {}", e.errno())))?;
    let api_version = kvm.get_api_version();
    validate_api_version(api_version)?;
    let user_memory = kvm.check_extension(Cap::UserMemory);
    validate_capabilities(user_memory)?;
    Ok((
        kvm,
        ProbeReport {
            api_version,
            user_memory,
            device_path: device.to_string(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_version_12_is_accepted() {
        assert!(validate_api_version(12).is_ok());
    }

    #[test]
    fn api_version_other_than_12_is_rejected() {
        for bad in [0, 11, 13, -1, i32::MAX] {
            let err = validate_api_version(bad).unwrap_err();
            assert!(matches!(err, ProbeError::BadApiVersion { got } if got == bad));
            assert_eq!(err.blocked_reason(), BlockedReason::BadApiVersion);
        }
    }

    #[test]
    fn user_memory_capability_is_required() {
        assert!(validate_capabilities(true).is_ok());
        let err = validate_capabilities(false).unwrap_err();
        assert!(matches!(err, ProbeError::MissingCapability("user_memory")));
        assert_eq!(err.blocked_reason(), BlockedReason::MissingCapability);
    }

    #[test]
    fn device_missing_maps_to_kvm_unavailable() {
        let err = ProbeError::DeviceMissing("open /dev/kvm: errno 2".to_string());
        assert_eq!(err.blocked_reason(), BlockedReason::KvmUnavailable);
        assert!(err.detail().contains("errno 2"));
    }

    #[test]
    fn failed_probe_is_blocked_not_pass() {
        let result: Result<ProbeReport, ProbeError> =
            Err(ProbeError::DeviceMissing("errno 2".to_string()));
        let outcome = probe_blocked_outcome(&result).expect("failed probe must block");
        assert!(outcome.is_blocked());
        assert!(!outcome.is_completed());
    }

    #[test]
    fn successful_probe_is_not_blocked() {
        let result: Result<ProbeReport, ProbeError> = Ok(ProbeReport {
            api_version: 12,
            user_memory: true,
            device_path: DEFAULT_KVM_DEVICE.to_string(),
        });
        assert!(probe_blocked_outcome(&result).is_none());
    }

    #[test]
    fn probe_report_serializes() {
        let report = ProbeReport {
            api_version: 12,
            user_memory: true,
            device_path: DEFAULT_KVM_DEVICE.to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"api_version\":12"));
        assert!(json.contains("\"user_memory\":true"));
    }
}
