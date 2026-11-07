//! Stable machine-readable error codes for the microvm
//! platform.
//!
//! Every [`ErrorCode`] variant maps to a stable `snake_case` string that will
//! never change across releases, making it safe to use in API responses,
//! logs, and client-side matching.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// ErrorCode
// ---------------------------------------------------------------------------

/// Stable, machine-readable error codes.
///
/// Each variant serializes to a fixed `snake_case` string. The string
/// representation is part of the public API contract and must not change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// An identifier failed validation.
    InvalidId,
    /// A resource specification failed validation.
    InvalidResourceSpec,
    /// A lifecycle state transition is not permitted.
    InvalidTransition,
    /// The principal lacks permission for the requested operation.
    PermissionDenied,
    /// A tenant quota has been exceeded.
    QuotaExceeded,
    /// The referenced artifact does not exist.
    ArtifactNotFound,
    /// A digest verification failed.
    DigestMismatch,
    /// A path attempted to escape its permitted root.
    PathEscape,
    /// A binary failed provenance verification.
    BinaryProvenanceError,
    /// A non-local artifact source was supplied where only a local
    /// `file://` URI or local digest/path source is permitted.
    LocalArtifactRequired,
    /// The required cgroup v2 hierarchy is unavailable.
    CgroupUnavailable,
    /// Network namespace or TAP setup failed.
    NetworkSetupError,
    /// Failed to spawn a child process.
    ProcessSpawnError,
    /// A snapshot is incompatible with the current runtime.
    SnapshotIncompatible,
    /// A transport-level error occurred.
    TransportError,
    /// An unexpected internal error.
    InternalError,
}

impl ErrorCode {
    /// Return the stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidId => "invalid_id",
            Self::InvalidResourceSpec => "invalid_resource_spec",
            Self::InvalidTransition => "invalid_transition",
            Self::PermissionDenied => "permission_denied",
            Self::QuotaExceeded => "quota_exceeded",
            Self::ArtifactNotFound => "artifact_not_found",
            Self::DigestMismatch => "digest_mismatch",
            Self::PathEscape => "path_escape",
            Self::BinaryProvenanceError => "binary_provenance_error",
            Self::LocalArtifactRequired => "local_artifact_required",
            Self::CgroupUnavailable => "cgroup_unavailable",
            Self::NetworkSetupError => "network_setup_error",
            Self::ProcessSpawnError => "process_spawn_error",
            Self::SnapshotIncompatible => "snapshot_incompatible",
            Self::TransportError => "transport_error",
            Self::InternalError => "internal_error",
        }
    }

    /// Return all error code variants.
    pub fn all() -> &'static [ErrorCode] {
        &[
            Self::InvalidId,
            Self::InvalidResourceSpec,
            Self::InvalidTransition,
            Self::PermissionDenied,
            Self::QuotaExceeded,
            Self::ArtifactNotFound,
            Self::DigestMismatch,
            Self::PathEscape,
            Self::BinaryProvenanceError,
            Self::LocalArtifactRequired,
            Self::CgroupUnavailable,
            Self::NetworkSetupError,
            Self::ProcessSpawnError,
            Self::SnapshotIncompatible,
            Self::TransportError,
            Self::InternalError,
        ]
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MicrovmError
// ---------------------------------------------------------------------------

/// A structured error carrying a stable code, human-readable message, and
/// optional key-value context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrovmError {
    /// Stable machine-readable error code.
    pub code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured context (sorted by key for deterministic output).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
}

impl MicrovmError {
    /// Create a new error with a code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    /// Builder-style: attach a context key-value pair.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for MicrovmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)?;
        if !self.context.is_empty() {
            write!(f, " (")?;
            for (i, (k, v)) in self.context.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}={}", k, v)?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

impl std::error::Error for MicrovmError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_duplicate_error_code_strings() {
        let all = ErrorCode::all();
        let mut seen = std::collections::HashSet::new();
        for code in all {
            let s = code.as_str();
            assert!(
                seen.insert(s),
                "duplicate error code string: {} (variant {:?})",
                s,
                code
            );
        }
        // Also verify we have the expected count.
        assert_eq!(all.len(), 16, "expected 16 error codes");
    }

    #[test]
    fn error_code_display_matches_as_str() {
        for code in ErrorCode::all() {
            assert_eq!(code.to_string(), code.as_str());
        }
    }

    #[test]
    fn error_code_serde_roundtrip() {
        for code in ErrorCode::all() {
            let json = serde_json::to_string(code).unwrap();
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(*code, back);
        }
    }

    #[test]
    fn error_code_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::InvalidId).unwrap(),
            r#""invalid_id""#
        );
        assert_eq!(
            serde_json::to_string(&ErrorCode::BinaryProvenanceError).unwrap(),
            r#""binary_provenance_error""#
        );
    }

    #[test]
    fn microvm_error_display_without_context() {
        let err = MicrovmError::new(ErrorCode::PermissionDenied, "cross-tenant access denied");
        assert_eq!(
            err.to_string(),
            "[permission_denied] cross-tenant access denied"
        );
    }

    #[test]
    fn microvm_error_display_with_context() {
        let err = MicrovmError::new(ErrorCode::QuotaExceeded, "vcpu limit reached")
            .with_context("tenant", "t-001")
            .with_context("limit", "16");
        assert_eq!(
            err.to_string(),
            "[quota_exceeded] vcpu limit reached (limit=16, tenant=t-001)"
        );
    }

    #[test]
    fn microvm_error_serde_roundtrip() {
        let err = MicrovmError::new(ErrorCode::DigestMismatch, "sha256 mismatch")
            .with_context("expected", "abc123")
            .with_context("actual", "def456");
        let json = serde_json::to_string(&err).unwrap();
        let back: MicrovmError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn microvm_error_serde_roundtrip_no_context() {
        let err = MicrovmError::new(ErrorCode::InternalError, "unexpected state");
        let json = serde_json::to_string(&err).unwrap();
        // context should be absent when empty.
        assert!(!json.contains("context"));
        let back: MicrovmError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn microvm_error_implements_std_error() {
        let err = MicrovmError::new(ErrorCode::TransportError, "socket closed");
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.to_string().contains("transport_error"));
    }
}
