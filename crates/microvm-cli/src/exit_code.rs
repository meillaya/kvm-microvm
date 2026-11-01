//! Stable process exit codes for the `microvm` CLI.
//!
//! Every command maps its outcome to one of these codes so scripts and
//! operators can branch on `$?` without parsing stdout/stderr text.
//! The numeric values are a stable contract and must never change.
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Success |
//! | 1 | General error (transport, internal, conflict, …) |
//! | 2 | Usage error (bad flags, malformed arguments) |
//! | 3 | Resource not found (VM, snapshot, artifact) |
//! | 4 | Local artifact required (remote/tag-only reference rejected) |
//! | 5 | Permission denied (wrong socket owner, unauthorized) |

use microvm_errors::ErrorCode;
use std::process;

/// Stable process exit codes for the `microvm` CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The command completed successfully.
    Success = 0,
    /// A general error occurred (transport failure, internal error,
    /// invalid transition, quota exceeded, digest mismatch, …).
    GeneralError = 1,
    /// The command-line arguments were invalid or incomplete.
    UsageError = 2,
    /// The referenced resource (VM, snapshot, artifact) was not found.
    NotFound = 3,
    /// A local artifact is required but a remote or tag-only reference
    /// was supplied.
    LocalArtifactRequired = 4,
    /// The caller lacks permission (wrong socket owner, unauthorized
    /// principal).
    PermissionDenied = 5,
}

impl ExitCode {
    /// The stable numeric exit code.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Convert to a [`std::process::ExitCode`].
    pub fn to_process_exit_code(self) -> process::ExitCode {
        // process::ExitCode::from takes u8; our codes are 0-5.
        process::ExitCode::from(self.code() as u8)
    }

    /// Map a platform [`ErrorCode`] to the corresponding CLI exit code.
    ///
    /// The mapping is deterministic and covers every [`ErrorCode`] variant:
    ///
    /// | ErrorCode | ExitCode |
    /// |-----------|----------|
    /// | `invalid_id` | UsageError (2) |
    /// | `invalid_resource_spec` | UsageError (2) |
    /// | `invalid_transition` | GeneralError (1) |
    /// | `permission_denied` | PermissionDenied (5) |
    /// | `quota_exceeded` | GeneralError (1) |
    /// | `artifact_not_found` | NotFound (3) |
    /// | `digest_mismatch` | GeneralError (1) |
    /// | `path_escape` | GeneralError (1) |
    /// | `binary_provenance_error` | GeneralError (1) |
    /// | `local_artifact_required` | LocalArtifactRequired (4) |
    /// | `cgroup_unavailable` | GeneralError (1) |
    /// | `network_setup_error` | GeneralError (1) |
    /// | `process_spawn_error` | GeneralError (1) |
    /// | `snapshot_incompatible` | GeneralError (1) |
    /// | `transport_error` | GeneralError (1) |
    /// | `internal_error` | GeneralError (1) |
    pub fn from_error_code(code: ErrorCode) -> Self {
        match code {
            ErrorCode::InvalidId | ErrorCode::InvalidResourceSpec => Self::UsageError,
            ErrorCode::PermissionDenied => Self::PermissionDenied,
            ErrorCode::ArtifactNotFound => Self::NotFound,
            ErrorCode::LocalArtifactRequired => Self::LocalArtifactRequired,
            // Everything else is a general error.
            ErrorCode::InvalidTransition
            | ErrorCode::QuotaExceeded
            | ErrorCode::DigestMismatch
            | ErrorCode::PathEscape
            | ErrorCode::BinaryProvenanceError
            | ErrorCode::CgroupUnavailable
            | ErrorCode::NetworkSetupError
            | ErrorCode::ProcessSpawnError
            | ErrorCode::SnapshotIncompatible
            | ErrorCode::TransportError
            | ErrorCode::InternalError => Self::GeneralError,
        }
    }
}

impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Success => "success",
            Self::GeneralError => "general_error",
            Self::UsageError => "usage_error",
            Self::NotFound => "not_found",
            Self::LocalArtifactRequired => "local_artifact_required",
            Self::PermissionDenied => "permission_denied",
        };
        write!(f, "{} ({})", label, self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_numeric_values_are_stable() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::GeneralError.code(), 1);
        assert_eq!(ExitCode::UsageError.code(), 2);
        assert_eq!(ExitCode::NotFound.code(), 3);
        assert_eq!(ExitCode::LocalArtifactRequired.code(), 4);
        assert_eq!(ExitCode::PermissionDenied.code(), 5);
    }

    #[test]
    fn all_error_codes_map_to_an_exit_code() {
        for code in ErrorCode::all() {
            let exit = ExitCode::from_error_code(*code);
            // Must be in the valid range 0-5.
            assert!(
                (0..=5).contains(&exit.code()),
                "ErrorCode {:?} mapped to out-of-range exit code {}",
                code,
                exit.code()
            );
        }
    }

    #[test]
    fn specific_error_code_mappings() {
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::InvalidId),
            ExitCode::UsageError
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::InvalidResourceSpec),
            ExitCode::UsageError
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::PermissionDenied),
            ExitCode::PermissionDenied
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::ArtifactNotFound),
            ExitCode::NotFound
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::LocalArtifactRequired),
            ExitCode::LocalArtifactRequired
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::TransportError),
            ExitCode::GeneralError
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::InternalError),
            ExitCode::GeneralError
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::InvalidTransition),
            ExitCode::GeneralError
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::QuotaExceeded),
            ExitCode::GeneralError
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::DigestMismatch),
            ExitCode::GeneralError
        );
    }

    #[test]
    fn exit_code_display_includes_label_and_number() {
        assert_eq!(ExitCode::Success.to_string(), "success (0)");
        assert_eq!(ExitCode::GeneralError.to_string(), "general_error (1)");
        assert_eq!(ExitCode::UsageError.to_string(), "usage_error (2)");
        assert_eq!(ExitCode::NotFound.to_string(), "not_found (3)");
        assert_eq!(
            ExitCode::LocalArtifactRequired.to_string(),
            "local_artifact_required (4)"
        );
        assert_eq!(
            ExitCode::PermissionDenied.to_string(),
            "permission_denied (5)"
        );
    }

    #[test]
    fn process_exit_code_roundtrip() {
        // Verify the process::ExitCode conversion does not panic.
        for code in [
            ExitCode::Success,
            ExitCode::GeneralError,
            ExitCode::UsageError,
            ExitCode::NotFound,
            ExitCode::LocalArtifactRequired,
            ExitCode::PermissionDenied,
        ] {
            let _ = code.to_process_exit_code();
        }
    }
}
