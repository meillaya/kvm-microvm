//! Stable error mapping from [`MicrovmError`] codes to gRPC status codes.
//!
//! Every [`ErrorCode`] variant maps to a deterministic [`tonic::Code`], chosen
//! to correspond with the REST transport's HTTP status mapping so the *same*
//! service error surfaces as the *same* semantic failure on both transports.
//! The structured error body ([`ErrorBody`]) is carried verbatim in the gRPC
//! status `details` as JSON, byte-identical to the REST response body, so
//! clients can recover the stable `error_code`, `message`, and `context`
//! regardless of transport.
//!
//! # ErrorCode → gRPC code (with REST correspondence)
//!
//! | ErrorCode | REST HTTP | gRPC code |
//! |-----------|-----------|-----------|
//! | `invalid_id` | 400 | `InvalidArgument` |
//! | `invalid_resource_spec` | 400 | `InvalidArgument` |
//! | `invalid_transition` | 409 | `FailedPrecondition` |
//! | `permission_denied` | 403 | `PermissionDenied` |
//! | `quota_exceeded` | 409 | `ResourceExhausted` |
//! | `artifact_not_found` | 404 | `NotFound` |
//! | `digest_mismatch` | 400 | `InvalidArgument` |
//! | `path_escape` | 400 | `InvalidArgument` |
//! | `binary_provenance_error` | 400 | `InvalidArgument` |
//! | `cgroup_unavailable` | 500 | `Internal` |
//! | `network_setup_error` | 500 | `Internal` |
//! | `process_spawn_error` | 500 | `Internal` |
//! | `snapshot_incompatible` | 409 | `FailedPrecondition` |
//! | `transport_error` | 500 | `Internal` |
//! | `internal_error` | 500 | `Internal` |

use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tonic::{Code, Status};

/// Structured error body carried in gRPC status `details`.
///
/// Field-for-field identical to the REST `ErrorResponse` schema so the JSON
/// encoding is byte-identical across transports for the same error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable machine-readable error code (snake_case).
    pub error_code: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured key-value context.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
}

impl ErrorBody {
    /// Build an error body from a [`MicrovmError`].
    pub fn from_microvm_error(err: &MicrovmError) -> Self {
        Self {
            error_code: err.code.as_str().to_string(),
            message: err.message.clone(),
            context: err.context.clone(),
        }
    }

    /// Build an error body for authentication failure.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::PermissionDenied.as_str().to_string(),
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    /// Build an error body for an invalid identifier.
    pub fn invalid_id(message: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::InvalidId.as_str().to_string(),
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    /// Build an error body for an invalid resource specification.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::InvalidResourceSpec.as_str().to_string(),
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ErrorBody serialization cannot fail")
    }
}

/// Map an [`ErrorCode`] to its deterministic gRPC [`Code`].
///
/// The mapping is total and stable; see the module-level table for the REST
/// correspondence.
pub fn error_code_to_grpc(code: ErrorCode) -> Code {
    match code {
        ErrorCode::InvalidId => Code::InvalidArgument,
        ErrorCode::InvalidResourceSpec => Code::InvalidArgument,
        ErrorCode::InvalidTransition => Code::FailedPrecondition,
        ErrorCode::PermissionDenied => Code::PermissionDenied,
        ErrorCode::QuotaExceeded => Code::ResourceExhausted,
        ErrorCode::ArtifactNotFound => Code::NotFound,
        ErrorCode::DigestMismatch => Code::InvalidArgument,
        ErrorCode::PathEscape => Code::InvalidArgument,
        ErrorCode::BinaryProvenanceError => Code::InvalidArgument,
        ErrorCode::LocalArtifactRequired => Code::InvalidArgument,
        ErrorCode::CgroupUnavailable => Code::Internal,
        ErrorCode::NetworkSetupError => Code::Internal,
        ErrorCode::ProcessSpawnError => Code::Internal,
        ErrorCode::SnapshotIncompatible => Code::FailedPrecondition,
        ErrorCode::TransportError => Code::Internal,
        ErrorCode::InternalError => Code::Internal,
    }
}

/// Convert a [`MicrovmError`] into a tonic [`Status`].
///
/// - `code` is the deterministic mapping from [`error_code_to_grpc`].
/// - `message` is the human-readable error message (same as REST `message`).
/// - `details` carries the [`ErrorBody`] JSON (same bytes as the REST body),
///   so the stable `error_code` and `context` survive the round trip.
pub fn microvm_error_to_status(err: &MicrovmError) -> Status {
    let code = error_code_to_grpc(err.code);
    let body = ErrorBody::from_microvm_error(err);
    Status::with_details(code, err.message.clone(), body.to_json_bytes().into())
}

/// Build a [`Status`] for a failed peer authentication.
///
/// Mirrors the REST transport's `403` for unauthenticated peers, carrying a
/// `permission_denied` [`ErrorBody`] in the details.
pub fn authentication_failed_status() -> Status {
    let body = ErrorBody::forbidden("peer authentication failed");
    Status::with_details(
        Code::PermissionDenied,
        "peer authentication failed",
        body.to_json_bytes().into(),
    )
}

/// Build a [`Status`] for an invalid request identifier (path/field parse).
pub fn invalid_id_status(message: impl Into<String>) -> Status {
    let message = message.into();
    let body = ErrorBody::invalid_id(message.clone());
    Status::with_details(Code::InvalidArgument, message, body.to_json_bytes().into())
}

/// Build a [`Status`] for an invalid resource specification.
pub fn invalid_resource_spec_status(message: impl Into<String>) -> Status {
    let message = message.into();
    let body = ErrorBody::bad_request(message.clone());
    Status::with_details(Code::InvalidArgument, message, body.to_json_bytes().into())
}

/// Recover the structured [`ErrorBody`] from a status's `details`, if present.
///
/// Returns `None` when the details are empty or not a valid `ErrorBody` JSON
/// encoding (e.g. a status produced outside this crate).
pub fn error_body_from_status(status: &Status) -> Option<ErrorBody> {
    if status.details().is_empty() {
        return None;
    }
    serde_json::from_slice(status.details()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_error_codes_map_to_a_grpc_code() {
        // Every code must map; mapping is total. Exercise all variants.
        for code in ErrorCode::all() {
            let _ = error_code_to_grpc(*code);
        }
        assert_eq!(ErrorCode::all().len(), 16);
    }

    #[test]
    fn deterministic_mapping_table() {
        assert_eq!(
            error_code_to_grpc(ErrorCode::InvalidId),
            Code::InvalidArgument
        );
        assert_eq!(
            error_code_to_grpc(ErrorCode::InvalidResourceSpec),
            Code::InvalidArgument
        );
        assert_eq!(
            error_code_to_grpc(ErrorCode::InvalidTransition),
            Code::FailedPrecondition
        );
        assert_eq!(
            error_code_to_grpc(ErrorCode::PermissionDenied),
            Code::PermissionDenied
        );
        assert_eq!(
            error_code_to_grpc(ErrorCode::QuotaExceeded),
            Code::ResourceExhausted
        );
        assert_eq!(
            error_code_to_grpc(ErrorCode::ArtifactNotFound),
            Code::NotFound
        );
        assert_eq!(error_code_to_grpc(ErrorCode::InternalError), Code::Internal);
        assert_eq!(
            error_code_to_grpc(ErrorCode::SnapshotIncompatible),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn microvm_error_to_status_carries_code_message_and_details() {
        let err = MicrovmError::new(ErrorCode::PermissionDenied, "cross-tenant access")
            .with_context("vm_id", "vm-001");
        let status = microvm_error_to_status(&err);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "cross-tenant access");

        let body = error_body_from_status(&status).expect("details must decode");
        assert_eq!(body.error_code, "permission_denied");
        assert_eq!(body.message, "cross-tenant access");
        assert_eq!(body.context.get("vm_id").unwrap(), "vm-001");
    }

    #[test]
    fn details_json_omits_empty_context() {
        let err = MicrovmError::new(ErrorCode::ArtifactNotFound, "gone");
        let status = microvm_error_to_status(&err);
        let json = String::from_utf8(status.details().to_vec()).unwrap();
        assert!(!json.contains("context"));
        assert!(json.contains("artifact_not_found"));
    }

    #[test]
    fn authentication_failed_is_permission_denied() {
        let status = authentication_failed_status();
        assert_eq!(status.code(), Code::PermissionDenied);
        let body = error_body_from_status(&status).unwrap();
        assert_eq!(body.error_code, "permission_denied");
    }

    #[test]
    fn error_body_from_status_none_when_no_details() {
        let status = Status::new(Code::Internal, "no details");
        assert!(error_body_from_status(&status).is_none());
    }

    #[test]
    fn invalid_id_status_maps_to_invalid_argument() {
        let status = invalid_id_status("bad vm_id");
        assert_eq!(status.code(), Code::InvalidArgument);
        let body = error_body_from_status(&status).unwrap();
        assert_eq!(body.error_code, "invalid_id");
    }
}
