//! Stable error mapping from [`MicrovmError`] codes to HTTP status and body.
//!
//! Every [`ErrorCode`] variant maps to a deterministic HTTP status code.
//! The response body follows the OpenAPI `ErrorResponse` schema with
//! `error_code`, `message`, and optional `context` fields.

use microvm_errors::{ErrorCode, MicrovmError};
use serde::Serialize;
use std::collections::BTreeMap;

/// HTTP status codes used by the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpStatus {
    /// 400 Bad Request
    BadRequest = 400,
    /// 403 Forbidden
    Forbidden = 403,
    /// 404 Not Found
    NotFound = 404,
    /// 409 Conflict
    Conflict = 409,
    /// 500 Internal Server Error
    InternalError = 500,
}

impl HttpStatus {
    /// Return the numeric status code.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Return the canonical reason phrase.
    pub fn reason(self) -> &'static str {
        match self {
            Self::BadRequest => "Bad Request",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::Conflict => "Conflict",
            Self::InternalError => "Internal Server Error",
        }
    }
}

/// JSON error response body matching the OpenAPI `ErrorResponse` schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// Stable machine-readable error code (snake_case).
    pub error_code: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured key-value context.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
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

    /// Build an error body for a malformed request (parse failure).
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::InvalidResourceSpec.as_str().to_string(),
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    /// Build an error body for an invalid identifier in the path.
    pub fn invalid_id(message: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::InvalidId.as_str().to_string(),
            message: message.into(),
            context: BTreeMap::new(),
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

    /// Build an error body for an unknown route.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::ArtifactNotFound.as_str().to_string(),
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ErrorBody serialization cannot fail")
    }
}

/// Map a [`MicrovmError`] to its stable HTTP status code.
///
/// The mapping is deterministic and covers all [`ErrorCode`] variants:
///
/// | ErrorCode | HTTP Status |
/// |-----------|-------------|
/// | `invalid_id` | 400 |
/// | `invalid_resource_spec` | 400 |
/// | `invalid_transition` | 409 |
/// | `permission_denied` | 403 |
/// | `quota_exceeded` | 409 |
/// | `artifact_not_found` | 404 |
/// | `digest_mismatch` | 400 |
/// | `path_escape` | 400 |
/// | `binary_provenance_error` | 400 |
/// | `local_artifact_required` | 400 |
/// | `cgroup_unavailable` | 500 |
/// | `network_setup_error` | 500 |
/// | `process_spawn_error` | 500 |
/// | `snapshot_incompatible` | 409 |
/// | `transport_error` | 500 |
/// | `internal_error` | 500 |
pub fn error_to_http_status(code: ErrorCode) -> HttpStatus {
    match code {
        ErrorCode::InvalidId => HttpStatus::BadRequest,
        ErrorCode::InvalidResourceSpec => HttpStatus::BadRequest,
        ErrorCode::InvalidTransition => HttpStatus::Conflict,
        ErrorCode::PermissionDenied => HttpStatus::Forbidden,
        ErrorCode::QuotaExceeded => HttpStatus::Conflict,
        ErrorCode::ArtifactNotFound => HttpStatus::NotFound,
        ErrorCode::DigestMismatch => HttpStatus::BadRequest,
        ErrorCode::PathEscape => HttpStatus::BadRequest,
        ErrorCode::BinaryProvenanceError => HttpStatus::BadRequest,
        ErrorCode::LocalArtifactRequired => HttpStatus::BadRequest,
        ErrorCode::CgroupUnavailable => HttpStatus::InternalError,
        ErrorCode::NetworkSetupError => HttpStatus::InternalError,
        ErrorCode::ProcessSpawnError => HttpStatus::InternalError,
        ErrorCode::SnapshotIncompatible => HttpStatus::Conflict,
        ErrorCode::TransportError => HttpStatus::InternalError,
        ErrorCode::InternalError => HttpStatus::InternalError,
    }
}

/// Map a full [`MicrovmError`] to an HTTP status code.
pub fn microvm_error_status(err: &MicrovmError) -> HttpStatus {
    error_to_http_status(err.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_error_codes_map_to_a_status() {
        for code in ErrorCode::all() {
            let status = error_to_http_status(*code);
            // Every code must map to a valid HTTP status.
            assert!(
                [400, 403, 404, 409, 500].contains(&status.code()),
                "ErrorCode {:?} mapped to unexpected status {}",
                code,
                status.code()
            );
        }
    }

    #[test]
    fn client_errors_map_to_4xx() {
        assert_eq!(error_to_http_status(ErrorCode::InvalidId).code(), 400);
        assert_eq!(
            error_to_http_status(ErrorCode::InvalidResourceSpec).code(),
            400
        );
        assert_eq!(
            error_to_http_status(ErrorCode::PermissionDenied).code(),
            403
        );
        assert_eq!(
            error_to_http_status(ErrorCode::ArtifactNotFound).code(),
            404
        );
        assert_eq!(
            error_to_http_status(ErrorCode::InvalidTransition).code(),
            409
        );
        assert_eq!(error_to_http_status(ErrorCode::QuotaExceeded).code(), 409);
    }

    #[test]
    fn server_errors_map_to_500() {
        assert_eq!(error_to_http_status(ErrorCode::InternalError).code(), 500);
        assert_eq!(
            error_to_http_status(ErrorCode::CgroupUnavailable).code(),
            500
        );
        assert_eq!(
            error_to_http_status(ErrorCode::NetworkSetupError).code(),
            500
        );
        assert_eq!(
            error_to_http_status(ErrorCode::ProcessSpawnError).code(),
            500
        );
        assert_eq!(error_to_http_status(ErrorCode::TransportError).code(), 500);
    }

    #[test]
    fn error_body_from_microvm_error() {
        let err = MicrovmError::new(ErrorCode::PermissionDenied, "cross-tenant access")
            .with_context("vm_id", "vm-001");
        let body = ErrorBody::from_microvm_error(&err);
        assert_eq!(body.error_code, "permission_denied");
        assert_eq!(body.message, "cross-tenant access");
        assert_eq!(body.context.get("vm_id").unwrap(), "vm-001");
    }

    #[test]
    fn error_body_json_omits_empty_context() {
        let body = ErrorBody::bad_request("malformed JSON");
        let json = String::from_utf8(body.to_json_bytes()).unwrap();
        assert!(!json.contains("context"));
        assert!(json.contains("invalid_resource_spec"));
    }

    #[test]
    fn error_body_json_includes_context() {
        let err = MicrovmError::new(ErrorCode::QuotaExceeded, "vcpu limit")
            .with_context("tenant", "t-001");
        let body = ErrorBody::from_microvm_error(&err);
        let json = String::from_utf8(body.to_json_bytes()).unwrap();
        assert!(json.contains("context"));
        assert!(json.contains("t-001"));
    }

    #[test]
    fn http_status_reason_phrases() {
        assert_eq!(HttpStatus::BadRequest.reason(), "Bad Request");
        assert_eq!(HttpStatus::Forbidden.reason(), "Forbidden");
        assert_eq!(HttpStatus::NotFound.reason(), "Not Found");
        assert_eq!(HttpStatus::Conflict.reason(), "Conflict");
        assert_eq!(HttpStatus::InternalError.reason(), "Internal Server Error");
    }

    #[test]
    fn microvm_error_status_delegates() {
        let err = MicrovmError::new(ErrorCode::ArtifactNotFound, "gone");
        assert_eq!(microvm_error_status(&err), HttpStatus::NotFound);
    }
}
