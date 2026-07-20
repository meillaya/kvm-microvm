//! CLI error type and host-path sanitization.
//!
//! The CLI surfaces errors from the service and from local validation
//! without ever leaking host-specific filesystem paths. Every
//! [`CliError`] carries a stable [`ExitCode`] and a sanitized message
//! safe for display on any host.

use crate::exit_code::ExitCode;
use microvm_errors::{ErrorCode, MicrovmError};
use std::fmt;

/// A CLI error carrying a stable exit code and a sanitized message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    /// The stable exit code for this error.
    pub exit_code: ExitCode,
    /// The stable platform error code, if this error originated from the
    /// service or a typed validation.
    pub error_code: Option<ErrorCode>,
    /// Human-readable message, sanitized of host paths.
    pub message: String,
}

impl CliError {
    /// Create a new CLI error with an exit code and message.
    pub fn new(exit_code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            error_code: None,
            message: message.into(),
        }
    }

    /// Create a CLI error from a platform [`MicrovmError`], sanitizing
    /// any host paths from the message and context.
    pub fn from_microvm_error(err: &MicrovmError) -> Self {
        let exit_code = ExitCode::from_error_code(err.code);
        let message = sanitize_message(&err.message);
        Self {
            exit_code,
            error_code: Some(err.code),
            message,
        }
    }

    /// Create a usage error (exit code 2).
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ExitCode::UsageError, message)
    }

    /// Create a transport error (exit code 1).
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            exit_code: ExitCode::GeneralError,
            error_code: Some(ErrorCode::TransportError),
            message: sanitize_message(&message.into()),
        }
    }

    /// Create a permission-denied error (exit code 5) for a wrong-owner
    /// socket, without leaking the socket path.
    pub fn wrong_owner(expected_uid: u32, actual_uid: u32) -> Self {
        Self {
            exit_code: ExitCode::PermissionDenied,
            error_code: Some(ErrorCode::PermissionDenied),
            message: format!(
                "socket owner mismatch: expected uid {}, found uid {}; \
                 refusing to connect",
                expected_uid, actual_uid
            ),
        }
    }

    /// Create a not-found error (exit code 3) for a missing socket file,
    /// without leaking the socket path.
    pub fn socket_not_found() -> Self {
        Self {
            exit_code: ExitCode::NotFound,
            error_code: Some(ErrorCode::ArtifactNotFound),
            message: "service socket not found; is the microvm daemon running?".to_string(),
        }
    }

    /// Create a local-artifact-required error (exit code 4).
    pub fn local_artifact_required(reference: &str, reason: &str) -> Self {
        Self {
            exit_code: ExitCode::LocalArtifactRequired,
            error_code: Some(ErrorCode::LocalArtifactRequired),
            message: format!(
                "local artifact required: reference '{}' rejected: {}",
                reference, reason
            ),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = &self.error_code {
            write!(f, "[{}] {}", code.as_str(), self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for CliError {}

/// Sanitize a message by replacing absolute filesystem paths with a
/// generic placeholder, preventing host-path leakage in CLI output.
///
/// Detects sequences that look like absolute Unix paths (`/` followed
/// by path-like characters) and replaces them with `<path>`.
pub fn sanitize_message(message: &str) -> String {
    let mut result = String::with_capacity(message.len());
    let chars: Vec<char> = message.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '/'
            && (i == 0
                || chars[i - 1] == ' '
                || chars[i - 1] == '('
                || chars[i - 1] == '='
                || chars[i - 1] == ':')
        {
            // Potential absolute path start. Consume path characters.
            let start = i;
            i += 1;
            let mut has_component = false;
            while i < len && is_path_char(chars[i]) {
                if chars[i] == '/' {
                    has_component = true;
                }
                i += 1;
            }
            // Only redact if it looks like a real path (has at least one
            // path separator beyond the leading `/` and some content).
            if has_component && i - start > 2 {
                result.push_str("<path>");
            } else {
                // Not a real path; emit the characters as-is.
                for c in &chars[start..i] {
                    result.push(*c);
                }
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

/// Returns `true` if the character is valid in a Unix path component.
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.' || c == '~'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_redacts_absolute_paths() {
        let msg = "cannot stat socket /run/microvm/api/rest.sock: permission denied";
        let sanitized = sanitize_message(msg);
        assert!(
            !sanitized.contains("/run/microvm"),
            "must redact path: {sanitized}"
        );
        assert!(
            sanitized.contains("<path>"),
            "must insert placeholder: {sanitized}"
        );
        assert!(sanitized.contains("permission denied"));
    }

    #[test]
    fn sanitize_redacts_multiple_paths() {
        let msg = "artifact at /var/lib/microvm/img not found, expected /opt/data/blob";
        let sanitized = sanitize_message(msg);
        assert!(!sanitized.contains("/var/lib"), "must redact: {sanitized}");
        assert!(!sanitized.contains("/opt/data"), "must redact: {sanitized}");
    }

    #[test]
    fn sanitize_preserves_non_path_slashes() {
        let msg = "ratio 1/2 is fine";
        let sanitized = sanitize_message(msg);
        // "1/2" should not be redacted (no leading / at word boundary).
        assert!(sanitized.contains("1/2"), "must preserve: {sanitized}");
    }

    #[test]
    fn sanitize_preserves_plain_messages() {
        let msg = "no such VM";
        assert_eq!(sanitize_message(msg), "no such VM");
    }

    #[test]
    fn cli_error_from_microvm_error_sanitizes() {
        let err = MicrovmError::new(
            ErrorCode::ArtifactNotFound,
            "blob at /var/lib/microvm/blobs/sha256/abc not found",
        );
        let cli_err = CliError::from_microvm_error(&err);
        assert_eq!(cli_err.exit_code, ExitCode::NotFound);
        assert!(
            !cli_err.message.contains("/var/lib"),
            "must sanitize: {}",
            cli_err.message
        );
    }

    #[test]
    fn cli_error_wrong_owner_does_not_leak_path() {
        let err = CliError::wrong_owner(1000, 0);
        assert_eq!(err.exit_code, ExitCode::PermissionDenied);
        assert!(err.message.contains("uid 1000"));
        assert!(err.message.contains("uid 0"));
        // Must not contain any path-like strings.
        assert!(!err.message.contains('/'));
    }

    #[test]
    fn cli_error_socket_not_found_does_not_leak_path() {
        let err = CliError::socket_not_found();
        assert_eq!(err.exit_code, ExitCode::NotFound);
        assert!(!err.message.contains('/'));
    }

    #[test]
    fn cli_error_display_includes_code() {
        let err =
            CliError::from_microvm_error(&MicrovmError::new(ErrorCode::PermissionDenied, "denied"));
        assert!(err.to_string().contains("permission_denied"));
        assert!(err.to_string().contains("denied"));
    }

    #[test]
    fn cli_error_local_artifact_required() {
        let err = CliError::local_artifact_required(
            "nginx:latest",
            "tag-only references are not permitted",
        );
        assert_eq!(err.exit_code, ExitCode::LocalArtifactRequired);
        assert!(err.message.contains("nginx:latest"));
    }
}
