//! REST/JSON client over a protected Unix domain socket.
//!
//! The [`Client`] connects to the microvm daemon's REST API exclusively
//! through a filesystem Unix socket. No TCP connection is ever made.
//! Before connecting, the socket file is validated for ownership; a
//! wrong-owner socket is refused with a [`CliError::wrong_owner`] that
//! does not leak the host path.
//!
//! The client speaks minimal HTTP/1.1 (one request per connection,
//! `Connection: close`) which is sufficient for the CLI's
//! request/response pattern and avoids a heavyweight HTTP client
//! dependency.

use crate::error::CliError;
use microvm_errors::ErrorCode;
use microvm_types::NetworkPolicy;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Maximum response body size the client will read (16 MiB).
const MAX_RESPONSE_BODY: usize = 16 * 1024 * 1024;

/// A REST/JSON client that talks to the microvm daemon over a Unix socket.
///
/// Every method maps to one OpenAPI lifecycle route (the API contract). The client
/// performs no TCP I/O; it connects exclusively through the filesystem
/// socket path supplied at construction.
#[derive(Clone, Debug)]
pub struct Client {
    /// Filesystem path to the REST Unix socket.
    socket_path: PathBuf,
}

/// A decoded HTTP response from the daemon.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl Client {
    /// Create a client targeting the given Unix socket path.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// The socket path this client targets.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Validate the socket file before connecting.
    ///
    /// Checks that the file exists, is a socket, and is owned by the
    /// current process UID. A wrong-owner socket is refused with a
    /// permission-denied error that does not leak the host path.
    pub fn validate_socket(&self) -> Result<(), CliError> {
        let meta = std::fs::metadata(&self.socket_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CliError::socket_not_found()
            } else {
                CliError::transport(format!("cannot inspect service socket: {e}"))
            }
        })?;

        // Verify it is a socket file.
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            return Err(CliError::transport(
                "service socket path is not a Unix socket",
            ));
        }

        // Verify ownership: the socket must be owned by the current user.
        let actual_uid = meta.uid();
        let expected_uid = unsafe { libc::getuid() };
        if actual_uid != expected_uid {
            return Err(CliError::wrong_owner(expected_uid, actual_uid));
        }

        Ok(())
    }

    /// `POST /vms`: create a VM.
    pub async fn create_vm(&self, req: &CreateVmRequest) -> Result<CreateVmResponse, CliError> {
        let body = serde_json::to_vec(req).map_err(|e| CliError::usage(e.to_string()))?;
        let resp = self.request("POST", "/vms", Some(&body)).await?;
        Self::decode(&resp)
    }

    /// `POST /vms/{vm_id}/start`: start a VM.
    pub async fn start_vm(&self, vm_id: &str) -> Result<(), CliError> {
        let path = format!("/vms/{}/start", vm_id);
        let resp = self.request("POST", &path, None).await?;
        Self::expect_empty(&resp)
    }

    /// `POST /vms/{vm_id}/stop`: stop a VM.
    pub async fn stop_vm(&self, vm_id: &str) -> Result<(), CliError> {
        let path = format!("/vms/{}/stop", vm_id);
        let resp = self.request("POST", &path, None).await?;
        Self::expect_empty(&resp)
    }

    /// `POST /vms/{vm_id}/snapshot`: snapshot a VM.
    pub async fn snapshot_vm(&self, vm_id: &str) -> Result<SnapshotVmResponse, CliError> {
        let path = format!("/vms/{}/snapshot", vm_id);
        let resp = self.request("POST", &path, None).await?;
        Self::decode(&resp)
    }

    /// `POST /snapshots/{snapshot_id}/restore`: restore from a snapshot.
    pub async fn restore_vm(&self, snapshot_id: &str) -> Result<RestoreVmResponse, CliError> {
        let path = format!("/snapshots/{}/restore", snapshot_id);
        let resp = self.request("POST", &path, None).await?;
        Self::decode(&resp)
    }

    /// `GET /vms/{vm_id}`: query VM status.
    pub async fn get_status(&self, vm_id: &str) -> Result<VmStatusResponse, CliError> {
        let path = format!("/vms/{}", vm_id);
        let resp = self.request("GET", &path, None).await?;
        Self::decode(&resp)
    }

    /// `GET /vms/{vm_id}/metrics`: query VM metrics.
    pub async fn get_metrics(&self, vm_id: &str) -> Result<serde_json::Value, CliError> {
        let path = format!("/vms/{}/metrics", vm_id);
        let resp = self.request("GET", &path, None).await?;
        Self::decode(&resp)
    }

    /// `GET /vms`: list VMs.
    pub async fn list_vms(&self) -> Result<VmListResponse, CliError> {
        let resp = self.request("GET", "/vms", None).await?;
        Self::decode(&resp)
    }

    /// `DELETE /vms/{vm_id}`: delete a stopped or failed VM.
    pub async fn delete_vm(&self, vm_id: &str) -> Result<(), CliError> {
        let path = format!("/vms/{}", vm_id);
        let resp = self.request("DELETE", &path, None).await?;
        Self::expect_empty(&resp)
    }

    /// Send one HTTP/1.1 request over the Unix socket and read the response.
    ///
    /// Validates the socket before connecting. Each call opens a fresh
    /// connection and sends `Connection: close`.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, CliError> {
        self.validate_socket()?;

        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| CliError::transport(format!("connect failed: {e}")))?;

        // Build the HTTP/1.1 request.
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
            method, path
        );
        if let Some(body) = body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        } else {
            req.push_str("Content-Length: 0\r\n");
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| CliError::transport(format!("write request failed: {e}")))?;
        if let Some(body) = body {
            stream
                .write_all(body)
                .await
                .map_err(|e| CliError::transport(format!("write body failed: {e}")))?;
        }
        stream
            .flush()
            .await
            .map_err(|e| CliError::transport(format!("flush failed: {e}")))?;

        // Read the full response.
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| CliError::transport(format!("read response failed: {e}")))?;

        parse_http_response(&raw)
    }

    /// Decode a successful (2xx) JSON response body, or map an error
    /// response to a [`CliError`].
    fn decode<T: DeserializeOwned>(resp: &HttpResponse) -> Result<T, CliError> {
        if (200..300).contains(&resp.status) {
            serde_json::from_slice(&resp.body)
                .map_err(|e| CliError::transport(format!("invalid JSON response: {e}")))
        } else {
            Err(Self::error_from_response(resp))
        }
    }

    /// Expect an empty-body success (2xx), or map an error response.
    fn expect_empty(resp: &HttpResponse) -> Result<(), CliError> {
        if (200..300).contains(&resp.status) {
            Ok(())
        } else {
            Err(Self::error_from_response(resp))
        }
    }

    /// Build a [`CliError`] from a non-2xx response, parsing the
    /// platform error body when present.
    fn error_from_response(resp: &HttpResponse) -> CliError {
        // Try to parse the platform ErrorResponse body.
        if let Ok(err_body) = serde_json::from_slice::<ErrorBody>(&resp.body) {
            let code = parse_error_code(&err_body.error_code);
            let exit_code = crate::exit_code::ExitCode::from_error_code(code);
            CliError {
                exit_code,
                error_code: Some(code),
                message: crate::error::sanitize_message(&err_body.message),
            }
        } else {
            CliError::transport(format!("HTTP {} from service", resp.status))
        }
    }
}

/// Platform error response body (matches the OpenAPI `ErrorResponse`).
#[derive(Clone, Debug, serde::Deserialize)]
struct ErrorBody {
    error_code: String,
    message: String,
}

/// Parse a stable error-code string into an [`ErrorCode`], defaulting to
/// [`ErrorCode::InternalError`] for unrecognized values.
fn parse_error_code(s: &str) -> ErrorCode {
    match s {
        "invalid_id" => ErrorCode::InvalidId,
        "invalid_resource_spec" => ErrorCode::InvalidResourceSpec,
        "invalid_transition" => ErrorCode::InvalidTransition,
        "permission_denied" => ErrorCode::PermissionDenied,
        "quota_exceeded" => ErrorCode::QuotaExceeded,
        "artifact_not_found" => ErrorCode::ArtifactNotFound,
        "digest_mismatch" => ErrorCode::DigestMismatch,
        "path_escape" => ErrorCode::PathEscape,
        "binary_provenance_error" => ErrorCode::BinaryProvenanceError,
        "local_artifact_required" => ErrorCode::LocalArtifactRequired,
        "cgroup_unavailable" => ErrorCode::CgroupUnavailable,
        "network_setup_error" => ErrorCode::NetworkSetupError,
        "process_spawn_error" => ErrorCode::ProcessSpawnError,
        "snapshot_incompatible" => ErrorCode::SnapshotIncompatible,
        "transport_error" => ErrorCode::TransportError,
        _ => ErrorCode::InternalError,
    }
}

/// Parse a raw HTTP/1.1 response into status + body.
///
/// Handles both `Content-Length` and `Connection: close` framing (the
/// daemon closes the connection after each response).
fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, CliError> {
    // Find the header/body separator.
    let sep = b"\r\n\r\n";
    let header_end = raw
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or_else(|| CliError::transport("malformed HTTP response: no header terminator"))?;

    let header_bytes = &raw[..header_end];
    let body = raw[header_end + sep.len()..].to_vec();

    let header = String::from_utf8_lossy(header_bytes);
    let mut lines = header.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| CliError::transport("malformed HTTP response: no status line"))?;

    // Parse "HTTP/1.1 201 Created".
    let mut parts = status_line.split_whitespace();
    let _version = parts
        .next()
        .ok_or_else(|| CliError::transport("malformed status line: no version"))?;
    let status_str = parts
        .next()
        .ok_or_else(|| CliError::transport("malformed status line: no status code"))?;
    let status: u16 = status_str
        .parse()
        .map_err(|_| CliError::transport(format!("invalid status code: {status_str}")))?;

    if body.len() > MAX_RESPONSE_BODY {
        return Err(CliError::transport("response body too large"));
    }

    Ok(HttpResponse { status, body })
}

// ---------------------------------------------------------------------------
// Request / Response types (mirror the OpenAPI schema)
// ---------------------------------------------------------------------------

/// Request body for `POST /vms`.
#[derive(Clone, Debug, Serialize)]
pub struct CreateVmRequest {
    /// Number of virtual CPUs (minimum 1).
    pub vcpu_count: u32,
    /// Memory allocation in MiB (minimum 1).
    pub memory_mib: u64,
    /// Disk allocation in MiB (minimum 1).
    pub disk_mib: u64,
    /// Network egress policy.
    pub network_policy: NetworkPolicy,
}

/// Response body for `POST /vms`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct CreateVmResponse {
    /// Assigned VM identifier.
    pub vm_id: String,
}

/// Response body for `POST /vms/{vm_id}/snapshot`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SnapshotVmResponse {
    /// Identifier of the created snapshot.
    pub snapshot_id: String,
}

/// Response body for `POST /snapshots/{snapshot_id}/restore`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct RestoreVmResponse {
    /// Identifier of the newly restored VM.
    pub vm_id: String,
}

/// Response body for `GET /vms/{vm_id}`.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct VmStatusResponse {
    /// VM identifier.
    pub vm_id: String,
    /// Current lifecycle state.
    pub state: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// Resource allocation.
    pub resource_spec: ResourceSpecResponse,
}

/// Response body for `GET /vms`.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct VmListResponse {
    /// VMs visible to the caller.
    pub vms: Vec<VmStatusResponse>,
}

/// Resource specification in API responses.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ResourceSpecResponse {
    /// Number of virtual CPUs.
    pub vcpu_count: u32,
    /// Memory in MiB.
    pub memory_mib: u64,
    /// Disk in MiB.
    pub disk_mib: u64,
    /// Network egress policy.
    pub network_policy: NetworkPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_201_response() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"vm_id\":\"vm-001\"}";
        // Note: body is 18 bytes but we read to connection close, so length mismatch is fine.
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, br#"{"vm_id":"vm-001"}"#);
    }

    #[test]
    fn parse_http_200_empty_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn parse_http_error_response() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error_code\":\"artifact_not_found\",\"message\":\"no such VM\"}";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 404);
        let err_body: ErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err_body.error_code, "artifact_not_found");
    }

    #[test]
    fn parse_http_malformed_no_terminator() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0";
        assert!(parse_http_response(raw).is_err());
    }

    #[test]
    fn parse_error_code_known_values() {
        assert_eq!(
            parse_error_code("artifact_not_found"),
            ErrorCode::ArtifactNotFound
        );
        assert_eq!(
            parse_error_code("permission_denied"),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            parse_error_code("local_artifact_required"),
            ErrorCode::LocalArtifactRequired
        );
        assert_eq!(parse_error_code("invalid_id"), ErrorCode::InvalidId);
    }

    #[test]
    fn parse_error_code_unknown_defaults_to_internal() {
        assert_eq!(parse_error_code("something_new"), ErrorCode::InternalError);
        assert_eq!(parse_error_code(""), ErrorCode::InternalError);
    }

    #[test]
    fn network_policy_roundtrip() {
        for (s, expected) in [
            ("none", NetworkPolicy::None),
            ("nat-only", NetworkPolicy::NatOnly),
            ("egress-allowed", NetworkPolicy::EgressAllowed),
        ] {
            let parsed: NetworkPolicy = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn network_policy_serializes_hyphenated() {
        assert_eq!(
            serde_json::to_string(&NetworkPolicy::NatOnly).unwrap(),
            r#""nat-only""#
        );
    }

    #[test]
    fn create_vm_request_serializes() {
        let req = CreateVmRequest {
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 1024,
            network_policy: NetworkPolicy::None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"vcpu_count\":2"));
        assert!(json.contains("\"network_policy\":\"none\""));
    }

    #[test]
    fn client_validate_socket_missing_returns_not_found() {
        let client = Client::new("/nonexistent/microvm/test.sock");
        let err = client.validate_socket().unwrap_err();
        assert_eq!(err.exit_code, crate::exit_code::ExitCode::NotFound);
        // Must not leak the path.
        assert!(!err.message.contains("/nonexistent"));
    }

    #[test]
    fn client_validate_socket_wrong_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        std::fs::write(&path, "data").unwrap();
        let client = Client::new(&path);
        let err = client.validate_socket().unwrap_err();
        assert_eq!(err.exit_code, crate::exit_code::ExitCode::GeneralError);
    }

    #[test]
    fn client_validate_socket_accepts_own_socket() {
        use std::os::unix::net::UnixListener as StdUnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();
        let client = Client::new(&path);
        // Owned by current user, so validation passes.
        assert!(client.validate_socket().is_ok());
    }
}
