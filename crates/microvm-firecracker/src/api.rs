//! Firecracker UDS API client: typed request/response bodies and an
//! HTTP/1.1-over-Unix-socket transport.
//!
//! Firecracker exposes a REST API on a Unix domain socket. Each VM gets its own
//! socket and therefore its own API server. This module models the subset of
//! the v1.16.1 API the boot adapter needs:
//!
//! | Method & path | Purpose |
//! |---|---|
//! | `GET /` | Instance info / state probe |
//! | `PUT /machine-config` | vCPU count and memory |
//! | `PUT /boot-source` | Kernel image path and boot args |
//! | `PUT /drives/{id}` | Rootfs block device |
//! | `PUT /network-interfaces/{id}` | TAP-backed network interface |
//! | `PUT /actions` | `InstanceStart` / `SendCtrlAltDel` |
//!
//! The [`FirecrackerApi`] trait abstracts these operations so the backend can be
//! driven by a scripted implementation in deterministic tests; [`UdsApiClient`]
//! is the real transport used on a capable host.
//!
//! # Security
//! The API socket is unauthenticated. Callers must never hand the socket
//! path to a tenant; the backend keeps it in a host-only socket root and it is
//! absent from every tenant-facing status/metrics response.

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The rootfs drive identifier used by the boot adapter.
pub const ROOT_DRIVE_ID: &str = "rootfs";

/// The network interface identifier used by the boot adapter.
pub const NET_IFACE_ID: &str = "eth0";

// ---------------------------------------------------------------------------
// Request bodies (Firecracker v1.16.1 swagger)
// ---------------------------------------------------------------------------

/// `PUT /machine-config` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineConfig {
    /// Number of vCPUs.
    pub vcpu_count: u32,
    /// Memory size in MiB.
    pub mem_size_mib: u64,
    /// Simultaneous multi-threading (disabled by default for isolation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
}

impl MachineConfig {
    /// Build a machine config with SMT explicitly disabled.
    pub fn new(vcpu_count: u32, mem_size_mib: u64) -> Self {
        Self {
            vcpu_count,
            mem_size_mib,
            smt: Some(false),
        }
    }
}

/// `PUT /boot-source` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootSource {
    /// Host path to the kernel image.
    pub kernel_image_path: String,
    /// Optional kernel command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

/// `PUT /drives/{drive_id}` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drive {
    /// Drive identifier (matches the URL segment).
    pub drive_id: String,
    /// Host path to the backing block device.
    pub path_on_host: String,
    /// Whether this is the root device.
    pub is_root_device: bool,
    /// Whether the drive is read-only.
    pub is_read_only: bool,
}

impl Drive {
    /// Build a read-write rootfs drive.
    pub fn rootfs(path_on_host: impl Into<String>) -> Self {
        Self {
            drive_id: ROOT_DRIVE_ID.to_string(),
            path_on_host: path_on_host.into(),
            is_root_device: true,
            is_read_only: false,
        }
    }
}

/// `PUT /network-interfaces/{iface_id}` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface identifier (matches the URL segment).
    pub iface_id: String,
    /// Host TAP device name backing this interface.
    pub host_dev_name: String,
}

impl NetworkInterface {
    /// Build a network interface bound to a TAP device.
    pub fn tap(host_dev_name: impl Into<String>) -> Self {
        Self {
            iface_id: NET_IFACE_ID.to_string(),
            host_dev_name: host_dev_name.into(),
        }
    }
}

/// `PUT /actions` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceAction {
    /// The action type Firecracker should perform.
    pub action_type: String,
}

impl InstanceAction {
    /// The `InstanceStart` action.
    pub fn instance_start() -> Self {
        Self {
            action_type: "InstanceStart".to_string(),
        }
    }

    /// The `SendCtrlAltDel` action (graceful guest shutdown).
    pub fn send_ctrl_alt_del() -> Self {
        Self {
            action_type: "SendCtrlAltDel".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Response bodies
// ---------------------------------------------------------------------------

/// Firecracker error payload returned on 4xx/5xx responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultMessage {
    /// Human-readable fault description.
    pub fault_message: String,
}

/// `GET /` response: instance information.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// Instance id (the Firecracker `--id`).
    #[serde(default)]
    pub id: String,
    /// Instance state string (`Not started`, `Running`, `Paused`).
    #[serde(default)]
    pub state: String,
    /// VMM version string.
    #[serde(default)]
    pub vmm_version: String,
}

impl InstanceInfo {
    /// True when the instance reports the `Running` state.
    pub fn is_running(&self) -> bool {
        self.state == "Running"
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstract Firecracker API operations.
///
/// Implemented by [`UdsApiClient`] for real VMs and by scripted fakes in tests.
/// Every method maps transport/API failures to [`ErrorCode::TransportError`].
#[async_trait]
pub trait FirecrackerApi: Send + Sync {
    /// Configure the machine shape (`PUT /machine-config`).
    async fn put_machine_config(&self, cfg: &MachineConfig) -> Result<(), MicrovmError>;
    /// Configure the kernel/boot args (`PUT /boot-source`).
    async fn put_boot_source(&self, cfg: &BootSource) -> Result<(), MicrovmError>;
    /// Attach a block device (`PUT /drives/{id}`).
    async fn put_drive(&self, cfg: &Drive) -> Result<(), MicrovmError>;
    /// Attach a network interface (`PUT /network-interfaces/{id}`).
    async fn put_network_interface(&self, cfg: &NetworkInterface) -> Result<(), MicrovmError>;
    /// Start the instance (`PUT /actions` with `InstanceStart`).
    async fn start_instance(&self) -> Result<(), MicrovmError>;
    /// Request a graceful guest shutdown (`PUT /actions` with `SendCtrlAltDel`).
    async fn send_ctrl_alt_del(&self) -> Result<(), MicrovmError>;
    /// Query instance info (`GET /`).
    async fn instance_info(&self) -> Result<InstanceInfo, MicrovmError>;
}

// ---------------------------------------------------------------------------
// Real UDS HTTP/1.1 client
// ---------------------------------------------------------------------------

/// A minimal HTTP/1.1 client speaking to the Firecracker API over a Unix
/// domain socket.
///
/// Each request opens a fresh connection, writes one request, and reads one
/// response. Firecracker's API server accepts sequential connections on its
/// socket, so per-request connections are safe and keep the client stateless.
#[derive(Clone, Debug)]
pub struct UdsApiClient {
    socket_path: PathBuf,
}

impl UdsApiClient {
    /// Create a client bound to `socket_path`.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// The socket path this client talks to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Perform a raw HTTP request and return `(status_code, body_bytes)`.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), MicrovmError> {
        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            MicrovmError::new(
                ErrorCode::TransportError,
                "failed to connect to Firecracker socket",
            )
            .with_context("socket", self.socket_path.display().to_string())
            .with_context("io", e.to_string())
        })?;

        let body = body.unwrap_or(b"");
        let mut req = Vec::with_capacity(160 + body.len());
        req.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());
        req.extend_from_slice(b"Host: localhost\r\n");
        req.extend_from_slice(b"Accept: application/json\r\n");
        if !body.is_empty() {
            req.extend_from_slice(b"Content-Type: application/json\r\n");
        }
        req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        req.extend_from_slice(b"Connection: close\r\n");
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(body);

        stream.write_all(&req).await.map_err(|e| {
            MicrovmError::new(ErrorCode::TransportError, "failed to write request")
                .with_context("socket", self.socket_path.display().to_string())
                .with_context("io", e.to_string())
        })?;
        stream.flush().await.map_err(|e| {
            MicrovmError::new(ErrorCode::TransportError, "failed to flush request")
                .with_context("io", e.to_string())
        })?;

        // Read the response by HTTP framing (headers, then exactly
        // `Content-Length` body bytes) rather than waiting for the connection to
        // close. Firecracker honors HTTP/1.1 keep-alive and answers mutating
        // calls with `204 No Content`, so reading to EOF would block forever.
        let mut buf = Vec::with_capacity(512);
        read_response_framed(&mut stream, &mut buf)
            .await
            .map_err(|e| e.with_context("socket", self.socket_path.display().to_string()))?;

        parse_http_response(&buf)
    }

    /// Perform a request carrying a JSON body and require a 2xx status.
    async fn put_json<T: Serialize>(&self, path: &str, payload: &T) -> Result<(), MicrovmError> {
        self.send_json("PUT", path, payload).await
    }

    /// Perform a request with an arbitrary HTTP method carrying a JSON body,
    /// requiring a 2xx status.
    ///
    /// Shared by the boot configuration paths (`PUT`) and the snapshot
    /// protocol ([`crate::snapshot`]), which additionally needs `PATCH /vm`.
    pub(crate) async fn send_json<T: Serialize>(
        &self,
        method: &str,
        path: &str,
        payload: &T,
    ) -> Result<(), MicrovmError> {
        let body = serde_json::to_vec(payload).map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "failed to serialize API payload")
                .with_context("path", path)
                .with_context("serde", e.to_string())
        })?;
        let (status, resp) = self.request(method, path, Some(&body)).await?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(api_error(method, path, status, &resp))
        }
    }
}

#[async_trait]
impl FirecrackerApi for UdsApiClient {
    async fn put_machine_config(&self, cfg: &MachineConfig) -> Result<(), MicrovmError> {
        self.put_json("/machine-config", cfg).await
    }

    async fn put_boot_source(&self, cfg: &BootSource) -> Result<(), MicrovmError> {
        self.put_json("/boot-source", cfg).await
    }

    async fn put_drive(&self, cfg: &Drive) -> Result<(), MicrovmError> {
        let path = format!("/drives/{}", cfg.drive_id);
        self.put_json(&path, cfg).await
    }

    async fn put_network_interface(&self, cfg: &NetworkInterface) -> Result<(), MicrovmError> {
        let path = format!("/network-interfaces/{}", cfg.iface_id);
        self.put_json(&path, cfg).await
    }

    async fn start_instance(&self) -> Result<(), MicrovmError> {
        self.put_json("/actions", &InstanceAction::instance_start())
            .await
    }

    async fn send_ctrl_alt_del(&self) -> Result<(), MicrovmError> {
        self.put_json("/actions", &InstanceAction::send_ctrl_alt_del())
            .await
    }

    async fn instance_info(&self) -> Result<InstanceInfo, MicrovmError> {
        let (status, resp) = self.request("GET", "/", None).await?;
        if !(200..300).contains(&status) {
            return Err(api_error("GET", "/", status, &resp));
        }
        serde_json::from_slice(&resp).map_err(|e| {
            MicrovmError::new(
                ErrorCode::TransportError,
                "malformed instance-info response",
            )
            .with_context("serde", e.to_string())
        })
    }
}

// ---------------------------------------------------------------------------
// HTTP parsing helpers
// ---------------------------------------------------------------------------

/// Parse a raw HTTP/1.1 response buffer into `(status_code, body)`.
///
/// Handles both `Content-Length`-delimited and read-to-close bodies. Returns
/// [`ErrorCode::TransportError`] if the status line is malformed.
/// Read a complete HTTP response from `stream` into `buf` using message framing
/// (headers up to the blank line, then exactly `Content-Length` body bytes)
/// instead of waiting for the connection to close.
///
/// Firecracker keeps the API socket alive (HTTP/1.1 keep-alive) and answers
/// mutating calls with `204 No Content`, so a read-to-EOF would block forever.
/// Headers are tiny, so reading them one byte at a time until `\r\n\r\n` is
/// negligible next to the VM operation being measured.
async fn read_response_framed(
    stream: &mut UnixStream,
    buf: &mut Vec<u8>,
) -> Result<(), MicrovmError> {
    // 1. Read until the header terminator (or EOF, which the parser reports).
    let mut byte = [0u8; 1];
    while find_subsequence(buf, b"\r\n\r\n").is_none() {
        match stream.read(&mut byte).await {
            Ok(0) => break,
            Ok(_) => buf.push(byte[0]),
            Err(e) => {
                return Err(MicrovmError::new(
                    ErrorCode::TransportError,
                    "failed to read response headers",
                )
                .with_context("io", e.to_string()));
            }
        }
    }

    // 2. Read exactly the remaining `Content-Length` body bytes (none for 204).
    if let Some(idx) = find_subsequence(buf, b"\r\n\r\n") {
        if let Some(content_length) = content_length_of(&buf[..idx]) {
            let have = buf.len() - (idx + 4);
            let need = content_length.saturating_sub(have);
            if need > 0 {
                let mut rest = vec![0u8; need];
                stream.read_exact(&mut rest).await.map_err(|e| {
                    MicrovmError::new(ErrorCode::TransportError, "failed to read response body")
                        .with_context("io", e.to_string())
                })?;
                buf.extend_from_slice(&rest);
            }
        }
    }
    Ok(())
}

/// Extract the `Content-Length` value from a raw header block, if present.
fn content_length_of(headers: &[u8]) -> Option<usize> {
    let mut lines = headers.split(|&b| b == b'\n');
    lines.next(); // skip the status line
    for line in lines {
        let line = trim_cr(line);
        if let Some(rest) = strip_prefix_ascii(line, b"content-length:") {
            let val = std::str::from_utf8(rest).unwrap_or("").trim();
            return val.parse::<usize>().ok();
        }
    }
    None
}

fn parse_http_response(buf: &[u8]) -> Result<(u16, Vec<u8>), MicrovmError> {
    let header_end = find_subsequence(buf, b"\r\n\r\n").ok_or_else(|| {
        MicrovmError::new(
            ErrorCode::TransportError,
            "incomplete HTTP response headers",
        )
    })?;
    let headers = &buf[..header_end];
    let body = &buf[header_end + 4..];

    let mut lines = headers.split(|&b| b == b'\n');
    let status_line = lines.next().unwrap_or(b"");
    let status = parse_status_line(status_line)?;

    // Determine body length from Content-Length if present; otherwise the
    // remainder (Connection: close) is the body.
    let mut content_length: Option<usize> = None;
    for line in lines {
        let line = trim_cr(line);
        if let Some(rest) = strip_prefix_ascii(line, b"content-length:") {
            let val = std::str::from_utf8(rest).unwrap_or("").trim();
            content_length = val.parse::<usize>().ok();
        }
    }

    let body = match content_length {
        Some(n) if n <= body.len() => body[..n].to_vec(),
        _ => body.to_vec(),
    };
    Ok((status, body))
}

/// Parse the numeric status code from an HTTP status line (`HTTP/1.1 200 OK`).
fn parse_status_line(line: &[u8]) -> Result<u16, MicrovmError> {
    let line = trim_cr(line);
    let mut parts = line.split(|&b| b == b' ');
    let _version = parts.next();
    let code = parts.next().ok_or_else(|| {
        MicrovmError::new(ErrorCode::TransportError, "malformed HTTP status line")
    })?;
    let code = std::str::from_utf8(code)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .ok_or_else(|| {
            MicrovmError::new(ErrorCode::TransportError, "non-numeric HTTP status code")
        })?;
    Ok(code)
}

/// Build a typed transport error from a non-2xx API response.
fn api_error(method: &str, path: &str, status: u16, body: &[u8]) -> MicrovmError {
    let fault = serde_json::from_slice::<FaultMessage>(body)
        .map(|f| f.fault_message)
        .unwrap_or_else(|_| String::from_utf8_lossy(body).into_owned());
    MicrovmError::new(ErrorCode::TransportError, "Firecracker API request failed")
        .with_context("method", method)
        .with_context("path", path)
        .with_context("status", status.to_string())
        .with_context("fault", truncate(&fault, 256))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!(
            "{}…",
            &s[..s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len())]
        )
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn strip_prefix_ascii<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if line.len() < prefix.len() {
        return None;
    }
    let (head, rest) = line.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        // Skip leading whitespace after the colon; return a sub-slice of `line`.
        let skip = rest
            .iter()
            .take_while(|b| **b == b' ' || **b == b'\t')
            .count();
        Some(&rest[skip..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_config_serializes_snake_case() {
        let cfg = MachineConfig::new(2, 512);
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"vcpu_count\":2"));
        assert!(json.contains("\"mem_size_mib\":512"));
        assert!(json.contains("\"smt\":false"));
    }

    #[test]
    fn boot_source_omits_absent_boot_args() {
        let bs = BootSource {
            kernel_image_path: "/srv/vmlinux".to_string(),
            boot_args: None,
        };
        let json = serde_json::to_string(&bs).unwrap();
        assert!(!json.contains("boot_args"));
    }

    #[test]
    fn drive_rootfs_defaults() {
        let d = Drive::rootfs("/srv/rootfs.ext4");
        assert_eq!(d.drive_id, ROOT_DRIVE_ID);
        assert!(d.is_root_device);
        assert!(!d.is_read_only);
    }

    #[test]
    fn instance_action_types() {
        assert_eq!(
            InstanceAction::instance_start().action_type,
            "InstanceStart"
        );
        assert_eq!(
            InstanceAction::send_ctrl_alt_del().action_type,
            "SendCtrlAltDel"
        );
    }

    #[test]
    fn instance_info_running_detection() {
        let running = InstanceInfo {
            id: "vm-1".into(),
            state: "Running".into(),
            vmm_version: "1.16.1".into(),
        };
        assert!(running.is_running());
        let not_started = InstanceInfo {
            state: "Not started".into(),
            ..running.clone()
        };
        assert!(!not_started.is_running());
    }

    #[test]
    fn parse_response_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"state\":\"x\"}";
        // body is 13 bytes: {"state":"x"}
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"state\":\"x\"}");
    }

    #[test]
    fn parse_response_read_to_close_body() {
        let raw = b"HTTP/1.1 400 Bad Request\r\n\r\n{\"fault_message\":\"bad\"}";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 400);
        let fault: FaultMessage = serde_json::from_slice(&body).unwrap();
        assert_eq!(fault.fault_message, "bad");
    }

    #[test]
    fn parse_response_incomplete_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5";
        assert!(parse_http_response(raw).is_err());
    }

    #[test]
    fn parse_status_line_malformed() {
        assert!(parse_status_line(b"GARBAGE").is_err());
        assert_eq!(parse_status_line(b"HTTP/1.1 204 No Content").unwrap(), 204);
    }

    #[test]
    fn api_error_extracts_fault_message() {
        let body = br#"{"fault_message":"kernel path invalid"}"#;
        let err = api_error("PUT", "/boot-source", 400, body);
        assert_eq!(err.code, ErrorCode::TransportError);
        assert_eq!(err.context.get("status").map(String::as_str), Some("400"));
        assert_eq!(
            err.context.get("fault").map(String::as_str),
            Some("kernel path invalid")
        );
    }

    #[test]
    fn api_error_handles_non_json_body() {
        let err = api_error("PUT", "/actions", 500, b"internal explosion");
        assert_eq!(
            err.context.get("fault").map(String::as_str),
            Some("internal explosion")
        );
    }

    #[test]
    fn content_length_of_parses_header() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nContent-Type: application/json";
        assert_eq!(content_length_of(headers), Some(42));
    }

    #[test]
    fn content_length_of_is_none_when_absent() {
        let headers = b"HTTP/1.1 204 No Content\r\nDate: x";
        assert_eq!(content_length_of(headers), None);
    }

    /// Regression: Firecracker answers mutating calls with `204 No Content` and
    /// keeps the socket open (HTTP/1.1 keep-alive). The reader must frame by
    /// headers, not wait for EOF: the old read-to-EOF hung forever here.
    #[tokio::test]
    async fn read_response_framed_does_not_wait_for_keep_alive_close() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let server_task = tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nDate: x\r\n\r\n")
                .await
                .unwrap();
            // Deliberately do not close: hold the connection open.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });

        let mut buf = Vec::new();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_response_framed(&mut client, &mut buf),
        )
        .await;
        let inner = outcome.expect("reader must not wait for the connection to close");
        inner.unwrap();
        let (status, body) = parse_http_response(&buf).unwrap();
        assert_eq!(status, 204);
        assert!(body.is_empty());
        server_task.abort();
    }

    /// The reader consumes exactly `Content-Length` body bytes and ignores any
    /// trailing keep-alive bytes still buffered on the socket.
    #[tokio::test]
    async fn read_response_framed_reads_exactly_content_length_bytes() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let server_task = tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_response_framed(&mut client, &mut buf),
        )
        .await
        .expect("reader must not hang")
        .unwrap();
        let (status, body) = parse_http_response(&buf).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        server_task.abort();
    }
}
