//! Unix socket REST server with peer credential authentication.
//!
//! Binds a filesystem Unix socket with mode `0660`, validates ownership,
//! extracts peer credentials via `SO_PEERCRED`, and serves HTTP/1.1
//! requests through the route dispatcher.
//!
//! **No TCP listener is ever created.** The server exclusively uses
//! `tokio::net::UnixListener`.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use microvm_lifecycle::LifecycleService;
use tokio::net::UnixListener;

use crate::config::SocketConfig;
use crate::error::{ErrorBody, HttpStatus};
use crate::peer::{get_peer_credentials, PeerAuthenticator};
use crate::router::{self, HttpResponse};

/// Error returned when the server cannot start.
#[derive(Debug)]
pub enum ServerError {
    /// Socket path validation failed.
    SocketValidation(String),
    /// I/O error during bind or accept.
    Io(std::io::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketValidation(msg) => write!(f, "socket validation error: {}", msg),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The REST Unix socket server.
///
/// Serves the OpenAPI lifecycle routes over a protected Unix domain socket.
/// Peer credentials are extracted before authorization, and the socket file
/// is validated for mode and ownership.
pub struct RestServer {
    config: SocketConfig,
    service: Arc<dyn LifecycleService>,
    authenticator: Arc<dyn PeerAuthenticator>,
}

impl RestServer {
    /// Create a new REST server.
    ///
    /// - `config`: socket path, mode, and ownership expectations.
    /// - `service`: the lifecycle service backend (business policy lives here).
    /// - `authenticator`: maps peer UID/GID to a [`Principal`].
    pub fn new(
        config: SocketConfig,
        service: Arc<dyn LifecycleService>,
        authenticator: Arc<dyn PeerAuthenticator>,
    ) -> Self {
        Self {
            config,
            service,
            authenticator,
        }
    }

    /// Validate the socket file after binding.
    ///
    /// Checks that the file exists, has the expected mode, and is owned by
    /// the expected UID/GID. Returns an error if validation fails.
    pub fn validate_socket(path: &Path, config: &SocketConfig) -> Result<(), ServerError> {
        let meta = std::fs::metadata(path).map_err(|e| {
            ServerError::SocketValidation(format!("cannot stat socket {}: {}", path.display(), e))
        })?;

        // Verify it is a socket file.
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            return Err(ServerError::SocketValidation(format!(
                "{} is not a Unix socket",
                path.display()
            )));
        }

        // Verify mode (mask out file-type bits).
        let actual_mode = meta.permissions().mode() & 0o7777;
        if actual_mode != config.mode {
            return Err(ServerError::SocketValidation(format!(
                "socket mode is {:04o}, expected {:04o}",
                actual_mode, config.mode
            )));
        }

        // Verify ownership.
        use std::os::unix::fs::MetadataExt;
        let actual_uid = meta.uid();
        let actual_gid = meta.gid();
        let expected_uid = config.resolve_uid();
        let expected_gid = config.resolve_gid();

        if actual_uid != expected_uid {
            return Err(ServerError::SocketValidation(format!(
                "socket owner UID is {}, expected {}",
                actual_uid, expected_uid
            )));
        }

        if actual_gid != expected_gid {
            return Err(ServerError::SocketValidation(format!(
                "socket group GID is {}, expected {}",
                actual_gid, expected_gid
            )));
        }

        Ok(())
    }

    /// Bind the Unix socket and return the listener.
    ///
    /// Creates parent directories, removes any stale socket file, binds,
    /// and sets the file mode to the configured value.
    pub fn bind(&self) -> Result<UnixListener, ServerError> {
        let path = &self.config.path;

        // Create parent directory if needed.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Remove stale socket file if it exists.
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        // Bind the Unix listener.
        let listener = UnixListener::bind(path)?;

        // Set socket file permissions.
        let perms = std::fs::Permissions::from_mode(self.config.mode);
        std::fs::set_permissions(path, perms)?;

        Ok(listener)
    }

    /// Run the server, accepting connections until the future is dropped.
    ///
    /// Each connection has its peer credentials extracted via `SO_PEERCRED`
    /// before any HTTP processing. Unauthenticated peers receive 403.
    pub async fn serve(self) -> Result<(), ServerError> {
        let listener = self.bind()?;

        // Validate the socket after binding.
        Self::validate_socket(&self.config.path, &self.config)?;

        let service = self.service;
        let authenticator = self.authenticator;

        loop {
            let (stream, _addr) = listener.accept().await?;

            // Extract peer credentials BEFORE any authorization.
            let peer_creds = match get_peer_credentials(&stream) {
                Ok(creds) => creds,
                Err(_) => {
                    // Cannot identify peer — reject the connection.
                    continue;
                }
            };

            // Authenticate the peer.
            let principal = authenticator.authenticate(&peer_creds);

            let svc = Arc::clone(&service);

            tokio::spawn(async move {
                let svc_fn = service_fn(move |req: Request<Incoming>| {
                    let svc = Arc::clone(&svc);
                    let principal = principal.clone();
                    async move { handle_request(req, principal, svc).await }
                });

                let io = TokioIo::new(stream);
                let _ = http1::Builder::new().serve_connection(io, svc_fn).await;
            });
        }
    }
}

/// Handle a single HTTP request: route, dispatch, and build the response.
async fn handle_request(
    req: Request<Incoming>,
    principal: Option<microvm_types::Principal>,
    service: Arc<dyn LifecycleService>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Unauthenticated peers get 403 for everything.
    let principal = match principal {
        Some(p) => p,
        None => {
            let body = ErrorBody::forbidden("peer authentication failed");
            return Ok(build_hyper_response(
                HttpStatus::Forbidden,
                &body.to_json_bytes(),
            ));
        }
    };

    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    // Read the request body.
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => {
            let body = ErrorBody::bad_request("failed to read request body");
            return Ok(build_hyper_response(
                HttpStatus::BadRequest,
                &body.to_json_bytes(),
            ));
        }
    };

    // Route and dispatch.
    let http_resp = match router::match_route(&method, &path) {
        Some(route) => router::dispatch(&route, &body_bytes, &principal, &service).await,
        None => router::handle_unknown_route(),
    };

    Ok(build_hyper_response_from(&http_resp))
}

/// Build a hyper response from status and body bytes.
fn build_hyper_response(status: HttpStatus, body: &[u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status.code())
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("response builder cannot fail")
}

/// Build a hyper response from our router's HttpResponse.
fn build_hyper_response_from(resp: &HttpResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(resp.status);

    if !resp.body.is_empty() {
        builder = builder.header("Content-Type", "application/json");
    }

    builder
        .body(Full::new(Bytes::copy_from_slice(&resp.body)))
        .expect("response builder cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SocketConfig;
    use std::path::PathBuf;

    #[test]
    fn validate_socket_rejects_nonexistent_path() {
        let config = SocketConfig::with_path("/tmp/nonexistent-microvm-test.sock");
        let result = RestServer::validate_socket(
            &PathBuf::from("/tmp/nonexistent-microvm-test.sock"),
            &config,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_socket_rejects_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        std::fs::write(&path, "hello").unwrap();

        let config = SocketConfig::with_path(&path);
        let result = RestServer::validate_socket(&path, &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not a Unix socket"));
    }

    #[test]
    fn validate_socket_rejects_wrong_mode() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();

        // Set mode to 0777 (wrong).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();

        let config = SocketConfig::with_path(&path).with_mode(0o660);
        let result = RestServer::validate_socket(&path, &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("mode"));
    }

    #[test]
    fn validate_socket_accepts_correct_mode() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();

        // Set mode to 0660 (correct).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

        // Use current process UID/GID as expected.
        let config = SocketConfig::with_path(&path).with_mode(0o660);
        let result = RestServer::validate_socket(&path, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_socket_rejects_wrong_uid() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

        // Expect a UID that is definitely not ours.
        let config = SocketConfig::with_path(&path)
            .with_mode(0o660)
            .with_uid(99999);
        let result = RestServer::validate_socket(&path, &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("UID"));
    }

    #[tokio::test]
    async fn bind_creates_socket_with_correct_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("api.sock");

        let config = SocketConfig::with_path(&path).with_mode(0o660);

        // We need a service and authenticator to construct RestServer,
        // but bind() only uses config.
        let server = RestServer {
            config: config.clone(),
            service: Arc::new(NoopService),
            authenticator: Arc::new(crate::peer::StaticAuthenticator::new(
                0,
                microvm_types::Principal::new(
                    microvm_types::TenantId::new("t").unwrap(),
                    microvm_types::Role::Owner,
                ),
            )),
        };

        let _listener = server.bind().unwrap();

        // Verify the socket file exists with correct mode.
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o660);
    }

    #[tokio::test]
    async fn bind_removes_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");

        // Create a stale file.
        std::fs::write(&path, "stale").unwrap();

        let config = SocketConfig::with_path(&path).with_mode(0o660);
        let server = RestServer {
            config,
            service: Arc::new(NoopService),
            authenticator: Arc::new(crate::peer::StaticAuthenticator::new(
                0,
                microvm_types::Principal::new(
                    microvm_types::TenantId::new("t").unwrap(),
                    microvm_types::Role::Owner,
                ),
            )),
        };

        let _listener = server.bind().unwrap();

        // Should now be a socket, not a regular file.
        use std::os::unix::fs::FileTypeExt;
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
    }

    // -- Noop service for testing bind --------------------------------------

    struct NoopService;

    #[async_trait::async_trait]
    impl LifecycleService for NoopService {
        async fn create(
            &self,
            _spec: microvm_types::ResourceSpec,
            _owner: microvm_types::Principal,
        ) -> Result<microvm_types::VmId, microvm_errors::MicrovmError> {
            unimplemented!()
        }
        async fn start(
            &self,
            _vm_id: &microvm_types::VmId,
            _principal: &microvm_types::Principal,
        ) -> Result<(), microvm_errors::MicrovmError> {
            unimplemented!()
        }
        async fn stop(
            &self,
            _vm_id: &microvm_types::VmId,
            _principal: &microvm_types::Principal,
        ) -> Result<(), microvm_errors::MicrovmError> {
            unimplemented!()
        }
        async fn snapshot(
            &self,
            _vm_id: &microvm_types::VmId,
            _principal: &microvm_types::Principal,
        ) -> Result<microvm_types::SnapshotId, microvm_errors::MicrovmError> {
            unimplemented!()
        }
        async fn restore(
            &self,
            _snapshot_id: &microvm_types::SnapshotId,
            _principal: &microvm_types::Principal,
        ) -> Result<microvm_types::VmId, microvm_errors::MicrovmError> {
            unimplemented!()
        }
        async fn status(
            &self,
            _vm_id: &microvm_types::VmId,
            _principal: &microvm_types::Principal,
        ) -> Result<microvm_lifecycle::VmStatus, microvm_errors::MicrovmError> {
            unimplemented!()
        }
        async fn metrics(
            &self,
            _vm_id: &microvm_types::VmId,
            _principal: &microvm_types::Principal,
        ) -> Result<microvm_lifecycle::VmMetrics, microvm_errors::MicrovmError> {
            unimplemented!()
        }
    }
}
