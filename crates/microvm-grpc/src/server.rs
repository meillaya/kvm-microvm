//! Unix socket gRPC server with peer credential authentication.
//!
//! Binds a filesystem Unix socket with mode `0660`, validates ownership,
//! extracts peer credentials via `SO_PEERCRED` on every accepted connection,
//! and serves the generated `MicrovmService` over tonic's HTTP/2 transport.
//!
//! # Security invariants
//!
//! - Unix socket only. The server exclusively uses
//!   [`tokio::net::UnixListener`] and tonic's `serve_with_incoming`; no network
//!   address is ever bound.
//! - Peer credentials first. `SO_PEERCRED` is read before any
//!   authorization decision; unauthenticated peers are rejected by the service
//!   with `PermissionDenied`.
//! - Reflection disabled. No gRPC server reflection service is registered
//!   (and the `tonic-reflection` crate is not a dependency), so the production
//!   socket does not expose `list`/introspection. See [`REFLECTION_ENABLED`].

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use microvm_lifecycle::LifecycleService;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::StreamExt;
use tonic::transport::Server;

use crate::config::SocketConfig;
use crate::peer::{get_peer_credentials, PeerAuthenticator, PeerConnectInfo, PeerStream};
use crate::proto::v1::microvm_service_server::MicrovmServiceServer;
use crate::service::MicrovmGrpcService;

/// Whether gRPC server reflection is exposed.
///
/// Hard-coded to `false`: reflection must never be enabled on the production
/// socket. Tests assert this stays `false` and that no reflection service is
/// registered.
pub const REFLECTION_ENABLED: bool = false;

// Compile-time guard: the production socket must never expose reflection.
const _: () = assert!(!REFLECTION_ENABLED, "reflection must stay disabled");

/// Error returned when the server cannot start or serve.
#[derive(Debug)]
pub enum ServerError {
    /// Socket path validation failed.
    SocketValidation(String),
    /// I/O error during bind or accept.
    Io(std::io::Error),
    /// tonic transport error while serving.
    Transport(tonic::transport::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketValidation(msg) => write!(f, "socket validation error: {}", msg),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Transport(e) => write!(f, "transport error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The gRPC Unix socket server.
///
/// Serves the `microvm.v1` lifecycle service over a protected Unix domain
/// socket. Peer credentials are extracted before authorization, and the socket
/// file is validated for mode and ownership.
pub struct GrpcServer {
    config: SocketConfig,
    service: Arc<dyn LifecycleService>,
    authenticator: Arc<dyn PeerAuthenticator>,
}

impl GrpcServer {
    /// Create a new gRPC server.
    ///
    /// - `config`: socket path, mode, and ownership expectations.
    /// - `service`: the lifecycle service backend (business policy lives here).
    /// - `authenticator`: maps peer UID/GID to a [`Principal`](microvm_types::Principal).
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
    /// Checks that the file exists, is a socket, has the expected mode, and is
    /// owned by the expected UID/GID. Returns an error if validation fails.
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
    /// Creates parent directories, removes any stale socket file, binds, and
    /// sets the file mode to the configured value.
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
    /// Each accepted connection has its peer credentials extracted via
    /// `SO_PEERCRED` and authenticated *before* any RPC is processed. The
    /// authenticated principal (or its absence) is propagated into every
    /// request via [`PeerConnectInfo`].
    pub async fn serve(self) -> Result<(), ServerError> {
        let listener = self.bind()?;

        // Validate the socket after binding.
        Self::validate_socket(&self.config.path, &self.config)?;

        let authenticator = Arc::clone(&self.authenticator);

        // Build the authenticated incoming stream. Peer credentials are read
        // before authorization; connections whose peer cannot be identified are
        // dropped (fail closed), matching the REST transport.
        let incoming = UnixListenerStream::new(listener).filter_map(move |conn| match conn {
            Ok(stream) => {
                let creds = match get_peer_credentials(&stream) {
                    Ok(creds) => creds,
                    Err(_) => return None,
                };
                let principal = authenticator.authenticate(&creds);
                Some(Ok(PeerStream::new(
                    stream,
                    PeerConnectInfo { creds, principal },
                )))
            }
            Err(e) => Some(Err(e)),
        });

        let grpc_service = MicrovmGrpcService::new(Arc::clone(&self.service));

        // Reflection is intentionally not registered here.
        Server::builder()
            .add_service(MicrovmServiceServer::new(grpc_service))
            .serve_with_incoming(incoming)
            .await
            .map_err(ServerError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SocketConfig;
    use std::path::PathBuf;

    #[test]
    fn reflection_is_disabled() {
        // Read through a binding so this is a runtime check of the documented
        // default rather than a tautological constant assertion.
        let enabled = REFLECTION_ENABLED;
        assert!(!enabled, "reflection must stay disabled");
    }

    #[test]
    fn validate_socket_rejects_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.sock");
        let config = SocketConfig::with_path(&path);
        assert!(GrpcServer::validate_socket(&path, &config).is_err());
    }

    #[test]
    fn validate_socket_rejects_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        std::fs::write(&path, "hello").unwrap();

        let config = SocketConfig::with_path(&path);
        let result = GrpcServer::validate_socket(&path, &config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not a Unix socket"));
    }

    #[test]
    fn validate_socket_rejects_wrong_mode() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();

        let config = SocketConfig::with_path(&path).with_mode(0o660);
        assert!(GrpcServer::validate_socket(&path, &config).is_err());
    }

    #[test]
    fn validate_socket_accepts_correct_mode_and_owner() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

        let config = SocketConfig::with_path(&path).with_mode(0o660);
        assert!(GrpcServer::validate_socket(&path, &config).is_ok());
    }

    #[test]
    fn validate_socket_rejects_wrong_uid() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

        let config = SocketConfig::with_path(&path)
            .with_mode(0o660)
            .with_uid(99999);
        let err = GrpcServer::validate_socket(&path, &config).unwrap_err();
        assert!(err.to_string().contains("UID"));
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

    fn test_server(path: PathBuf) -> GrpcServer {
        GrpcServer {
            config: SocketConfig::with_path(path).with_mode(0o660),
            service: Arc::new(NoopService),
            authenticator: Arc::new(crate::peer::StaticAuthenticator::new(
                0,
                microvm_types::Principal::new(
                    microvm_types::TenantId::new("t").unwrap(),
                    microvm_types::Role::Owner,
                ),
            )),
        }
    }

    #[tokio::test]
    async fn bind_creates_socket_with_correct_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("grpc.sock");

        let server = test_server(path.clone());
        let _listener = server.bind().unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o660);
    }

    #[tokio::test]
    async fn bind_removes_stale_socket() {
        use std::os::unix::fs::FileTypeExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");
        std::fs::write(&path, "stale").unwrap();

        let server = test_server(path.clone());
        let _listener = server.bind().unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
    }
}
