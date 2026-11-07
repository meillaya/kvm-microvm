//! `microvmd`: a small Firecracker control plane over Unix sockets.

pub mod auth;
pub mod config;
pub mod host;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microvm_artifacts::ArtifactStore;
use microvm_firecracker::{
    AutoReadinessProbe, FirecrackerBackend, GuestReadinessProbe, HostPrerequisiteChecker,
    SerialMarkerProbe, TcpHealthProbe, TokioLauncher, UdsApiFactory,
};
use microvm_grpc::{GrpcServer, SocketConfig as GrpcSocketConfig};
use microvm_isolation::{CgroupManager, CleanupManager, NetManager, RealCleanupBackend};
use microvm_lifecycle::LifecycleService;
use microvm_metrics::MetricsCollector;
use microvm_rest::{RestServer, SocketConfig as RestSocketConfig};
use microvm_service::VmLifecycleService;
use microvm_sim::SimBackend;
use microvm_types::Principal;
use tokio::net::UnixListener;
use tokio::sync::oneshot;

use crate::auth::AllowedUids;
use crate::config::{BackendKind, DaemonConfig};
use crate::host::Prepared;

/// A daemon startup or runtime error.
#[derive(Debug)]
pub struct DaemonError {
    /// Human-readable error.
    pub message: String,
}

impl DaemonError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DaemonError {}

/// A running daemon.
pub struct DaemonHandle {
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    sockets: Vec<PathBuf>,
}

impl DaemonHandle {
    /// The socket paths this daemon serves.
    pub fn sockets(&self) -> &[PathBuf] {
        &self.sockets
    }

    /// Stop accepting requests, stop every VM, remove the sockets, and wait
    /// for the daemon task to finish.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.task.await;
        for path in &self.sockets {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Validate a config without writing or serving.
pub fn check(config: &DaemonConfig) -> Result<Vec<String>, DaemonError> {
    config
        .validate()
        .map_err(|e| DaemonError::new(e.to_string()))?;
    host::check(config).map_err(DaemonError::new)
}

/// Build the daemon, bind both sockets, and start serving.
pub async fn start(config: DaemonConfig) -> Result<DaemonHandle, DaemonError> {
    config
        .validate()
        .map_err(|e| DaemonError::new(e.to_string()))?;
    create_directories(&config)?;
    let prepared = host::prepare(&config).map_err(DaemonError::new)?;
    let principal = Principal::new(
        config.tenant(),
        config.role().map_err(|e| DaemonError::new(e.to_string()))?,
    );

    let (service, _backend): (Arc<dyn LifecycleService>, Option<Arc<FirecrackerBackend>>) =
        match config.backend {
            BackendKind::Sim => (Arc::new(SimBackend::new()), None),
            BackendKind::Firecracker => {
                let backend = build_firecracker(&config, &prepared)?;
                let service = Arc::new(
                    VmLifecycleService::builder()
                        .firecracker(backend.clone())
                        .build(),
                );
                (service, Some(backend))
            }
        };

    let auth = Arc::new(AllowedUids::new(
        config.server.allowed_uids.iter().copied(),
        principal.clone(),
    ));
    let rest_auth: Arc<dyn microvm_rest::PeerAuthenticator> = auth.clone();
    let grpc_auth: Arc<dyn microvm_grpc::PeerAuthenticator> = auth.clone();

    let mode = config
        .socket_mode()
        .map_err(|e| DaemonError::new(e.to_string()))?;
    let mut rest_config =
        RestSocketConfig::with_path(config.server.rest_socket.clone()).with_mode(mode);
    if let Some(uid) = config.server.socket_uid {
        rest_config = rest_config.with_uid(uid);
    }
    if let Some(gid) = config.server.socket_gid {
        rest_config = rest_config.with_gid(gid);
    }
    let mut grpc_config =
        GrpcSocketConfig::with_path(config.server.grpc_socket.clone()).with_mode(mode);
    if let Some(uid) = config.server.socket_uid {
        grpc_config = grpc_config.with_uid(uid);
    }
    if let Some(gid) = config.server.socket_gid {
        grpc_config = grpc_config.with_gid(gid);
    }

    let rest = RestServer::new(rest_config, Arc::clone(&service), rest_auth);
    let grpc = GrpcServer::new(grpc_config, Arc::clone(&service), grpc_auth);

    let rest_listener = rest.bind().map_err(|e| DaemonError::new(e.to_string()))?;
    let grpc_listener = match grpc.bind() {
        Ok(listener) => listener,
        Err(e) => {
            let _ = std::fs::remove_file(&config.server.rest_socket);
            return Err(DaemonError::new(e.to_string()));
        }
    };

    let sockets = vec![
        config.server.rest_socket.clone(),
        config.server.grpc_socket.clone(),
    ];
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(run_loop(
        rest,
        rest_listener,
        grpc,
        grpc_listener,
        service,
        principal,
        sockets.clone(),
        shutdown_rx,
    ));
    Ok(DaemonHandle {
        shutdown: shutdown_tx,
        task,
        sockets,
    })
}

/// Serve until SIGINT or SIGTERM, then stop VMs and remove the sockets.
pub async fn serve(config: DaemonConfig) -> Result<(), DaemonError> {
    let handle = start(config).await?;
    handle
        .task
        .await
        .map_err(|e| DaemonError::new(format!("daemon task failed: {e}")))?;
    Ok(())
}

fn create_directories(config: &DaemonConfig) -> Result<(), DaemonError> {
    for dir in [
        &config.paths.state_dir,
        &config.paths.artifact_dir,
        &config.paths.snapshot_dir,
        &config.paths.socket_dir,
        &config.paths.chroot_dir,
        &config.paths.log_dir,
    ] {
        std::fs::create_dir_all(dir)
            .map_err(|e| DaemonError::new(format!("cannot create {}: {e}", dir.display())))?;
    }
    Ok(())
}

fn build_firecracker(
    config: &DaemonConfig,
    prepared: &Prepared,
) -> Result<Arc<FirecrackerBackend>, DaemonError> {
    let boot = prepared
        .boot
        .clone()
        .ok_or_else(|| DaemonError::new("firecracker backend needs a prepared image"))?;
    let backend_config = host::backend_config(config, prepared);
    let cgroup = CgroupManager::new(config.isolation.cgroup_root.clone());
    let prereq = HostPrerequisiteChecker::builder()
        .firecracker_binary(config.runtime.firecracker.clone())
        .jailer_binary(
            config
                .runtime
                .jailer
                .clone()
                .unwrap_or_else(|| PathBuf::from("")),
        )
        .require_jailer(config.runtime.use_jailer)
        .cgroup(cgroup.clone())
        .build();
    let artifacts = ArtifactStore::new(config.paths.artifact_dir.clone())
        .map_err(|e| DaemonError::new(e.to_string()))?;
    let cleanup = CleanupManager::new(
        config.isolation.cgroup_root.clone(),
        config.paths.chroot_dir.clone(),
        config.paths.socket_dir.clone(),
    );
    let metrics = Arc::new(MetricsCollector::host_only(
        config.isolation.cgroup_root.clone(),
        "/sys",
    ));
    let probe: Arc<dyn GuestReadinessProbe> = match config.runtime.readiness.as_str() {
        "serial" => Arc::new(SerialMarkerProbe::new(
            config.runtime.readiness_marker.clone(),
        )),
        "tcp" => Arc::new(TcpHealthProbe::new(config.runtime.readiness_port)),
        _ => Arc::new(AutoReadinessProbe::new(
            config.runtime.readiness_port,
            config.runtime.readiness_marker.clone(),
        )),
    };

    let backend = FirecrackerBackend::builder()
        .config(backend_config)
        .launcher(Arc::new(TokioLauncher::new()))
        .api_factory(Arc::new(UdsApiFactory))
        .probe(probe)
        .prereq(Arc::new(prereq))
        .cleanup_backend(Arc::new(RealCleanupBackend::new()))
        .artifacts(artifacts)
        .cgroup(cgroup)
        .net(NetManager::new("/var/run/netns"))
        .cleanup(cleanup)
        .metrics(metrics)
        .default_boot(boot)
        .build();
    Ok(Arc::new(backend))
}

#[allow(clippy::too_many_arguments)]
async fn run_loop(
    rest: RestServer,
    rest_listener: UnixListener,
    grpc: GrpcServer,
    grpc_listener: UnixListener,
    service: Arc<dyn LifecycleService>,
    principal: Principal,
    sockets: Vec<PathBuf>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut rest_task = tokio::spawn(async move { rest.serve_with_listener(rest_listener).await });
    let mut grpc_task = tokio::spawn(async move { grpc.serve_with_listener(grpc_listener).await });
    let mut sigterm = signal_stream(libc::SIGTERM);
    let mut sigint = signal_stream(libc::SIGINT);

    let shutdown_requested = tokio::select! {
        _ = &mut shutdown => "shutdown",
        _ = wait_signal(&mut sigterm) => "SIGTERM",
        _ = wait_signal(&mut sigint) => "SIGINT",
        result = &mut rest_task => {
            if let Ok(Err(e)) = result {
                eprintln!("microvmd: REST server stopped: {e}");
            }
            "rest stopped"
        }
        result = &mut grpc_task => {
            if let Ok(Err(e)) = result {
                eprintln!("microvmd: gRPC server stopped: {e}");
            }
            "grpc stopped"
        }
    };
    eprintln!("microvmd: shutting down ({shutdown_requested})");

    if let Ok(vms) = service.list(&principal).await {
        for vm in vms {
            if matches!(
                vm.state,
                microvm_lifecycle::VmState::Running | microvm_lifecycle::VmState::Paused
            ) {
                if let Err(e) = service.stop(&vm.vm_id, &principal).await {
                    eprintln!("microvmd: failed to stop {} during shutdown: {e}", vm.vm_id);
                }
            }
        }
    }
    rest_task.abort();
    grpc_task.abort();
    for path in &sockets {
        let _ = std::fs::remove_file(path);
    }
}

fn signal_stream(signum: libc::c_int) -> Option<tokio::signal::unix::Signal> {
    use tokio::signal::unix::{signal, SignalKind};
    let kind = SignalKind::from_raw(signum);
    signal(kind).ok()
}

async fn wait_signal(signal: &mut Option<tokio::signal::unix::Signal>) {
    match signal {
        Some(signal) => {
            let _ = signal.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// A simple default for the daemon task timeout used by tests.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_types::{Role, TenantId};

    #[test]
    fn daemon_error_displays() {
        let err = DaemonError::new("boom");
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn principal_types_are_reexported_through_config() {
        let tenant = TenantId::new("local").unwrap();
        let principal = Principal::new(tenant, Role::Owner);
        assert_eq!(principal.role(), Role::Owner);
    }
}
