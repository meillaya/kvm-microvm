//! Validated daemon configuration.
//!
//! The daemon reads one TOML file. Relative paths resolve against the
//! directory that holds the file, so a checkout can run from `.work/` without
//! writing outside the repository.

use microvm_types::{Role, TenantId};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The backend the daemon serves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Real Firecracker on KVM.
    #[default]
    Firecracker,
    /// In-memory simulation for tests and CLI exploration.
    Sim,
}

/// Control socket settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// REST/JSON Unix socket path.
    pub rest_socket: PathBuf,
    /// gRPC Unix socket path.
    pub grpc_socket: PathBuf,
    /// Octal socket mode, for example `"0600"`.
    #[serde(default = "default_socket_mode")]
    pub socket_mode: String,
    /// Socket owner UID. Defaults to the daemon's UID.
    #[serde(default)]
    pub socket_uid: Option<u32>,
    /// Socket owner GID. Defaults to the daemon's GID.
    #[serde(default)]
    pub socket_gid: Option<u32>,
    /// Peer UIDs allowed to call the API.
    pub allowed_uids: Vec<u32>,
    /// Tenant assigned to every allowed caller.
    pub tenant: String,
    /// Role assigned to every allowed caller.
    pub role: String,
}

/// The single guest image the daemon boots.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageConfig {
    /// Path to the guest kernel image.
    pub kernel: PathBuf,
    /// Path to the guest root filesystem image.
    pub rootfs: PathBuf,
    /// Kernel command line.
    #[serde(default = "default_boot_args")]
    pub boot_args: String,
}

/// Local state paths.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsConfig {
    /// Daemon state directory.
    pub state_dir: PathBuf,
    /// Root of the per-tenant artifact store.
    pub artifact_dir: PathBuf,
    /// Root of local snapshot files and manifests.
    pub snapshot_dir: PathBuf,
    /// Root of per-VM API sockets.
    pub socket_dir: PathBuf,
    /// Jailer chroot base.
    pub chroot_dir: PathBuf,
    /// Serial log directory.
    pub log_dir: PathBuf,
}

/// Runtime and readiness settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Path to the Firecracker binary.
    pub firecracker: PathBuf,
    /// Path to the jailer binary. Required only when `use_jailer` is true.
    #[serde(default)]
    pub jailer: Option<PathBuf>,
    /// Pinned Firecracker version recorded in snapshot manifests.
    #[serde(default = "default_firecracker_version")]
    pub firecracker_version: String,
    /// Readiness strategy: `auto`, `serial`, or `tcp`.
    #[serde(default = "default_readiness")]
    pub readiness: String,
    /// Serial marker printed by the guest image.
    #[serde(default = "default_readiness_marker")]
    pub readiness_marker: String,
    /// TCP port used by the health server in the guest.
    #[serde(default = "default_readiness_port")]
    pub readiness_port: u16,
    /// Time to wait for the Firecracker API socket.
    #[serde(default = "default_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
    /// Time to wait for guest readiness.
    #[serde(default = "default_readiness_timeout_ms")]
    pub readiness_timeout_ms: u64,
    /// Launch networked VMs under the jailer.
    #[serde(default = "default_use_jailer")]
    pub use_jailer: bool,
}

/// cgroup and jailer isolation settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationConfig {
    /// cgroup v2 root, normally `/sys/fs/cgroup` or a delegated subtree.
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: PathBuf,
    /// UID the jailer drops to.
    #[serde(default = "default_jailer_uid")]
    pub jailer_uid: u32,
    /// GID the jailer drops to.
    #[serde(default = "default_jailer_gid")]
    pub jailer_gid: u32,
    /// `pids.max` for each VM cgroup leaf.
    #[serde(default = "default_pids_max")]
    pub pids_max: u64,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            cgroup_root: default_cgroup_root(),
            jailer_uid: default_jailer_uid(),
            jailer_gid: default_jailer_gid(),
            pids_max: default_pids_max(),
        }
    }
}

/// The complete daemon configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Selected backend.
    #[serde(default)]
    pub backend: BackendKind,
    /// Control socket settings.
    pub server: ServerConfig,
    /// Guest image. Required for the Firecracker backend.
    #[serde(default)]
    pub image: Option<ImageConfig>,
    /// Local state paths.
    pub paths: PathsConfig,
    /// Runtime and readiness settings.
    pub runtime: RuntimeConfig,
    /// cgroup and jailer settings.
    #[serde(default)]
    pub isolation: IsolationConfig,
}

/// A configuration error with the field and reason.
#[derive(Debug)]
pub struct ConfigError {
    /// Human-readable error.
    pub message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

impl DaemonConfig {
    /// Load and validate a TOML config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::new(format!("cannot read config {}: {e}", path.display())))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let mut config: DaemonConfig = toml::from_str(&text)
            .map_err(|e| ConfigError::new(format!("invalid config {}: {e}", path.display())))?;
        config.resolve_paths(base);
        config.validate()?;
        Ok(config)
    }

    fn resolve_paths(&mut self, base: &Path) {
        fn resolve(base: &Path, path: &mut PathBuf) {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
        resolve(base, &mut self.server.rest_socket);
        resolve(base, &mut self.server.grpc_socket);
        if let Some(image) = &mut self.image {
            resolve(base, &mut image.kernel);
            resolve(base, &mut image.rootfs);
        }
        resolve(base, &mut self.paths.state_dir);
        resolve(base, &mut self.paths.artifact_dir);
        resolve(base, &mut self.paths.snapshot_dir);
        resolve(base, &mut self.paths.socket_dir);
        resolve(base, &mut self.paths.chroot_dir);
        resolve(base, &mut self.paths.log_dir);
        resolve(base, &mut self.runtime.firecracker);
        if let Some(jailer) = &mut self.runtime.jailer {
            resolve(base, jailer);
        }
        resolve(base, &mut self.isolation.cgroup_root);
    }

    /// Validate every field that can be checked without touching the host.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.rest_socket == self.server.grpc_socket {
            return Err(ConfigError::new(
                "rest_socket and grpc_socket must be different paths",
            ));
        }
        if self.server.allowed_uids.is_empty() {
            return Err(ConfigError::new("server.allowed_uids must not be empty"));
        }
        let mode = self.socket_mode()?;
        if mode & 0o002 != 0 {
            return Err(ConfigError::new(
                "server.socket_mode must not be world-writable",
            ));
        }
        TenantId::new(self.server.tenant.clone())
            .map_err(|e| ConfigError::new(format!("server.tenant is invalid: {}", e.reason)))?;
        self.role()?;
        match self.runtime.readiness.as_str() {
            "auto" | "serial" | "tcp" => {}
            other => {
                return Err(ConfigError::new(format!(
                    "runtime.readiness must be auto, serial, or tcp; got {other}"
                )))
            }
        }
        if self.runtime.use_jailer && self.runtime.jailer.is_none() {
            return Err(ConfigError::new(
                "runtime.jailer is required when runtime.use_jailer is true",
            ));
        }
        if self.backend == BackendKind::Firecracker {
            let image = self
                .image
                .as_ref()
                .ok_or_else(|| ConfigError::new("image is required for the firecracker backend"))?;
            if !image.kernel.is_file() {
                return Err(ConfigError::new(format!(
                    "image.kernel does not exist: {}",
                    image.kernel.display()
                )));
            }
            if !image.rootfs.is_file() {
                return Err(ConfigError::new(format!(
                    "image.rootfs does not exist: {}",
                    image.rootfs.display()
                )));
            }
            if !self.runtime.firecracker.is_file() {
                return Err(ConfigError::new(format!(
                    "runtime.firecracker does not exist: {}",
                    self.runtime.firecracker.display()
                )));
            }
        }
        Ok(())
    }

    /// Parse the octal socket mode.
    pub fn socket_mode(&self) -> Result<u32, ConfigError> {
        u32::from_str_radix(&self.server.socket_mode, 8).map_err(|_| {
            ConfigError::new(format!(
                "server.socket_mode is not octal: {}",
                self.server.socket_mode
            ))
        })
    }

    /// The configured tenant.
    pub fn tenant(&self) -> TenantId {
        TenantId::new(self.server.tenant.clone()).expect("tenant was validated")
    }

    /// The configured role.
    pub fn role(&self) -> Result<Role, ConfigError> {
        match self.server.role.as_str() {
            "owner" => Ok(Role::Owner),
            "operator" => Ok(Role::Operator),
            "viewer" => Ok(Role::Viewer),
            other => Err(ConfigError::new(format!(
                "server.role must be owner, operator, or viewer; got {other}"
            ))),
        }
    }
}

fn default_socket_mode() -> String {
    "0600".to_string()
}

fn default_boot_args() -> String {
    "console=ttyS0 reboot=k panic=1 pci=off init=/init".to_string()
}

fn default_firecracker_version() -> String {
    "1.16.1".to_string()
}

fn default_readiness() -> String {
    "auto".to_string()
}

fn default_readiness_marker() -> String {
    microvm_firecracker::DEFAULT_SERIAL_MARKER.to_string()
}

fn default_readiness_port() -> u16 {
    8080
}

fn default_socket_timeout_ms() -> u64 {
    10_000
}

fn default_readiness_timeout_ms() -> u64 {
    30_000
}

fn default_use_jailer() -> bool {
    true
}

fn default_cgroup_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

fn default_jailer_uid() -> u32 {
    microvm_firecracker::DEFAULT_JAILER_UID
}

fn default_jailer_gid() -> u32 {
    microvm_firecracker::DEFAULT_JAILER_GID
}

fn default_pids_max() -> u64 {
    microvm_firecracker::DEFAULT_PIDS_MAX
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("microvmd.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn sim_config_needs_no_image() {
        let (_dir, path) = write_config(
            r#"
backend = "sim"
[server]
rest_socket = "run/rest.sock"
grpc_socket = "run/grpc.sock"
allowed_uids = [1000]
tenant = "local"
role = "owner"
[paths]
state_dir = "state"
artifact_dir = "artifacts"
snapshot_dir = "snapshots"
socket_dir = "sockets"
chroot_dir = "jailer"
log_dir = "logs"
[runtime]
firecracker = "firecracker"
use_jailer = false
"#,
        );
        let config = DaemonConfig::load(&path).unwrap();
        assert_eq!(config.backend, BackendKind::Sim);
        assert!(config.server.rest_socket.is_absolute());
        assert_eq!(config.socket_mode().unwrap(), 0o600);
    }

    #[test]
    fn fancier_config_parses() {
        let (_dir, path) = write_config(
            r#"
backend = "sim"
[server]
rest_socket = "run/rest.sock"
grpc_socket = "run/grpc.sock"
socket_mode = "0660"
allowed_uids = [1000, 1001]
tenant = "local"
role = "owner"
[paths]
state_dir = "state"
artifact_dir = "artifacts"
snapshot_dir = "snapshots"
socket_dir = "sockets"
chroot_dir = "jailer"
log_dir = "logs"
[runtime]
firecracker = "firecracker"
use_jailer = false
readiness = "serial"
[isolation]
cgroup_root = "/sys/fs/cgroup"
"#,
        );
        let config = DaemonConfig::load(&path).unwrap();
        assert_eq!(config.socket_mode().unwrap(), 0o660);
        assert_eq!(config.server.allowed_uids.len(), 2);
    }

    #[test]
    fn world_writable_socket_mode_is_rejected() {
        let (_dir, path) = write_config(
            r#"
backend = "sim"
[server]
rest_socket = "run/rest.sock"
grpc_socket = "run/grpc.sock"
socket_mode = "0666"
allowed_uids = [1000]
tenant = "local"
role = "owner"
[paths]
state_dir = "state"
artifact_dir = "artifacts"
snapshot_dir = "snapshots"
socket_dir = "sockets"
chroot_dir = "jailer"
log_dir = "logs"
[runtime]
firecracker = "firecracker"
use_jailer = false
"#,
        );
        assert!(DaemonConfig::load(&path).is_err());
    }
}
