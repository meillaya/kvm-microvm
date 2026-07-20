//! Socket configuration for the REST Unix socket server.

use std::path::PathBuf;

/// Default socket path for the REST API.
pub const DEFAULT_SOCKET_PATH: &str = "/run/microvm/api/rest.sock";

/// Default socket file mode: owner+group read/write only.
pub const DEFAULT_SOCKET_MODE: u32 = 0o660;

/// Configuration for the REST Unix domain socket.
#[derive(Clone, Debug)]
pub struct SocketConfig {
    /// Filesystem path for the Unix socket.
    pub path: PathBuf,
    /// Expected file mode (default `0660`).
    pub mode: u32,
    /// Expected owner UID. If `None`, the current process UID is used.
    pub expected_uid: Option<u32>,
    /// Expected group GID. If `None`, the current process GID is used.
    pub expected_gid: Option<u32>,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_SOCKET_PATH),
            mode: DEFAULT_SOCKET_MODE,
            expected_uid: None,
            expected_gid: None,
        }
    }
}

impl SocketConfig {
    /// Create a configuration with a custom socket path.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    /// Set the expected socket mode.
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// Set the expected owner UID.
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.expected_uid = Some(uid);
        self
    }

    /// Set the expected group GID.
    pub fn with_gid(mut self, gid: u32) -> Self {
        self.expected_gid = Some(gid);
        self
    }

    /// Resolve the expected UID (explicit or current process).
    pub fn resolve_uid(&self) -> u32 {
        self.expected_uid
            .unwrap_or_else(|| unsafe { libc::getuid() })
    }

    /// Resolve the expected GID (explicit or current process).
    pub fn resolve_gid(&self) -> u32 {
        self.expected_gid
            .unwrap_or_else(|| unsafe { libc::getgid() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_expected_path() {
        let cfg = SocketConfig::default();
        assert_eq!(cfg.path, PathBuf::from("/run/microvm/api/rest.sock"));
        assert_eq!(cfg.mode, 0o660);
        assert!(cfg.expected_uid.is_none());
        assert!(cfg.expected_gid.is_none());
    }

    #[test]
    fn builder_methods_set_fields() {
        let cfg = SocketConfig::with_path("/tmp/test.sock")
            .with_mode(0o600)
            .with_uid(1000)
            .with_gid(1000);
        assert_eq!(cfg.path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(cfg.mode, 0o600);
        assert_eq!(cfg.expected_uid, Some(1000));
        assert_eq!(cfg.expected_gid, Some(1000));
    }

    #[test]
    fn resolve_uses_explicit_values() {
        let cfg = SocketConfig::default().with_uid(42).with_gid(99);
        assert_eq!(cfg.resolve_uid(), 42);
        assert_eq!(cfg.resolve_gid(), 99);
    }
}
