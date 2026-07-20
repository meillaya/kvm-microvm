//! Peer credential extraction and authentication for Unix domain sockets.
//!
//! Uses `SO_PEERCRED` to extract the UID/GID of the connecting process
//! before any authorization decision is made.

use microvm_types::Principal;
use std::os::unix::io::AsRawFd;

/// Peer credentials extracted from a Unix domain socket via `SO_PEERCRED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Process ID of the peer.
    pub pid: i32,
    /// User ID of the peer process.
    pub uid: u32,
    /// Group ID of the peer process.
    pub gid: u32,
}

/// Error returned when peer credential extraction fails.
#[derive(Debug)]
pub struct PeerCredError {
    /// Human-readable reason.
    pub reason: String,
}

impl std::fmt::Display for PeerCredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer credential error: {}", self.reason)
    }
}

impl std::error::Error for PeerCredError {}

/// Extract peer credentials from a connected Unix stream socket.
///
/// Calls `getsockopt(SOL_SOCKET, SO_PEERCRED)` on the file descriptor.
/// Must be called before any authorization decision.
pub fn get_peer_credentials(stream: &impl AsRawFd) -> Result<PeerCredentials, PeerCredError> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(PeerCredError {
            reason: format!(
                "getsockopt(SO_PEERCRED) failed: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(PeerCredError {
            reason: format!(
                "SO_PEERCRED returned unexpected length: {} (expected {})",
                len,
                std::mem::size_of::<libc::ucred>()
            ),
        });
    }

    Ok(PeerCredentials {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Trait for mapping peer credentials to an authenticated [`Principal`].
///
/// Implementations define the platform's authentication policy: how a
/// Unix UID/GID maps to a tenant identity and role. This keeps the REST
/// layer transport-focused without duplicating business policy.
pub trait PeerAuthenticator: Send + Sync {
    /// Authenticate a peer and return the corresponding principal.
    ///
    /// Returns `None` if the peer is not authorized to access the API.
    fn authenticate(&self, creds: &PeerCredentials) -> Option<Principal>;
}

/// A simple UID-based authenticator that maps a fixed UID to a principal.
///
/// Useful for single-tenant deployments or testing. Production deployments
/// should implement a richer mapping (e.g., from a tenant registry).
#[derive(Clone, Debug)]
pub struct StaticAuthenticator {
    /// The UID that is allowed to connect.
    pub allowed_uid: u32,
    /// The principal to assign to the allowed UID.
    pub principal: Principal,
}

impl StaticAuthenticator {
    /// Create a new static authenticator.
    pub fn new(allowed_uid: u32, principal: Principal) -> Self {
        Self {
            allowed_uid,
            principal,
        }
    }
}

impl PeerAuthenticator for StaticAuthenticator {
    fn authenticate(&self, creds: &PeerCredentials) -> Option<Principal> {
        if creds.uid == self.allowed_uid {
            Some(self.principal.clone())
        } else {
            None
        }
    }
}

/// An authenticator that accepts any peer and maps UID 0 (root) to a
/// configurable principal, rejecting all others.
///
/// This is the default for privileged daemon deployments where only root
/// (or the service user) should access the control socket.
#[derive(Clone, Debug)]
pub struct RootOnlyAuthenticator {
    /// The principal assigned to the root user.
    pub principal: Principal,
}

impl RootOnlyAuthenticator {
    /// Create a new root-only authenticator.
    pub fn new(principal: Principal) -> Self {
        Self { principal }
    }
}

impl PeerAuthenticator for RootOnlyAuthenticator {
    fn authenticate(&self, creds: &PeerCredentials) -> Option<Principal> {
        if creds.uid == 0 {
            Some(self.principal.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_types::{Role, TenantId};

    fn test_principal() -> Principal {
        Principal::new(TenantId::new("test-tenant").unwrap(), Role::Owner)
    }

    #[test]
    fn static_authenticator_accepts_matching_uid() {
        let auth = StaticAuthenticator::new(1000, test_principal());
        let creds = PeerCredentials {
            pid: 123,
            uid: 1000,
            gid: 1000,
        };
        assert!(auth.authenticate(&creds).is_some());
    }

    #[test]
    fn static_authenticator_rejects_wrong_uid() {
        let auth = StaticAuthenticator::new(1000, test_principal());
        let creds = PeerCredentials {
            pid: 123,
            uid: 9999,
            gid: 1000,
        };
        assert!(auth.authenticate(&creds).is_none());
    }

    #[test]
    fn root_only_authenticator_accepts_uid_zero() {
        let auth = RootOnlyAuthenticator::new(test_principal());
        let creds = PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        assert!(auth.authenticate(&creds).is_some());
    }

    #[test]
    fn root_only_authenticator_rejects_non_root() {
        let auth = RootOnlyAuthenticator::new(test_principal());
        let creds = PeerCredentials {
            pid: 123,
            uid: 1000,
            gid: 1000,
        };
        assert!(auth.authenticate(&creds).is_none());
    }

    #[test]
    fn peer_credentials_equality() {
        let a = PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let b = PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        assert_eq!(a, b);
    }
}
