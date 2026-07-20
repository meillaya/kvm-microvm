//! Peer credential extraction, authentication, and per-connection principal
//! propagation for the gRPC Unix domain socket.
//!
//! This is the gRPC counterpart of the REST crate's `peer` module and uses the
//! *same* authentication mechanism: `SO_PEERCRED` is read from the connected
//! socket before any authorization decision, and a [`PeerAuthenticator`] maps
//! the peer UID/GID to a [`Principal`]. The authenticated principal is then
//! carried into every tonic request via the [`Connected`] implementation on
//! [`PeerStream`], so service handlers can enforce the same ownership policy as
//! REST.

use microvm_types::Principal;
use std::io;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tonic::transport::server::Connected;

// ---------------------------------------------------------------------------
// Peer credentials (SO_PEERCRED)
// ---------------------------------------------------------------------------

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
/// Must be called before any authorization decision. This is byte-for-byte the
/// same mechanism the REST transport uses.
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
                io::Error::last_os_error()
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

// ---------------------------------------------------------------------------
// Authentication policy
// ---------------------------------------------------------------------------

/// Trait for mapping peer credentials to an authenticated [`Principal`].
///
/// Implementations define the platform's authentication policy: how a Unix
/// UID/GID maps to a tenant identity and role. Identical contract to the REST
/// transport's authenticator so both transports share one policy shape.
pub trait PeerAuthenticator: Send + Sync {
    /// Authenticate a peer and return the corresponding principal.
    ///
    /// Returns `None` if the peer is not authorized to access the API.
    fn authenticate(&self, creds: &PeerCredentials) -> Option<Principal>;
}

/// A simple UID-based authenticator that maps a fixed UID to a principal.
///
/// Useful for single-tenant deployments or testing.
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

/// An authenticator that accepts only UID 0 (root), mapping it to a
/// configurable principal.
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

// ---------------------------------------------------------------------------
// Per-connection principal propagation into tonic
// ---------------------------------------------------------------------------

/// Connection metadata propagated into every tonic request's extensions.
///
/// tonic inserts the [`Connected::ConnectInfo`] value into each request's
/// extensions; service handlers read it to recover the authenticated principal
/// (or detect an unauthenticated peer).
#[derive(Clone, Debug)]
pub struct PeerConnectInfo {
    /// Raw peer credentials captured via `SO_PEERCRED`.
    pub creds: PeerCredentials,
    /// Authenticated principal, or `None` if the peer failed authentication.
    pub principal: Option<Principal>,
}

/// A accepted Unix stream paired with its authenticated peer metadata.
///
/// Wraps the raw [`UnixStream`] and implements tonic's [`Connected`] so the
/// [`PeerConnectInfo`] is available to handlers via request extensions. I/O is
/// delegated straight through to the inner stream.
pub struct PeerStream {
    inner: UnixStream,
    info: PeerConnectInfo,
}

impl PeerStream {
    /// Wrap an accepted stream with its already-authenticated peer metadata.
    pub fn new(inner: UnixStream, info: PeerConnectInfo) -> Self {
        Self { inner, info }
    }

    /// The peer metadata associated with this connection.
    pub fn info(&self) -> &PeerConnectInfo {
        &self.info
    }
}

impl AsyncRead for PeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connected for PeerStream {
    type ConnectInfo = PeerConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
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
    fn peer_connect_info_carries_principal() {
        let info = PeerConnectInfo {
            creds: PeerCredentials {
                pid: 1,
                uid: 0,
                gid: 0,
            },
            principal: Some(test_principal()),
        };
        assert!(info.principal.is_some());
        assert_eq!(info.creds.uid, 0);
    }
}
