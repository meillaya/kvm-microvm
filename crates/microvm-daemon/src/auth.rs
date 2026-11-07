//! Peer authentication for both control transports.
//!
//! The daemon has one configured tenant and one role. Every UID in
//! `server.allowed_uids` maps to that principal; every other peer is denied.

use microvm_types::Principal;
use std::collections::HashSet;

/// UID allowlist shared by the REST and gRPC servers.
#[derive(Clone, Debug)]
pub struct AllowedUids {
    allowed: HashSet<u32>,
    principal: Principal,
}

impl AllowedUids {
    /// Build an allowlist that maps every allowed UID to `principal`.
    pub fn new(allowed: impl IntoIterator<Item = u32>, principal: Principal) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
            principal,
        }
    }

    fn permits(&self, uid: u32) -> bool {
        self.allowed.contains(&uid)
    }

    /// The principal assigned to allowed callers.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
}

impl microvm_rest::PeerAuthenticator for AllowedUids {
    fn authenticate(&self, creds: &microvm_rest::PeerCredentials) -> Option<Principal> {
        if self.permits(creds.uid) {
            Some(self.principal.clone())
        } else {
            None
        }
    }
}

impl microvm_grpc::PeerAuthenticator for AllowedUids {
    fn authenticate(&self, creds: &microvm_grpc::PeerCredentials) -> Option<Principal> {
        if self.permits(creds.uid) {
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

    fn principal() -> Principal {
        Principal::new(TenantId::new("local").unwrap(), Role::Owner)
    }

    #[test]
    fn allowed_uid_maps_to_principal() {
        let auth = AllowedUids::new([1000], principal());
        let creds = microvm_rest::PeerCredentials {
            pid: 1,
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(
            microvm_rest::PeerAuthenticator::authenticate(&auth, &creds),
            Some(principal())
        );
    }

    #[test]
    fn unknown_uid_is_denied() {
        let auth = AllowedUids::new([1000], principal());
        let creds = microvm_grpc::PeerCredentials {
            pid: 1,
            uid: 999,
            gid: 999,
        };
        assert_eq!(
            microvm_grpc::PeerAuthenticator::authenticate(&auth, &creds),
            None
        );
    }
}
