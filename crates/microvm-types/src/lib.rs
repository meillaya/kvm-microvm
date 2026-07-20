//! Typed identifiers, resource specifications, and tenancy types for the
//! kvm-microvm-orchestrator platform.
//!
//! This crate contains **no I/O and no host API calls**. All types are
//! validated at construction time and are safe to serialize/deserialize
//! across transport boundaries.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// ID validation
// ---------------------------------------------------------------------------

/// Maximum length in bytes for any identifier.
pub const MAX_ID_BYTES: usize = 64;

/// Error returned when an identifier fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIdError {
    /// Human-readable reason for rejection.
    pub reason: String,
}

impl fmt::Display for InvalidIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid identifier: {}", self.reason)
    }
}

impl std::error::Error for InvalidIdError {}

/// Validate a raw identifier string.
///
/// Rules:
/// - Must not be empty.
/// - Must not exceed [`MAX_ID_BYTES`] bytes.
/// - Must not contain `/`.
/// - Must not contain the substring `..`.
/// - Must not contain uppercase ASCII letters.
/// - Must contain only ASCII alphanumeric characters, `-`, `_`, or `.`.
fn validate_id(raw: &str) -> Result<(), InvalidIdError> {
    if raw.is_empty() {
        return Err(InvalidIdError {
            reason: "identifier must not be empty".to_string(),
        });
    }
    if raw.len() > MAX_ID_BYTES {
        return Err(InvalidIdError {
            reason: format!(
                "identifier exceeds maximum length of {} bytes (got {})",
                MAX_ID_BYTES,
                raw.len()
            ),
        });
    }
    if raw.contains('/') {
        return Err(InvalidIdError {
            reason: "identifier must not contain '/'".to_string(),
        });
    }
    if raw.contains("..") {
        return Err(InvalidIdError {
            reason: "identifier must not contain '..'".to_string(),
        });
    }
    if raw.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(InvalidIdError {
            reason: "identifier must not contain uppercase letters".to_string(),
        });
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(InvalidIdError {
            reason: "identifier contains invalid characters; allowed: a-z 0-9 - _ .".to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Macro for newtype IDs
// ---------------------------------------------------------------------------

macro_rules! define_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Create a new validated identifier.
            pub fn new(raw: impl Into<String>) -> Result<Self, InvalidIdError> {
                let s = raw.into();
                validate_id(&s)?;
                Ok(Self(s))
            }

            /// Return the identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidIdError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

define_id! {
    /// Unique identifier for a virtual machine instance.
    VmId
}

define_id! {
    /// Unique identifier for a bootable machine image.
    ImageId
}

define_id! {
    /// Unique identifier for a point-in-time VM snapshot.
    SnapshotId
}

define_id! {
    /// Unique identifier for a tenant (owner of resources).
    TenantId
}

// ---------------------------------------------------------------------------
// Network policy
// ---------------------------------------------------------------------------

/// Network egress policy applied to a VM's TAP interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No network interface is attached.
    #[default]
    None,
    /// NAT-only: VM can reach the host but not the external network.
    NatOnly,
    /// Full egress allowed through controlled NAT.
    EgressAllowed,
}

// ---------------------------------------------------------------------------
// Resource specification
// ---------------------------------------------------------------------------

/// Error returned when a [`ResourceSpec`] fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidResourceSpecError {
    /// Human-readable reason for rejection.
    pub reason: String,
}

impl fmt::Display for InvalidResourceSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid resource spec: {}", self.reason)
    }
}

impl std::error::Error for InvalidResourceSpecError {}

/// Resource allocation for a virtual machine.
///
/// All numeric fields are validated to be strictly greater than zero at
/// construction time.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceSpec {
    vcpu_count: u32,
    memory_mib: u64,
    disk_mib: u64,
    #[serde(default)]
    network_policy: NetworkPolicy,
}

impl ResourceSpec {
    /// Create a new validated resource specification.
    ///
    /// # Errors
    /// Returns [`InvalidResourceSpecError`] if any numeric field is zero.
    pub fn new(
        vcpu_count: u32,
        memory_mib: u64,
        disk_mib: u64,
        network_policy: NetworkPolicy,
    ) -> Result<Self, InvalidResourceSpecError> {
        if vcpu_count == 0 {
            return Err(InvalidResourceSpecError {
                reason: "vcpu_count must be greater than zero".to_string(),
            });
        }
        if memory_mib == 0 {
            return Err(InvalidResourceSpecError {
                reason: "memory_mib must be greater than zero".to_string(),
            });
        }
        if disk_mib == 0 {
            return Err(InvalidResourceSpecError {
                reason: "disk_mib must be greater than zero".to_string(),
            });
        }
        Ok(Self {
            vcpu_count,
            memory_mib,
            disk_mib,
            network_policy,
        })
    }

    /// Number of virtual CPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    /// Memory allocation in MiB.
    pub fn memory_mib(&self) -> u64 {
        self.memory_mib
    }

    /// Disk allocation in MiB.
    pub fn disk_mib(&self) -> u64 {
        self.disk_mib
    }

    /// Network egress policy.
    pub fn network_policy(&self) -> NetworkPolicy {
        self.network_policy
    }
}

// ---------------------------------------------------------------------------
// Principal / tenancy
// ---------------------------------------------------------------------------

/// Role a principal holds within a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full control including deletion and quota management.
    Owner,
    /// Can create, start, stop, and snapshot VMs.
    Operator,
    /// Read-only access to status and metrics.
    Viewer,
}

/// An authenticated actor scoped to a tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    tenant_id: TenantId,
    role: Role,
}

impl Principal {
    /// Create a new principal.
    pub fn new(tenant_id: TenantId, role: Role) -> Self {
        Self { tenant_id, role }
    }

    /// The tenant this principal belongs to.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The role held by this principal.
    pub fn role(&self) -> Role {
        self.role
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ID validation tests ------------------------------------------------

    #[test]
    fn valid_ids_accepted() {
        assert!(VmId::new("vm-001").is_ok());
        assert!(ImageId::new("img_abc123").is_ok());
        assert!(SnapshotId::new("snap.v2.20260101").is_ok());
        assert!(TenantId::new("tenant-42").is_ok());
    }

    #[test]
    fn empty_id_rejected() {
        assert!(VmId::new("").is_err());
    }

    #[test]
    fn id_exceeding_64_bytes_rejected() {
        let long = "a".repeat(65);
        assert!(VmId::new(long).is_err());
        // Exactly 64 is fine.
        let ok = "a".repeat(64);
        assert!(VmId::new(ok).is_ok());
    }

    #[test]
    fn id_with_slash_rejected() {
        assert!(VmId::new("vm/001").is_err());
    }

    #[test]
    fn id_with_dotdot_rejected() {
        assert!(VmId::new("vm..001").is_err());
        assert!(ImageId::new("../etc/passwd").is_err());
    }

    #[test]
    fn id_with_uppercase_rejected() {
        assert!(VmId::new("VM-001").is_err());
        assert!(TenantId::new("Tenant").is_err());
    }

    #[test]
    fn id_with_invalid_chars_rejected() {
        assert!(VmId::new("vm 001").is_err());
        assert!(VmId::new("vm@001").is_err());
        assert!(VmId::new("vm:001").is_err());
    }

    #[test]
    fn id_display_and_as_str() {
        let id = VmId::new("vm-001").unwrap();
        assert_eq!(id.as_str(), "vm-001");
        assert_eq!(id.to_string(), "vm-001");
    }

    // -- ResourceSpec tests -------------------------------------------------

    #[test]
    fn valid_resource_spec() {
        let spec = ResourceSpec::new(2, 512, 1024, NetworkPolicy::NatOnly).unwrap();
        assert_eq!(spec.vcpu_count(), 2);
        assert_eq!(spec.memory_mib(), 512);
        assert_eq!(spec.disk_mib(), 1024);
        assert_eq!(spec.network_policy(), NetworkPolicy::NatOnly);
    }

    #[test]
    fn zero_vcpu_rejected() {
        assert!(ResourceSpec::new(0, 512, 1024, NetworkPolicy::None).is_err());
    }

    #[test]
    fn zero_memory_rejected() {
        assert!(ResourceSpec::new(1, 0, 1024, NetworkPolicy::None).is_err());
    }

    #[test]
    fn zero_disk_rejected() {
        assert!(ResourceSpec::new(1, 512, 0, NetworkPolicy::None).is_err());
    }

    // -- Principal tests ----------------------------------------------------

    #[test]
    fn principal_accessors() {
        let tid = TenantId::new("tenant-1").unwrap();
        let p = Principal::new(tid.clone(), Role::Operator);
        assert_eq!(p.tenant_id(), &tid);
        assert_eq!(p.role(), Role::Operator);
    }

    // -- NetworkPolicy default ----------------------------------------------

    #[test]
    fn network_policy_default_is_none() {
        assert_eq!(NetworkPolicy::default(), NetworkPolicy::None);
    }
}
