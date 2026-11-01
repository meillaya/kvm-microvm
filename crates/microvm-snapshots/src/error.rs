//! Typed snapshot integrity and compatibility errors.
//!
//! Every failure the [`crate::gate::CompatibilityGate`] (or the manifest
//! integrity check) can produce is represented as a [`SnapshotError`] variant
//! *before* any Firecracker process is spawned or `/snapshot/load` is issued.
//! Each variant maps to a stable [`ErrorCode`] so it can be surfaced through
//! the platform's transport-neutral error contract via [`MicrovmError`].
//!
//! # Error-code mapping
//!
//! | Variant | ErrorCode |
//! |---|---|
//! | [`SnapshotError::UnsupportedSchema`] | [`ErrorCode::SnapshotIncompatible`] |
//! | [`SnapshotError::BinaryIncompatible`] | [`ErrorCode::SnapshotIncompatible`] |
//! | [`SnapshotError::CpuIncompatible`] | [`ErrorCode::SnapshotIncompatible`] |
//! | [`SnapshotError::KvmApiIncompatible`] | [`ErrorCode::SnapshotIncompatible`] |
//! | [`SnapshotError::CgroupIncompatible`] | [`ErrorCode::SnapshotIncompatible`] |
//! | [`SnapshotError::MemoryNotImmutable`] | [`ErrorCode::SnapshotIncompatible`] |
//! | [`SnapshotError::ForeignOwner`] | [`ErrorCode::PermissionDenied`] |
//! | [`SnapshotError::QuotaOverflow`] | [`ErrorCode::QuotaExceeded`] |
//! | [`SnapshotError::Integrity`] | [`ErrorCode::DigestMismatch`] |
//! | [`SnapshotError::MissingComponent`] | [`ErrorCode::DigestMismatch`] |
//!
//! Compatibility failures use [`ErrorCode::SnapshotIncompatible`] as required
//! by the platform plan. Hash-mismatch integrity failures use
//! [`ErrorCode::DigestMismatch`]; they are a distinct class from compatibility
//! and are never conflated with Firecracker's own (unauthenticated) CRC.

use microvm_artifacts::Digest;
use microvm_errors::{ErrorCode, MicrovmError};
use std::fmt;

/// A snapshot component whose content hash is verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotComponent {
    /// The guest kernel image.
    Kernel,
    /// The root filesystem image.
    Rootfs,
    /// A block-device backing file, keyed by Firecracker drive id.
    BlockDevice(String),
    /// The guest memory file.
    Memory,
    /// The Firecracker VM-state file.
    VmState,
}

impl SnapshotComponent {
    /// Stable `snake_case` identifier for use in error context.
    pub fn as_str(&self) -> String {
        match self {
            Self::Kernel => "kernel".to_string(),
            Self::Rootfs => "rootfs".to_string(),
            Self::BlockDevice(id) => format!("block_device:{}", id),
            Self::Memory => "memory".to_string(),
            Self::VmState => "vmstate".to_string(),
        }
    }
}

impl fmt::Display for SnapshotComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// A typed snapshot integrity or compatibility failure.
///
/// Produced by [`crate::gate::CompatibilityGate::validate`] and
/// [`crate::manifest::SnapshotManifest::verify_artifacts`]; it converts into
/// the platform's [`MicrovmError`] via [`From`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The manifest schema/format version is not supported.
    UnsupportedSchema {
        /// Version declared by the manifest.
        found: u32,
        /// Version(s) this build supports.
        supported: u32,
    },
    /// The manifest owner does not equal the caller tenant.
    ForeignOwner {
        /// Tenant recorded in the manifest.
        manifest_owner: String,
        /// Tenant of the caller attempting restore.
        caller: String,
    },
    /// The Firecracker binary version or hash does not match the pinned binary.
    BinaryIncompatible {
        /// Human-readable reason.
        reason: String,
    },
    /// The CPU compatibility envelope does not match the restore host.
    CpuIncompatible {
        /// Human-readable reason.
        reason: String,
    },
    /// The KVM API version does not match.
    KvmApiIncompatible {
        /// KVM API version recorded in the manifest.
        manifest: u32,
        /// KVM API version of the restore host.
        host: u32,
    },
    /// The cgroup version does not match (the platform requires cgroup v2).
    CgroupIncompatible {
        /// cgroup version recorded in the manifest.
        manifest: String,
        /// cgroup version of the restore host.
        host: String,
    },
    /// The manifest does not declare the memory file as immutable.
    MemoryNotImmutable,
    /// The snapshot's required resources overflow the caller tenant's quota.
    QuotaOverflow {
        /// Human-readable reason.
        reason: String,
    },
    /// A content hash did not match (the "snapshot integrity error").
    ///
    /// This is the typed integrity failure: a single flipped byte in the
    /// memory, VM-state, kernel, rootfs, or a block-device file produces this
    /// variant before any child process is spawned. It is detected via the
    /// orchestrator's own SHA-256 digests, not via Firecracker's CRC.
    Integrity {
        /// The component whose hash mismatched.
        component: SnapshotComponent,
        /// Expected digest recorded in the manifest.
        expected: Digest,
        /// Actual digest computed from on-disk content.
        actual: Digest,
    },
    /// A component recorded in the manifest is absent from the actual set
    /// (or vice versa), so its integrity cannot be verified.
    MissingComponent {
        /// The component that could not be matched.
        component: SnapshotComponent,
    },
}

impl SnapshotError {
    /// The stable [`ErrorCode`] this failure maps to.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedSchema { .. }
            | Self::BinaryIncompatible { .. }
            | Self::CpuIncompatible { .. }
            | Self::KvmApiIncompatible { .. }
            | Self::CgroupIncompatible { .. }
            | Self::MemoryNotImmutable => ErrorCode::SnapshotIncompatible,
            Self::ForeignOwner { .. } => ErrorCode::PermissionDenied,
            Self::QuotaOverflow { .. } => ErrorCode::QuotaExceeded,
            Self::Integrity { .. } | Self::MissingComponent { .. } => ErrorCode::DigestMismatch,
        }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { found, supported } => write!(
                f,
                "unsupported snapshot schema version {} (supported: {})",
                found, supported
            ),
            Self::ForeignOwner {
                manifest_owner,
                caller,
            } => write!(
                f,
                "snapshot owner '{}' does not match caller tenant '{}'",
                manifest_owner, caller
            ),
            Self::BinaryIncompatible { reason } => {
                write!(f, "firecracker binary incompatible: {}", reason)
            }
            Self::CpuIncompatible { reason } => write!(f, "cpu incompatible: {}", reason),
            Self::KvmApiIncompatible { manifest, host } => write!(
                f,
                "kvm api version mismatch (manifest {}, host {})",
                manifest, host
            ),
            Self::CgroupIncompatible { manifest, host } => write!(
                f,
                "cgroup version mismatch (manifest {}, host {})",
                manifest, host
            ),
            Self::MemoryNotImmutable => {
                write!(f, "snapshot memory file must be declared immutable")
            }
            Self::QuotaOverflow { reason } => write!(f, "snapshot quota overflow: {}", reason),
            Self::Integrity {
                component,
                expected,
                actual,
            } => write!(
                f,
                "snapshot integrity error: {} hash mismatch (expected {}, actual {})",
                component,
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::MissingComponent { component } => {
                write!(f, "snapshot component missing: {}", component)
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<SnapshotError> for MicrovmError {
    fn from(err: SnapshotError) -> Self {
        let code = err.code();
        let mut out = MicrovmError::new(code, err.to_string());
        match &err {
            SnapshotError::UnsupportedSchema { found, supported } => {
                out = out
                    .with_context("found", found.to_string())
                    .with_context("supported", supported.to_string());
            }
            SnapshotError::ForeignOwner {
                manifest_owner,
                caller,
            } => {
                out = out
                    .with_context("manifest_owner", manifest_owner.clone())
                    .with_context("caller", caller.clone());
            }
            SnapshotError::KvmApiIncompatible { manifest, host } => {
                out = out
                    .with_context("manifest", manifest.to_string())
                    .with_context("host", host.to_string());
            }
            SnapshotError::CgroupIncompatible { manifest, host } => {
                out = out
                    .with_context("manifest", manifest.clone())
                    .with_context("host", host.clone());
            }
            SnapshotError::Integrity {
                component,
                expected,
                actual,
            } => {
                out = out
                    .with_context("component", component.as_str())
                    .with_context("expected", expected.to_hex())
                    .with_context("actual", actual.to_hex());
            }
            SnapshotError::MissingComponent { component } => {
                out = out.with_context("component", component.as_str());
            }
            SnapshotError::BinaryIncompatible { .. }
            | SnapshotError::CpuIncompatible { .. }
            | SnapshotError::QuotaOverflow { .. }
            | SnapshotError::MemoryNotImmutable => {}
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_variants_map_to_snapshot_incompatible() {
        assert_eq!(
            SnapshotError::UnsupportedSchema {
                found: 2,
                supported: 1
            }
            .code(),
            ErrorCode::SnapshotIncompatible
        );
        assert_eq!(
            SnapshotError::BinaryIncompatible { reason: "x".into() }.code(),
            ErrorCode::SnapshotIncompatible
        );
        assert_eq!(
            SnapshotError::CpuIncompatible { reason: "x".into() }.code(),
            ErrorCode::SnapshotIncompatible
        );
        assert_eq!(
            SnapshotError::KvmApiIncompatible {
                manifest: 12,
                host: 13
            }
            .code(),
            ErrorCode::SnapshotIncompatible
        );
        assert_eq!(
            SnapshotError::CgroupIncompatible {
                manifest: "v1".into(),
                host: "v2".into()
            }
            .code(),
            ErrorCode::SnapshotIncompatible
        );
        assert_eq!(
            SnapshotError::MemoryNotImmutable.code(),
            ErrorCode::SnapshotIncompatible
        );
    }

    #[test]
    fn owner_quota_integrity_map_to_distinct_codes() {
        assert_eq!(
            SnapshotError::ForeignOwner {
                manifest_owner: "a".into(),
                caller: "b".into()
            }
            .code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            SnapshotError::QuotaOverflow { reason: "x".into() }.code(),
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            SnapshotError::MissingComponent {
                component: SnapshotComponent::Memory
            }
            .code(),
            ErrorCode::DigestMismatch
        );
    }

    #[test]
    fn integrity_error_converts_to_microvm_error_with_context() {
        let expected = Digest::from_hex(&"a".repeat(64)).unwrap();
        let actual = Digest::from_hex(&"b".repeat(64)).unwrap();
        let err = SnapshotError::Integrity {
            component: SnapshotComponent::Memory,
            expected,
            actual,
        };
        let m: MicrovmError = err.into();
        assert_eq!(m.code, ErrorCode::DigestMismatch);
        assert_eq!(
            m.context.get("component").map(String::as_str),
            Some("memory")
        );
        assert!(m.context.contains_key("expected"));
        assert!(m.context.contains_key("actual"));
    }

    #[test]
    fn component_as_str_is_stable() {
        assert_eq!(SnapshotComponent::Kernel.as_str(), "kernel");
        assert_eq!(SnapshotComponent::Rootfs.as_str(), "rootfs");
        assert_eq!(SnapshotComponent::Memory.as_str(), "memory");
        assert_eq!(SnapshotComponent::VmState.as_str(), "vmstate");
        assert_eq!(
            SnapshotComponent::BlockDevice("root".into()).as_str(),
            "block_device:root"
        );
    }
}
