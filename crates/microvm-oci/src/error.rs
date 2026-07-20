//! Typed rejection reasons for the constrained local OCI-like importer.
//!
//! Every failure mode of [`crate::importer::OciImporter`] is expressed as a
//! distinct [`ImportError`] variant so callers (and the `microvm run` CLI) can
//! match on *why* an import was refused without parsing messages. Each variant
//! maps onto a stable [`ErrorCode`] and converts losslessly into a
//! [`MicrovmError`] for transport across the Unix-socket APIs.
//!
//! The importer is a **constrained local import** surface, not an OCI runtime;
//! the variants deliberately encode the things it refuses to do: pull remote
//! references, apply host mounts, add capabilities, honour privileged/host
//! namespaces, or apply arbitrary host process controls.

use microvm_artifacts::MediaKind;
use microvm_errors::{ErrorCode, MicrovmError};
use std::fmt;

/// A runtime field the constrained importer refuses to apply to the host.
///
/// These correspond to OCI runtime-spec / compose knobs that would let an
/// imported image dictate host-side process, namespace, or device behaviour.
/// The importer is fail-closed: if any of these keys appear anywhere in the
/// imported manifest or image config, the import is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForbiddenField {
    /// A host or bind mount (`mounts` / `mount`).
    Mounts,
    /// A capability addition or set (`capabilities`, `cap_add`, `cap_drop`).
    Capabilities,
    /// A privileged-mode request (`privileged`).
    Privileged,
    /// Host network sharing (`host_network`, `network_mode`).
    HostNetwork,
    /// Host PID namespace sharing (`host_pid`, `pid_mode`).
    HostPid,
    /// Host IPC namespace sharing (`host_ipc`, `ipc_mode`).
    HostIpc,
    /// Arbitrary host process control (`process`, `rlimits`, `devices`,
    /// `sysctls`, `oom_score_adj`, LSM profiles).
    HostProcessControl,
}

impl ForbiddenField {
    /// Stable `snake_case` name used in error context.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mounts => "mounts",
            Self::Capabilities => "capabilities",
            Self::Privileged => "privileged",
            Self::HostNetwork => "host_network",
            Self::HostPid => "host_pid",
            Self::HostIpc => "host_ipc",
            Self::HostProcessControl => "host_process_control",
        }
    }
}

impl fmt::Display for ForbiddenField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed reason a constrained local OCI import was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// A remote or tag-only reference was supplied where a local,
    /// digest-pinned layout is required (`https://…`, `docker://…`,
    /// `nginx:latest`, `repo/img@sha256:…`).
    RemoteReference {
        /// The offending reference string.
        reference: String,
        /// Why it was classified as non-local.
        reason: String,
    },
    /// A descriptor carried remote `urls` for out-of-band blob retrieval.
    RemoteDescriptor {
        /// Digest of the descriptor that referenced remote URLs.
        digest: String,
    },
    /// The manifest bytes did not parse or violated the constrained schema
    /// (wrong `schemaVersion`, empty layers, malformed digest).
    ManifestInvalid {
        /// Human-readable reason.
        reason: String,
    },
    /// The image config blob did not parse into the constrained config shape.
    ConfigInvalid {
        /// Human-readable reason.
        reason: String,
    },
    /// A digest string was not a well-formed `sha256:<64 hex>` value.
    MalformedDigest {
        /// The offending digest string.
        value: String,
    },
    /// The image platform is not one of the supported targets.
    UnsupportedPlatform {
        /// The `os` value from the image config.
        os: String,
        /// The `architecture` value from the image config.
        architecture: String,
    },
    /// The requested platform did not match the image config platform.
    PlatformMismatch {
        /// The platform the caller asked for.
        requested: String,
        /// The platform the image config declares.
        actual: String,
    },
    /// A forbidden runtime field was present in the imported document.
    Forbidden {
        /// The category of forbidden field.
        field: ForbiddenField,
        /// The exact offending key as it appeared in the document.
        key: String,
    },
    /// A blob's content did not hash to its declared digest.
    DigestMismatch {
        /// Digest of the blob that failed verification.
        digest: String,
        /// Declared (expected) hex digest.
        expected: String,
        /// Actual computed hex digest.
        actual: String,
    },
    /// A blob's byte length did not match its declared size.
    SizeMismatch {
        /// Digest of the blob that failed verification.
        digest: String,
        /// Declared (expected) size in bytes.
        expected: u64,
        /// Actual size in bytes.
        actual: u64,
    },
    /// A referenced blob was not present in the local layout.
    BlobNotFound {
        /// Digest of the missing blob.
        digest: String,
    },
    /// No layer was annotated as the requested guest media.
    MissingMedia {
        /// The media role that was absent.
        media: MediaKind,
    },
    /// More than one layer was annotated as the same guest media.
    DuplicateMedia {
        /// The media role that appeared more than once.
        media: MediaKind,
    },
    /// The resource specification derived from image labels was invalid.
    InvalidResources {
        /// Human-readable reason.
        reason: String,
    },
    /// An underlying artifact-store / I/O error (path escape, open failure).
    Artifact(MicrovmError),
}

impl ImportError {
    /// The stable [`ErrorCode`] this rejection maps to.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::RemoteReference { .. } | Self::RemoteDescriptor { .. } => {
                ErrorCode::LocalArtifactRequired
            }
            Self::ManifestInvalid { .. }
            | Self::ConfigInvalid { .. }
            | Self::MalformedDigest { .. }
            | Self::UnsupportedPlatform { .. }
            | Self::PlatformMismatch { .. }
            | Self::MissingMedia { .. }
            | Self::DuplicateMedia { .. }
            | Self::InvalidResources { .. } => ErrorCode::InvalidResourceSpec,
            Self::Forbidden { .. } => ErrorCode::PermissionDenied,
            Self::DigestMismatch { .. } | Self::SizeMismatch { .. } => ErrorCode::DigestMismatch,
            Self::BlobNotFound { .. } => ErrorCode::ArtifactNotFound,
            Self::Artifact(err) => err.code,
        }
    }

    /// A short human-readable description of the rejection.
    fn message(&self) -> String {
        match self {
            Self::RemoteReference { reference, reason } => {
                format!("local digest-pinned layout required: {reason} ({reference})")
            }
            Self::RemoteDescriptor { digest } => {
                format!("descriptor {digest} references remote urls; remote blob retrieval is not permitted")
            }
            Self::ManifestInvalid { reason } => format!("invalid local OCI manifest: {reason}"),
            Self::ConfigInvalid { reason } => format!("invalid image config: {reason}"),
            Self::MalformedDigest { value } => {
                format!("malformed digest (want sha256:<64 hex>): {value}")
            }
            Self::UnsupportedPlatform { os, architecture } => {
                format!(
                    "unsupported platform {os}/{architecture}; supported: linux/amd64, linux/arm64"
                )
            }
            Self::PlatformMismatch { requested, actual } => {
                format!("requested platform {requested} does not match image platform {actual}")
            }
            Self::Forbidden { field, key } => {
                format!(
                    "forbidden runtime field '{}' (category {}); constrained import does not apply it",
                    key,
                    field.as_str()
                )
            }
            Self::DigestMismatch {
                digest,
                expected,
                actual,
            } => format!("layer {digest} digest mismatch: expected {expected}, got {actual}"),
            Self::SizeMismatch {
                digest,
                expected,
                actual,
            } => format!("layer {digest} size mismatch: expected {expected}, got {actual}"),
            Self::BlobNotFound { digest } => format!("blob not found in local layout: {digest}"),
            Self::MissingMedia { media } => {
                format!("no layer annotated as guest {}", media.as_str())
            }
            Self::DuplicateMedia { media } => {
                format!("more than one layer annotated as guest {}", media.as_str())
            }
            Self::InvalidResources { reason } => {
                format!("invalid microvm resource specification: {reason}")
            }
            Self::Artifact(err) => err.message.clone(),
        }
    }

    /// Convert into a structured [`MicrovmError`] with typed context.
    pub fn to_microvm_error(&self) -> MicrovmError {
        let mut err = MicrovmError::new(self.code(), self.message());
        match self {
            Self::RemoteReference { reference, .. } => {
                err = err.with_context("reference", reference.clone());
            }
            Self::RemoteDescriptor { digest } | Self::BlobNotFound { digest } => {
                err = err.with_context("digest", digest.clone());
            }
            Self::Forbidden { field, key } => {
                err = err
                    .with_context("forbidden_field", field.as_str())
                    .with_context("key", key.clone());
            }
            Self::DigestMismatch {
                digest,
                expected,
                actual,
            } => {
                err = err
                    .with_context("digest", digest.clone())
                    .with_context("expected", expected.clone())
                    .with_context("actual", actual.clone());
            }
            Self::SizeMismatch {
                digest,
                expected,
                actual,
            } => {
                err = err
                    .with_context("digest", digest.clone())
                    .with_context("expected", expected.to_string())
                    .with_context("actual", actual.to_string());
            }
            Self::UnsupportedPlatform { os, architecture } => {
                err = err
                    .with_context("os", os.clone())
                    .with_context("architecture", architecture.clone());
            }
            Self::PlatformMismatch { requested, actual } => {
                err = err
                    .with_context("requested", requested.clone())
                    .with_context("actual", actual.clone());
            }
            Self::MissingMedia { media } | Self::DuplicateMedia { media } => {
                err = err.with_context("media", media.as_str());
            }
            _ => {}
        }
        err
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code().as_str(), self.message())
    }
}

impl std::error::Error for ImportError {}

impl From<ImportError> for MicrovmError {
    fn from(err: ImportError) -> Self {
        err.to_microvm_error()
    }
}

impl From<MicrovmError> for ImportError {
    fn from(err: MicrovmError) -> Self {
        Self::Artifact(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_reference_maps_to_local_artifact_required() {
        let err = ImportError::RemoteReference {
            reference: "nginx:latest".to_string(),
            reason: "tag-only references are not permitted".to_string(),
        };
        assert_eq!(err.code(), ErrorCode::LocalArtifactRequired);
        let m: MicrovmError = err.into();
        assert_eq!(m.code, ErrorCode::LocalArtifactRequired);
        assert_eq!(
            m.context.get("reference").map(String::as_str),
            Some("nginx:latest")
        );
    }

    #[test]
    fn forbidden_maps_to_permission_denied_with_context() {
        let err = ImportError::Forbidden {
            field: ForbiddenField::Privileged,
            key: "privileged".to_string(),
        };
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        let m = err.to_microvm_error();
        assert_eq!(
            m.context.get("forbidden_field").map(String::as_str),
            Some("privileged")
        );
        assert_eq!(m.context.get("key").map(String::as_str), Some("privileged"));
    }

    #[test]
    fn digest_mismatch_maps_to_digest_mismatch() {
        let err = ImportError::DigestMismatch {
            digest: "sha256:aa".to_string(),
            expected: "aa".to_string(),
            actual: "bb".to_string(),
        };
        assert_eq!(err.code(), ErrorCode::DigestMismatch);
    }

    #[test]
    fn blob_not_found_maps_to_artifact_not_found() {
        let err = ImportError::BlobNotFound {
            digest: "sha256:cc".to_string(),
        };
        assert_eq!(err.code(), ErrorCode::ArtifactNotFound);
    }

    #[test]
    fn artifact_error_passes_through_its_code() {
        let inner = MicrovmError::new(ErrorCode::PathEscape, "escape");
        let err = ImportError::from(inner.clone());
        assert_eq!(err.code(), ErrorCode::PathEscape);
        assert_eq!(err.to_microvm_error(), inner);
    }

    #[test]
    fn display_includes_code_prefix() {
        let err = ImportError::UnsupportedPlatform {
            os: "windows".to_string(),
            architecture: "amd64".to_string(),
        };
        let s = err.to_string();
        assert!(s.starts_with("[invalid_resource_spec]"), "got: {s}");
        assert!(s.contains("windows/amd64"));
    }

    #[test]
    fn forbidden_field_names_are_stable() {
        assert_eq!(ForbiddenField::Mounts.as_str(), "mounts");
        assert_eq!(ForbiddenField::Capabilities.as_str(), "capabilities");
        assert_eq!(ForbiddenField::Privileged.as_str(), "privileged");
        assert_eq!(ForbiddenField::HostNetwork.as_str(), "host_network");
        assert_eq!(ForbiddenField::HostPid.as_str(), "host_pid");
        assert_eq!(ForbiddenField::HostIpc.as_str(), "host_ipc");
        assert_eq!(
            ForbiddenField::HostProcessControl.as_str(),
            "host_process_control"
        );
    }
}
