//! Constrained **local** OCI-like image importer and `microvm run` interface.
//!
//! This crate turns a local, digest-pinned OCI-like image layout into a typed
//! [`MicroVmSpec`] (kernel layer, rootfs layer, and resource limits) that the
//! rest of the platform can boot. It is a **constrained import surface, not an
//! OCI runtime**, and it makes no claim of OCI runtime compatibility.
//!
//! # Guarantees
//! - **Local only.** Remote and tag-only references (`https://…`, `docker://…`,
//!   `oci://…`, `repo/img@sha256:…`, `nginx:latest`) are rejected with
//!   [`ImportError::RemoteReference`] before any I/O. The crate performs no
//!   network I/O and has no remote client dependency.
//! - **Every layer hash is verified.** The config blob and every layer blob are
//!   read through the descriptor-relative artifact resolver and checked against
//!   their declared SHA-256 digest and size; the first mismatch fails closed
//!   with [`ImportError::DigestMismatch`] / [`ImportError::SizeMismatch`].
//! - **Platform selection.** Only `linux/amd64` and `linux/arm64` are accepted
//!   ([`Platform`]); anything else is rejected with
//!   [`ImportError::UnsupportedPlatform`].
//! - **Hard refusal of host-side knobs.** Host mounts, host network/PID/IPC
//!   sharing, privileged mode, capability additions, and arbitrary host process
//!   controls are rejected with [`ImportError::Forbidden`] regardless of where
//!   they appear in the manifest or image config.
//! - **Typed rejections.** Every failure is an [`ImportError`] variant mapping
//!   to a stable [`microvm_errors::ErrorCode`].
//!
//! # Layout convention
//! ```text
//! <layout-root>/
//!   manifest.json          OCI image manifest (schemaVersion 2)
//!   blobs/sha256/<hex>     config + layer blobs, named by digest
//! ```
//! Layers declare their guest role with the `org.microvm.media` annotation
//! (`kernel` or `rootfs`); the microVM resource spec is carried by
//! `org.microvm.*` labels in the image config.
//!
//! [`MicroVmSpec`]: spec::MicroVmSpec
//! [`Platform`]: platform::Platform

pub mod config;
pub mod error;
pub mod help;
pub mod importer;
pub mod manifest;
pub mod platform;
pub mod reference;
pub mod spec;

pub use config::{
    MicroVmResources, OciContainerConfig, OciImageConfig, OciRootfs, DEFAULT_BOOT_ARGS,
    DEFAULT_DISK_MIB, DEFAULT_MEMORY_MIB, DEFAULT_VCPU, LABEL_BOOT_ARGS, LABEL_DISK_MIB,
    LABEL_MEMORY_MIB, LABEL_NETWORK, LABEL_VCPU,
};
pub use error::{ForbiddenField, ImportError};
pub use help::{run_help_text, RUN_LONG_ABOUT, RUN_SHORT_ABOUT};
pub use importer::{OciImporter, MANIFEST_RELPATH, ROLE_KERNEL, ROLE_ROOTFS};
pub use manifest::{
    blob_rel_path, parse_sha256_digest, OciDescriptor, OciManifest, OciPlatform, MEDIA_ANNOTATION,
    REQUIRED_SCHEMA_VERSION,
};
pub use platform::Platform;
pub use reference::validate_local_reference;
pub use spec::{LayerRef, MicroVmSpec};
