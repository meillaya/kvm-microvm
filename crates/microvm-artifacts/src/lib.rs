//! Secure descriptor-relative artifact path resolution and digest verification
//! for the kvm-microvm-orchestrator platform.
//!
//! This crate owns the platform's local artifact-integrity boundary. Firecracker
//! and its jailer treat operator-supplied paths as trusted and (as of v1.16.1)
//! reverted `O_NOFOLLOW` for some path operations, so the orchestrator must do
//! its own path validation rather than relying on the runtime. Every artifact is
//! therefore opened **relative to a held directory descriptor** for a per-tenant
//! root using `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS)`, with a component-wise `openat(O_NOFOLLOW)` fallback
//! for kernels that lack `openat2`.
//!
//! # Guarantees
//! - No absolute path, `..` component, symlink, magic link, or remote URI is
//!   ever resolved ([`path::validate_relative_path`], [`path::PathResolver`]).
//! - Opened artifacts must be regular files that are not world-writable, with an
//!   optional foreign-owner rejection policy.
//! - Content is SHA-256 content-addressed and verified in constant time
//!   ([`digest`]).
//! - [`store::ArtifactStore::verify_manifest`] re-opens and re-hashes every
//!   manifest entry, failing closed on the first mismatch.
//!
//! # Error contract
//! All failures are typed [`MicrovmError`]s, primarily
//! [`ErrorCode::PathEscape`], [`ErrorCode::DigestMismatch`], and
//! [`ErrorCode::ArtifactNotFound`].
//!
//! [`MicrovmError`]: microvm_errors::MicrovmError
//! [`ErrorCode::PathEscape`]: microvm_errors::ErrorCode::PathEscape
//! [`ErrorCode::DigestMismatch`]: microvm_errors::ErrorCode::DigestMismatch
//! [`ErrorCode::ArtifactNotFound`]: microvm_errors::ErrorCode::ArtifactNotFound

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod digest;
pub mod path;
pub mod store;

pub use digest::{compute_sha256, verify_sha256, Digest};
pub use path::{validate_relative_path, PathResolver};
pub use store::{Artifact, ArtifactManifest, ArtifactStore, ManifestEntry};

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_errors::ErrorCode;
    use microvm_types::TenantId;
    use std::io::Write;
    use tempfile::TempDir;

    /// End-to-end: build a store, write an artifact, and verify a manifest that
    /// references it by digest.
    #[test]
    fn end_to_end_digest_addressed_open_and_verify() {
        let tmp = TempDir::new().unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();
        let dir = store.tenant_root(&tenant).join("images");
        std::fs::create_dir_all(&dir).unwrap();

        let content = b"guest-kernel-bzimage".to_vec();
        let mut f = std::fs::File::create(dir.join("vmlinux")).unwrap();
        f.write_all(&content).unwrap();
        f.sync_all().unwrap();

        let digest = compute_sha256(&content[..]).unwrap();
        let manifest =
            ArtifactManifest::new().with_entry(ManifestEntry::new("images/vmlinux", digest));
        store
            .verify_manifest(&tenant, &manifest)
            .expect("valid manifest verifies");

        // A one-bit change in the expected digest must fail closed.
        let mut bad_bytes = *digest.as_bytes();
        bad_bytes[0] ^= 0x01;
        let bad = Digest::from_bytes(bad_bytes);
        let bad_manifest =
            ArtifactManifest::new().with_entry(ManifestEntry::new("images/vmlinux", bad));
        let err = store.verify_manifest(&tenant, &bad_manifest).unwrap_err();
        assert_eq!(err.code, ErrorCode::DigestMismatch);
    }
}
