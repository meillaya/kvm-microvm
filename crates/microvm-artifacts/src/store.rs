//! Digest-addressed artifact store with per-tenant roots.
//!
//! [`ArtifactStore`] maps a [`TenantId`] to a root directory beneath a shared
//! base, then resolves and verifies artifacts relative to a held descriptor for
//! that root. Manifest verification re-opens every entry and confirms its
//! SHA-256 digest, failing closed on the first mismatch.

use crate::digest::{compute_sha256, verify_sha256, Digest};
use crate::path::PathResolver;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::TenantId;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// A single manifest entry: a tenant-relative path and its expected digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Path relative to the tenant root (must pass [`crate::path::validate_relative_path`]).
    pub path: String,
    /// Expected SHA-256 digest of the file contents.
    pub sha256: Digest,
}

impl ManifestEntry {
    /// Construct a manifest entry.
    pub fn new(path: impl Into<String>, sha256: Digest) -> Self {
        Self {
            path: path.into(),
            sha256,
        }
    }
}

/// An ordered set of artifact entries to verify atomically.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// Entries to verify, in order.
    pub entries: Vec<ManifestEntry>,
}

impl ArtifactManifest {
    /// Construct an empty manifest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style: append an entry.
    #[must_use]
    pub fn with_entry(mut self, entry: ManifestEntry) -> Self {
        self.entries.push(entry);
        self
    }
}

/// An opened, metadata-validated artifact backed by a held descriptor.
#[derive(Debug)]
pub struct Artifact {
    file: File,
    path: String,
}

impl Artifact {
    /// The tenant-relative path this artifact was opened from.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Borrow the underlying file descriptor.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Compute the SHA-256 digest of the artifact contents. The file offset is
    /// restored to the start before returning.
    pub fn compute_sha256(&mut self) -> Result<Digest, MicrovmError> {
        self.rewind()?;
        let digest = compute_sha256(&mut self.file)?;
        self.rewind()?;
        Ok(digest)
    }

    /// Verify the artifact contents against `expected`.
    pub fn verify_sha256(&mut self, expected: &Digest) -> Result<(), MicrovmError> {
        self.rewind()?;
        let result = verify_sha256(&mut self.file, expected);
        self.rewind()?;
        result.map_err(|e| e.with_context("path", self.path.clone()))
    }

    fn rewind(&mut self) -> Result<(), MicrovmError> {
        self.file.seek(SeekFrom::Start(0)).map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "failed to rewind artifact")
                .with_context("path", self.path.clone())
                .with_context("io", e.to_string())
        })?;
        Ok(())
    }
}

/// Digest-addressed store rooted at a base directory with per-tenant subroots.
pub struct ArtifactStore {
    base: PathBuf,
    expected_owner: Option<u32>,
}

impl ArtifactStore {
    /// Create a store whose tenant roots live beneath `base`.
    ///
    /// `base` must already exist and be a directory.
    pub fn new(base: impl Into<PathBuf>) -> Result<Self, MicrovmError> {
        let base = base.into();
        let meta = std::fs::metadata(&base).map_err(|e| {
            MicrovmError::new(ErrorCode::ArtifactNotFound, "artifact store base not found")
                .with_context("base", base.display().to_string())
                .with_context("io", e.to_string())
        })?;
        if !meta.is_dir() {
            return Err(MicrovmError::new(
                ErrorCode::ArtifactNotFound,
                "artifact store base is not a directory",
            )
            .with_context("base", base.display().to_string()));
        }
        Ok(Self {
            base,
            expected_owner: None,
        })
    }

    /// Require opened artifacts to be owned by `uid`, rejecting foreign owners.
    #[must_use]
    pub fn with_expected_owner(mut self, uid: u32) -> Self {
        self.expected_owner = Some(uid);
        self
    }

    /// The store base directory.
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The root directory for a tenant: `<base>/<tenant>`.
    ///
    /// [`TenantId`] validation forbids `/` and `..`, so this component cannot
    /// escape the base.
    pub fn tenant_root(&self, tenant: &TenantId) -> PathBuf {
        self.base.join(tenant.as_str())
    }

    /// Open a [`PathResolver`] anchored at the tenant root.
    pub fn resolver_for(&self, tenant: &TenantId) -> Result<PathResolver, MicrovmError> {
        PathResolver::open_root(&self.tenant_root(tenant))
    }

    /// Open and metadata-validate an artifact for a tenant.
    pub fn open_artifact(&self, tenant: &TenantId, rel: &str) -> Result<Artifact, MicrovmError> {
        let resolver = self.resolver_for(tenant)?;
        let file = resolver.open(rel)?;
        if let Some(uid) = self.expected_owner {
            check_owner(&file, rel, uid)?;
        }
        Ok(Artifact {
            file,
            path: rel.to_string(),
        })
    }

    /// Verify every manifest entry for a tenant, failing on the first digest
    /// mismatch or missing artifact.
    pub fn verify_manifest(
        &self,
        tenant: &TenantId,
        manifest: &ArtifactManifest,
    ) -> Result<(), MicrovmError> {
        for entry in &manifest.entries {
            let mut artifact = self.open_artifact(tenant, &entry.path)?;
            artifact.verify_sha256(&entry.sha256)?;
        }
        Ok(())
    }
}

fn check_owner(file: &File, rel: &str, expected_uid: u32) -> Result<(), MicrovmError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    use std::os::fd::AsRawFd;
    let ret = unsafe { libc::fstat(file.as_raw_fd(), &mut stat) };
    if ret < 0 {
        return Err(
            MicrovmError::new(ErrorCode::InternalError, "failed to stat artifact")
                .with_context("path", rel),
        );
    }
    if stat.st_uid != expected_uid {
        return Err(MicrovmError::new(
            ErrorCode::PermissionDenied,
            "artifact owned by foreign uid",
        )
        .with_context("path", rel)
        .with_context("expected_uid", expected_uid.to_string())
        .with_context("actual_uid", stat.st_uid.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::compute_sha256;
    use std::io::Write;
    use tempfile::TempDir;

    fn store_with_artifact() -> (TempDir, ArtifactStore, TenantId, Vec<u8>) {
        let tmp = TempDir::new().unwrap();
        let tenant = TenantId::new("tenant-1").unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();
        let blobs = store.tenant_root(&tenant).join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        let content = b"rootfs-content-v1".to_vec();
        let mut f = std::fs::File::create(blobs.join("rootfs.img")).unwrap();
        f.write_all(&content).unwrap();
        f.sync_all().unwrap();
        (tmp, store, tenant, content)
    }

    #[test]
    fn opens_artifact_and_computes_digest() {
        let (_tmp, store, tenant, content) = store_with_artifact();
        let mut artifact = store.open_artifact(&tenant, "blobs/rootfs.img").unwrap();
        let expected = compute_sha256(&content[..]).unwrap();
        assert_eq!(artifact.compute_sha256().unwrap(), expected);
        // Offset restored: computing again yields the same digest.
        assert_eq!(artifact.compute_sha256().unwrap(), expected);
    }

    #[test]
    fn digest_mismatch_on_tampered_expectation() {
        let (_tmp, store, tenant, _) = store_with_artifact();
        let mut artifact = store.open_artifact(&tenant, "blobs/rootfs.img").unwrap();
        let wrong = compute_sha256(&b"something-else"[..]).unwrap();
        let err = artifact.verify_sha256(&wrong).unwrap_err();
        assert_eq!(err.code, ErrorCode::DigestMismatch);
        assert_eq!(
            err.context.get("path").map(String::as_str),
            Some("blobs/rootfs.img")
        );
    }

    #[test]
    fn verify_manifest_success() {
        let (_tmp, store, tenant, content) = store_with_artifact();
        let digest = compute_sha256(&content[..]).unwrap();
        let manifest =
            ArtifactManifest::new().with_entry(ManifestEntry::new("blobs/rootfs.img", digest));
        assert!(store.verify_manifest(&tenant, &manifest).is_ok());
    }

    #[test]
    fn verify_manifest_digest_mismatch() {
        let (_tmp, store, tenant, _) = store_with_artifact();
        let wrong = compute_sha256(&b"tampered"[..]).unwrap();
        let manifest =
            ArtifactManifest::new().with_entry(ManifestEntry::new("blobs/rootfs.img", wrong));
        let err = store.verify_manifest(&tenant, &manifest).unwrap_err();
        assert_eq!(err.code, ErrorCode::DigestMismatch);
    }

    #[test]
    fn verify_manifest_missing_entry() {
        let (_tmp, store, tenant, _) = store_with_artifact();
        let digest = compute_sha256(&b"x"[..]).unwrap();
        let manifest =
            ArtifactManifest::new().with_entry(ManifestEntry::new("blobs/absent.img", digest));
        let err = store.verify_manifest(&tenant, &manifest).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactNotFound);
    }

    #[test]
    fn verify_manifest_rejects_escape_entry() {
        let (_tmp, store, tenant, _) = store_with_artifact();
        let digest = compute_sha256(&b"x"[..]).unwrap();
        let manifest =
            ArtifactManifest::new().with_entry(ManifestEntry::new("../../etc/passwd", digest));
        let err = store.verify_manifest(&tenant, &manifest).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape);
    }

    #[test]
    fn rejects_foreign_owner() {
        let (_tmp, store, tenant, _) = store_with_artifact();
        // Expect a uid that is (almost certainly) not the current owner.
        let current = unsafe { libc::getuid() };
        let foreign = current.wrapping_add(1);
        let strict = ArtifactStore::new(store.base())
            .unwrap()
            .with_expected_owner(foreign);
        let err = strict
            .open_artifact(&tenant, "blobs/rootfs.img")
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.message.contains("foreign uid"));
    }

    #[test]
    fn accepts_matching_owner() {
        let (_tmp, store, tenant, _) = store_with_artifact();
        let current = unsafe { libc::getuid() };
        let strict = ArtifactStore::new(store.base())
            .unwrap()
            .with_expected_owner(current);
        assert!(strict.open_artifact(&tenant, "blobs/rootfs.img").is_ok());
    }

    #[test]
    fn cross_tenant_isolation() {
        let (_tmp, store, tenant, _) = store_with_artifact();
        let other = TenantId::new("tenant-2").unwrap();
        // The owning tenant can open its artifact...
        assert!(store.open_artifact(&tenant, "blobs/rootfs.img").is_ok());
        // ...but tenant-2 has no root; opening must fail closed, not leak data.
        let err = store.open_artifact(&other, "blobs/rootfs.img").unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactNotFound);
    }

    #[test]
    fn tenant_roots_are_disjoint() {
        let tmp = TempDir::new().unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();
        let a = store.tenant_root(&TenantId::new("tenant-a").unwrap());
        let b = store.tenant_root(&TenantId::new("tenant-b").unwrap());
        assert_ne!(a, b);
        assert!(a.starts_with(store.base()));
        assert!(b.starts_with(store.base()));
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let digest = compute_sha256(&b"abc"[..]).unwrap();
        let manifest =
            ArtifactManifest::new().with_entry(ManifestEntry::new("blobs/rootfs.img", digest));
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ArtifactManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }

    #[test]
    fn base_must_be_directory() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(ArtifactStore::new(&file).is_err());
        assert!(ArtifactStore::new(tmp.path().join("missing")).is_err());
    }
}
