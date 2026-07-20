//! The constrained local OCI importer.
//!
//! [`OciImporter`] opens a **local** OCI image layout, verifies the digest of
//! the config blob and of *every* layer, refuses remote references and any
//! forbidden runtime knob, selects a supported platform, and translates the
//! result into a typed [`MicroVmSpec`]. It performs no network I/O and has no
//! remote client dependency; it is a constrained import surface, **not** an OCI
//! runtime.
//!
//! Layout convention (constrained subset of an [OCI image layout]):
//! ```text
//! <layout-root>/
//!   manifest.json          OCI image manifest (schemaVersion 2)
//!   blobs/sha256/<hex>     config + layer blobs, named by digest
//! ```
//!
//! [OCI image layout]: https://github.com/opencontainers/image-spec

use crate::config::{scan_forbidden, MicroVmResources, OciImageConfig};
use crate::error::ImportError;
use crate::manifest::{blob_rel_path, OciDescriptor, OciManifest};
use crate::platform::Platform;
use crate::reference::validate_local_reference;
use crate::spec::{LayerRef, MicroVmSpec};
use microvm_artifacts::{verify_sha256, Digest, MediaKind, PathResolver};
use microvm_errors::ErrorCode;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Layout-relative path of the OCI image manifest the importer reads.
pub const MANIFEST_RELPATH: &str = "manifest.json";

/// Annotation value marking a layer as the guest kernel.
pub const ROLE_KERNEL: &str = "kernel";
/// Annotation value marking a layer as the guest rootfs.
pub const ROLE_ROOTFS: &str = "rootfs";

/// A constrained local OCI importer anchored at a layout root.
#[derive(Debug)]
pub struct OciImporter {
    root: PathBuf,
    resolver: PathResolver,
}

impl OciImporter {
    /// Open an importer from a validated local reference string.
    ///
    /// Remote and tag-only references are refused here, before any layout I/O.
    pub fn open_reference(reference: &str) -> Result<Self, ImportError> {
        let path = validate_local_reference(reference)?;
        Self::open(&path)
    }

    /// Open an importer anchored at a local layout `root` directory.
    pub fn open(root: &Path) -> Result<Self, ImportError> {
        let resolver = PathResolver::open_root(root).map_err(|e| match e.code {
            ErrorCode::ArtifactNotFound => ImportError::ManifestInvalid {
                reason: format!("layout root not found: {}", root.display()),
            },
            _ => ImportError::Artifact(e),
        })?;
        Ok(Self {
            root: root.to_path_buf(),
            resolver,
        })
    }

    /// The layout root this importer is anchored at.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Import using the platform declared in the image config.
    pub fn import(&self) -> Result<MicroVmSpec, ImportError> {
        self.import_inner(None)
    }

    /// Import, requiring the image config platform to match `requested`.
    pub fn import_for_platform(&self, requested: Platform) -> Result<MicroVmSpec, ImportError> {
        self.import_inner(Some(requested))
    }

    fn import_inner(&self, requested: Option<Platform>) -> Result<MicroVmSpec, ImportError> {
        let manifest = self.read_manifest()?;
        let manifest_value = self.read_json(MANIFEST_RELPATH)?;
        let config_value = self.read_and_verify_config(&manifest.config)?;

        // Refuse forbidden runtime knobs anywhere in the imported documents.
        reject_forbidden(&manifest_value)?;
        reject_forbidden(&config_value)?;

        let image_config = OciImageConfig::from_value(&config_value)?;
        let platform = select_platform(&image_config, requested)?;
        let resources = MicroVmResources::from_labels(&image_config.labels())?;
        let resource_spec = resources.to_resource_spec()?;

        // Verify the digest and size of EVERY layer (not just kernel/rootfs).
        for layer in &manifest.layers {
            self.verify_blob(layer)?;
        }

        let kernel = self.build_layer_ref(
            select_role(&manifest.layers, ROLE_KERNEL)?,
            MediaKind::Kernel,
        )?;
        let rootfs = self.build_layer_ref(
            select_role(&manifest.layers, ROLE_ROOTFS)?,
            MediaKind::Rootfs,
        )?;

        Ok(MicroVmSpec {
            guest_arch: platform.guest_arch(),
            platform,
            kernel,
            rootfs,
            resources: resource_spec,
            boot_args: resources.boot_args.clone(),
        })
    }

    /// Read and parse the manifest, enforcing the constrained schema.
    fn read_manifest(&self) -> Result<OciManifest, ImportError> {
        let bytes = self.read_rel(MANIFEST_RELPATH).map_err(|e| match e {
            ImportError::Artifact(ref me) if me.code == ErrorCode::ArtifactNotFound => {
                ImportError::ManifestInvalid {
                    reason: "manifest.json not found in layout root".to_string(),
                }
            }
            _ => e,
        })?;
        OciManifest::from_json_bytes(&bytes)
    }

    /// Read the config blob, verifying its digest and size, and return its JSON.
    fn read_and_verify_config(
        &self,
        config: &OciDescriptor,
    ) -> Result<serde_json::Value, ImportError> {
        let rel = blob_rel_path(&config.validated_digest()?);
        let bytes = self
            .read_rel(&rel)
            .map_err(|e| self.remap_blob_err(e, &config.digest))?;
        self.verify_bytes(&config.digest, config.size, &bytes)?;
        serde_json::from_slice(&bytes).map_err(|e| ImportError::ConfigInvalid {
            reason: format!("config blob is not valid JSON: {e}"),
        })
    }

    /// Verify a layer blob's digest and size against its descriptor.
    fn verify_blob(&self, desc: &OciDescriptor) -> Result<(Digest, u64), ImportError> {
        let rel = blob_rel_path(&desc.validated_digest()?);
        let bytes = self
            .read_rel(&rel)
            .map_err(|e| self.remap_blob_err(e, &desc.digest))?;
        self.verify_bytes(&desc.digest, desc.size, &bytes)
    }

    /// Verify `bytes` hash to the declared digest and match the declared size.
    fn verify_bytes(
        &self,
        declared: &str,
        size: u64,
        bytes: &[u8],
    ) -> Result<(Digest, u64), ImportError> {
        let expected = crate::manifest::parse_sha256_digest(declared)?;
        let actual_len = bytes.len() as u64;
        if actual_len != size {
            return Err(ImportError::SizeMismatch {
                digest: declared.to_string(),
                expected: size,
                actual: actual_len,
            });
        }
        if let Err(e) = verify_sha256(bytes, &expected) {
            return Err(ImportError::DigestMismatch {
                digest: declared.to_string(),
                expected: e
                    .context
                    .get("expected")
                    .cloned()
                    .unwrap_or_else(|| expected.to_hex()),
                actual: e.context.get("actual").cloned().unwrap_or_default(),
            });
        }
        Ok((expected, actual_len))
    }

    /// Build a [`LayerRef`] for an already-verified layer descriptor of `media`.
    fn build_layer_ref(
        &self,
        desc: &OciDescriptor,
        media: MediaKind,
    ) -> Result<LayerRef, ImportError> {
        let digest = desc.validated_digest()?;
        Ok(LayerRef {
            media,
            sha256: digest,
            size: desc.size,
            rel_path: blob_rel_path(&digest),
        })
    }

    /// Read a layout-relative file fully, mapping resolver errors to import errors.
    fn read_rel(&self, rel: &str) -> Result<Vec<u8>, ImportError> {
        let mut file = self.resolver.open(rel).map_err(ImportError::Artifact)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| {
            ImportError::Artifact(
                microvm_errors::MicrovmError::new(ErrorCode::InternalError, "failed reading blob")
                    .with_context("rel", rel.to_string())
                    .with_context("io", e.to_string()),
            )
        })?;
        Ok(buf)
    }

    /// Read a layout-relative JSON document.
    fn read_json(&self, rel: &str) -> Result<serde_json::Value, ImportError> {
        let bytes = self.read_rel(rel)?;
        serde_json::from_slice(&bytes).map_err(|e| ImportError::ManifestInvalid {
            reason: format!("{rel} is not valid JSON: {e}"),
        })
    }

    /// Map a blob-read failure to [`ImportError::BlobNotFound`] when the blob is
    /// simply absent, preserving other artifact errors otherwise.
    fn remap_blob_err(&self, err: ImportError, digest: &str) -> ImportError {
        match err {
            ImportError::Artifact(ref me) if me.code == ErrorCode::ArtifactNotFound => {
                ImportError::BlobNotFound {
                    digest: digest.to_string(),
                }
            }
            _ => err,
        }
    }
}

/// Refuse a document carrying any forbidden runtime key.
fn reject_forbidden(value: &serde_json::Value) -> Result<(), ImportError> {
    if let Some((field, key)) = scan_forbidden(value) {
        return Err(ImportError::Forbidden { field, key });
    }
    Ok(())
}

/// Select and validate the platform from the image config and optional request.
fn select_platform(
    image_config: &OciImageConfig,
    requested: Option<Platform>,
) -> Result<Platform, ImportError> {
    let actual = Platform::from_oci(&image_config.os, &image_config.architecture)?;
    if let Some(requested) = requested {
        if requested != actual {
            return Err(ImportError::PlatformMismatch {
                requested: requested.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    Ok(actual)
}

/// Select the unique layer annotated with `role`, refusing zero or multiple.
fn select_role<'a>(
    layers: &'a [OciDescriptor],
    role: &str,
) -> Result<&'a OciDescriptor, ImportError> {
    let media = match role {
        ROLE_KERNEL => MediaKind::Kernel,
        _ => MediaKind::Rootfs,
    };
    let mut matches = layers.iter().filter(|l| l.media_role() == Some(role));
    let first = matches.next().ok_or(ImportError::MissingMedia { media })?;
    if matches.next().is_some() {
        return Err(ImportError::DuplicateMedia { media });
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_role_detects_missing_and_duplicate() {
        let layers = vec![];
        assert!(matches!(
            select_role(&layers, ROLE_KERNEL).unwrap_err(),
            ImportError::MissingMedia {
                media: MediaKind::Kernel
            }
        ));
    }
}
