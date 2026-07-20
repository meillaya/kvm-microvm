//! Parsing for the constrained local OCI image manifest subset.
//!
//! The importer accepts a local [OCI image manifest] (`schemaVersion: 2`) with
//! a single config descriptor and one or more layer descriptors, each pinned by
//! a `sha256:<hex>` digest. This is a *constrained* subset: descriptors must not
//! carry remote `urls`, and every digest must be well formed so its blob can be
//! resolved at the deterministic local path `blobs/sha256/<hex>`.
//!
//! [OCI image manifest]: https://github.com/opencontainers/image-spec

use crate::error::ImportError;
use microvm_artifacts::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Annotation key marking which guest media a layer provides.
///
/// Recognized values: `kernel`, `rootfs`. Exactly one layer of each is required.
pub const MEDIA_ANNOTATION: &str = "org.microvm.media";

/// The OCI image manifest `schemaVersion` the constrained importer accepts.
pub const REQUIRED_SCHEMA_VERSION: u32 = 2;

/// An OCI content descriptor (config or layer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    /// IANA media type of the referenced blob.
    #[serde(default)]
    pub media_type: String,
    /// Content digest in `sha256:<hex>` form.
    pub digest: String,
    /// Declared blob size in bytes.
    pub size: u64,
    /// Remote retrieval URLs. **Forbidden**: the importer is local-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    /// Arbitrary metadata; used to mark a layer's guest media role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Optional per-layer platform hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<OciPlatform>,
}

/// An OCI `os`/`architecture` platform hint carried by a descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciPlatform {
    /// Operating system (e.g. `linux`).
    #[serde(default)]
    pub os: String,
    /// CPU architecture (e.g. `amd64`, `arm64`).
    #[serde(default)]
    pub architecture: String,
}

/// A constrained local OCI image manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    /// Manifest schema version; must be [`REQUIRED_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// IANA media type of the manifest itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Descriptor of the image config blob.
    pub config: OciDescriptor,
    /// Ordered layer descriptors.
    pub layers: Vec<OciDescriptor>,
}

impl OciDescriptor {
    /// Parse and validate the descriptor digest, refusing remote `urls` and
    /// malformed digests.
    pub fn validated_digest(&self) -> Result<Digest, ImportError> {
        if self.urls.as_ref().is_some_and(|u| !u.is_empty()) {
            return Err(ImportError::RemoteDescriptor {
                digest: self.digest.clone(),
            });
        }
        parse_sha256_digest(&self.digest)
    }

    /// The layer's guest media role from [`MEDIA_ANNOTATION`], if annotated.
    pub fn media_role(&self) -> Option<&str> {
        self.annotations
            .as_ref()
            .and_then(|a| a.get(MEDIA_ANNOTATION))
            .map(String::as_str)
    }
}

impl OciManifest {
    /// Parse a manifest from JSON bytes, enforcing the constrained schema.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ImportError> {
        let manifest: OciManifest =
            serde_json::from_slice(bytes).map_err(|e| ImportError::ManifestInvalid {
                reason: format!("manifest JSON did not parse: {e}"),
            })?;
        manifest.validate_shape()?;
        Ok(manifest)
    }

    /// Enforce the constrained structural rules (schema version, non-empty
    /// layers, well-formed digests, no remote descriptor urls).
    pub fn validate_shape(&self) -> Result<(), ImportError> {
        if self.schema_version != REQUIRED_SCHEMA_VERSION {
            return Err(ImportError::ManifestInvalid {
                reason: format!(
                    "schemaVersion must be {REQUIRED_SCHEMA_VERSION}, got {}",
                    self.schema_version
                ),
            });
        }
        if self.layers.is_empty() {
            return Err(ImportError::ManifestInvalid {
                reason: "manifest must declare at least one layer".to_string(),
            });
        }
        // Config descriptor must be digest-pinned and local.
        self.config.validated_digest()?;
        // Every layer must be digest-pinned and local.
        for layer in &self.layers {
            layer.validated_digest()?;
        }
        Ok(())
    }
}

/// Parse a `sha256:<64 hex>` digest string into a [`Digest`].
pub fn parse_sha256_digest(value: &str) -> Result<Digest, ImportError> {
    let hex = match value.strip_prefix("sha256:") {
        Some(hex) => hex,
        None => {
            return Err(ImportError::MalformedDigest {
                value: value.to_string(),
            })
        }
    };
    Digest::from_hex(hex).map_err(|_| ImportError::MalformedDigest {
        value: value.to_string(),
    })
}

/// The deterministic layout-relative blob path for a parsed digest.
///
/// The path is derived purely from the validated hex digest, so it can never
/// contain `..`, a leading `/`, or a remote URI; it still passes
/// [`microvm_artifacts::validate_relative_path`].
pub fn blob_rel_path(digest: &Digest) -> String {
    format!("blobs/sha256/{}", digest.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn descriptor(digest: &str) -> OciDescriptor {
        OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
            digest: digest.to_string(),
            size: 10,
            urls: None,
            annotations: None,
            platform: None,
        }
    }

    #[test]
    fn parses_minimal_manifest() {
        let json = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{HEX}","size":2}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{HEX}","size":10}}]}}"#
        );
        let m = OciManifest::from_json_bytes(json.as_bytes()).unwrap();
        assert_eq!(m.schema_version, 2);
        assert_eq!(m.layers.len(), 1);
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let json = format!(
            r#"{{"schemaVersion":1,"config":{{"digest":"sha256:{HEX}","size":2}},"layers":[{{"digest":"sha256:{HEX}","size":10}}]}}"#
        );
        let err = OciManifest::from_json_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, ImportError::ManifestInvalid { .. }));
    }

    #[test]
    fn rejects_empty_layers() {
        let json = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"sha256:{HEX}","size":2}},"layers":[]}}"#
        );
        let err = OciManifest::from_json_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, ImportError::ManifestInvalid { .. }));
    }

    #[test]
    fn rejects_descriptor_with_remote_urls() {
        let mut d = descriptor(&format!("sha256:{HEX}"));
        d.urls = Some(vec!["https://example.com/blob".to_string()]);
        let err = d.validated_digest().unwrap_err();
        assert!(matches!(err, ImportError::RemoteDescriptor { .. }));
        assert_eq!(err.code(), microvm_errors::ErrorCode::LocalArtifactRequired);
    }

    #[test]
    fn parse_digest_requires_sha256_prefix_and_hex() {
        assert!(parse_sha256_digest(&format!("sha256:{HEX}")).is_ok());
        assert!(matches!(
            parse_sha256_digest(HEX).unwrap_err(),
            ImportError::MalformedDigest { .. }
        ));
        assert!(matches!(
            parse_sha256_digest("sha256:abcd").unwrap_err(),
            ImportError::MalformedDigest { .. }
        ));
        assert!(matches!(
            parse_sha256_digest("md5:abcd").unwrap_err(),
            ImportError::MalformedDigest { .. }
        ));
    }

    #[test]
    fn blob_rel_path_is_relative_and_safe() {
        let d = parse_sha256_digest(&format!("sha256:{HEX}")).unwrap();
        let rel = blob_rel_path(&d);
        assert_eq!(rel, format!("blobs/sha256/{HEX}"));
        assert!(microvm_artifacts::validate_relative_path(&rel).is_ok());
    }

    #[test]
    fn media_role_reads_annotation() {
        let mut d = descriptor(&format!("sha256:{HEX}"));
        let mut ann = BTreeMap::new();
        ann.insert(MEDIA_ANNOTATION.to_string(), "kernel".to_string());
        d.annotations = Some(ann);
        assert_eq!(d.media_role(), Some("kernel"));
        assert_eq!(descriptor(&format!("sha256:{HEX}")).media_role(), None);
    }
}
