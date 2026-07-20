//! The typed microVM specification produced by a successful constrained import.
//!
//! [`MicroVmSpec`] is the transport-neutral, fully-validated output the rest
//! of the platform consumes: a digest-pinned kernel layer, a digest-pinned
//! rootfs layer, a validated [`ResourceSpec`], the selected [`Platform`], and
//! the kernel boot arguments. Every layer it references has already had its
//! SHA-256 verified against the manifest by [`crate::importer::OciImporter`].

use crate::platform::Platform;
use microvm_artifacts::{Digest, GuestArch, MediaKind};
use microvm_types::ResourceSpec;
use serde::{Deserialize, Serialize};

/// A digest-pinned reference to a verified layer blob in the local layout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerRef {
    /// The guest media this layer provides.
    pub media: MediaKind,
    /// Verified SHA-256 content digest.
    pub sha256: Digest,
    /// Verified blob size in bytes.
    pub size: u64,
    /// Layout-relative blob path (`blobs/sha256/<hex>`); opens only through the
    /// descriptor-relative artifact resolver.
    pub rel_path: String,
}

impl LayerRef {
    /// The `sha256:<hex>` digest string for this layer.
    pub fn digest_string(&self) -> String {
        format!("sha256:{}", self.sha256.to_hex())
    }
}

/// The typed output of a constrained local OCI import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmSpec {
    /// The selected guest platform.
    pub platform: Platform,
    /// The guest CPU architecture (derived from [`MicroVmSpec::platform`]).
    pub guest_arch: GuestArch,
    /// The verified kernel layer.
    pub kernel: LayerRef,
    /// The verified rootfs layer.
    pub rootfs: LayerRef,
    /// The validated resource specification.
    pub resources: ResourceSpec,
    /// Kernel boot arguments (cmdline).
    pub boot_args: String,
}

impl MicroVmSpec {
    /// The guest architecture implied by the selected platform.
    pub fn arch(&self) -> GuestArch {
        self.guest_arch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_artifacts::compute_sha256;
    use microvm_types::NetworkPolicy;

    fn layer_ref(media: MediaKind, bytes: &[u8]) -> LayerRef {
        let sha = compute_sha256(bytes).unwrap();
        LayerRef {
            media,
            sha256: sha,
            size: bytes.len() as u64,
            rel_path: format!("blobs/sha256/{}", sha.to_hex()),
        }
    }

    #[test]
    fn spec_serde_roundtrip() {
        let spec = MicroVmSpec {
            platform: Platform::LINUX_AMD64,
            guest_arch: GuestArch::X86_64,
            kernel: layer_ref(MediaKind::Kernel, b"kernel"),
            rootfs: layer_ref(MediaKind::Rootfs, b"rootfs"),
            resources: ResourceSpec::new(2, 512, 1024, NetworkPolicy::NatOnly).unwrap(),
            boot_args: "console=ttyS0".to_string(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: MicroVmSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn layer_ref_digest_string_is_sha256_prefixed() {
        let l = layer_ref(MediaKind::Kernel, b"kernel");
        assert!(l.digest_string().starts_with("sha256:"));
        assert_eq!(l.digest_string().len(), "sha256:".len() + 64);
    }

    #[test]
    fn arch_matches_platform() {
        let spec = MicroVmSpec {
            platform: Platform::LINUX_ARM64,
            guest_arch: Platform::LINUX_ARM64.guest_arch(),
            kernel: layer_ref(MediaKind::Kernel, b"k"),
            rootfs: layer_ref(MediaKind::Rootfs, b"r"),
            resources: ResourceSpec::new(1, 256, 512, NetworkPolicy::None).unwrap(),
            boot_args: String::new(),
        };
        assert_eq!(spec.arch(), GuestArch::Aarch64);
    }
}
