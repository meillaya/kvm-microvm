//! Target platform selection for the constrained importer.
//!
//! The importer supports exactly two guest platforms, mirroring the
//! architectures Firecracker builds for: `linux/amd64` (x86_64) and
//! `linux/arm64` (aarch64). Any other `os`/`architecture` pair is refused with
//! a typed [`ImportError::UnsupportedPlatform`].

use crate::error::ImportError;
use microvm_artifacts::GuestArch;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A supported guest platform: an `os`/`architecture` pair.
///
/// A `Platform` only ever holds one of the two supported constants, so it
/// (de)serializes as an `{os, architecture}` pair and validates on the way in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Platform {
    /// Operating system (always `linux` for supported platforms).
    os: &'static str,
    /// OCI architecture token (`amd64` or `arm64`).
    architecture: &'static str,
}

impl Platform {
    /// `linux/amd64` — 64-bit x86 (Firecracker `x86_64`).
    pub const LINUX_AMD64: Platform = Platform {
        os: "linux",
        architecture: "amd64",
    };

    /// `linux/arm64` — 64-bit ARM (Firecracker `aarch64`).
    pub const LINUX_ARM64: Platform = Platform {
        os: "linux",
        architecture: "arm64",
    };

    /// The operating system component.
    pub fn os(self) -> &'static str {
        self.os
    }

    /// The OCI architecture component.
    pub fn architecture(self) -> &'static str {
        self.architecture
    }

    /// The guest CPU architecture this platform maps to.
    pub fn guest_arch(self) -> GuestArch {
        match self.architecture {
            "amd64" => GuestArch::X86_64,
            // Only amd64 and arm64 are constructible via `from_oci`/constants.
            _ => GuestArch::Aarch64,
        }
    }

    /// Parse an OCI `os`/`architecture` pair into a supported [`Platform`].
    ///
    /// Architecture synonyms `x86_64`/`aarch64` are normalized to the OCI
    /// tokens `amd64`/`arm64`. Anything else is refused.
    pub fn from_oci(os: &str, architecture: &str) -> Result<Self, ImportError> {
        let os_lc = os.to_ascii_lowercase();
        let arch_lc = architecture.to_ascii_lowercase();
        if os_lc != "linux" {
            return Err(ImportError::UnsupportedPlatform {
                os: os.to_string(),
                architecture: architecture.to_string(),
            });
        }
        match arch_lc.as_str() {
            "amd64" | "x86_64" => Ok(Self::LINUX_AMD64),
            "arm64" | "aarch64" => Ok(Self::LINUX_ARM64),
            _ => Err(ImportError::UnsupportedPlatform {
                os: os.to_string(),
                architecture: architecture.to_string(),
            }),
        }
    }

    /// All supported platforms, in a stable order.
    pub fn supported() -> &'static [Platform] {
        &[Self::LINUX_AMD64, Self::LINUX_ARM64]
    }
}

impl Serialize for Platform {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Platform", 2)?;
        state.serialize_field("os", self.os)?;
        state.serialize_field("architecture", self.architecture)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            os: String,
            architecture: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        Platform::from_oci(&raw.os, &raw.architecture).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_platforms_select_guest_arch() {
        assert_eq!(Platform::LINUX_AMD64.guest_arch(), GuestArch::X86_64);
        assert_eq!(Platform::LINUX_ARM64.guest_arch(), GuestArch::Aarch64);
    }

    #[test]
    fn from_oci_accepts_supported_and_synonyms() {
        assert_eq!(
            Platform::from_oci("linux", "amd64").unwrap(),
            Platform::LINUX_AMD64
        );
        assert_eq!(
            Platform::from_oci("linux", "arm64").unwrap(),
            Platform::LINUX_ARM64
        );
        assert_eq!(
            Platform::from_oci("linux", "x86_64").unwrap(),
            Platform::LINUX_AMD64
        );
        assert_eq!(
            Platform::from_oci("linux", "aarch64").unwrap(),
            Platform::LINUX_ARM64
        );
        // Case-insensitive.
        assert_eq!(
            Platform::from_oci("Linux", "AMD64").unwrap(),
            Platform::LINUX_AMD64
        );
    }

    #[test]
    fn from_oci_rejects_non_linux() {
        let err = Platform::from_oci("windows", "amd64").unwrap_err();
        assert_eq!(
            err,
            ImportError::UnsupportedPlatform {
                os: "windows".to_string(),
                architecture: "amd64".to_string()
            }
        );
    }

    #[test]
    fn from_oci_rejects_unsupported_arch() {
        for arch in ["386", "riscv64", "s390x", "ppc64le", ""] {
            let err = Platform::from_oci("linux", arch).unwrap_err();
            assert!(
                matches!(err, ImportError::UnsupportedPlatform { .. }),
                "arch={arch}"
            );
        }
    }

    #[test]
    fn display_is_slash_separated() {
        assert_eq!(Platform::LINUX_AMD64.to_string(), "linux/amd64");
        assert_eq!(Platform::LINUX_ARM64.to_string(), "linux/arm64");
    }

    #[test]
    fn supported_list_is_stable() {
        assert_eq!(
            Platform::supported(),
            &[Platform::LINUX_AMD64, Platform::LINUX_ARM64]
        );
    }

    #[test]
    fn serde_roundtrip_supported_platforms() {
        for p in Platform::supported() {
            let json = serde_json::to_string(p).unwrap();
            let back: Platform = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
        }
    }

    #[test]
    fn deserialize_rejects_unsupported_platform() {
        let bad = r#"{"os":"windows","architecture":"amd64"}"#;
        let res: Result<Platform, _> = serde_json::from_str(bad);
        assert!(res.is_err());
    }
}
