//! Benchmark configuration: the pinned workload, the requested conditions, and
//! the sample budget.
//!
//! # Reproducibility invariant
//! A [`BenchmarkConfig`] holds exactly one [`Workload`]. Every lane the
//! harness runs (Firecracker snapshot/restore *and* Docker start) is pinned to
//! that single workload's `payload_sha256`. The harness therefore always
//! compares identical artifact content across runtimes; it never compares
//! different images and never treats a single number or a content mismatch as
//! proof of superiority. The pinned payload hash is recorded in the output JSON
//! so a reviewer can verify both lanes used the same bytes.
//!
//! # Sample budget
//! The harness requires `N >= 100` measurements per condition for an unblocked
//! run. [`BenchmarkConfig::MIN_SAMPLES`] encodes that floor; the CLI enforces
//! it for real runs while deterministic tests may use smaller budgets.

use microvm_artifacts::Digest;
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};

/// Minimum measurements per condition for an unblocked benchmark run.
///
/// The harness requires `N >= 100`. The constant is part of the harness contract
/// and is asserted by the deterministic suite.
pub const MIN_SAMPLES: usize = 100;

/// Page-cache condition applied to each sample.
///
/// Serializes to the `page_cache_state` enum in
/// `schemas/evidence-benchmark.v1.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageCachePolicy {
    /// Caches are dropped (`drop_caches=3`) before each sample. Requires
    /// privilege; an unsupported drop blocks the cold condition with evidence.
    Cold,
    /// Caches are primed with the workload and reused across samples.
    Warm,
    /// The harness describes its own per-sample policy in the artifact.
    Mixed,
}

impl PageCachePolicy {
    /// Stable `snake_case` token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::Mixed => "mixed",
        }
    }
}

/// The requested run conditions: cgroup-v2, nested virtualization, and the
/// page-cache policy.
///
/// These drive harness behaviour (whether resource-limited or nested lanes are
/// attempted, whether caches are dropped between samples). The *observed*
/// host actuals are recorded separately in [`crate::result::HostMetadata`];
/// this type is the request, not the measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conditions {
    /// Whether the run may depend on a unified cgroup-v2 hierarchy.
    pub cgroup_v2: bool,
    /// Whether the run may depend on nested virtualization.
    pub nested: bool,
    /// The page-cache policy applied per sample.
    pub page_cache: PageCachePolicy,
}

impl Default for Conditions {
    fn default() -> Self {
        Self {
            cgroup_v2: true,
            nested: false,
            page_cache: PageCachePolicy::Mixed,
        }
    }
}

/// A pinned, content-addressed benchmark workload.
///
/// `payload_sha256` is the single content hash both the Firecracker and
/// Docker lanes must use. The optional kernel/rootfs/image
/// hashes further pin the VM-side artifacts so a reviewer can reproduce the
/// exact bytes measured.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    /// Stable workload identifier (e.g. `snapshot-restore`).
    pub name: String,
    /// The pinned payload hash shared by the Docker and VM lanes.
    pub payload_sha256: Digest,
    /// Guest kernel image hash (VM lane), when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_sha256: Option<Digest>,
    /// Root filesystem image hash (VM lane), when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs_sha256: Option<Digest>,
    /// Container/OCI image hash (Docker lane), when applicable. Must be derived
    /// from the same `payload_sha256` content as the VM rootfs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<Digest>,
}

impl Workload {
    /// Create a workload pinned to `payload_sha256`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] when `name` is empty.
    pub fn new(name: impl Into<String>, payload_sha256: Digest) -> Result<Self, MicrovmError> {
        let name = name.into();
        if name.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "workload name must not be empty",
            )
            .with_context("field", "workload.name"));
        }
        Ok(Self {
            name,
            payload_sha256,
            kernel_sha256: None,
            rootfs_sha256: None,
            image_sha256: None,
        })
    }

    /// Set the VM-side kernel hash.
    #[must_use]
    pub fn with_kernel(mut self, kernel_sha256: Digest) -> Self {
        self.kernel_sha256 = Some(kernel_sha256);
        self
    }

    /// Set the VM-side rootfs hash.
    #[must_use]
    pub fn with_rootfs(mut self, rootfs_sha256: Digest) -> Self {
        self.rootfs_sha256 = Some(rootfs_sha256);
        self
    }

    /// Set the Docker-side image hash.
    #[must_use]
    pub fn with_image(mut self, image_sha256: Digest) -> Self {
        self.image_sha256 = Some(image_sha256);
        self
    }
}

/// Runtime versions for the compared lanes.
///
/// The host kernel version lives in [`crate::result::HostMetadata::kernel`];
/// this type records the Firecracker and Docker versions so the full
/// kernel/Firecracker/Docker version set is present in the
/// output JSON. Either field is `None` when that runtime is unavailable
/// (a blocked lane still records the other runtime's version).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeVersions {
    /// Firecracker VMM version (`firecracker --version`), or `null` if absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firecracker: Option<String>,
    /// Docker Engine version (`docker version`), or `null` if the daemon is down.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker: Option<String>,
}

/// A complete benchmark configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// The single pinned workload shared by all lanes.
    pub workload: Workload,
    /// Measurements per condition (the `N` in `N >= 100`).
    pub samples: usize,
    /// Requested run conditions.
    pub conditions: Conditions,
}

impl BenchmarkConfig {
    /// The minimum per-condition sample count for an unblocked run.
    pub const MIN_SAMPLES: usize = MIN_SAMPLES;

    /// Build a configuration.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] when `samples == 0`.
    pub fn new(
        workload: Workload,
        samples: usize,
        conditions: Conditions,
    ) -> Result<Self, MicrovmError> {
        if samples == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "benchmark sample count must be at least 1",
            )
            .with_context("field", "samples"));
        }
        Ok(Self {
            workload,
            samples,
            conditions,
        })
    }

    /// True when the sample budget meets the harness's `N >= 100` floor.
    pub fn meets_minimum_samples(&self) -> bool {
        self.samples >= Self::MIN_SAMPLES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::from_bytes([byte; 32])
    }

    #[test]
    fn min_samples_floor_is_100() {
        assert_eq!(MIN_SAMPLES, 100);
        assert_eq!(BenchmarkConfig::MIN_SAMPLES, 100);
    }

    #[test]
    fn workload_requires_non_empty_name() {
        assert!(Workload::new("", digest(1)).is_err());
        assert!(Workload::new("snapshot-restore", digest(1)).is_ok());
    }

    #[test]
    fn config_rejects_zero_samples() {
        let w = Workload::new("w", digest(1)).unwrap();
        let err = BenchmarkConfig::new(w, 0, Conditions::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn meets_minimum_samples_boundary() {
        let w = Workload::new("w", digest(1)).unwrap();
        let c99 = BenchmarkConfig::new(w.clone(), 99, Conditions::default()).unwrap();
        let c100 = BenchmarkConfig::new(w, 100, Conditions::default()).unwrap();
        assert!(!c99.meets_minimum_samples());
        assert!(c100.meets_minimum_samples());
    }

    #[test]
    fn page_cache_policy_tokens_are_stable() {
        assert_eq!(PageCachePolicy::Cold.as_str(), "cold");
        assert_eq!(PageCachePolicy::Warm.as_str(), "warm");
        assert_eq!(PageCachePolicy::Mixed.as_str(), "mixed");
    }

    #[test]
    fn workload_serializes_payload_and_optional_hashes() {
        let w = Workload::new("snapshot-restore", digest(0xaa))
            .unwrap()
            .with_kernel(digest(0xbb))
            .with_image(digest(0xcc));
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["name"], "snapshot-restore");
        assert_eq!(json["payload_sha256"], digest(0xaa).to_hex());
        assert_eq!(json["kernel_sha256"], digest(0xbb).to_hex());
        assert_eq!(json["image_sha256"], digest(0xcc).to_hex());
        // rootfs unset -> omitted.
        assert!(json.get("rootfs_sha256").is_none());
    }

    #[test]
    fn runtime_versions_omit_absent_lanes() {
        let v = RuntimeVersions {
            firecracker: Some("1.16.1".into()),
            docker: None,
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["firecracker"], "1.16.1");
        assert!(json.get("docker").is_none());
    }
}
