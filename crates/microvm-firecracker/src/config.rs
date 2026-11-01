//! Validated boot configuration for a Firecracker VM.
//!
//! A [`BootConfig`] carries everything the Firecracker API needs to boot a
//! guest: the kernel and rootfs artifact locations (as relative paths
//! within a tenant artifact root), their expected SHA-256 digests, the machine
//! shape (vCPU count, memory), optional kernel boot arguments, and an optional
//! network attachment.
//!
//! # Integrity model
//! Kernel and rootfs paths are stored *relative* and are lexically validated
//! with [`validate_relative_path`] at construction. They are never interpreted
//! as absolute paths, symlinks, or URIs. The actual digest verification against
//! on-disk content happens at boot time inside the backend via
//! [`microvm_artifacts::ArtifactStore`]; the digests stored here are the
//! expected values that content must match. This separation keeps [`BootConfig`]
//! pure (no I/O) while still binding every path to a content digest.

use microvm_artifacts::{validate_relative_path, Digest};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::NetworkPolicy;
use serde::{Deserialize, Serialize};

/// Maximum kernel boot-argument length accepted by the adapter.
///
/// Firecracker passes boot args to the kernel command line; we bound them to a
/// conservative 4 KiB to keep the serialized API payload small and to reject
/// obviously malformed input before it reaches the VMM.
pub const MAX_BOOT_ARGS_LEN: usize = 4096;

/// Network attachment for a boot configuration.
///
/// The TAP device name and addressing are produced by the isolation crate's
/// [`microvm_isolation::NetManager`]; this struct carries only the policy that
/// selects whether (and how) a network interface is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkBootConfig {
    /// The egress policy applied to the VM's TAP interface.
    pub policy: NetworkPolicy,
}

impl NetworkBootConfig {
    /// Create a network boot config for `policy`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if `policy` is
    /// [`NetworkPolicy::None`] (a network config with no policy is meaningless;
    /// omit the field instead).
    pub fn new(policy: NetworkPolicy) -> Result<Self, MicrovmError> {
        if policy == NetworkPolicy::None {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "network boot config requires a policy other than none",
            ));
        }
        Ok(Self { policy })
    }
}

/// A fully validated Firecracker boot configuration.
///
/// Construct via [`BootConfig::builder`]. All fields are immutable after
/// construction; the builder fails closed on any invalid field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootConfig {
    kernel_path: String,
    kernel_sha256: Digest,
    rootfs_path: String,
    rootfs_sha256: Digest,
    vcpu_count: u32,
    mem_size_mib: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_args: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<NetworkBootConfig>,
}

impl BootConfig {
    /// Start building a boot configuration.
    pub fn builder() -> BootConfigBuilder {
        BootConfigBuilder::default()
    }

    /// Relative path to the kernel image within the tenant artifact root.
    pub fn kernel_path(&self) -> &str {
        &self.kernel_path
    }

    /// Expected SHA-256 of the kernel image.
    pub fn kernel_sha256(&self) -> &Digest {
        &self.kernel_sha256
    }

    /// Relative path to the rootfs block device within the tenant artifact root.
    pub fn rootfs_path(&self) -> &str {
        &self.rootfs_path
    }

    /// Expected SHA-256 of the rootfs block device.
    pub fn rootfs_sha256(&self) -> &Digest {
        &self.rootfs_sha256
    }

    /// Number of vCPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    /// Memory size in MiB.
    pub fn mem_size_mib(&self) -> u64 {
        self.mem_size_mib
    }

    /// Optional kernel boot arguments.
    pub fn boot_args(&self) -> Option<&str> {
        self.boot_args.as_deref()
    }

    /// Optional network attachment.
    pub fn network(&self) -> Option<NetworkBootConfig> {
        self.network
    }

    /// True when a network interface should be attached.
    pub fn has_network(&self) -> bool {
        self.network.is_some()
    }
}

/// Builder for a validated [`BootConfig`].
#[derive(Clone, Debug, Default)]
pub struct BootConfigBuilder {
    kernel_path: Option<String>,
    kernel_sha256: Option<Digest>,
    rootfs_path: Option<String>,
    rootfs_sha256: Option<Digest>,
    vcpu_count: Option<u32>,
    mem_size_mib: Option<u64>,
    boot_args: Option<String>,
    network: Option<NetworkBootConfig>,
}

impl BootConfigBuilder {
    /// Set the relative kernel path (validated by [`validate_relative_path`]).
    pub fn kernel_path(mut self, path: impl Into<String>) -> Self {
        self.kernel_path = Some(path.into());
        self
    }

    /// Set the expected kernel SHA-256.
    pub fn kernel_sha256(mut self, digest: Digest) -> Self {
        self.kernel_sha256 = Some(digest);
        self
    }

    /// Set the relative rootfs path (validated by [`validate_relative_path`]).
    pub fn rootfs_path(mut self, path: impl Into<String>) -> Self {
        self.rootfs_path = Some(path.into());
        self
    }

    /// Set the expected rootfs SHA-256.
    pub fn rootfs_sha256(mut self, digest: Digest) -> Self {
        self.rootfs_sha256 = Some(digest);
        self
    }

    /// Set the vCPU count (must be > 0).
    pub fn vcpu_count(mut self, n: u32) -> Self {
        self.vcpu_count = Some(n);
        self
    }

    /// Set the memory size in MiB (must be > 0).
    pub fn mem_size_mib(mut self, mib: u64) -> Self {
        self.mem_size_mib = Some(mib);
        self
    }

    /// Set optional kernel boot arguments.
    pub fn boot_args(mut self, args: impl Into<String>) -> Self {
        self.boot_args = Some(args.into());
        self
    }

    /// Attach a network interface with the given policy.
    pub fn network(mut self, network: NetworkBootConfig) -> Self {
        self.network = Some(network);
        self
    }

    /// Validate every field and build the configuration.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] for missing/invalid fields and
    /// [`ErrorCode::PathEscape`] for a kernel/rootfs path that fails relative-path
    /// validation.
    pub fn build(self) -> Result<BootConfig, MicrovmError> {
        let invalid = |msg: &str, field: &str| {
            MicrovmError::new(ErrorCode::InvalidResourceSpec, msg).with_context("field", field)
        };

        let kernel_path = self
            .kernel_path
            .ok_or_else(|| invalid("kernel_path is required", "kernel_path"))?;
        validate_relative_path(&kernel_path).map_err(|e| {
            MicrovmError::new(
                ErrorCode::PathEscape,
                "kernel_path failed relative-path validation",
            )
            .with_context("field", "kernel_path")
            .with_context("path", &kernel_path)
            .with_context("cause", e.message)
        })?;

        let kernel_sha256 = self
            .kernel_sha256
            .ok_or_else(|| invalid("kernel_sha256 is required", "kernel_sha256"))?;

        let rootfs_path = self
            .rootfs_path
            .ok_or_else(|| invalid("rootfs_path is required", "rootfs_path"))?;
        validate_relative_path(&rootfs_path).map_err(|e| {
            MicrovmError::new(
                ErrorCode::PathEscape,
                "rootfs_path failed relative-path validation",
            )
            .with_context("field", "rootfs_path")
            .with_context("path", &rootfs_path)
            .with_context("cause", e.message)
        })?;

        let rootfs_sha256 = self
            .rootfs_sha256
            .ok_or_else(|| invalid("rootfs_sha256 is required", "rootfs_sha256"))?;

        let vcpu_count = self
            .vcpu_count
            .ok_or_else(|| invalid("vcpu_count is required", "vcpu_count"))?;
        if vcpu_count == 0 {
            return Err(invalid(
                "vcpu_count must be greater than zero",
                "vcpu_count",
            ));
        }

        let mem_size_mib = self
            .mem_size_mib
            .ok_or_else(|| invalid("mem_size_mib is required", "mem_size_mib"))?;
        if mem_size_mib == 0 {
            return Err(invalid(
                "mem_size_mib must be greater than zero",
                "mem_size_mib",
            ));
        }

        if let Some(args) = &self.boot_args {
            if args.len() > MAX_BOOT_ARGS_LEN {
                return Err(invalid("boot_args exceeds maximum length", "boot_args")
                    .with_context("max", MAX_BOOT_ARGS_LEN.to_string())
                    .with_context("len", args.len().to_string()));
            }
        }

        Ok(BootConfig {
            kernel_path,
            kernel_sha256,
            rootfs_path,
            rootfs_sha256,
            vcpu_count,
            mem_size_mib,
            boot_args: self.boot_args,
            network: self.network,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_artifacts::compute_sha256;

    fn digest(s: &[u8]) -> Digest {
        compute_sha256(s).unwrap()
    }

    fn valid_builder() -> BootConfigBuilder {
        BootConfig::builder()
            .kernel_path("images/vmlinux")
            .kernel_sha256(digest(b"kernel"))
            .rootfs_path("images/rootfs.ext4")
            .rootfs_sha256(digest(b"rootfs"))
            .vcpu_count(2)
            .mem_size_mib(512)
    }

    #[test]
    fn valid_config_builds() {
        let cfg = valid_builder().build().unwrap();
        assert_eq!(cfg.kernel_path(), "images/vmlinux");
        assert_eq!(cfg.rootfs_path(), "images/rootfs.ext4");
        assert_eq!(cfg.vcpu_count(), 2);
        assert_eq!(cfg.mem_size_mib(), 512);
        assert_eq!(cfg.boot_args(), None);
        assert!(!cfg.has_network());
    }

    #[test]
    fn config_with_boot_args_and_network() {
        let cfg = valid_builder()
            .boot_args("console=ttyS0 reboot=k panic=1 pci=off")
            .network(NetworkBootConfig::new(NetworkPolicy::NatOnly).unwrap())
            .build()
            .unwrap();
        assert_eq!(
            cfg.boot_args(),
            Some("console=ttyS0 reboot=k panic=1 pci=off")
        );
        assert!(cfg.has_network());
        assert_eq!(cfg.network().unwrap().policy, NetworkPolicy::NatOnly);
    }

    #[test]
    fn missing_kernel_path_rejected() {
        let err = valid_builder()
            .kernel_path("") // will be overwritten below by omission
            .build();
        // empty path fails relative-path validation
        assert!(err.is_err());
    }

    #[test]
    fn omitted_required_field_rejected() {
        let err = BootConfig::builder()
            .kernel_sha256(digest(b"k"))
            .rootfs_path("images/rootfs.ext4")
            .rootfs_sha256(digest(b"r"))
            .vcpu_count(1)
            .mem_size_mib(128)
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert_eq!(
            err.context.get("field").map(String::as_str),
            Some("kernel_path")
        );
    }

    #[test]
    fn absolute_kernel_path_rejected() {
        let err = valid_builder()
            .kernel_path("/etc/passwd")
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape);
        assert_eq!(
            err.context.get("field").map(String::as_str),
            Some("kernel_path")
        );
    }

    #[test]
    fn traversal_rootfs_path_rejected() {
        let err = valid_builder()
            .rootfs_path("../images/rootfs.ext4")
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape);
        assert_eq!(
            err.context.get("field").map(String::as_str),
            Some("rootfs_path")
        );
    }

    #[test]
    fn uri_path_rejected() {
        let err = valid_builder()
            .kernel_path("s3://bucket/vmlinux")
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape);
    }

    #[test]
    fn zero_vcpu_rejected() {
        let err = valid_builder().vcpu_count(0).build().unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert_eq!(
            err.context.get("field").map(String::as_str),
            Some("vcpu_count")
        );
    }

    #[test]
    fn zero_memory_rejected() {
        let err = valid_builder().mem_size_mib(0).build().unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert_eq!(
            err.context.get("field").map(String::as_str),
            Some("mem_size_mib")
        );
    }

    #[test]
    fn oversized_boot_args_rejected() {
        let huge = "x".repeat(MAX_BOOT_ARGS_LEN + 1);
        let err = valid_builder().boot_args(huge).build().unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert_eq!(
            err.context.get("field").map(String::as_str),
            Some("boot_args")
        );
    }

    #[test]
    fn network_none_policy_rejected() {
        let err = NetworkBootConfig::new(NetworkPolicy::None).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = valid_builder()
            .boot_args("console=ttyS0")
            .network(NetworkBootConfig::new(NetworkPolicy::EgressAllowed).unwrap())
            .build()
            .unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: BootConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn serde_omits_absent_optionals() {
        let cfg = valid_builder().build().unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("boot_args"));
        assert!(!json.contains("network"));
    }
}
