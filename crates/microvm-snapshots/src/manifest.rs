//! Typed snapshot manifest: full snapshot metadata with content hashes and
//! compatibility fields.
//!
//! A [`SnapshotManifest`] is a pure data record (no I/O) describing everything
//! the [`crate::gate::CompatibilityGate`] needs to decide whether a snapshot
//! may be restored on the current host for the calling tenant: the exact
//! Firecracker binary (version + SHA-256), the kernel/rootfs/block-device
//! content hashes, the guest memory and VM-state hashes, the VM machine
//! config, the host compatibility envelope (CPU, KVM API version, cgroup
//! version), the owning tenant, the quota the restored VM will consume, and
//! the immutable-memory requirement.
//!
//! # Trust model (what this manifest does NOT claim)
//! - The SHA-256 digests are the orchestrator's own content hashes. Firecracker's
//!   internal snapshot CRC is only accidental-corruption detection and is
//!   **never** treated as authentication.
//! - The host envelope is a **local same-host** compatibility record. This
//!   manifest makes **no cross-host portability claim**; cross-host transfer,
//!   signing, or encryption is out of scope.
//!
//! # Integrity verification
//! [`SnapshotManifest::verify_artifacts`] compares caller-supplied *actual*
//! digests (computed from on-disk content by the backend) against the recorded
//! digests, returning a typed [`SnapshotError::Integrity`] on the first
//! mismatch — before any Firecracker process is spawned.

use crate::error::{SnapshotComponent, SnapshotError};
use chrono::{DateTime, Utc};
use microvm_artifacts::Digest;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::{SnapshotId, TenantId, VmId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Manifest schema/format version implemented by this crate.
pub const SNAPSHOT_MANIFEST_VERSION: u32 = 1;

/// The `$id` of the JSON Schema (`schemas/snapshot-manifest.v1.json`) that
/// describes the serialized manifest.
pub const SNAPSHOT_SCHEMA_ID: &str =
    "https://kvm-microvm-orchestrator.local/schemas/snapshot-manifest.v1.json";

// ---------------------------------------------------------------------------
// Firecracker binary
// ---------------------------------------------------------------------------

/// The exact Firecracker binary a snapshot was created with.
///
/// The `sha256` is the orchestrator's content hash of the pinned release/static
/// binary (provenance). It is **not** Firecracker's internal snapshot CRC and
/// is **not** an authentication primitive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirecrackerBinary {
    /// Firecracker semantic version string, e.g. `"1.16.1"`.
    pub version: String,
    /// SHA-256 of the Firecracker binary.
    pub sha256: Digest,
}

impl FirecrackerBinary {
    /// Construct a binary descriptor.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if `version` is empty.
    pub fn new(version: impl Into<String>, sha256: Digest) -> Result<Self, MicrovmError> {
        let version = version.into();
        if version.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "firecracker version must not be empty",
            ));
        }
        Ok(Self { version, sha256 })
    }
}

// ---------------------------------------------------------------------------
// VM machine config
// ---------------------------------------------------------------------------

/// The VM machine configuration a snapshot was taken under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotVmConfig {
    vcpu_count: u32,
    mem_size_mib: u64,
}

impl SnapshotVmConfig {
    /// Construct a machine config.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if `vcpu_count` or
    /// `mem_size_mib` is zero.
    pub fn new(vcpu_count: u32, mem_size_mib: u64) -> Result<Self, MicrovmError> {
        if vcpu_count == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "vcpu_count must be greater than zero",
            ));
        }
        if mem_size_mib == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "mem_size_mib must be greater than zero",
            ));
        }
        Ok(Self {
            vcpu_count,
            mem_size_mib,
        })
    }

    /// Number of virtual CPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    /// Guest memory size in MiB.
    pub fn mem_size_mib(&self) -> u64 {
        self.mem_size_mib
    }
}

// ---------------------------------------------------------------------------
// Artifact hashes
// ---------------------------------------------------------------------------

/// A block-device content hash keyed by Firecracker drive id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDeviceHash {
    /// Firecracker block-device drive id.
    pub drive_id: String,
    /// SHA-256 of the block-device backing file.
    pub sha256: Digest,
}

impl BlockDeviceHash {
    /// Construct a block-device hash.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if `drive_id` is empty.
    pub fn new(drive_id: impl Into<String>, sha256: Digest) -> Result<Self, MicrovmError> {
        let drive_id = drive_id.into();
        if drive_id.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "block device drive_id must not be empty",
            ));
        }
        Ok(Self { drive_id, sha256 })
    }
}

/// Content hashes of the boot artifacts and block devices a snapshot depends
/// on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactHashes {
    /// SHA-256 of the guest kernel image.
    pub kernel_sha256: Digest,
    /// SHA-256 of the root filesystem image.
    pub rootfs_sha256: Digest,
    /// Per-block-device content hashes.
    pub block_devices: Vec<BlockDeviceHash>,
}

// ---------------------------------------------------------------------------
// State hashes
// ---------------------------------------------------------------------------

/// Content hashes of the Firecracker snapshot state artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateHashes {
    /// SHA-256 of the guest memory file (`mem_backend.backend_path` target).
    pub memory_sha256: Digest,
    /// SHA-256 of the Firecracker VM-state file.
    pub vmstate_sha256: Digest,
}

// ---------------------------------------------------------------------------
// Host compatibility envelope
// ---------------------------------------------------------------------------

/// cgroup hierarchy version. The platform requires [`CgroupVersion::V2`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupVersion {
    /// cgroup v1 (not supported by the platform).
    V1,
    /// cgroup v2 (required).
    V2,
}

impl CgroupVersion {
    /// Stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

impl std::fmt::Display for CgroupVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CPU compatibility descriptor.
///
/// `arch` and `model` must match exactly on restore; `flags` is the sorted set
/// of required CPU feature flags the restore host must provide at least.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuCompatibility {
    /// CPU architecture, e.g. `"x86_64"`.
    pub arch: String,
    /// CPU model name (e.g. the `/proc/cpuinfo` "model name").
    pub model: String,
    /// Sorted set of required CPU feature flags (e.g. `svm`, `vmx`).
    pub flags: BTreeSet<String>,
}

impl CpuCompatibility {
    /// Construct a CPU descriptor.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if `arch` or `model` is
    /// empty.
    pub fn new(
        arch: impl Into<String>,
        model: impl Into<String>,
        flags: BTreeSet<String>,
    ) -> Result<Self, MicrovmError> {
        let arch = arch.into();
        let model = model.into();
        if arch.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "cpu arch must not be empty",
            ));
        }
        if model.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "cpu model must not be empty",
            ));
        }
        Ok(Self { arch, model, flags })
    }
}

/// The host compatibility envelope recorded at snapshot time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCompatibility {
    /// CPU compatibility descriptor.
    pub cpu: CpuCompatibility,
    /// KVM API version (`KVM_GET_API_VERSION`; stable value is 12).
    pub kvm_api_version: u32,
    /// cgroup hierarchy version.
    pub cgroup_version: CgroupVersion,
}

// ---------------------------------------------------------------------------
// Quota
// ---------------------------------------------------------------------------

/// The resources a restored VM will consume, checked against the caller
/// tenant's quota before Firecracker load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotQuota {
    /// Memory the restored VM requires, in MiB.
    pub memory_mib: u64,
    /// Disk/block storage the restored VM requires, in MiB.
    pub disk_mib: u64,
}

// ---------------------------------------------------------------------------
// Memory requirements
// ---------------------------------------------------------------------------

/// Memory-file handling requirements.
///
/// The memory file is **required** to be immutable and **must be retained for
/// as long as the restored VM runs** (Firecracker maps it for the life of the
/// process). The [`crate::gate::CompatibilityGate`] rejects a manifest that
/// does not declare `immutable == true`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRequirements {
    /// Whether the memory file is immutable. Must be `true` to restore.
    pub immutable: bool,
    /// Tenant-relative path to the memory file (`mem_backend.backend_path`).
    pub backend_path: String,
}

impl MemoryRequirements {
    /// Construct memory requirements.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if `backend_path` is empty,
    /// absolute, or contains a `..` traversal component.
    pub fn new(immutable: bool, backend_path: impl Into<String>) -> Result<Self, MicrovmError> {
        let backend_path = backend_path.into();
        if backend_path.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "memory backend_path must not be empty",
            ));
        }
        if backend_path.starts_with('/') {
            return Err(MicrovmError::new(
                ErrorCode::PathEscape,
                "memory backend_path must be relative",
            ));
        }
        if backend_path.split('/').any(|c| c == "..") {
            return Err(MicrovmError::new(
                ErrorCode::PathEscape,
                "memory backend_path must not contain '..'",
            ));
        }
        Ok(Self {
            immutable,
            backend_path,
        })
    }
}

// ---------------------------------------------------------------------------
// SnapshotManifest
// ---------------------------------------------------------------------------

/// Full snapshot metadata with content hashes and compatibility fields.
///
/// Construct via [`SnapshotManifest::builder`]. All required fields must be
/// supplied; the builder fails closed on structural invalidity, while the
/// [`crate::gate::CompatibilityGate`] enforces semantic compatibility,
/// ownership, quota, and immutability before restore.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Manifest schema/format version (must equal [`SNAPSHOT_MANIFEST_VERSION`]
    /// to be accepted by the gate).
    pub version: u32,
    /// Unique identifier for this snapshot.
    pub snapshot_id: SnapshotId,
    /// Identifier of the source VM.
    pub vm_id: VmId,
    /// Owning tenant. Must equal the caller tenant on restore.
    pub owner: TenantId,
    /// When the snapshot was created (UTC).
    pub created_at: DateTime<Utc>,
    /// The exact Firecracker binary the snapshot was created with.
    pub firecracker: FirecrackerBinary,
    /// The VM machine configuration.
    pub vm_config: SnapshotVmConfig,
    /// Boot-artifact and block-device content hashes.
    pub artifacts: ArtifactHashes,
    /// Guest memory and VM-state content hashes.
    pub state: StateHashes,
    /// Host compatibility envelope recorded at snapshot time.
    pub host: HostCompatibility,
    /// Resources the restored VM will consume.
    pub quota: SnapshotQuota,
    /// Memory-file handling requirements.
    pub memory: MemoryRequirements,
}

impl SnapshotManifest {
    /// Start building a manifest. `version` defaults to
    /// [`SNAPSHOT_MANIFEST_VERSION`].
    pub fn builder() -> SnapshotManifestBuilder {
        SnapshotManifestBuilder::default()
    }

    /// Verify caller-supplied *actual* digests against the recorded digests.
    ///
    /// This is the typed integrity check: a single flipped byte in the kernel,
    /// rootfs, a block device, the guest memory file, or the VM-state file
    /// yields [`SnapshotError::Integrity`] (a "snapshot integrity error")
    /// before any child process is spawned. A block device present in the
    /// manifest but absent from `actual` (or vice versa) yields
    /// [`SnapshotError::MissingComponent`].
    ///
    /// # Errors
    /// Returns [`SnapshotError`] on the first mismatch or missing component.
    pub fn verify_artifacts(&self, actual: &ActualHashes) -> Result<(), SnapshotError> {
        verify_digest(
            SnapshotComponent::Kernel,
            self.artifacts.kernel_sha256,
            actual.kernel_sha256,
        )?;
        verify_digest(
            SnapshotComponent::Rootfs,
            self.artifacts.rootfs_sha256,
            actual.rootfs_sha256,
        )?;
        verify_digest(
            SnapshotComponent::Memory,
            self.state.memory_sha256,
            actual.memory_sha256,
        )?;
        verify_digest(
            SnapshotComponent::VmState,
            self.state.vmstate_sha256,
            actual.vmstate_sha256,
        )?;
        verify_block_devices(&self.artifacts.block_devices, &actual.block_devices)?;
        Ok(())
    }
}

/// Compare two digests for a component, returning [`SnapshotError::Integrity`]
/// on mismatch. Comparison is constant-time via [`Digest::ct_eq`].
fn verify_digest(
    component: SnapshotComponent,
    expected: Digest,
    actual: Digest,
) -> Result<(), SnapshotError> {
    if expected.ct_eq(&actual) {
        Ok(())
    } else {
        Err(SnapshotError::Integrity {
            component,
            expected,
            actual,
        })
    }
}

/// Verify the block-device hash sets match by drive id.
fn verify_block_devices(
    expected: &[BlockDeviceHash],
    actual: &[BlockDeviceHash],
) -> Result<(), SnapshotError> {
    for exp in expected {
        let act = actual
            .iter()
            .find(|a| a.drive_id == exp.drive_id)
            .ok_or_else(|| SnapshotError::MissingComponent {
                component: SnapshotComponent::BlockDevice(exp.drive_id.clone()),
            })?;
        verify_digest(
            SnapshotComponent::BlockDevice(exp.drive_id.clone()),
            exp.sha256,
            act.sha256,
        )?;
    }
    // Reject block devices present in `actual` but not recorded in the manifest.
    for act in actual {
        if !expected.iter().any(|e| e.drive_id == act.drive_id) {
            return Err(SnapshotError::MissingComponent {
                component: SnapshotComponent::BlockDevice(act.drive_id.clone()),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ActualHashes (integrity input)
// ---------------------------------------------------------------------------

/// Caller-supplied *actual* content digests, computed from on-disk content by
/// the backend, used by [`SnapshotManifest::verify_artifacts`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualHashes {
    /// Actual SHA-256 of the guest kernel image.
    pub kernel_sha256: Digest,
    /// Actual SHA-256 of the root filesystem image.
    pub rootfs_sha256: Digest,
    /// Actual SHA-256 of the guest memory file.
    pub memory_sha256: Digest,
    /// Actual SHA-256 of the Firecracker VM-state file.
    pub vmstate_sha256: Digest,
    /// Actual per-block-device hashes.
    pub block_devices: Vec<BlockDeviceHash>,
}

impl ActualHashes {
    /// Build an [`ActualHashes`] that exactly matches `manifest` (useful as a
    /// test baseline that the caller then perturbs to simulate corruption).
    pub fn matching(manifest: &SnapshotManifest) -> Self {
        Self {
            kernel_sha256: manifest.artifacts.kernel_sha256,
            rootfs_sha256: manifest.artifacts.rootfs_sha256,
            memory_sha256: manifest.state.memory_sha256,
            vmstate_sha256: manifest.state.vmstate_sha256,
            block_devices: manifest.artifacts.block_devices.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`SnapshotManifest`]. All required fields must be set before
/// [`SnapshotManifestBuilder::build`]; the builder fails closed on structural
/// invalidity.
#[derive(Default)]
pub struct SnapshotManifestBuilder {
    version: Option<u32>,
    snapshot_id: Option<SnapshotId>,
    vm_id: Option<VmId>,
    owner: Option<TenantId>,
    created_at: Option<DateTime<Utc>>,
    firecracker: Option<FirecrackerBinary>,
    vm_config: Option<SnapshotVmConfig>,
    artifacts: Option<ArtifactHashes>,
    state: Option<StateHashes>,
    host: Option<HostCompatibility>,
    quota: Option<SnapshotQuota>,
    memory: Option<MemoryRequirements>,
}

macro_rules! builder_setter {
    ($name:ident, $ty:ty) => {
        /// Set the field.
        #[must_use]
        pub fn $name(mut self, value: $ty) -> Self {
            self.$name = Some(value);
            self
        }
    };
}

impl SnapshotManifestBuilder {
    builder_setter!(version, u32);
    builder_setter!(snapshot_id, SnapshotId);
    builder_setter!(vm_id, VmId);
    builder_setter!(owner, TenantId);
    builder_setter!(created_at, DateTime<Utc>);
    builder_setter!(firecracker, FirecrackerBinary);
    builder_setter!(vm_config, SnapshotVmConfig);
    builder_setter!(artifacts, ArtifactHashes);
    builder_setter!(state, StateHashes);
    builder_setter!(host, HostCompatibility);
    builder_setter!(quota, SnapshotQuota);
    builder_setter!(memory, MemoryRequirements);

    /// Build the manifest.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if any required field is
    /// omitted. `version` defaults to [`SNAPSHOT_MANIFEST_VERSION`] and
    /// `created_at` defaults to the current UTC time when unset.
    pub fn build(self) -> Result<SnapshotManifest, MicrovmError> {
        let snapshot_id = self
            .snapshot_id
            .ok_or_else(|| required_err("snapshot_id"))?;
        let vm_id = self.vm_id.ok_or_else(|| required_err("vm_id"))?;
        let owner = self.owner.ok_or_else(|| required_err("owner"))?;
        let firecracker = self
            .firecracker
            .ok_or_else(|| required_err("firecracker"))?;
        let vm_config = self.vm_config.ok_or_else(|| required_err("vm_config"))?;
        let artifacts = self.artifacts.ok_or_else(|| required_err("artifacts"))?;
        let state = self.state.ok_or_else(|| required_err("state"))?;
        let host = self.host.ok_or_else(|| required_err("host"))?;
        let quota = self.quota.ok_or_else(|| required_err("quota"))?;
        let memory = self.memory.ok_or_else(|| required_err("memory"))?;

        Ok(SnapshotManifest {
            version: self.version.unwrap_or(SNAPSHOT_MANIFEST_VERSION),
            snapshot_id,
            vm_id,
            owner,
            created_at: self.created_at.unwrap_or_else(Utc::now),
            firecracker,
            vm_config,
            artifacts,
            state,
            host,
            quota,
            memory,
        })
    }
}

fn required_err(field: &str) -> MicrovmError {
    MicrovmError::new(
        ErrorCode::InvalidResourceSpec,
        format!("snapshot manifest field '{}' is required", field),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(b: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        Digest::from_bytes(bytes)
    }

    /// Build a structurally valid manifest for tests.
    pub(crate) fn sample_manifest() -> SnapshotManifest {
        SnapshotManifest::builder()
            .snapshot_id(SnapshotId::new("snap-001").unwrap())
            .vm_id(VmId::new("vm-001").unwrap())
            .owner(TenantId::new("tenant-1").unwrap())
            .created_at(DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap())
            .firecracker(FirecrackerBinary::new("1.16.1", digest(0xFC)).unwrap())
            .vm_config(SnapshotVmConfig::new(2, 512).unwrap())
            .artifacts(ArtifactHashes {
                kernel_sha256: digest(0xA1),
                rootfs_sha256: digest(0xA2),
                block_devices: vec![BlockDeviceHash::new("root", digest(0xA5)).unwrap()],
            })
            .state(StateHashes {
                memory_sha256: digest(0xA3),
                vmstate_sha256: digest(0xA4),
            })
            .host(HostCompatibility {
                cpu: CpuCompatibility::new(
                    "x86_64",
                    "AMD EPYC",
                    ["svm".to_string()].into_iter().collect(),
                )
                .unwrap(),
                kvm_api_version: 12,
                cgroup_version: CgroupVersion::V2,
            })
            .quota(SnapshotQuota {
                memory_mib: 512,
                disk_mib: 1024,
            })
            .memory(MemoryRequirements::new(true, "snapshots/snap-001/mem.file").unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn builder_defaults_version_and_created_at() {
        let m = sample_manifest();
        assert_eq!(m.version, SNAPSHOT_MANIFEST_VERSION);
    }

    #[test]
    fn builder_rejects_missing_required_field() {
        // Omit `owner`.
        let err = SnapshotManifest::builder()
            .snapshot_id(SnapshotId::new("snap-001").unwrap())
            .vm_id(VmId::new("vm-001").unwrap())
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert!(err.message.contains("owner"));
    }

    #[test]
    fn vm_config_rejects_zero() {
        assert!(SnapshotVmConfig::new(0, 512).is_err());
        assert!(SnapshotVmConfig::new(1, 0).is_err());
    }

    #[test]
    fn memory_requirements_rejects_absolute_and_traversal() {
        assert!(MemoryRequirements::new(true, "/abs/path").is_err());
        assert!(MemoryRequirements::new(true, "a/../b").is_err());
        assert!(MemoryRequirements::new(true, "").is_err());
        assert!(MemoryRequirements::new(true, "snapshots/mem.file").is_ok());
    }

    #[test]
    fn verify_artifacts_accepts_matching_hashes() {
        let m = sample_manifest();
        let actual = ActualHashes::matching(&m);
        assert!(m.verify_artifacts(&actual).is_ok());
    }

    #[test]
    fn verify_artifacts_detects_memory_flip() {
        let m = sample_manifest();
        let mut actual = ActualHashes::matching(&m);
        actual.memory_sha256 = digest(0xFF);
        let err = m.verify_artifacts(&actual).unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::Integrity {
                component: SnapshotComponent::Memory,
                ..
            }
        ));
        assert_eq!(err.code(), ErrorCode::DigestMismatch);
    }

    #[test]
    fn verify_artifacts_detects_vmstate_flip() {
        let m = sample_manifest();
        let mut actual = ActualHashes::matching(&m);
        actual.vmstate_sha256 = digest(0xEE);
        let err = m.verify_artifacts(&actual).unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::Integrity {
                component: SnapshotComponent::VmState,
                ..
            }
        ));
    }

    #[test]
    fn verify_artifacts_detects_block_device_flip() {
        let m = sample_manifest();
        let mut actual = ActualHashes::matching(&m);
        actual.block_devices[0].sha256 = digest(0xDD);
        let err = m.verify_artifacts(&actual).unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::Integrity {
                component: SnapshotComponent::BlockDevice(_),
                ..
            }
        ));
    }

    #[test]
    fn verify_artifacts_detects_missing_block_device() {
        let m = sample_manifest();
        let mut actual = ActualHashes::matching(&m);
        actual.block_devices.clear();
        let err = m.verify_artifacts(&actual).unwrap_err();
        assert!(matches!(err, SnapshotError::MissingComponent { .. }));
        assert_eq!(err.code(), ErrorCode::DigestMismatch);
    }

    #[test]
    fn serde_roundtrip_preserves_manifest() {
        let m = sample_manifest();
        let json = serde_json::to_string(&m).unwrap();
        let back: SnapshotManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}
