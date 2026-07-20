//! Pre-restore compatibility gate.
//!
//! [`CompatibilityGate`] validates a [`SnapshotManifest`] against the current
//! host, the pinned Firecracker binary, and the caller tenant's quota **before
//! any Firecracker process is spawned or `/snapshot/load` is issued**. Every
//! failure is a typed [`SnapshotError`] mapping to a stable [`ErrorCode`].
//!
//! # Checks (in order, all fail-closed before Firecracker load)
//! 1. Schema version is supported ([`SnapshotError::UnsupportedSchema`]).
//! 2. Manifest owner equals the caller tenant ([`SnapshotError::ForeignOwner`]).
//! 3. Firecracker binary version + hash match ([`SnapshotError::BinaryIncompatible`]).
//! 4. CPU arch/model/flags compatible ([`SnapshotError::CpuIncompatible`]).
//! 5. KVM API version matches ([`SnapshotError::KvmApiIncompatible`]).
//! 6. cgroup version matches and is v2 ([`SnapshotError::CgroupIncompatible`]).
//! 7. Memory file declared immutable ([`SnapshotError::MemoryNotImmutable`]).
//! 8. Required resources fit the tenant quota ([`SnapshotError::QuotaOverflow`]).
//!
//! # What the gate does NOT do
//! - It does **not** treat Firecracker's internal snapshot CRC as
//!   authentication; integrity is the orchestrator's own SHA-256 check
//!   ([`SnapshotManifest::verify_artifacts`]).
//! - It does **not** invent cross-host compatibility: the host envelope is a
//!   local same-host record, and a mismatch is a hard rejection.

use crate::error::SnapshotError;
use crate::manifest::{
    CgroupVersion, CpuCompatibility, FirecrackerBinary, SnapshotManifest, SNAPSHOT_MANIFEST_VERSION,
};
use microvm_types::TenantId;

/// The current host's compatibility envelope, supplied to the gate.
///
/// This is a pure description (no I/O); the backend or preflight populates it
/// from the real host. Keeping it as data keeps the gate deterministic and
/// testable without `/dev/kvm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEnvironment {
    /// CPU compatibility descriptor of the restore host.
    pub cpu: CpuCompatibility,
    /// KVM API version of the restore host (`KVM_GET_API_VERSION`).
    pub kvm_api_version: u32,
    /// cgroup hierarchy version of the restore host.
    pub cgroup_version: CgroupVersion,
}

/// A tenant's resource quota limits, supplied to the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantQuota {
    /// Maximum memory the tenant may have running, in MiB.
    pub max_memory_mib: u64,
    /// Maximum disk/block storage the tenant may consume, in MiB.
    pub max_disk_mib: u64,
}

/// Validates a [`SnapshotManifest`] against the current host/binary/config
/// before restore.
#[derive(Clone, Debug)]
pub struct CompatibilityGate {
    host: HostEnvironment,
    binary: FirecrackerBinary,
    quota: TenantQuota,
}

impl CompatibilityGate {
    /// Construct a gate from the current host envelope, the pinned Firecracker
    /// binary, and the caller tenant's quota limits.
    pub fn new(host: HostEnvironment, binary: FirecrackerBinary, quota: TenantQuota) -> Self {
        Self {
            host,
            binary,
            quota,
        }
    }

    /// Validate `manifest` for restore by `caller`.
    ///
    /// Runs every compatibility, ownership, immutability, and quota check
    /// before Firecracker load. Returns `Ok(())` only if all pass.
    ///
    /// # Errors
    /// Returns the first [`SnapshotError`] encountered. Compatibility failures
    /// map to [`ErrorCode::SnapshotIncompatible`]; a foreign owner maps to
    /// [`ErrorCode::PermissionDenied`]; a quota overflow maps to
    /// [`ErrorCode::QuotaExceeded`].
    pub fn validate(
        &self,
        manifest: &SnapshotManifest,
        caller: &TenantId,
    ) -> Result<(), SnapshotError> {
        self.check_schema(manifest)?;
        self.check_owner(manifest, caller)?;
        self.check_binary(manifest)?;
        self.check_cpu(manifest)?;
        self.check_kvm_api(manifest)?;
        self.check_cgroup(manifest)?;
        self.check_memory_immutable(manifest)?;
        self.check_quota(manifest)?;
        Ok(())
    }

    fn check_schema(&self, manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
        if manifest.version == SNAPSHOT_MANIFEST_VERSION {
            Ok(())
        } else {
            Err(SnapshotError::UnsupportedSchema {
                found: manifest.version,
                supported: SNAPSHOT_MANIFEST_VERSION,
            })
        }
    }

    fn check_owner(
        &self,
        manifest: &SnapshotManifest,
        caller: &TenantId,
    ) -> Result<(), SnapshotError> {
        if manifest.owner == *caller {
            Ok(())
        } else {
            Err(SnapshotError::ForeignOwner {
                manifest_owner: manifest.owner.to_string(),
                caller: caller.to_string(),
            })
        }
    }

    fn check_binary(&self, manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
        let m = &manifest.firecracker;
        if m.version != self.binary.version {
            return Err(SnapshotError::BinaryIncompatible {
                reason: format!(
                    "firecracker version mismatch (manifest {}, host {})",
                    m.version, self.binary.version
                ),
            });
        }
        if !m.sha256.ct_eq(&self.binary.sha256) {
            return Err(SnapshotError::BinaryIncompatible {
                reason: format!(
                    "firecracker binary hash mismatch (manifest {}, host {})",
                    m.sha256.to_hex(),
                    self.binary.sha256.to_hex()
                ),
            });
        }
        Ok(())
    }

    fn check_cpu(&self, manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
        let m = &manifest.host.cpu;
        let h = &self.host.cpu;
        if m.arch != h.arch {
            return Err(SnapshotError::CpuIncompatible {
                reason: format!("arch mismatch (manifest {}, host {})", m.arch, h.arch),
            });
        }
        if m.model != h.model {
            return Err(SnapshotError::CpuIncompatible {
                reason: format!("model mismatch (manifest {}, host {})", m.model, h.model),
            });
        }
        // The restore host must provide at least the flags the snapshot needs.
        if !m.flags.is_subset(&h.flags) {
            let missing: Vec<&String> = m.flags.difference(&h.flags).collect();
            return Err(SnapshotError::CpuIncompatible {
                reason: format!("host is missing required cpu flags {:?}", missing),
            });
        }
        Ok(())
    }

    fn check_kvm_api(&self, manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
        if manifest.host.kvm_api_version == self.host.kvm_api_version {
            Ok(())
        } else {
            Err(SnapshotError::KvmApiIncompatible {
                manifest: manifest.host.kvm_api_version,
                host: self.host.kvm_api_version,
            })
        }
    }

    fn check_cgroup(&self, manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
        // The platform requires cgroup v2 on both sides.
        if manifest.host.cgroup_version != CgroupVersion::V2 {
            return Err(SnapshotError::CgroupIncompatible {
                manifest: manifest.host.cgroup_version.to_string(),
                host: self.host.cgroup_version.to_string(),
            });
        }
        if manifest.host.cgroup_version != self.host.cgroup_version {
            return Err(SnapshotError::CgroupIncompatible {
                manifest: manifest.host.cgroup_version.to_string(),
                host: self.host.cgroup_version.to_string(),
            });
        }
        Ok(())
    }

    fn check_memory_immutable(&self, manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
        if manifest.memory.immutable {
            Ok(())
        } else {
            Err(SnapshotError::MemoryNotImmutable)
        }
    }

    fn check_quota(&self, manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
        if manifest.quota.memory_mib > self.quota.max_memory_mib {
            return Err(SnapshotError::QuotaOverflow {
                reason: format!(
                    "memory {} MiB exceeds tenant limit {} MiB",
                    manifest.quota.memory_mib, self.quota.max_memory_mib
                ),
            });
        }
        if manifest.quota.disk_mib > self.quota.max_disk_mib {
            return Err(SnapshotError::QuotaOverflow {
                reason: format!(
                    "disk {} MiB exceeds tenant limit {} MiB",
                    manifest.quota.disk_mib, self.quota.max_disk_mib
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        ArtifactHashes, BlockDeviceHash, HostCompatibility, MemoryRequirements, SnapshotQuota,
        SnapshotVmConfig, StateHashes,
    };
    use microvm_artifacts::Digest;
    use microvm_errors::ErrorCode;
    use microvm_types::{SnapshotId, VmId};

    fn digest(b: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        Digest::from_bytes(bytes)
    }

    fn host_cpu() -> CpuCompatibility {
        CpuCompatibility::new(
            "x86_64",
            "AMD EPYC",
            ["svm".to_string()].into_iter().collect(),
        )
        .unwrap()
    }

    fn host_env() -> HostEnvironment {
        HostEnvironment {
            cpu: host_cpu(),
            kvm_api_version: 12,
            cgroup_version: CgroupVersion::V2,
        }
    }

    fn binary() -> FirecrackerBinary {
        FirecrackerBinary::new("1.16.1", digest(0xFC)).unwrap()
    }

    fn quota() -> TenantQuota {
        TenantQuota {
            max_memory_mib: 4096,
            max_disk_mib: 8192,
        }
    }

    fn gate() -> CompatibilityGate {
        CompatibilityGate::new(host_env(), binary(), quota())
    }

    fn manifest(owner: &str) -> SnapshotManifest {
        SnapshotManifest::builder()
            .snapshot_id(SnapshotId::new("snap-001").unwrap())
            .vm_id(VmId::new("vm-001").unwrap())
            .owner(TenantId::new(owner).unwrap())
            .firecracker(binary())
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
                cpu: host_cpu(),
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
    fn accepts_compatible_manifest_for_owner() {
        let m = manifest("tenant-1");
        let caller = TenantId::new("tenant-1").unwrap();
        assert!(gate().validate(&m, &caller).is_ok());
    }

    #[test]
    fn rejects_unsupported_schema() {
        let mut m = manifest("tenant-1");
        m.version = 99;
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::UnsupportedSchema {
                found: 99,
                supported: 1
            }
        ));
        assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    }

    #[test]
    fn rejects_foreign_owner() {
        let m = manifest("tenant-1");
        let caller = TenantId::new("tenant-2").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::ForeignOwner { .. }));
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn rejects_binary_version_mismatch() {
        let mut m = manifest("tenant-1");
        m.firecracker = FirecrackerBinary::new("1.15.0", digest(0xFC)).unwrap();
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::BinaryIncompatible { .. }));
        assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    }

    #[test]
    fn rejects_binary_hash_mismatch() {
        let mut m = manifest("tenant-1");
        m.firecracker = FirecrackerBinary::new("1.16.1", digest(0x00)).unwrap();
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::BinaryIncompatible { .. }));
    }

    #[test]
    fn rejects_cpu_arch_mismatch() {
        let mut m = manifest("tenant-1");
        m.host.cpu = CpuCompatibility::new("aarch64", "AMD EPYC", Default::default()).unwrap();
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::CpuIncompatible { .. }));
        assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    }

    #[test]
    fn rejects_cpu_missing_required_flag() {
        let mut m = manifest("tenant-1");
        // Manifest requires vmx, but the host only offers svm.
        m.host.cpu = CpuCompatibility::new(
            "x86_64",
            "AMD EPYC",
            ["vmx".to_string()].into_iter().collect(),
        )
        .unwrap();
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::CpuIncompatible { .. }));
    }

    #[test]
    fn accepts_host_with_superset_flags() {
        let mut m = manifest("tenant-1");
        // Manifest needs svm; host offers svm + more.
        m.host.cpu = CpuCompatibility::new(
            "x86_64",
            "AMD EPYC",
            ["svm".to_string()].into_iter().collect(),
        )
        .unwrap();
        let mut env = host_env();
        env.cpu = CpuCompatibility::new(
            "x86_64",
            "AMD EPYC",
            ["svm".to_string(), "avx2".to_string()]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let gate = CompatibilityGate::new(env, binary(), quota());
        let caller = TenantId::new("tenant-1").unwrap();
        assert!(gate.validate(&m, &caller).is_ok());
    }

    #[test]
    fn rejects_kvm_api_mismatch() {
        let mut m = manifest("tenant-1");
        m.host.kvm_api_version = 11;
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::KvmApiIncompatible {
                manifest: 11,
                host: 12
            }
        ));
        assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    }

    #[test]
    fn rejects_cgroup_v1_manifest() {
        let mut m = manifest("tenant-1");
        m.host.cgroup_version = CgroupVersion::V1;
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::CgroupIncompatible { .. }));
        assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    }

    #[test]
    fn rejects_non_immutable_memory() {
        let mut m = manifest("tenant-1");
        m.memory = MemoryRequirements::new(false, "snapshots/snap-001/mem.file").unwrap();
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::MemoryNotImmutable));
        assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    }

    #[test]
    fn rejects_memory_quota_overflow() {
        let mut m = manifest("tenant-1");
        m.quota.memory_mib = 999_999;
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::QuotaOverflow { .. }));
        assert_eq!(err.code(), ErrorCode::QuotaExceeded);
    }

    #[test]
    fn rejects_disk_quota_overflow() {
        let mut m = manifest("tenant-1");
        m.quota.disk_mib = 999_999;
        let caller = TenantId::new("tenant-1").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::QuotaOverflow { .. }));
    }

    #[test]
    fn owner_check_precedes_binary_check() {
        // A foreign owner with an incompatible binary must fail on owner first.
        let mut m = manifest("tenant-1");
        m.firecracker = FirecrackerBinary::new("0.0.0", digest(0x00)).unwrap();
        let caller = TenantId::new("tenant-2").unwrap();
        let err = gate().validate(&m, &caller).unwrap_err();
        assert!(matches!(err, SnapshotError::ForeignOwner { .. }));
    }
}
