//! Snapshot-integrity and compatibility adversarial suite.
//!
//! Drives the real [`microvm_snapshots::SnapshotManifest::verify_artifacts`]
//! content-hash check and the pre-restore
//! [`microvm_snapshots::CompatibilityGate`].
//!
//! Traps covered: tampering with any content hash (kernel, rootfs, memory,
//! VM-state, block device), a missing or extra block device, a foreign owner,
//! an unsupported schema version, a Firecracker binary version/hash mismatch,
//! CPU arch/model/flag incompatibility, a KVM API mismatch, a cgroup-v1
//! manifest, a non-immutable memory file, and a quota overflow. Every probe
//! observes the typed [`microvm_snapshots::SnapshotError`] (and its stable
//! [`ErrorCode`]) the gate returns before any Firecracker load.
//!
//! The crate performs no I/O: the backend supplies digests and the host
//! envelope as data, so every probe is deterministic.

mod common;

use common::{assert_no_bypass, run_battery, Probe};
use microvm_artifacts::Digest;
use microvm_errors::ErrorCode;
use microvm_snapshots::{
    ActualHashes, ArtifactHashes, BlockDeviceHash, CgroupVersion, CompatibilityGate,
    CpuCompatibility, FirecrackerBinary, HostCompatibility, HostEnvironment, MemoryRequirements,
    SnapshotComponent, SnapshotManifest, SnapshotQuota, SnapshotVmConfig, StateHashes, TenantQuota,
};
use microvm_types::{SnapshotId, TenantId, VmId};

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

fn gate_binary() -> FirecrackerBinary {
    FirecrackerBinary::new("1.16.1", digest(0xFC)).unwrap()
}

fn gate() -> CompatibilityGate {
    CompatibilityGate::new(
        host_env(),
        gate_binary(),
        TenantQuota {
            max_memory_mib: 1024,
            max_disk_mib: 2048,
        },
    )
}

fn caller() -> TenantId {
    TenantId::new("tenant-1").unwrap()
}

/// A structurally valid manifest owned by `tenant-1`, compatible with `gate()`.
fn valid_manifest() -> SnapshotManifest {
    SnapshotManifest::builder()
        .snapshot_id(SnapshotId::new("snap-001").unwrap())
        .vm_id(VmId::new("vm-001").unwrap())
        .owner(caller())
        .firecracker(gate_binary())
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
        .memory(MemoryRequirements::new(true, "mem/guest.mem").unwrap())
        .build()
        .unwrap()
}

// -- Happy path (control) ---------------------------------------------------

#[test]
fn clean_manifest_passes_gate_and_integrity() {
    let m = valid_manifest();
    assert!(gate().validate(&m, &caller()).is_ok());
    assert!(m.verify_artifacts(&ActualHashes::matching(&m)).is_ok());
}

// -- Tamper detection (content hashes) --------------------------------------

#[test]
fn memory_tamper_is_detected() {
    let m = valid_manifest();
    let mut actual = ActualHashes::matching(&m);
    actual.memory_sha256 = digest(0xFF); // attacker rewrote the memory file
    let err = m.verify_artifacts(&actual).unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
    assert!(matches!(
        err,
        microvm_snapshots::SnapshotError::Integrity {
            component: SnapshotComponent::Memory,
            ..
        }
    ));
}

#[test]
fn kernel_rootfs_vmstate_tamper_is_detected() {
    let m = valid_manifest();
    for set in ["kernel", "rootfs", "vmstate"] {
        let mut actual = ActualHashes::matching(&m);
        match set {
            "kernel" => actual.kernel_sha256 = digest(0xEE),
            "rootfs" => actual.rootfs_sha256 = digest(0xEE),
            _ => actual.vmstate_sha256 = digest(0xEE),
        }
        let err = m.verify_artifacts(&actual).unwrap_err();
        assert_eq!(err.code(), ErrorCode::DigestMismatch, "component {set}");
    }
}

#[test]
fn block_device_tamper_is_detected() {
    let m = valid_manifest();
    let mut actual = ActualHashes::matching(&m);
    actual.block_devices = vec![BlockDeviceHash::new("root", digest(0xEE)).unwrap()];
    let err = m.verify_artifacts(&actual).unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
}

#[test]
fn missing_and_extra_block_devices_are_rejected() {
    let m = valid_manifest();
    // Missing the recorded "root" device.
    let mut actual = ActualHashes::matching(&m);
    actual.block_devices = vec![];
    let err = m.verify_artifacts(&actual).unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
    // An extra unrecorded device is also rejected.
    let mut actual = ActualHashes::matching(&m);
    actual
        .block_devices
        .push(BlockDeviceHash::new("evil", digest(0xA6)).unwrap());
    let err = m.verify_artifacts(&actual).unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
}

// -- Compatibility / ownership gate -----------------------------------------

#[test]
fn foreign_owner_is_denied() {
    let m = valid_manifest();
    let attacker = TenantId::new("tenant-evil").unwrap();
    let err = gate().validate(&m, &attacker).unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(matches!(
        err,
        microvm_snapshots::SnapshotError::ForeignOwner { .. }
    ));
}

#[test]
fn unsupported_schema_is_rejected() {
    let mut m = valid_manifest();
    m.version = 99;
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
}

#[test]
fn binary_version_and_hash_mismatch_are_rejected() {
    // Version mismatch.
    let mut m = valid_manifest();
    m.firecracker = FirecrackerBinary::new("1.15.0", digest(0xFC)).unwrap();
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    // Hash mismatch (same version, different binary).
    let mut m = valid_manifest();
    m.firecracker = FirecrackerBinary::new("1.16.1", digest(0xFD)).unwrap();
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
}

#[test]
fn cpu_incompatibility_is_rejected() {
    // arch mismatch
    let mut m = valid_manifest();
    m.host.cpu =
        CpuCompatibility::new("aarch64", "AMD EPYC", ["svm".into()].into_iter().collect()).unwrap();
    assert_eq!(
        gate().validate(&m, &caller()).unwrap_err().code(),
        ErrorCode::SnapshotIncompatible
    );
    // model mismatch
    let mut m = valid_manifest();
    m.host.cpu =
        CpuCompatibility::new("x86_64", "Intel Xeon", ["svm".into()].into_iter().collect())
            .unwrap();
    assert_eq!(
        gate().validate(&m, &caller()).unwrap_err().code(),
        ErrorCode::SnapshotIncompatible
    );
    // host missing a required flag
    let mut m = valid_manifest();
    m.host.cpu =
        CpuCompatibility::new("x86_64", "AMD EPYC", ["vmx".into()].into_iter().collect()).unwrap();
    assert_eq!(
        gate().validate(&m, &caller()).unwrap_err().code(),
        ErrorCode::SnapshotIncompatible
    );
}

#[test]
fn kvm_api_mismatch_is_rejected() {
    let mut m = valid_manifest();
    m.host.kvm_api_version = 13;
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
}

#[test]
fn cgroup_v1_manifest_is_rejected() {
    let mut m = valid_manifest();
    m.host.cgroup_version = CgroupVersion::V1;
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
}

#[test]
fn non_immutable_memory_is_rejected() {
    let mut m = valid_manifest();
    m.memory = MemoryRequirements::new(false, "mem/guest.mem").unwrap();
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
}

#[test]
fn quota_overflow_is_rejected() {
    // memory over the tenant limit
    let mut m = valid_manifest();
    m.quota = SnapshotQuota {
        memory_mib: 4096,
        disk_mib: 1024,
    };
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::QuotaExceeded);
    // disk over the tenant limit
    let mut m = valid_manifest();
    m.quota = SnapshotQuota {
        memory_mib: 512,
        disk_mib: 99999,
    };
    let err = gate().validate(&m, &caller()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::QuotaExceeded);
}

#[test]
fn memory_backend_path_is_validated() {
    // absolute path
    let err = MemoryRequirements::new(true, "/etc/passwd").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
    // traversal
    let err = MemoryRequirements::new(true, "../mem/file").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
    // empty
    let err = MemoryRequirements::new(true, "").unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
}

// -- Consolidated battery ---------------------------------------------------

#[test]
fn snapshot_security_battery_emits_evidence_and_detects_no_bypass() {
    let m = valid_manifest();
    let g = gate();
    let attacker = TenantId::new("tenant-evil").unwrap();

    let mut mem_tamper = ActualHashes::matching(&m);
    mem_tamper.memory_sha256 = digest(0xFF);
    let mut kernel_tamper = ActualHashes::matching(&m);
    kernel_tamper.kernel_sha256 = digest(0xFF);
    let mut bd_tamper = ActualHashes::matching(&m);
    bd_tamper.block_devices = vec![BlockDeviceHash::new("root", digest(0xFF)).unwrap()];
    let mut bd_missing = ActualHashes::matching(&m);
    bd_missing.block_devices = vec![];

    let mut schema = valid_manifest();
    schema.version = 99;
    let mut binver = valid_manifest();
    binver.firecracker = FirecrackerBinary::new("1.15.0", digest(0xFC)).unwrap();
    let mut binhash = valid_manifest();
    binhash.firecracker = FirecrackerBinary::new("1.16.1", digest(0xFD)).unwrap();
    let mut arch = valid_manifest();
    arch.host.cpu =
        CpuCompatibility::new("aarch64", "AMD EPYC", ["svm".into()].into_iter().collect()).unwrap();
    let mut kvm = valid_manifest();
    kvm.host.kvm_api_version = 13;
    let mut cg1 = valid_manifest();
    cg1.host.cgroup_version = CgroupVersion::V1;
    let mut notimm = valid_manifest();
    notimm.memory = MemoryRequirements::new(false, "mem/guest.mem").unwrap();
    let mut quota = valid_manifest();
    quota.quota = SnapshotQuota {
        memory_mib: 4096,
        disk_mib: 1024,
    };

    let probes = vec![
        Probe::from_result(
            "memory_tamper",
            "snapshot:tamper",
            ErrorCode::DigestMismatch,
            m.verify_artifacts(&mem_tamper),
        ),
        Probe::from_result(
            "kernel_tamper",
            "snapshot:tamper",
            ErrorCode::DigestMismatch,
            m.verify_artifacts(&kernel_tamper),
        ),
        Probe::from_result(
            "blockdev_tamper",
            "snapshot:tamper",
            ErrorCode::DigestMismatch,
            m.verify_artifacts(&bd_tamper),
        ),
        Probe::from_result(
            "blockdev_missing",
            "snapshot:tamper",
            ErrorCode::DigestMismatch,
            m.verify_artifacts(&bd_missing),
        ),
        Probe::from_result(
            "foreign_owner",
            "snapshot:foreign_owner",
            ErrorCode::PermissionDenied,
            g.validate(&m, &attacker),
        ),
        Probe::from_result(
            "unsupported_schema",
            "snapshot:compatibility",
            ErrorCode::SnapshotIncompatible,
            g.validate(&schema, &caller()),
        ),
        Probe::from_result(
            "binary_version",
            "snapshot:compatibility",
            ErrorCode::SnapshotIncompatible,
            g.validate(&binver, &caller()),
        ),
        Probe::from_result(
            "binary_hash",
            "snapshot:compatibility",
            ErrorCode::SnapshotIncompatible,
            g.validate(&binhash, &caller()),
        ),
        Probe::from_result(
            "cpu_arch",
            "snapshot:compatibility",
            ErrorCode::SnapshotIncompatible,
            g.validate(&arch, &caller()),
        ),
        Probe::from_result(
            "kvm_api",
            "snapshot:compatibility",
            ErrorCode::SnapshotIncompatible,
            g.validate(&kvm, &caller()),
        ),
        Probe::from_result(
            "cgroup_v1",
            "snapshot:compatibility",
            ErrorCode::SnapshotIncompatible,
            g.validate(&cg1, &caller()),
        ),
        Probe::from_result(
            "memory_not_immutable",
            "snapshot:compatibility",
            ErrorCode::SnapshotIncompatible,
            g.validate(&notimm, &caller()),
        ),
        Probe::from_result(
            "quota_overflow",
            "snapshot:quota",
            ErrorCode::QuotaExceeded,
            g.validate(&quota, &caller()),
        ),
        Probe::from_result(
            "mem_backend_absolute",
            "snapshot:path_escape",
            ErrorCode::PathEscape,
            MemoryRequirements::new(true, "/etc/passwd"),
        ),
        Probe::from_result(
            "mem_backend_traversal",
            "snapshot:path_escape",
            ErrorCode::PathEscape,
            MemoryRequirements::new(true, "../x"),
        ),
    ];

    let evidence = run_battery("snapshot_security", probes);
    assert_no_bypass(&evidence);
    assert!(evidence.summary.total >= 15);

    // Control: the clean manifest passes both gates.
    assert!(g.validate(&m, &caller()).is_ok());
    assert!(m.verify_artifacts(&ActualHashes::matching(&m)).is_ok());
}
