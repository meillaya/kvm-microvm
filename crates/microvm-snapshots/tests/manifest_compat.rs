//! Deterministic manifest + compatibility-gate contract tests (plan todo 21).
//!
//! These tests require no `/dev/kvm` and spawn no child process. They prove
//! that every rejection — unsupported schema, foreign owner, binary/CPU/KVM/
//! cgroup incompatibility, quota overflow, immutable-memory violation, and
//! content-hash mismatch — is a typed failure produced BEFORE any Firecracker
//! load would occur.

use chrono::{DateTime, Utc};
use microvm_artifacts::Digest;
use microvm_errors::ErrorCode;
use microvm_snapshots::{
    ActualHashes, ArtifactHashes, BlockDeviceHash, CgroupVersion, CompatibilityGate,
    CpuCompatibility, FirecrackerBinary, HostCompatibility, HostEnvironment, MemoryRequirements,
    SnapshotComponent, SnapshotError, SnapshotManifest, SnapshotQuota, SnapshotVmConfig,
    StateHashes, TenantQuota, SNAPSHOT_MANIFEST_VERSION,
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
        .created_at(DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap())
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

// ---------------------------------------------------------------------------
// Manifest validation
// ---------------------------------------------------------------------------

#[test]
fn manifest_serde_roundtrip() {
    let m = manifest("tenant-1");
    let json = serde_json::to_string_pretty(&m).unwrap();
    let back: SnapshotManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
    assert_eq!(back.version, SNAPSHOT_MANIFEST_VERSION);
}

#[test]
fn required_fields_cannot_be_omitted() {
    // Serialize a valid manifest, then delete each required top-level field and
    // assert deserialization fails. This proves no required field is optional.
    let m = manifest("tenant-1");
    let value = serde_json::to_value(&m).unwrap();
    let required = value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert!(!required.is_empty());
    for field in required {
        let mut obj = value.as_object().unwrap().clone();
        obj.remove(&field);
        let stripped = serde_json::Value::Object(obj);
        let res = serde_json::from_value::<SnapshotManifest>(stripped);
        assert!(
            res.is_err(),
            "manifest deserialized despite missing required field '{}'",
            field
        );
    }
}

#[test]
fn builder_rejects_missing_fields() {
    // Omitting required fields from the builder must fail closed with a typed
    // InvalidResourceSpec naming the missing field.
    let full = manifest("tenant-1");
    let without_memory = SnapshotManifest::builder()
        .snapshot_id(full.snapshot_id.clone())
        .vm_id(full.vm_id.clone())
        .owner(full.owner.clone())
        .firecracker(full.firecracker.clone())
        .vm_config(full.vm_config)
        .artifacts(full.artifacts.clone())
        .state(full.state)
        .host(full.host.clone())
        .quota(full.quota);
    let err = without_memory.build().unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    assert!(err.message.contains("memory"));

    // A builder with nothing set fails on the first required field.
    let err = SnapshotManifest::builder().build().unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
}

// ---------------------------------------------------------------------------
// Compatibility checks (all fail before Firecracker load)
// ---------------------------------------------------------------------------

#[test]
fn gate_accepts_compatible_manifest_for_owner() {
    let m = manifest("tenant-1");
    let caller = TenantId::new("tenant-1").unwrap();
    assert!(gate().validate(&m, &caller).is_ok());
}

#[test]
fn unsupported_schema_fails_before_load() {
    let mut m = manifest("tenant-1");
    m.version = 2;
    let caller = TenantId::new("tenant-1").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    assert!(matches!(
        err,
        SnapshotError::UnsupportedSchema {
            found: 2,
            supported: 1
        }
    ));
}

#[test]
fn foreign_owner_fails_before_load() {
    let m = manifest("tenant-1");
    let caller = TenantId::new("tenant-evil").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(matches!(err, SnapshotError::ForeignOwner { .. }));
}

#[test]
fn binary_incompatibility_fails_before_load() {
    let mut m = manifest("tenant-1");
    m.firecracker = FirecrackerBinary::new("1.16.1", digest(0x99)).unwrap();
    let caller = TenantId::new("tenant-1").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    assert!(matches!(err, SnapshotError::BinaryIncompatible { .. }));
}

#[test]
fn cpu_incompatibility_fails_before_load() {
    let mut m = manifest("tenant-1");
    m.host.cpu = CpuCompatibility::new("x86_64", "Intel Xeon", Default::default()).unwrap();
    let caller = TenantId::new("tenant-1").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    assert!(matches!(err, SnapshotError::CpuIncompatible { .. }));
}

#[test]
fn kvm_api_incompatibility_fails_before_load() {
    let mut m = manifest("tenant-1");
    m.host.kvm_api_version = 13;
    let caller = TenantId::new("tenant-1").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    assert!(matches!(err, SnapshotError::KvmApiIncompatible { .. }));
}

#[test]
fn cgroup_incompatibility_fails_before_load() {
    let mut m = manifest("tenant-1");
    m.host.cgroup_version = CgroupVersion::V1;
    let caller = TenantId::new("tenant-1").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    assert!(matches!(err, SnapshotError::CgroupIncompatible { .. }));
}

#[test]
fn non_immutable_memory_fails_before_load() {
    let mut m = manifest("tenant-1");
    m.memory = MemoryRequirements::new(false, "snapshots/snap-001/mem.file").unwrap();
    let caller = TenantId::new("tenant-1").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SnapshotIncompatible);
    assert!(matches!(err, SnapshotError::MemoryNotImmutable));
}

// ---------------------------------------------------------------------------
// Quota enforcement
// ---------------------------------------------------------------------------

#[test]
fn quota_overflow_fails_before_load() {
    let mut m = manifest("tenant-1");
    m.quota.memory_mib = quota().max_memory_mib + 1;
    let caller = TenantId::new("tenant-1").unwrap();
    let err = gate().validate(&m, &caller).unwrap_err();
    assert_eq!(err.code(), ErrorCode::QuotaExceeded);
    assert!(matches!(err, SnapshotError::QuotaOverflow { .. }));
}

// ---------------------------------------------------------------------------
// Hash mismatch detection (the "flip one byte" QA scenario)
// ---------------------------------------------------------------------------

#[test]
fn flipping_one_byte_in_memory_is_typed_integrity_error() {
    let m = manifest("tenant-1");
    let mut actual = ActualHashes::matching(&m);
    // Flip one byte of the memory digest to simulate on-disk corruption.
    actual.memory_sha256 = digest(actual.memory_sha256.as_bytes()[0] ^ 0x01);
    let err = m.verify_artifacts(&actual).unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
    assert!(matches!(
        err,
        SnapshotError::Integrity {
            component: SnapshotComponent::Memory,
            ..
        }
    ));
}

#[test]
fn flipping_one_byte_in_state_is_typed_integrity_error() {
    let m = manifest("tenant-1");
    let mut actual = ActualHashes::matching(&m);
    actual.vmstate_sha256 = digest(actual.vmstate_sha256.as_bytes()[0] ^ 0x01);
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
fn flipping_one_byte_in_block_device_is_typed_integrity_error() {
    let m = manifest("tenant-1");
    let mut actual = ActualHashes::matching(&m);
    let b = actual.block_devices[0].sha256.as_bytes()[0] ^ 0x01;
    actual.block_devices[0].sha256 = digest(b);
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
fn matching_artifacts_verify_cleanly() {
    let m = manifest("tenant-1");
    let actual = ActualHashes::matching(&m);
    assert!(m.verify_artifacts(&actual).is_ok());
}

// ---------------------------------------------------------------------------
// Full restore preflight: gate + integrity together, before any load
// ---------------------------------------------------------------------------

#[test]
fn full_restore_preflight_passes_then_detects_corruption() {
    let m = manifest("tenant-1");
    let caller = TenantId::new("tenant-1").unwrap();
    let actual = ActualHashes::matching(&m);

    // 1. Compatibility gate passes.
    gate().validate(&m, &caller).unwrap();
    // 2. Integrity check passes.
    m.verify_artifacts(&actual).unwrap();

    // 3. Corrupt the memory file: integrity now fails before any load.
    let mut corrupted = actual;
    corrupted.memory_sha256 = digest(0x00);
    let err = m.verify_artifacts(&corrupted).unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
}

// ---------------------------------------------------------------------------
// Schema drift guard: the Rust struct and the JSON Schema must agree
// ---------------------------------------------------------------------------

#[test]
fn rust_manifest_matches_json_schema_contract() {
    let schema_path = format!(
        "{}/../../schemas/snapshot-manifest.v1.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&schema_path).unwrap()).unwrap();

    // The schema must be the v1 snapshot-manifest schema.
    assert_eq!(
        schema["$id"].as_str().unwrap(),
        microvm_snapshots::SNAPSHOT_SCHEMA_ID
    );

    // Top-level required fields in the schema...
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let properties: Vec<&str> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();

    // ...must exactly match the serialized Rust manifest's top-level keys.
    let m = manifest("tenant-1");
    let value = serde_json::to_value(&m).unwrap();
    let mut rust_keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    rust_keys.sort_unstable();

    let mut required_sorted = required.clone();
    required_sorted.sort_unstable();
    let mut props_sorted = properties.clone();
    props_sorted.sort_unstable();

    assert_eq!(
        rust_keys, required_sorted,
        "Rust manifest keys must equal the schema's required fields"
    );
    assert_eq!(
        required_sorted, props_sorted,
        "every schema property must be required (no optional fields)"
    );
}

#[test]
fn schema_example_fixture_is_a_valid_manifest() {
    // The positive fixture in schemas/examples/ must deserialize into a valid
    // SnapshotManifest and carry the supported schema version. This locks the
    // hand-published example to the Rust type so the two cannot drift.
    let path = format!(
        "{}/../../schemas/examples/snapshot-manifest-ok.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap();
    let m: SnapshotManifest = serde_json::from_str(&raw).unwrap();
    assert_eq!(m.version, SNAPSHOT_MANIFEST_VERSION);
    assert!(m.memory.immutable);
    assert_eq!(m.host.cgroup_version, CgroupVersion::V2);
    assert_eq!(m.host.kvm_api_version, 12);
}
