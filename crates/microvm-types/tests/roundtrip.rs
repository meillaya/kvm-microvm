//! Serde round-trip tests for every public type in microvm-types.

use microvm_types::*;

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}

#[test]
fn vm_id_roundtrip() {
    let id = VmId::new("vm-abc123").unwrap();
    assert_eq!(roundtrip(&id), id);
}

#[test]
fn image_id_roundtrip() {
    let id = ImageId::new("img-001").unwrap();
    assert_eq!(roundtrip(&id), id);
}

#[test]
fn snapshot_id_roundtrip() {
    let id = SnapshotId::new("snap.v2").unwrap();
    assert_eq!(roundtrip(&id), id);
}

#[test]
fn tenant_id_roundtrip() {
    let id = TenantId::new("tenant-xyz").unwrap();
    assert_eq!(roundtrip(&id), id);
}

#[test]
fn network_policy_roundtrip_all_variants() {
    for policy in [
        NetworkPolicy::None,
        NetworkPolicy::NatOnly,
        NetworkPolicy::EgressAllowed,
    ] {
        assert_eq!(roundtrip(&policy), policy);
    }
}

#[test]
fn resource_spec_roundtrip() {
    let spec = ResourceSpec::new(4, 2048, 10240, NetworkPolicy::EgressAllowed).unwrap();
    assert_eq!(roundtrip(&spec), spec);
}

#[test]
fn resource_spec_default_network_policy_roundtrip() {
    // network_policy defaults to None when absent in JSON.
    let json = r#"{"vcpu_count":1,"memory_mib":256,"disk_mib":512}"#;
    let spec: ResourceSpec = serde_json::from_str(json).unwrap();
    assert_eq!(spec.network_policy(), NetworkPolicy::None);
    assert_eq!(roundtrip(&spec), spec);
}

#[test]
fn role_roundtrip_all_variants() {
    for role in [Role::Owner, Role::Operator, Role::Viewer] {
        assert_eq!(roundtrip(&role), role);
    }
}

#[test]
fn principal_roundtrip() {
    let tid = TenantId::new("tenant-99").unwrap();
    let p = Principal::new(tid, Role::Viewer);
    assert_eq!(roundtrip(&p), p);
}

#[test]
fn vm_id_deserialize_rejects_invalid() {
    // Uppercase must be rejected even through serde.
    let json = r#""VM-BAD""#;
    let result: Result<VmId, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn vm_id_deserialize_rejects_slash() {
    let json = r#""vm/bad""#;
    let result: Result<VmId, _> = serde_json::from_str(json);
    assert!(result.is_err());
}
