//! Deterministic boot-config validation tests (public API).

use microvm_artifacts::compute_sha256;
use microvm_errors::ErrorCode;
use microvm_firecracker::config::{BootConfig, NetworkBootConfig, MAX_BOOT_ARGS_LEN};
use microvm_types::NetworkPolicy;

fn digest(b: &[u8]) -> microvm_artifacts::Digest {
    compute_sha256(b).unwrap()
}

fn builder() -> microvm_firecracker::config::BootConfigBuilder {
    BootConfig::builder()
        .kernel_path("images/vmlinux")
        .kernel_sha256(digest(b"k"))
        .rootfs_path("images/rootfs.ext4")
        .rootfs_sha256(digest(b"r"))
        .vcpu_count(2)
        .mem_size_mib(512)
}

#[test]
fn valid_config_binds_paths_to_digests() {
    let cfg = builder().build().unwrap();
    assert_eq!(cfg.kernel_path(), "images/vmlinux");
    assert_eq!(cfg.kernel_sha256(), &digest(b"k"));
    assert_eq!(cfg.rootfs_path(), "images/rootfs.ext4");
    assert_eq!(cfg.rootfs_sha256(), &digest(b"r"));
    assert_eq!(cfg.vcpu_count(), 2);
    assert_eq!(cfg.mem_size_mib(), 512);
}

#[test]
fn path_escape_variants_rejected() {
    for bad in [
        "/abs/vmlinux",
        "../escape",
        "images/../../etc/passwd",
        "s3://bucket/vmlinux",
        "oci://registry/img",
    ] {
        let err = builder().kernel_path(bad).build().unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape, "path {bad}");
    }
}

#[test]
fn zero_shapes_rejected() {
    assert_eq!(
        builder().vcpu_count(0).build().unwrap_err().code,
        ErrorCode::InvalidResourceSpec
    );
    assert_eq!(
        builder().mem_size_mib(0).build().unwrap_err().code,
        ErrorCode::InvalidResourceSpec
    );
}

#[test]
fn boot_args_length_bounded() {
    let ok = "x".repeat(MAX_BOOT_ARGS_LEN);
    assert!(builder().boot_args(ok).build().is_ok());
    let too_big = "x".repeat(MAX_BOOT_ARGS_LEN + 1);
    assert_eq!(
        builder().boot_args(too_big).build().unwrap_err().code,
        ErrorCode::InvalidResourceSpec
    );
}

#[test]
fn network_config_requires_non_none_policy() {
    assert!(NetworkBootConfig::new(NetworkPolicy::None).is_err());
    let net = NetworkBootConfig::new(NetworkPolicy::NatOnly).unwrap();
    assert_eq!(net.policy, NetworkPolicy::NatOnly);
    let cfg = builder().network(net).build().unwrap();
    assert!(cfg.has_network());
}

#[test]
fn config_serde_roundtrip_preserves_digests() {
    let cfg = builder()
        .boot_args("console=ttyS0")
        .network(NetworkBootConfig::new(NetworkPolicy::EgressAllowed).unwrap())
        .build()
        .unwrap();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: BootConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
    // Digests survive as hex strings.
    assert!(json.contains(&digest(b"k").to_hex()));
}
