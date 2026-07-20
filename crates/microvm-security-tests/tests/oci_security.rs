//! Constrained-OCI adversarial suite.
//!
//! Drives the real [`microvm_oci::validate_local_reference`] gate, the
//! forbidden-field scanner ([`microvm_oci::config::scan_forbidden`]), and the
//! full [`microvm_oci::OciImporter`] against real on-disk layouts.
//!
//! Traps covered: remote/tag-only/digest-pinned references, remote descriptor
//! `urls`, layer/config digest and size mismatches, missing blobs, unsupported
//! and mismatched platforms, missing/duplicate guest media, malformed digests,
//! invalid manifests, and every forbidden runtime knob (mounts, capabilities,
//! privileged, host network/PID/IPC, and arbitrary host process control).
//! Every probe observes the typed [`microvm_oci::ImportError`] (and its stable
//! [`ErrorCode`]) the importer returns before any artifact is trusted.

mod common;

use common::{
    assert_no_bypass, config_value, materialize_config, materialize_layer, run_battery,
    standard_labels, standard_layout, write_layout, OciLayer, Probe, KERNEL_BYTES, ROOTFS_BYTES,
};
use microvm_errors::ErrorCode;
use microvm_oci::{validate_local_reference, ForbiddenField, ImportError, OciImporter, Platform};
use serde_json::{json, Value};
use tempfile::TempDir;

// -- Reference validation (local-only) --------------------------------------

#[test]
fn remote_and_tag_references_are_rejected() {
    for bad in [
        "https://example.com/img",
        "http://example.com/img",
        "oci://registry.local/img",
        "docker://nginx:latest",
        "registry://local/img",
        "s3://bucket/img",
        "ssh://host/img",
        "git://host/repo",
        "file://remote-host/export/img",
        "nginx:latest",
        "ubuntu:22.04",
        "fedora",
        "repo/img:v1",
        "repo/img@sha256:abcdef0123456789",
        "docker:nginx",
        "",
    ] {
        let err = validate_local_reference(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LocalArtifactRequired, "bad={bad:?}");
        assert!(matches!(err, ImportError::RemoteReference { .. }));
    }
}

#[test]
fn local_references_are_accepted() {
    assert!(validate_local_reference("/var/lib/microvm/layouts/img").is_ok());
    assert!(validate_local_reference("./layouts/img").is_ok());
    assert!(validate_local_reference("layouts/img").is_ok());
    let p = validate_local_reference("file:///var/lib/layouts/img").unwrap();
    assert_eq!(p, std::path::PathBuf::from("/var/lib/layouts/img"));
    let p = validate_local_reference("file://localhost/var/lib/layouts/img").unwrap();
    assert_eq!(p, std::path::PathBuf::from("/var/lib/layouts/img"));
}

#[test]
fn importer_open_reference_rejects_remote_before_io() {
    // open_reference must refuse a remote reference without touching the
    // network or filesystem.
    let err = OciImporter::open_reference("docker://nginx:latest").unwrap_err();
    assert_eq!(err.code(), ErrorCode::LocalArtifactRequired);
}

// -- Forbidden runtime knobs (scanner) --------------------------------------

#[test]
fn forbidden_scanner_catches_every_category() {
    use microvm_oci::config::scan_forbidden;
    let cases: &[(&str, Value, ForbiddenField)] = &[
        (
            "mounts",
            json!({"mounts": [{"target":"/x"}]}),
            ForbiddenField::Mounts,
        ),
        ("mount", json!({"mount": "/x"}), ForbiddenField::Mounts),
        (
            "capabilities",
            json!({"capabilities": ["CAP_SYS_ADMIN"]}),
            ForbiddenField::Capabilities,
        ),
        (
            "cap_add",
            json!({"cap_add": ["NET_ADMIN"]}),
            ForbiddenField::Capabilities,
        ),
        (
            "privileged",
            json!({"privileged": true}),
            ForbiddenField::Privileged,
        ),
        (
            "host_network",
            json!({"host_network": true}),
            ForbiddenField::HostNetwork,
        ),
        (
            "network_mode",
            json!({"network_mode": "host"}),
            ForbiddenField::HostNetwork,
        ),
        (
            "host_pid",
            json!({"host_pid": true}),
            ForbiddenField::HostPid,
        ),
        (
            "pid_mode",
            json!({"pid_mode": "host"}),
            ForbiddenField::HostPid,
        ),
        (
            "host_ipc",
            json!({"host_ipc": true}),
            ForbiddenField::HostIpc,
        ),
        (
            "ipc_mode",
            json!({"ipc_mode": "host"}),
            ForbiddenField::HostIpc,
        ),
        (
            "process",
            json!({"process": {"args": []}}),
            ForbiddenField::HostProcessControl,
        ),
        (
            "rlimits",
            json!({"rlimits": []}),
            ForbiddenField::HostProcessControl,
        ),
        (
            "devices",
            json!({"devices": ["/dev/kvm"]}),
            ForbiddenField::HostProcessControl,
        ),
        (
            "sysctls",
            json!({"sysctls": {"net.ipv4.ip_forward":"1"}}),
            ForbiddenField::HostProcessControl,
        ),
        (
            "oom_score_adj",
            json!({"oom_score_adj": 500}),
            ForbiddenField::HostProcessControl,
        ),
    ];
    for (name, doc, field) in cases {
        let (found, key) = scan_forbidden(doc).unwrap_or_else(|| panic!("must detect {name}"));
        assert_eq!(found, *field, "category for {name}");
        assert!(!key.is_empty());
    }
    // Case-insensitive + nested detection.
    let nested = json!({"a": {"b": [{"Privileged": true}]}});
    assert_eq!(
        scan_forbidden(&nested).unwrap().0,
        ForbiddenField::Privileged
    );
    // A clean document has no forbidden field.
    assert!(scan_forbidden(&json!({"architecture":"amd64","os":"linux"})).is_none());
}

/// Build a layout whose image config carries a forbidden key, and assert the
/// full importer refuses it with `PermissionDenied`.
fn import_with_forbidden(extra: Value) -> ImportError {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let mut config = config_value("linux", "amd64", standard_labels());
    // Merge the forbidden key into the config document.
    if let (Some(obj), Value::Object(extra)) = (config.as_object_mut(), extra) {
        for (k, v) in extra {
            obj.insert(k, v);
        }
    }
    let config_desc = materialize_config(root, &config, None);
    let layers = vec![
        materialize_layer(root, &OciLayer::kernel()),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    OciImporter::open(root).unwrap().import().unwrap_err()
}

#[test]
fn importer_refuses_forbidden_knobs_end_to_end() {
    for (extra, field) in [
        (json!({"privileged": true}), ForbiddenField::Privileged),
        (
            json!({"mounts": [{"target":"/host"}]}),
            ForbiddenField::Mounts,
        ),
        (
            json!({"capabilities": ["CAP_SYS_ADMIN"]}),
            ForbiddenField::Capabilities,
        ),
        (json!({"host_network": true}), ForbiddenField::HostNetwork),
        (json!({"host_pid": true}), ForbiddenField::HostPid),
        (json!({"host_ipc": true}), ForbiddenField::HostIpc),
        (
            json!({"devices": ["/dev/kvm"]}),
            ForbiddenField::HostProcessControl,
        ),
    ] {
        let err = import_with_forbidden(extra);
        assert_eq!(err.code(), ErrorCode::PermissionDenied, "field {field}");
        assert!(matches!(err, ImportError::Forbidden { field: f, .. } if f == field));
    }
}

// -- Digest / size / blob integrity -----------------------------------------

#[test]
fn layer_digest_mismatch_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    let mut bad_kernel = OciLayer::kernel();
    bad_kernel.declared_digest = Some(format!("sha256:{}", common::sha256_hex(b"other-kernel")));
    let layers = vec![
        materialize_layer(root, &bad_kernel),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
}

#[test]
fn layer_size_mismatch_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    let mut bad_rootfs = OciLayer::rootfs();
    bad_rootfs.declared_size = Some((ROOTFS_BYTES.len() + 100) as u64);
    let layers = vec![
        materialize_layer(root, &OciLayer::kernel()),
        materialize_layer(root, &bad_rootfs),
    ];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
}

#[test]
fn remote_descriptor_urls_are_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    let mut remote_kernel = OciLayer::kernel();
    remote_kernel.urls = Some(vec!["https://cdn.example.com/kernel".into()]);
    let layers = vec![
        materialize_layer(root, &remote_kernel),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::LocalArtifactRequired);
    assert!(matches!(err, ImportError::RemoteDescriptor { .. }));
}

#[test]
fn missing_blob_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    // Declare a kernel layer whose blob we never write.
    let hex = common::sha256_hex(KERNEL_BYTES);
    let kernel_desc = json!({
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "digest": format!("sha256:{hex}"),
        "size": KERNEL_BYTES.len(),
        "annotations": { microvm_oci::MEDIA_ANNOTATION: "kernel" },
    });
    let layers = vec![kernel_desc, materialize_layer(root, &OciLayer::rootfs())];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArtifactNotFound);
}

// -- Platform / media / manifest shape --------------------------------------

#[test]
fn unsupported_platform_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("windows", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    let layers = vec![
        materialize_layer(root, &OciLayer::kernel()),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidResourceSpec);
    assert!(matches!(err, ImportError::UnsupportedPlatform { .. }));
}

#[test]
fn platform_mismatch_is_rejected() {
    let tmp = standard_layout(); // linux/amd64
    let err = OciImporter::open(tmp.path())
        .unwrap()
        .import_for_platform(Platform::LINUX_ARM64)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidResourceSpec);
    assert!(matches!(err, ImportError::PlatformMismatch { .. }));
}

#[test]
fn missing_media_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    // Only a rootfs layer; no kernel layer.
    let layers = vec![materialize_layer(root, &OciLayer::rootfs())];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidResourceSpec);
    assert!(matches!(err, ImportError::MissingMedia { .. }));
}

#[test]
fn duplicate_media_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    // Two kernel-annotated layers.
    let mut k2 = OciLayer::kernel();
    k2.bytes = b"second-kernel-bytes".to_vec();
    let layers = vec![
        materialize_layer(root, &OciLayer::kernel()),
        materialize_layer(root, &k2),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidResourceSpec);
    assert!(matches!(err, ImportError::DuplicateMedia { .. }));
}

#[test]
fn invalid_manifest_shape_is_rejected() {
    // Wrong schemaVersion.
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    let layers = vec![
        materialize_layer(root, &OciLayer::kernel()),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    let manifest = json!({
        "schemaVersion": 1,
        "config": config_desc,
        "layers": layers,
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidResourceSpec);
}

#[test]
fn malformed_digest_is_rejected() {
    let err = microvm_oci::parse_sha256_digest("sha256:nothex").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidResourceSpec);
    assert!(matches!(err, ImportError::MalformedDigest { .. }));
}

// -- Happy path (control) ---------------------------------------------------

#[test]
fn clean_local_layout_imports() {
    let tmp = standard_layout();
    let spec = OciImporter::open(tmp.path()).unwrap().import().unwrap();
    assert_eq!(spec.platform, Platform::LINUX_AMD64);
    assert_eq!(
        spec.kernel.sha256.to_hex(),
        common::sha256_hex(KERNEL_BYTES)
    );
    assert_eq!(
        spec.rootfs.sha256.to_hex(),
        common::sha256_hex(ROOTFS_BYTES)
    );
}

// -- Consolidated battery ---------------------------------------------------

#[test]
fn oci_security_battery_emits_evidence_and_detects_no_bypass() {
    let remote_ref = validate_local_reference("docker://nginx:latest");
    let tag_ref = validate_local_reference("nginx:latest");
    let digest_ref = validate_local_reference("repo/img@sha256:abcdef0123456789");
    let open_remote = OciImporter::open_reference("https://example.com/img");

    let forbidden_priv = import_with_forbidden(json!({"privileged": true}));
    let forbidden_mounts = import_with_forbidden(json!({"mounts": []}));
    let forbidden_caps = import_with_forbidden(json!({"capabilities": []}));
    let forbidden_hostnet = import_with_forbidden(json!({"host_network": true}));
    let forbidden_devices = import_with_forbidden(json!({"devices": []}));

    // Digest mismatch layout.
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    let mut bad_kernel = OciLayer::kernel();
    bad_kernel.declared_digest = Some(format!("sha256:{}", common::sha256_hex(b"other")));
    let layers = vec![
        materialize_layer(root, &bad_kernel),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    let digest_mismatch = OciImporter::open(root).unwrap().import();

    // Unsupported platform layout.
    let tmp2 = TempDir::new().unwrap();
    let root2 = tmp2.path();
    let config2 = config_value("windows", "amd64", standard_labels());
    let config_desc2 = materialize_config(root2, &config2, None);
    let layers2 = vec![
        materialize_layer(root2, &OciLayer::kernel()),
        materialize_layer(root2, &OciLayer::rootfs()),
    ];
    write_layout(root2, config_desc2, layers2);
    let unsupported = OciImporter::open(root2).unwrap().import();

    let probes = vec![
        Probe::from_result(
            "remote_ref_docker",
            "oci:remote_reference",
            ErrorCode::LocalArtifactRequired,
            remote_ref,
        ),
        Probe::from_result(
            "remote_ref_tag",
            "oci:remote_reference",
            ErrorCode::LocalArtifactRequired,
            tag_ref,
        ),
        Probe::from_result(
            "remote_ref_digest",
            "oci:remote_reference",
            ErrorCode::LocalArtifactRequired,
            digest_ref,
        ),
        Probe::from_result(
            "open_remote_https",
            "oci:remote_reference",
            ErrorCode::LocalArtifactRequired,
            open_remote,
        ),
        Probe::from_result(
            "forbidden_privileged",
            "oci:forbidden_field",
            ErrorCode::PermissionDenied,
            Result::<(), _>::Err(forbidden_priv),
        ),
        Probe::from_result(
            "forbidden_mounts",
            "oci:forbidden_field",
            ErrorCode::PermissionDenied,
            Result::<(), _>::Err(forbidden_mounts),
        ),
        Probe::from_result(
            "forbidden_capabilities",
            "oci:forbidden_field",
            ErrorCode::PermissionDenied,
            Result::<(), _>::Err(forbidden_caps),
        ),
        Probe::from_result(
            "forbidden_host_network",
            "oci:forbidden_field",
            ErrorCode::PermissionDenied,
            Result::<(), _>::Err(forbidden_hostnet),
        ),
        Probe::from_result(
            "forbidden_devices",
            "oci:forbidden_field",
            ErrorCode::PermissionDenied,
            Result::<(), _>::Err(forbidden_devices),
        ),
        Probe::from_result(
            "layer_digest_mismatch",
            "oci:digest_mismatch",
            ErrorCode::DigestMismatch,
            digest_mismatch,
        ),
        Probe::from_result(
            "unsupported_platform",
            "oci:unsupported_platform",
            ErrorCode::InvalidResourceSpec,
            unsupported,
        ),
        Probe::from_result(
            "malformed_digest",
            "oci:malformed_digest",
            ErrorCode::InvalidResourceSpec,
            microvm_oci::parse_sha256_digest("sha256:zz"),
        ),
    ];

    let evidence = run_battery("oci_security", probes);
    assert_no_bypass(&evidence);
    assert!(evidence.summary.total >= 12);

    // Control: a clean local layout imports.
    let clean = standard_layout();
    assert!(OciImporter::open(clean.path()).unwrap().import().is_ok());
}
