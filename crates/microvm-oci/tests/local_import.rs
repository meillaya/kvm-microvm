//! End-to-end tests for the constrained local OCI importer.
//!
//! These tests build real local OCI-like layouts in a tempdir and drive
//! [`OciImporter`] through the happy path and every rejection class named in the
//! plan: digest verification of every layer, remote/tag-only reference
//! rejection, and refusal of host mounts, capabilities, privileged mode, host
//! network, and arbitrary host process controls. They run without `/dev/kvm`,
//! without any network access, and with no remote client dependency.

use microvm_artifacts::{compute_sha256, GuestArch, MediaKind};
use microvm_errors::ErrorCode;
use microvm_oci::{
    run_help_text, ForbiddenField, ImportError, OciImporter, Platform, MEDIA_ANNOTATION,
};
use microvm_types::NetworkPolicy;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Layout construction helpers
// ---------------------------------------------------------------------------

const KERNEL_BYTES: &[u8] = b"microvm-guest-kernel-bzimage-v1";
const ROOTFS_BYTES: &[u8] = b"microvm-guest-rootfs-ext4-v1-bytes";

fn sha256_hex(bytes: &[u8]) -> String {
    compute_sha256(bytes).unwrap().to_hex()
}

/// Write `bytes` to `<root>/blobs/sha256/<hex>` and return the absolute path.
fn write_blob_at(root: &Path, hex: &str, bytes: &[u8]) -> PathBuf {
    let dir = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(hex);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A layer to materialize into a test layout, with optional overrides to craft
/// mismatch/remote scenarios.
struct TestLayer {
    role: Option<&'static str>,
    bytes: Vec<u8>,
    declared_digest: Option<String>,
    declared_size: Option<u64>,
    urls: Option<Vec<String>>,
}

impl TestLayer {
    fn kernel() -> Self {
        Self {
            role: Some("kernel"),
            bytes: KERNEL_BYTES.to_vec(),
            declared_digest: None,
            declared_size: None,
            urls: None,
        }
    }
    fn rootfs() -> Self {
        Self {
            role: Some("rootfs"),
            bytes: ROOTFS_BYTES.to_vec(),
            declared_digest: None,
            declared_size: None,
            urls: None,
        }
    }
}

/// Materialize a layer, returning its manifest descriptor JSON.
fn materialize_layer(root: &Path, layer: &TestLayer) -> Value {
    let actual_hex = sha256_hex(&layer.bytes);
    let declared = layer
        .declared_digest
        .clone()
        .unwrap_or_else(|| format!("sha256:{actual_hex}"));
    let declared_hex = declared.strip_prefix("sha256:").unwrap().to_string();
    let size = layer.declared_size.unwrap_or(layer.bytes.len() as u64);
    // The importer resolves the blob by its DECLARED digest, so write the bytes
    // under the declared hex (mismatch scenarios put different bytes there).
    write_blob_at(root, &declared_hex, &layer.bytes);

    let mut descriptor = json!({
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "digest": declared,
        "size": size,
    });
    if let Some(role) = layer.role {
        descriptor["annotations"] = json!({ MEDIA_ANNOTATION: role });
    }
    if let Some(urls) = &layer.urls {
        descriptor["urls"] = json!(urls);
    }
    descriptor
}

/// A config blob to materialize, with an optional declared-digest override.
struct TestConfig {
    value: Value,
    declared_digest: Option<String>,
}

/// Materialize the config blob, returning its manifest descriptor JSON.
fn materialize_config(root: &Path, config: &TestConfig) -> Value {
    let bytes = serde_json::to_vec(&config.value).unwrap();
    let actual_hex = sha256_hex(&bytes);
    let declared = config
        .declared_digest
        .clone()
        .unwrap_or_else(|| format!("sha256:{actual_hex}"));
    let declared_hex = declared.strip_prefix("sha256:").unwrap().to_string();
    write_blob_at(root, &declared_hex, &bytes);
    json!({
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": declared,
        "size": bytes.len(),
    })
}

/// Standard `org.microvm.*` labels for a small NAT-only VM.
fn standard_labels() -> Map<String, Value> {
    let mut labels = Map::new();
    labels.insert("org.microvm.vcpu".into(), json!("2"));
    labels.insert("org.microvm.memory-mib".into(), json!("512"));
    labels.insert("org.microvm.disk-mib".into(), json!("1024"));
    labels.insert("org.microvm.network".into(), json!("nat-only"));
    labels.insert(
        "org.microvm.boot-args".into(),
        json!("console=ttyS0 reboot=k"),
    );
    labels
}

/// Build a config Value for `os`/`arch` with the given labels.
fn config_value(os: &str, arch: &str, labels: Map<String, Value>) -> Value {
    json!({
        "architecture": arch,
        "os": os,
        "config": { "Labels": labels },
        "rootfs": { "type": "layers", "diff_ids": [] },
    })
}

/// Write a complete layout and return the layout root path.
fn write_layout(root: &Path, config_descriptor: Value, layers: Vec<Value>) {
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": config_descriptor,
        "layers": layers,
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// Build a standard valid linux/amd64 layout and return its root.
fn standard_layout() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    let layers = vec![
        materialize_layer(root, &TestLayer::kernel()),
        materialize_layer(root, &TestLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    tmp
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn local_import_produces_typed_microvm_spec() {
    let tmp = standard_layout();
    let importer = OciImporter::open(tmp.path()).unwrap();
    let spec = importer.import().unwrap();

    // Platform selection + arch translation.
    assert_eq!(spec.platform, Platform::LINUX_AMD64);
    assert_eq!(spec.guest_arch, GuestArch::X86_64);
    assert_eq!(spec.arch(), GuestArch::X86_64);

    // Kernel/rootfs layers are digest-pinned and point at verified blob paths.
    assert_eq!(spec.kernel.media, MediaKind::Kernel);
    assert_eq!(spec.kernel.sha256.to_hex(), sha256_hex(KERNEL_BYTES));
    assert_eq!(spec.kernel.size, KERNEL_BYTES.len() as u64);
    assert_eq!(
        spec.kernel.rel_path,
        format!("blobs/sha256/{}", sha256_hex(KERNEL_BYTES))
    );
    assert_eq!(spec.rootfs.media, MediaKind::Rootfs);
    assert_eq!(spec.rootfs.sha256.to_hex(), sha256_hex(ROOTFS_BYTES));

    // Resource spec translated from labels.
    assert_eq!(spec.resources.vcpu_count(), 2);
    assert_eq!(spec.resources.memory_mib(), 512);
    assert_eq!(spec.resources.disk_mib(), 1024);
    assert_eq!(spec.resources.network_policy(), NetworkPolicy::NatOnly);
    assert_eq!(spec.boot_args, "console=ttyS0 reboot=k");

    // The referenced blobs actually open through the resolver at the given path.
    let kernel_on_disk = tmp.path().join(&spec.kernel.rel_path);
    assert_eq!(std::fs::read(&kernel_on_disk).unwrap(), KERNEL_BYTES);
}

#[test]
fn import_is_deterministic_across_runs() {
    let tmp = standard_layout();
    let importer = OciImporter::open(tmp.path()).unwrap();
    let a = importer.import().unwrap();
    let b = importer.import().unwrap();
    assert_eq!(a, b);
    // Serialization is stable too.
    assert_eq!(
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&b).unwrap()
    );
}

#[test]
fn open_reference_accepts_local_path_and_file_uri() {
    let tmp = standard_layout();
    let by_path = OciImporter::open_reference(tmp.path().to_str().unwrap()).unwrap();
    assert!(by_path.import().is_ok());
    let uri = format!("file://{}", tmp.path().display());
    let by_uri = OciImporter::open_reference(&uri).unwrap();
    assert!(by_uri.import().is_ok());
}

// ---------------------------------------------------------------------------
// Every layer hash is verified
// ---------------------------------------------------------------------------

#[test]
fn layer_digest_mismatch_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    // Kernel layer declares the digest of DIFFERENT bytes than it contains.
    let mut bad_kernel = TestLayer::kernel();
    bad_kernel.declared_digest = Some(format!("sha256:{}", sha256_hex(b"some-other-kernel")));
    let layers = vec![
        materialize_layer(root, &bad_kernel),
        materialize_layer(root, &TestLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
    assert!(
        matches!(err, ImportError::DigestMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn config_digest_mismatch_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: Some(format!("sha256:{}", sha256_hex(b"not-the-config"))),
    };
    let config_desc = materialize_config(root, &config);
    let layers = vec![
        materialize_layer(root, &TestLayer::kernel()),
        materialize_layer(root, &TestLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
}

#[test]
fn layer_size_mismatch_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    let mut bad_rootfs = TestLayer::rootfs();
    bad_rootfs.declared_size = Some(ROOTFS_BYTES.len() as u64 + 100);
    let layers = vec![
        materialize_layer(root, &TestLayer::kernel()),
        materialize_layer(root, &bad_rootfs),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
    assert!(
        matches!(err, ImportError::SizeMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn every_layer_is_verified_even_unmapped_ones() {
    // A third, un-annotated layer with a bad digest must still fail the import,
    // proving verification is not limited to the kernel/rootfs roles.
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    let extra = TestLayer {
        role: None,
        bytes: b"extra-layer-bytes".to_vec(),
        declared_digest: Some(format!("sha256:{}", sha256_hex(b"different"))),
        declared_size: None,
        urls: None,
    };
    let layers = vec![
        materialize_layer(root, &TestLayer::kernel()),
        materialize_layer(root, &TestLayer::rootfs()),
        materialize_layer(root, &extra),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::DigestMismatch);
}

#[test]
fn missing_blob_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    // Declare a kernel layer whose digest names a blob we never write: craft
    // the descriptor by hand and only materialize the rootfs blob.
    let ghost_digest = format!("sha256:{}", sha256_hex(b"ghost-kernel-never-written"));
    let ghost_desc = json!({
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "digest": ghost_digest,
        "size": KERNEL_BYTES.len(),
        "annotations": { MEDIA_ANNOTATION: "kernel" },
    });
    let layers = vec![ghost_desc, materialize_layer(root, &TestLayer::rootfs())];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArtifactNotFound);
    assert!(
        matches!(err, ImportError::BlobNotFound { .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Remote / tag-only reference rejection (no network, no side effects)
// ---------------------------------------------------------------------------

#[test]
fn remote_and_tag_references_are_rejected_without_side_effect() {
    for bad in [
        "https://example.com/image",
        "http://example.com/image",
        "docker://nginx:latest",
        "oci://registry.local/img",
        "registry://local/img",
        "s3://bucket/img",
        "nginx:latest",
        "ubuntu:22.04",
        "repo/img@sha256:abcdef0123456789",
    ] {
        let err = OciImporter::open_reference(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LocalArtifactRequired, "bad={bad}");
        assert!(
            matches!(err, ImportError::RemoteReference { .. }),
            "bad={bad}"
        );
    }
    // No layout directory was created anywhere by the rejections above: the
    // importer performs no I/O for a rejected reference.
    assert!(!Path::new("nginx:latest").exists());
}

#[test]
fn descriptor_with_remote_urls_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    let mut remote_kernel = TestLayer::kernel();
    remote_kernel.urls = Some(vec!["https://cdn.example.com/kernel".to_string()]);
    let layers = vec![
        materialize_layer(root, &remote_kernel),
        materialize_layer(root, &TestLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::LocalArtifactRequired);
    assert!(
        matches!(err, ImportError::RemoteDescriptor { .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Forbidden runtime knobs
// ---------------------------------------------------------------------------

/// Build a layout whose image config is `config` and assert the import fails
/// with a Forbidden rejection in `expected_field`.
fn assert_forbidden(config: Value, expected_field: ForbiddenField) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cfg = TestConfig {
        value: config,
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &cfg);
    let layers = vec![
        materialize_layer(root, &TestLayer::kernel()),
        materialize_layer(root, &TestLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    match err {
        ImportError::Forbidden { field, .. } => assert_eq!(field, expected_field),
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[test]
fn host_mounts_are_rejected() {
    let mut config = config_value("linux", "amd64", standard_labels());
    config["mounts"] = json!([{ "destination": "/data", "source": "/host/data" }]);
    assert_forbidden(config, ForbiddenField::Mounts);
}

#[test]
fn capability_additions_are_rejected() {
    let mut config = config_value("linux", "amd64", standard_labels());
    config["capabilities"] = json!({ "bounding": ["CAP_NET_ADMIN"] });
    assert_forbidden(config, ForbiddenField::Capabilities);

    let mut config2 = config_value("linux", "amd64", standard_labels());
    config2["cap_add"] = json!(["NET_ADMIN"]);
    assert_forbidden(config2, ForbiddenField::Capabilities);
}

#[test]
fn privileged_mode_is_rejected() {
    let mut config = config_value("linux", "amd64", standard_labels());
    config["privileged"] = json!(true);
    assert_forbidden(config, ForbiddenField::Privileged);
}

#[test]
fn host_network_is_rejected() {
    let mut config = config_value("linux", "amd64", standard_labels());
    config["host_network"] = json!(true);
    assert_forbidden(config, ForbiddenField::HostNetwork);

    let mut config2 = config_value("linux", "amd64", standard_labels());
    config2["network_mode"] = json!("host");
    assert_forbidden(config2, ForbiddenField::HostNetwork);
}

#[test]
fn host_pid_and_ipc_are_rejected() {
    let mut config = config_value("linux", "amd64", standard_labels());
    config["host_pid"] = json!(true);
    assert_forbidden(config, ForbiddenField::HostPid);

    let mut config2 = config_value("linux", "amd64", standard_labels());
    config2["host_ipc"] = json!(true);
    assert_forbidden(config2, ForbiddenField::HostIpc);
}

#[test]
fn arbitrary_host_process_controls_are_rejected() {
    // A runtime-spec `process` block (args/capabilities/rlimits) is a host
    // process control the constrained importer refuses.
    let mut config = config_value("linux", "amd64", standard_labels());
    config["process"] = json!({ "args": ["sh", "-c", "echo hi"], "rlimits": [] });
    assert_forbidden(config, ForbiddenField::HostProcessControl);

    let mut config2 = config_value("linux", "amd64", standard_labels());
    config2["sysctls"] = json!({ "net.ipv4.ip_forward": "1" });
    assert_forbidden(config2, ForbiddenField::HostProcessControl);

    let mut config3 = config_value("linux", "amd64", standard_labels());
    config3["devices"] = json!([{ "path": "/dev/kvm" }]);
    assert_forbidden(config3, ForbiddenField::HostProcessControl);
}

#[test]
fn forbidden_key_nested_deeply_is_rejected() {
    let mut config = config_value("linux", "amd64", standard_labels());
    config["linux"] = json!({ "namespaces": [], "resources": {}, "masked": [] });
    config["linux"]["resources"]["devices"] = json!([]);
    // `devices` nested under linux.resources must still be caught.
    assert_forbidden(config, ForbiddenField::HostProcessControl);
}

// ---------------------------------------------------------------------------
// Platform selection
// ---------------------------------------------------------------------------

#[test]
fn arm64_platform_selects_aarch64() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "arm64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    let layers = vec![
        materialize_layer(root, &TestLayer::kernel()),
        materialize_layer(root, &TestLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let spec = importer.import().unwrap();
    assert_eq!(spec.platform, Platform::LINUX_ARM64);
    assert_eq!(spec.guest_arch, GuestArch::Aarch64);
}

#[test]
fn import_for_platform_enforces_match() {
    let tmp = standard_layout(); // linux/amd64
    let importer = OciImporter::open(tmp.path()).unwrap();
    // Matching request succeeds.
    assert!(importer.import_for_platform(Platform::LINUX_AMD64).is_ok());
    // Mismatching request is refused with a typed error.
    let err = importer
        .import_for_platform(Platform::LINUX_ARM64)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidResourceSpec);
    assert!(
        matches!(err, ImportError::PlatformMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn unsupported_platforms_are_rejected() {
    for (os, arch) in [
        ("windows", "amd64"),
        ("linux", "riscv64"),
        ("linux", "386"),
        ("linux", "s390x"),
        ("darwin", "arm64"),
    ] {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let config = TestConfig {
            value: config_value(os, arch, standard_labels()),
            declared_digest: None,
        };
        let config_desc = materialize_config(root, &config);
        let layers = vec![
            materialize_layer(root, &TestLayer::kernel()),
            materialize_layer(root, &TestLayer::rootfs()),
        ];
        write_layout(root, config_desc, layers);

        let importer = OciImporter::open(root).unwrap();
        let err = importer.import().unwrap_err();
        assert!(
            matches!(err, ImportError::UnsupportedPlatform { .. }),
            "{os}/{arch}: got {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Media role validation
// ---------------------------------------------------------------------------

#[test]
fn missing_kernel_or_rootfs_is_rejected() {
    // Only a rootfs layer, no kernel.
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    let layers = vec![materialize_layer(root, &TestLayer::rootfs())];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert!(
        matches!(
            err,
            ImportError::MissingMedia {
                media: MediaKind::Kernel
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn duplicate_kernel_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let config = TestConfig {
        value: config_value("linux", "amd64", standard_labels()),
        declared_digest: None,
    };
    let config_desc = materialize_config(root, &config);
    let mut second_kernel = TestLayer::kernel();
    second_kernel.bytes = b"another-kernel".to_vec();
    let layers = vec![
        materialize_layer(root, &TestLayer::kernel()),
        materialize_layer(root, &second_kernel),
        materialize_layer(root, &TestLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);

    let importer = OciImporter::open(root).unwrap();
    let err = importer.import().unwrap_err();
    assert!(
        matches!(
            err,
            ImportError::DuplicateMedia {
                media: MediaKind::Kernel
            }
        ),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Documentation contract: constrained import, not an OCI runtime
// ---------------------------------------------------------------------------

#[test]
fn run_help_says_constrained_import_not_oci_runtime() {
    let help = run_help_text();
    let lower = help.to_ascii_lowercase();
    assert!(lower.contains("constrained local import"));
    assert!(lower.contains("not an oci runtime"));
    assert!(!lower.contains("oci runtime compatible"));
    assert!(!lower.contains("is an oci runtime"));
}

#[test]
fn no_remote_client_dependency_is_required() {
    // The importer rejects remote references purely lexically and never needs a
    // remote client: a reference to a non-existent remote host fails with
    // local_artifact_required, not a network/transport error.
    let err = OciImporter::open_reference("https://nonexistent.invalid/img").unwrap_err();
    assert_eq!(err.code(), ErrorCode::LocalArtifactRequired);
    assert_ne!(err.code(), ErrorCode::TransportError);
}
