//! Deterministic image-builder acceptance tests (the image builder).
//!
//! QA happy path: `cargo test -p microvm-artifacts --test reproducible_builder`.
//!
//! These tests are fully deterministic and require no privileged host
//! capabilities: they build from local fixture bytes in a tempdir and assert
//! reproducibility, digest/size coverage, source-provenance rejection, and that
//! generated artifacts open only through the descriptor-relative
//! [`PathResolver`] (the path resolver).

use microvm_artifacts::{
    compute_sha256, validate_relative_path, verify_sha256, BuildOutput, GuestArch, ImageBuilder,
    ImageManifest, PathResolver, KERNEL_RELPATH, MANIFEST_RELPATH, ROOTFS_RELPATH,
};
use microvm_errors::ErrorCode;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Fixed kernel/rootfs fixture bytes (stand-ins for an uncompressed vmlinux and
/// a ready ext4 image; the builder copies them verbatim).
const KERNEL_BYTES: &[u8] = b"\x7fELF-uncompressed-guest-kernel-fixture";
const ROOTFS_BYTES: &[u8] = b"ext4-rootfs-image-fixture-bytes-0123456789";
const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";

/// Write the kernel/rootfs fixtures into a fresh source directory.
fn source_fixtures() -> (TempDir, PathBuf, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let kernel = tmp.path().join("vmlinux");
    let rootfs = tmp.path().join("rootfs.ext4");
    std::fs::write(&kernel, KERNEL_BYTES).unwrap();
    std::fs::write(&rootfs, ROOTFS_BYTES).unwrap();
    (tmp, kernel, rootfs)
}

fn builder() -> ImageBuilder {
    ImageBuilder::new(GuestArch::X86_64, BOOT_ARGS).unwrap()
}

fn build_once(out: &Path) -> BuildOutput {
    let (_src, kernel, rootfs) = source_fixtures();
    builder()
        .build(kernel.to_str().unwrap(), rootfs.to_str().unwrap(), out)
        .unwrap()
}

/// Read a file fully and return its bytes.
fn read_all(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

// ---------------------------------------------------------------------------
// Reproducibility
// ---------------------------------------------------------------------------

#[test]
fn reproducible_builds_produce_identical_manifest_and_file_hashes() {
    // Build the SAME local inputs into two distinct output directories.
    let (_src, kernel, rootfs) = source_fixtures();
    let out_a = TempDir::new().unwrap();
    let out_b = TempDir::new().unwrap();
    let a = builder()
        .build(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            out_a.path(),
        )
        .unwrap();
    let b = builder()
        .build(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            out_b.path(),
        )
        .unwrap();

    // Manifest hashes are identical...
    assert_eq!(a.manifest_sha256, b.manifest_sha256);
    assert_eq!(a.manifest_size, b.manifest_size);
    // ...and so are the serialized manifest bytes.
    assert_eq!(read_all(&a.manifest_path()), read_all(&b.manifest_path()));

    // Artifact file hashes are identical across builds...
    assert_eq!(
        compute_sha256(&read_all(&a.kernel_path())[..]).unwrap(),
        compute_sha256(&read_all(&b.kernel_path())[..]).unwrap()
    );
    assert_eq!(
        compute_sha256(&read_all(&a.rootfs_path())[..]).unwrap(),
        compute_sha256(&read_all(&b.rootfs_path())[..]).unwrap()
    );

    // ...and every artifact hash equals its source content hash (verbatim copy).
    assert_eq!(m_kernel_digest(&a), compute_sha256(KERNEL_BYTES).unwrap());
    assert_eq!(m_rootfs_digest(&a), compute_sha256(ROOTFS_BYTES).unwrap());
    // On-disk artifact bytes equal the source bytes exactly.
    assert_eq!(read_all(&a.kernel_path()), KERNEL_BYTES);
    assert_eq!(read_all(&a.rootfs_path()), ROOTFS_BYTES);
}

fn m_kernel_digest(b: &BuildOutput) -> microvm_artifacts::Digest {
    b.manifest.kernel.sha256
}
fn m_rootfs_digest(b: &BuildOutput) -> microvm_artifacts::Digest {
    b.manifest.rootfs.sha256
}

#[test]
fn rebuilding_into_the_same_directory_is_stable() {
    // Same local inputs (same files), rebuilt into the same output directory.
    let (_src, kernel, rootfs) = source_fixtures();
    let out = TempDir::new().unwrap();
    let first = builder()
        .build(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            out.path(),
        )
        .unwrap();
    let second = builder()
        .build(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            out.path(),
        )
        .unwrap();
    assert_eq!(first.manifest_sha256, second.manifest_sha256);
    assert_eq!(first.manifest, second.manifest);
}

// ---------------------------------------------------------------------------
// Digest + size coverage
// ---------------------------------------------------------------------------

#[test]
fn all_files_have_sha256_and_size() {
    let out = TempDir::new().unwrap();
    let built = build_once(out.path());
    let m = &built.manifest;

    // Kernel record: digest + size match the bytes on disk.
    let kernel_bytes = read_all(&built.kernel_path());
    assert_eq!(m.kernel.sha256, compute_sha256(&kernel_bytes[..]).unwrap());
    assert_eq!(m.kernel.size as usize, kernel_bytes.len());
    assert_eq!(m.kernel.size, KERNEL_BYTES.len() as u64);

    // Rootfs record: digest + size match the bytes on disk.
    let rootfs_bytes = read_all(&built.rootfs_path());
    assert_eq!(m.rootfs.sha256, compute_sha256(&rootfs_bytes[..]).unwrap());
    assert_eq!(m.rootfs.size as usize, rootfs_bytes.len());
    assert_eq!(m.rootfs.size, ROOTFS_BYTES.len() as u64);

    // Provenance digests equal the artifact digests (content-addressed copy).
    assert_eq!(m.kernel.provenance.sha256, m.kernel.sha256);
    assert_eq!(m.rootfs.provenance.sha256, m.rootfs.sha256);

    // The manifest file itself has a digest + size that match disk.
    let manifest_bytes = read_all(&built.manifest_path());
    assert_eq!(
        built.manifest_sha256,
        compute_sha256(&manifest_bytes[..]).unwrap()
    );
    assert_eq!(built.manifest_size as usize, manifest_bytes.len());
}

#[test]
fn manifest_records_version_arch_boot_args_and_provenance() {
    let (_src, kernel, rootfs) = source_fixtures();
    let out = TempDir::new().unwrap();
    let built = builder()
        .build(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            out.path(),
        )
        .unwrap();
    let m = &built.manifest;

    assert_eq!(m.version, microvm_artifacts::IMAGE_MANIFEST_VERSION);
    assert_eq!(m.guest_arch, GuestArch::X86_64);
    assert_eq!(m.boot_args, BOOT_ARGS);

    // Provenance is local-file, normalized to a file:// origin, per media.
    assert_eq!(
        m.kernel.provenance.origin,
        format!("file://{}", kernel.display())
    );
    assert_eq!(
        m.rootfs.provenance.origin,
        format!("file://{}", rootfs.display())
    );
    assert_eq!(
        m.kernel.provenance.media,
        microvm_artifacts::MediaKind::Kernel
    );
    assert_eq!(
        m.rootfs.provenance.media,
        microvm_artifacts::MediaKind::Rootfs
    );
    assert_eq!(
        m.kernel.provenance.kind,
        microvm_artifacts::SourceKind::LocalFile
    );

    // The manifest round-trips through JSON losslessly.
    let json = read_all(&built.manifest_path());
    let back: ImageManifest = serde_json::from_slice(&json).unwrap();
    assert_eq!(&back, m);
}

// ---------------------------------------------------------------------------
// Artifacts open only through the PathResolver (the path resolver)
// ---------------------------------------------------------------------------

#[test]
fn generated_artifacts_open_only_through_path_resolver() {
    let out = TempDir::new().unwrap();
    let built = build_once(out.path());
    let m = &built.manifest;

    // The recorded relative paths are valid resolver paths.
    validate_relative_path(KERNEL_RELPATH).unwrap();
    validate_relative_path(ROOTFS_RELPATH).unwrap();
    validate_relative_path(MANIFEST_RELPATH).unwrap();
    assert_eq!(m.kernel.path, KERNEL_RELPATH);
    assert_eq!(m.rootfs.path, ROOTFS_RELPATH);

    // Open every artifact through the held-directory resolver and verify digests.
    let resolver = PathResolver::open_root(out.path()).unwrap();

    let mut kernel = resolver.open(KERNEL_RELPATH).unwrap();
    verify_sha256(&mut kernel, &m.kernel.sha256).unwrap();

    let mut rootfs = resolver.open(ROOTFS_RELPATH).unwrap();
    verify_sha256(&mut rootfs, &m.rootfs.sha256).unwrap();

    // The manifest itself opens through the resolver and matches its own digest.
    let mut manifest = resolver.open(MANIFEST_RELPATH).unwrap();
    verify_sha256(&mut manifest, &built.manifest_sha256).unwrap();

    // A tampered expectation fails closed.
    let mut bad = *m.kernel.sha256.as_bytes();
    bad[0] ^= 0x01;
    let bad_digest = microvm_artifacts::Digest::from_bytes(bad);
    let mut kernel2 = resolver.open(KERNEL_RELPATH).unwrap();
    assert_eq!(
        verify_sha256(&mut kernel2, &bad_digest).unwrap_err().code,
        ErrorCode::DigestMismatch
    );
}

#[test]
fn resolver_rejects_escape_and_symlink_within_build_tree() {
    let out = TempDir::new().unwrap();
    build_once(out.path());
    let resolver = PathResolver::open_root(out.path()).unwrap();

    // Absolute paths and `..` traversal are refused by the resolver contract.
    assert!(validate_relative_path("/etc/passwd").is_err());
    assert_eq!(
        resolver.open("/etc/passwd").unwrap_err().code,
        ErrorCode::PathEscape
    );
    assert_eq!(
        resolver.open("images/../../etc/passwd").unwrap_err().code,
        ErrorCode::PathEscape
    );

    // A symlink planted inside the build tree cannot be followed out of the root.
    std::os::unix::fs::symlink("/etc/passwd", out.path().join("images/evil-link")).unwrap();
    assert_eq!(
        resolver.open("images/evil-link").unwrap_err().code,
        ErrorCode::PathEscape
    );
}

// ---------------------------------------------------------------------------
// Remote / tag-only source rejection (no output, no network)
// ---------------------------------------------------------------------------

#[test]
fn remote_and_tag_sources_are_rejected_with_no_output() {
    // The builder performs no network I/O by construction; a rejected source
    // must fail with LocalArtifactRequired and leave no partial artifact tree.
    let (_src, _kernel, rootfs) = source_fixtures();
    let bad_sources = [
        "https://example.com/vmlinux",
        "http://example.com/vmlinux",
        "oci://registry.local/kernel@sha256:deadbeef",
        "docker://nginx:latest",
        "registry://internal/kernel:v1",
        "s3://bucket/vmlinux",
        "gs://bucket/vmlinux",
        "ftp://host/vmlinux",
        "ssh://host/vmlinux",
        "git://host/repo",
        "registry.local/kernel:latest",
        "nginx:latest",
        "ubuntu:22.04",
        "fedora",
        "repo/img@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "file://remote-host/export/vmlinux",
    ];

    for bad_kernel in bad_sources {
        let out = TempDir::new().unwrap();
        let target = out.path().join("build");
        assert!(!target.exists(), "precondition: target absent");
        let err = builder()
            .build(bad_kernel, rootfs.to_str().unwrap(), &target)
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::LocalArtifactRequired,
            "src={bad_kernel}"
        );
        // No partial artifact directory was created.
        assert!(!target.exists(), "no output dir for src={bad_kernel}");
    }

    // A bad rootfs source is rejected the same way (with a valid kernel).
    let (_s, kernel, _r) = source_fixtures();
    for bad_rootfs in ["docker://ubuntu:22.04", "quay.io/img:tag", "tagonly"] {
        let out = TempDir::new().unwrap();
        let target = out.path().join("build");
        let err = builder()
            .build(kernel.to_str().unwrap(), bad_rootfs, &target)
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::LocalArtifactRequired,
            "rootfs={bad_rootfs}"
        );
        assert!(!target.exists(), "no output dir for rootfs={bad_rootfs}");
    }
}

// ---------------------------------------------------------------------------
// Malformed source rejection before any output
// ---------------------------------------------------------------------------

#[test]
fn malformed_sources_are_rejected_before_output() {
    let src = TempDir::new().unwrap();
    let good_kernel = src.path().join("vmlinux");
    std::fs::write(&good_kernel, KERNEL_BYTES).unwrap();
    let good_rootfs = src.path().join("rootfs.ext4");
    std::fs::write(&good_rootfs, ROOTFS_BYTES).unwrap();

    let out = TempDir::new().unwrap();
    let target = out.path().join("build");

    // Missing path-shaped source -> ArtifactNotFound, no output.
    let missing = src.path().join("absent.img");
    let err = builder()
        .build(
            missing.to_str().unwrap(),
            good_rootfs.to_str().unwrap(),
            &target,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);
    assert!(!target.exists(), "no output for missing kernel");

    // Directory target -> InvalidResourceSpec, no output.
    let err = builder()
        .build(
            src.path().to_str().unwrap(),
            good_rootfs.to_str().unwrap(),
            &target,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    assert!(!target.exists(), "no output for directory kernel");

    // Empty file -> InvalidResourceSpec, no output.
    let empty = src.path().join("empty.img");
    std::fs::write(&empty, b"").unwrap();
    let err = builder()
        .build(
            empty.to_str().unwrap(),
            good_rootfs.to_str().unwrap(),
            &target,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    assert!(!target.exists(), "no output for empty kernel");

    // Symlink source -> InvalidResourceSpec, no output.
    let link = src.path().join("link.img");
    std::os::unix::fs::symlink(&good_kernel, &link).unwrap();
    let err = builder()
        .build(
            link.to_str().unwrap(),
            good_rootfs.to_str().unwrap(),
            &target,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    assert!(!target.exists(), "no output for symlink kernel");

    // Empty locator -> InvalidResourceSpec, no output.
    let err = builder()
        .build("", good_rootfs.to_str().unwrap(), &target)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    assert!(!target.exists(), "no output for empty locator");
}

#[test]
fn malformed_rootfs_is_rejected_before_any_kernel_output() {
    // A valid kernel must not be written when the rootfs source is malformed:
    // all sources are validated before any output is produced.
    let src = TempDir::new().unwrap();
    let good_kernel = src.path().join("vmlinux");
    std::fs::write(&good_kernel, KERNEL_BYTES).unwrap();
    let missing_rootfs = src.path().join("absent-rootfs.ext4");

    let out = TempDir::new().unwrap();
    let target = out.path().join("build");
    let err = builder()
        .build(
            good_kernel.to_str().unwrap(),
            missing_rootfs.to_str().unwrap(),
            &target,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);

    // Neither the output directory nor a partial kernel artifact exists.
    assert!(!target.exists(), "no output dir");
    assert!(!target.join(KERNEL_RELPATH).exists(), "no partial kernel");
}

// ---------------------------------------------------------------------------
// file:// local sources are accepted
// ---------------------------------------------------------------------------

#[test]
fn file_uri_local_sources_build_successfully() {
    let (_src, kernel, rootfs) = source_fixtures();
    let out = TempDir::new().unwrap();
    let kernel_uri = format!("file://{}", kernel.display());
    let rootfs_uri = format!("file://localhost{}", rootfs.display());
    let built = builder()
        .build(&kernel_uri, &rootfs_uri, out.path())
        .unwrap();
    assert_eq!(
        m_kernel_digest(&built),
        compute_sha256(KERNEL_BYTES).unwrap()
    );
    assert_eq!(
        m_rootfs_digest(&built),
        compute_sha256(ROOTFS_BYTES).unwrap()
    );
    // Both file:// forms normalize to the same origin.
    assert_eq!(
        built.manifest.kernel.provenance.origin,
        format!("file://{}", kernel.display())
    );
    assert_eq!(
        built.manifest.rootfs.provenance.origin,
        format!("file://{}", rootfs.display())
    );
}
