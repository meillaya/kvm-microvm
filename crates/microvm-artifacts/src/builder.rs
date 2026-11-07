//! Deterministic local image builder and digest-addressed artifact manifests.
//!
//! [`ImageBuilder`] packages local kernel and rootfs inputs into the
//! uncompressed kernel and ext4/rootfs artifacts a Firecracker guest boots,
//! alongside a content-addressed [`ImageManifest`]. The builder is the
//! provenance gate for the image lane: it only ever reads operator-supplied
//! local files (a `file://` URI with an empty/`localhost` host, or a local
//! filesystem path) and never contacts a registry, so two builds from
//! identical local inputs produce byte-identical artifacts and a byte-identical
//! manifest.
//!
//! # Determinism contract
//! - Kernel and rootfs bytes are copied verbatim; the builder never
//!   regenerates a filesystem or recompresses a kernel, so artifact bytes (and
//!   therefore their SHA-256 digests) are a pure function of the input bytes.
//! - The manifest carries no wall-clock timestamps and no volatile metadata:
//!   every field is either declared configuration (guest arch, boot args,
//!   schema version) or content-derived (per-file SHA-256, size, and a
//!   normalized `file://` provenance origin). Serialization field order is
//!   fixed by the struct layout, so the manifest bytes are reproducible.
//! - All source validation happens before any output is written. A rejected
//!   source leaves no partial artifact tree behind.
//!
//! # Security contract
//! - Remote registries and tag-only references (`https://…`, `oci://…`,
//!   `docker://…`, `s3://…`, `nginx:latest`, `repo/img@sha256:…`, …) are
//!   rejected with [`ErrorCode::LocalArtifactRequired`] before any I/O to the
//!   output directory. The builder performs no network I/O by construction.
//! - Malformed sources (empty locator, NUL byte, missing file, directory,
//!   symlink, or empty file) are rejected with [`ErrorCode::InvalidResourceSpec`]
//!   / [`ErrorCode::ArtifactNotFound`] before any output is produced.
//! - Generated artifacts are written beneath `out_dir` at stable relative paths
//!   ([`KERNEL_RELPATH`], [`ROOTFS_RELPATH`], [`MANIFEST_RELPATH`]) that pass
//!   [`crate::path::validate_relative_path`] and therefore open only through
//!   the descriptor-relative [`crate::path::PathResolver`] (the path resolver); never via
//!   an absolute, symlink-following `open(2)`.
//!
//! [`ErrorCode::LocalArtifactRequired`]: microvm_errors::ErrorCode::LocalArtifactRequired
//! [`ErrorCode::InvalidResourceSpec`]: microvm_errors::ErrorCode::InvalidResourceSpec
//! [`ErrorCode::ArtifactNotFound`]: microvm_errors::ErrorCode::ArtifactNotFound

use crate::digest::{compute_sha256, Digest};
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Schema version stamped into every [`ImageManifest`].
pub const IMAGE_MANIFEST_VERSION: u32 = 1;

/// Tenant-relative path of the uncompressed kernel artifact beneath `out_dir`.
pub const KERNEL_RELPATH: &str = "images/vmlinux";

/// Tenant-relative path of the ext4/rootfs artifact beneath `out_dir`.
pub const ROOTFS_RELPATH: &str = "images/rootfs.ext4";

/// Tenant-relative path of the JSON image manifest beneath `out_dir`.
pub const MANIFEST_RELPATH: &str = "image-manifest.json";

/// Streaming hash/copy buffer size.
const BUF_LEN: usize = 8192;

/// Guest CPU architecture the artifacts are built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestArch {
    /// 64-bit x86 (Firecracker `x86_64`).
    #[serde(rename = "x86_64")]
    X86_64,
    /// 64-bit ARM (Firecracker `aarch64`).
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl GuestArch {
    /// Stable `snake_case` name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// Which guest media an artifact or source describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    /// The uncompressed guest kernel.
    Kernel,
    /// The ext4/rootfs block image.
    Rootfs,
}

impl MediaKind {
    /// Stable `snake_case` name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Rootfs => "rootfs",
        }
    }
}

/// The kind of local source an artifact was built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A regular file on the local filesystem (via `file://` URI or path).
    LocalFile,
}

impl SourceKind {
    /// Stable `snake_case` name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalFile => "local_file",
        }
    }
}

/// Provenance record for a single built artifact: where its bytes came from
/// and the content digest/size that pin them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProvenance {
    /// The media this source provides.
    pub media: MediaKind,
    /// The kind of local source.
    pub kind: SourceKind,
    /// SHA-256 of the source bytes (equal to the artifact digest: verbatim copy).
    pub sha256: Digest,
    /// Size of the source in bytes.
    pub size: u64,
    /// Normalized `file://` origin URI of the local source.
    pub origin: String,
}

/// A single built artifact: its tenant-relative path, content digest, size, and
/// source provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Path relative to the build output root (passes
    /// [`crate::path::validate_relative_path`]).
    pub path: String,
    /// SHA-256 of the artifact bytes.
    pub sha256: Digest,
    /// Size of the artifact in bytes.
    pub size: u64,
    /// Where the artifact bytes came from.
    pub provenance: SourceProvenance,
}

/// Digest-addressed manifest describing a built kernel/rootfs image pair.
///
/// The manifest is a pure function of declared configuration (version, guest
/// arch, boot args) and content-derived fields (per-artifact SHA-256, size, and
/// normalized provenance), so it serializes to identical bytes for identical
/// inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    /// Manifest schema version ([`IMAGE_MANIFEST_VERSION`]).
    pub version: u32,
    /// Guest CPU architecture the artifacts target.
    pub guest_arch: GuestArch,
    /// Kernel boot arguments (cmdline) recorded for the image.
    pub boot_args: String,
    /// The uncompressed kernel artifact record.
    pub kernel: ArtifactRecord,
    /// The ext4/rootfs artifact record.
    pub rootfs: ArtifactRecord,
}

impl ImageManifest {
    /// Serialize to deterministic, newline-terminated pretty JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, MicrovmError> {
        let mut json = serde_json::to_string_pretty(self).map_err(|e| {
            MicrovmError::new(
                ErrorCode::InternalError,
                "failed to serialize image manifest",
            )
            .with_context("io", e.to_string())
        })?;
        json.push('\n');
        Ok(json.into_bytes())
    }
}

/// Result of a successful build: the output root, the manifest, and the
/// digest/size of the serialized manifest itself.
#[derive(Clone, Debug)]
pub struct BuildOutput {
    /// Directory the artifacts and manifest were written beneath.
    pub output_root: PathBuf,
    /// The image manifest describing the build.
    pub manifest: ImageManifest,
    /// SHA-256 of the serialized manifest bytes.
    pub manifest_sha256: Digest,
    /// Size of the serialized manifest in bytes.
    pub manifest_size: u64,
}

impl BuildOutput {
    /// Absolute path to the uncompressed kernel artifact.
    pub fn kernel_path(&self) -> PathBuf {
        self.output_root.join(KERNEL_RELPATH)
    }

    /// Absolute path to the ext4/rootfs artifact.
    pub fn rootfs_path(&self) -> PathBuf {
        self.output_root.join(ROOTFS_RELPATH)
    }

    /// Absolute path to the serialized image manifest.
    pub fn manifest_path(&self) -> PathBuf {
        self.output_root.join(MANIFEST_RELPATH)
    }
}

/// Builds deterministic kernel/rootfs artifacts from local inputs.
#[derive(Clone, Debug)]
pub struct ImageBuilder {
    guest_arch: GuestArch,
    boot_args: String,
}

impl ImageBuilder {
    /// Create a builder for `guest_arch` recording `boot_args` in the manifest.
    pub fn new(guest_arch: GuestArch, boot_args: impl Into<String>) -> Result<Self, MicrovmError> {
        let boot_args = boot_args.into();
        if boot_args.bytes().any(|b| b == 0) {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "boot args must not contain NUL",
            ));
        }
        Ok(Self {
            guest_arch,
            boot_args,
        })
    }

    /// The guest architecture this builder targets.
    pub fn guest_arch(&self) -> GuestArch {
        self.guest_arch
    }

    /// The boot args recorded in the manifest.
    pub fn boot_args(&self) -> &str {
        &self.boot_args
    }

    /// Build the kernel/rootfs artifacts and manifest beneath `out_dir`.
    ///
    /// `kernel_source` and `rootfs_source` are local source locators: a
    /// `file://` URI (empty/`localhost` host) or a local filesystem path. Remote
    /// registries and tag-only references are rejected with
    /// [`ErrorCode::LocalArtifactRequired`]; malformed or missing sources are
    /// rejected before any output is written.
    ///
    /// [`ErrorCode::LocalArtifactRequired`]: microvm_errors::ErrorCode::LocalArtifactRequired
    pub fn build(
        &self,
        kernel_source: &str,
        rootfs_source: &str,
        out_dir: &Path,
    ) -> Result<BuildOutput, MicrovmError> {
        // Phase 1: validate and resolve every source before producing output.
        let kernel = resolve_source(kernel_source, MediaKind::Kernel)?;
        let rootfs = resolve_source(rootfs_source, MediaKind::Rootfs)?;

        // Phase 2: produce the deterministic output tree.
        let images = out_dir.join("images");
        std::fs::create_dir_all(&images)
            .map_err(|e| output_error(out_dir, "create images directory", &e))?;

        let (kernel_sha, kernel_size) =
            copy_and_hash(&kernel.abs_path, &out_dir.join(KERNEL_RELPATH))?;
        let (rootfs_sha, rootfs_size) =
            copy_and_hash(&rootfs.abs_path, &out_dir.join(ROOTFS_RELPATH))?;

        let manifest = ImageManifest {
            version: IMAGE_MANIFEST_VERSION,
            guest_arch: self.guest_arch,
            boot_args: self.boot_args.clone(),
            kernel: ArtifactRecord {
                path: KERNEL_RELPATH.to_string(),
                sha256: kernel_sha,
                size: kernel_size,
                provenance: SourceProvenance {
                    media: MediaKind::Kernel,
                    kind: SourceKind::LocalFile,
                    sha256: kernel_sha,
                    size: kernel.size,
                    origin: kernel.origin,
                },
            },
            rootfs: ArtifactRecord {
                path: ROOTFS_RELPATH.to_string(),
                sha256: rootfs_sha,
                size: rootfs_size,
                provenance: SourceProvenance {
                    media: MediaKind::Rootfs,
                    kind: SourceKind::LocalFile,
                    sha256: rootfs_sha,
                    size: rootfs.size,
                    origin: rootfs.origin,
                },
            },
        };

        let manifest_bytes = manifest.to_json_bytes()?;
        write_deterministic(&out_dir.join(MANIFEST_RELPATH), &manifest_bytes)?;
        let manifest_sha256 = compute_sha256(&manifest_bytes[..])?;

        Ok(BuildOutput {
            output_root: out_dir.to_path_buf(),
            manifest,
            manifest_sha256,
            manifest_size: manifest_bytes.len() as u64,
        })
    }
}

/// A validated, resolved local source ready to be copied.
#[derive(Debug)]
struct ResolvedSource {
    abs_path: PathBuf,
    origin: String,
    size: u64,
}

/// Validate and resolve a source locator to a local file, rejecting remote
/// registries and tag-only references with [`ErrorCode::LocalArtifactRequired`]
/// and malformed/missing sources before any output is produced.
///
/// [`ErrorCode::LocalArtifactRequired`]: microvm_errors::ErrorCode::LocalArtifactRequired
fn resolve_source(locator: &str, media: MediaKind) -> Result<ResolvedSource, MicrovmError> {
    if locator.is_empty() {
        return Err(malformed(
            locator,
            "source locator must not be empty",
            media,
        ));
    }
    if locator.bytes().any(|b| b == 0) {
        return Err(malformed(
            locator,
            "source locator must not contain NUL",
            media,
        ));
    }
    if let Some((scheme, _)) = locator.split_once("://") {
        if scheme.eq_ignore_ascii_case("file") {
            return resolve_file_uri(locator, media);
        }
        return Err(local_required(
            locator,
            "only local file:// sources are permitted",
            media,
        ));
    }
    if has_remote_scheme_prefix(locator) {
        return Err(local_required(
            locator,
            "remote or local-escape scheme is not permitted",
            media,
        ));
    }
    if locator.contains('@') {
        return Err(local_required(
            locator,
            "digest-pinned registry references are not permitted",
            media,
        ));
    }
    resolve_local_or_tag(locator, media)
}

/// Resolve a `file://` URI, requiring an empty or `localhost` host and an
/// absolute path.
fn resolve_file_uri(locator: &str, media: MediaKind) -> Result<ResolvedSource, MicrovmError> {
    let rest = &locator["file://".len()..];
    let path_part = if let Some(tail) = rest.strip_prefix('/') {
        // Empty host: file:///abs/path
        format!("/{tail}")
    } else {
        let (host, tail) = match rest.split_once('/') {
            Some(parts) => parts,
            None => {
                return Err(local_required(
                    locator,
                    "file:// URI must include an absolute path",
                    media,
                ))
            }
        };
        if !host.eq_ignore_ascii_case("localhost") {
            return Err(local_required(
                locator,
                "file:// URI must use an empty or localhost host",
                media,
            ));
        }
        format!("/{tail}")
    };
    if path_part.len() <= 1 {
        return Err(local_required(
            locator,
            "file:// URI must reference a file path",
            media,
        ));
    }
    validate_local_file(&PathBuf::from(path_part), locator, media)
}

/// Resolve a locator with no `scheme://`: a local path if it is path-shaped or
/// names an existing file, otherwise a rejected tag-only reference.
fn resolve_local_or_tag(locator: &str, media: MediaKind) -> Result<ResolvedSource, MicrovmError> {
    let abs = absolutize(locator);
    let looks_like_path = locator.starts_with('/')
        || locator.starts_with("./")
        || locator.starts_with("../")
        || locator.contains('/');
    let exists_as_file = existing_file_at(&abs);

    // A ':' outside a scheme denotes a registry tag (nginx:latest, repo/img:v1).
    // Accept it only when it genuinely names an existing local file.
    if locator.contains(':') && !exists_as_file {
        return Err(local_required(
            locator,
            "tag-only references are not permitted; provide a local file:// URI or path",
            media,
        ));
    }
    if looks_like_path || exists_as_file {
        return validate_local_file(&abs, locator, media);
    }
    Err(local_required(
        locator,
        "tag-only references are not permitted; provide a local file:// URI or path",
        media,
    ))
}

/// Confirm `abs` is an existing, non-symlink, non-empty regular file and build
/// its resolved source record with a normalized `file://` origin.
fn validate_local_file(
    abs: &Path,
    locator: &str,
    media: MediaKind,
) -> Result<ResolvedSource, MicrovmError> {
    let meta = match std::fs::symlink_metadata(abs) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(not_found(locator, media))
        }
        Err(e) => {
            return Err(malformed(
                locator,
                &format!("cannot stat source: {e}"),
                media,
            ))
        }
    };
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Err(malformed(locator, "source must not be a symlink", media));
    }
    if !file_type.is_file() {
        return Err(malformed(locator, "source must be a regular file", media));
    }
    let size = meta.len();
    if size == 0 {
        return Err(malformed(locator, "source must not be empty", media));
    }
    Ok(ResolvedSource {
        origin: format!("file://{}", abs.display()),
        abs_path: abs.to_path_buf(),
        size,
    })
}

/// Detect bare `scheme:` prefixes for remote or local-escape schemes (including
/// a non-`//` `file:` form; only the standard `file://` URI is accepted).
fn has_remote_scheme_prefix(locator: &str) -> bool {
    const SCHEMES: &[&str] = &[
        "oci:",
        "docker:",
        "registry:",
        "http:",
        "https:",
        "s3:",
        "gs:",
        "ftp:",
        "ftps:",
        "ssh:",
        "git:",
        "unix:",
        "file:",
    ];
    let lower = locator.to_ascii_lowercase();
    SCHEMES.iter().any(|s| lower.starts_with(s))
}

/// Make a locator absolute without resolving symlinks (relative locators are
/// joined onto the current directory).
fn absolutize(locator: &str) -> PathBuf {
    let path = Path::new(locator);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    }
}

/// Whether `abs` currently names an existing regular file (or symlink to one,
/// which is later rejected by [`validate_local_file`]).
fn existing_file_at(abs: &Path) -> bool {
    std::fs::symlink_metadata(abs)
        .map(|m| m.is_file() || m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Copy `src` to `dst` verbatim while computing the SHA-256 digest, returning
/// the digest and byte count. Output permissions are pinned to `0o644`.
fn copy_and_hash(src: &Path, dst: &Path) -> Result<(Digest, u64), MicrovmError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(src)
        .map_err(|e| {
            MicrovmError::new(
                ErrorCode::ArtifactNotFound,
                "failed to open source artifact",
            )
            .with_context("source", src.display().to_string())
            .with_context("io", e.to_string())
        })?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(dst)
        .map_err(|e| output_error_path(dst, "create artifact", &e))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; BUF_LEN];
    let mut total: u64 = 0;
    loop {
        let n = input.read(&mut buf).map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "failed reading source bytes")
                .with_context("source", src.display().to_string())
                .with_context("io", e.to_string())
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output.write_all(&buf[..n]).map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "failed writing artifact bytes")
                .with_context("path", dst.display().to_string())
                .with_context("io", e.to_string())
        })?;
        total += n as u64;
    }
    output.sync_all().map_err(|e| {
        MicrovmError::new(ErrorCode::InternalError, "failed to sync artifact")
            .with_context("path", dst.display().to_string())
            .with_context("io", e.to_string())
    })?;
    set_perms_644(dst)?;

    let finalized = hasher.finalize();
    let mut bytes = [0u8; crate::digest::SHA256_LEN];
    bytes.copy_from_slice(&finalized);
    Ok((Digest::from_bytes(bytes), total))
}

/// Write `bytes` to `path` deterministically (truncate/create, sync, `0o644`).
fn write_deterministic(path: &Path, bytes: &[u8]) -> Result<(), MicrovmError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| output_error_path(path, "create manifest", &e))?;
    file.write_all(bytes).map_err(|e| {
        MicrovmError::new(ErrorCode::InternalError, "failed writing manifest bytes")
            .with_context("path", path.display().to_string())
            .with_context("io", e.to_string())
    })?;
    file.sync_all().map_err(|e| {
        MicrovmError::new(ErrorCode::InternalError, "failed to sync manifest")
            .with_context("path", path.display().to_string())
            .with_context("io", e.to_string())
    })?;
    set_perms_644(path)
}

/// Pin a written artifact's permissions to `0o644` (never world-writable, so it
/// passes the [`crate::path::PathResolver`] world-writable guard regardless of
/// the builder's umask).
fn set_perms_644(path: &Path) -> Result<(), MicrovmError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o644);
    std::fs::set_permissions(path, perms)
        .map_err(|e| output_error_path(path, "set artifact permissions", &e))
}

fn local_required(locator: &str, reason: &str, media: MediaKind) -> MicrovmError {
    MicrovmError::new(ErrorCode::LocalArtifactRequired, reason)
        .with_context("source", locator.to_string())
        .with_context("media", media.as_str())
}

fn malformed(locator: &str, reason: &str, media: MediaKind) -> MicrovmError {
    MicrovmError::new(ErrorCode::InvalidResourceSpec, reason)
        .with_context("source", locator.to_string())
        .with_context("media", media.as_str())
}

fn not_found(locator: &str, media: MediaKind) -> MicrovmError {
    MicrovmError::new(
        ErrorCode::ArtifactNotFound,
        "local source artifact not found",
    )
    .with_context("source", locator.to_string())
    .with_context("media", media.as_str())
}

fn output_error(out_dir: &Path, op: &str, e: &std::io::Error) -> MicrovmError {
    MicrovmError::new(ErrorCode::InternalError, "failed to write build output")
        .with_context("op", op)
        .with_context("out_dir", out_dir.display().to_string())
        .with_context("io", e.to_string())
}

fn output_error_path(path: &Path, op: &str, e: &std::io::Error) -> MicrovmError {
    MicrovmError::new(ErrorCode::InternalError, "failed to write build output")
        .with_context("op", op)
        .with_context("path", path.display().to_string())
        .with_context("io", e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_source(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn guest_arch_serde_is_stable() {
        assert_eq!(
            serde_json::to_string(&GuestArch::X86_64).unwrap(),
            "\"x86_64\""
        );
        assert_eq!(
            serde_json::to_string(&GuestArch::Aarch64).unwrap(),
            "\"aarch64\""
        );
        let back: GuestArch = serde_json::from_str("\"aarch64\"").unwrap();
        assert_eq!(back, GuestArch::Aarch64);
    }

    #[test]
    fn manifest_serialization_is_deterministic() {
        let tmp = TempDir::new().unwrap();
        let kernel = write_source(tmp.path(), "vmlinux", b"kernel-bytes");
        let rootfs = write_source(tmp.path(), "rootfs.ext4", b"rootfs-bytes");
        let out_a = tmp.path().join("a");
        let out_b = tmp.path().join("b");
        let builder = ImageBuilder::new(GuestArch::X86_64, "console=ttyS0 reboot=k").unwrap();
        let a = builder
            .build(kernel.to_str().unwrap(), rootfs.to_str().unwrap(), &out_a)
            .unwrap();
        let b = builder
            .build(kernel.to_str().unwrap(), rootfs.to_str().unwrap(), &out_b)
            .unwrap();
        assert_eq!(
            a.manifest.to_json_bytes().unwrap(),
            b.manifest.to_json_bytes().unwrap()
        );
        assert_eq!(a.manifest_sha256, b.manifest_sha256);
    }

    #[test]
    fn resolve_accepts_local_path_and_file_uri() {
        let tmp = TempDir::new().unwrap();
        let kernel = write_source(tmp.path(), "vmlinux", b"kernel-bytes");
        let abs = kernel.to_str().unwrap();
        assert!(resolve_source(abs, MediaKind::Kernel).is_ok());
        let uri = format!("file://{abs}");
        let resolved = resolve_source(&uri, MediaKind::Kernel).unwrap();
        // Both forms normalize to the same file:// origin.
        assert_eq!(resolved.origin, format!("file://{abs}"));
        let localhost = format!("file://localhost{abs}");
        assert_eq!(
            resolve_source(&localhost, MediaKind::Kernel)
                .unwrap()
                .origin,
            format!("file://{abs}")
        );
    }

    #[test]
    fn resolve_rejects_remote_and_tag_sources() {
        for bad in [
            "https://example.com/vmlinux",
            "oci://registry.local/kernel@sha256:deadbeef",
            "docker://nginx:latest",
            "s3://bucket/kernel",
            "registry.local/kernel:latest",
            "nginx:latest",
            "ubuntu:22.04",
            "fedora",
            "repo/img@sha256:abcdef0123456789",
            "file://remote-host/export/vmlinux",
        ] {
            let err = resolve_source(bad, MediaKind::Kernel).unwrap_err();
            assert_eq!(err.code, ErrorCode::LocalArtifactRequired, "bad={bad}");
        }
    }

    #[test]
    fn resolve_rejects_malformed_sources() {
        let tmp = TempDir::new().unwrap();
        // Missing path-shaped source.
        let missing = tmp.path().join("nope.img");
        let err = resolve_source(missing.to_str().unwrap(), MediaKind::Rootfs).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactNotFound);
        // Directory target.
        let err = resolve_source(tmp.path().to_str().unwrap(), MediaKind::Rootfs).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        // Empty locator and NUL byte.
        assert_eq!(
            resolve_source("", MediaKind::Kernel).unwrap_err().code,
            ErrorCode::InvalidResourceSpec
        );
        assert_eq!(
            resolve_source("a\0b", MediaKind::Kernel).unwrap_err().code,
            ErrorCode::InvalidResourceSpec
        );
        // Empty file.
        let empty = write_source(tmp.path(), "empty.img", b"");
        let err = resolve_source(empty.to_str().unwrap(), MediaKind::Rootfs).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        // Symlink source.
        let real = write_source(tmp.path(), "real.img", b"x");
        let link = tmp.path().join("link.img");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = resolve_source(link.to_str().unwrap(), MediaKind::Rootfs).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn builder_rejects_nul_boot_args() {
        assert!(ImageBuilder::new(GuestArch::X86_64, "console=\0").is_err());
    }
}
