//! Descriptor-relative artifact path resolution.
//!
//! Every artifact is opened relative to a held directory file descriptor for a
//! per-tenant root. Resolution prefers [`openat2(2)`] with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` so the kernel
//! itself refuses `..` escapes, symlink traversal, and magic-link traversal. On
//! kernels without `openat2` (pre-5.6, `ENOSYS`) or filesystems that do not
//! support the resolve flags (`EOPNOTSUPP`), a component-wise `openat` walk with
//! `O_NOFOLLOW` provides the same guarantees: `..` is rejected lexically and
//! every hop is opened with `O_NOFOLLOW` relative to the previous descriptor.
//!
//! The resolver never calls `open(2)` on an absolute, caller-controlled path and
//! never follows symlinks. Accepted paths are purely relative and must name a
//! regular, non-world-writable file beneath the tenant root.
//!
//! [`openat2(2)`]: https://man7.org/linux/man-pages/man2/openat2.2.html

use microvm_errors::{ErrorCode, MicrovmError};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// openat2 resolve flags: stay beneath the dirfd, refuse all symlinks and
/// magic links (e.g. `/proc/*/fd` references).
const RESOLVE_FLAGS: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

/// Flags applied to the final artifact open.
const FILE_FLAGS: i32 = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY;

/// Flags applied to intermediate directory hops in the fallback walk.
const DIR_FLAGS: i32 = FILE_FLAGS | libc::O_DIRECTORY;

/// A held directory descriptor anchoring all relative artifact resolution for a
/// single tenant root.
#[derive(Debug)]
pub struct PathResolver {
    dir: File,
    allow_openat2: bool,
}

impl PathResolver {
    /// Open `root` as the anchor directory.
    ///
    /// The root itself is opened with `O_DIRECTORY | O_NOFOLLOW`; a missing root
    /// yields [`ErrorCode::ArtifactNotFound`] and a symlinked root yields
    /// [`ErrorCode::PathEscape`].
    pub fn open_root(root: &Path) -> Result<Self, MicrovmError> {
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
            .open(root)
            .map_err(|e| root_open_error(e, root))?;
        Ok(Self {
            dir,
            allow_openat2: true,
        })
    }

    /// Disable the `openat2` fast path, forcing the `openat` fallback walk.
    ///
    /// Intended for tests that must prove the fallback is independently safe.
    #[must_use]
    pub fn with_openat2_disabled(mut self) -> Self {
        self.allow_openat2 = false;
        self
    }

    /// Validate and open `rel` beneath the held root, returning a descriptor to a
    /// regular, non-world-writable file.
    pub fn open(&self, rel: &str) -> Result<File, MicrovmError> {
        validate_relative_path(rel)?;
        let fd = self.open_raw(rel)?;
        // SAFETY: `open_raw` returned a freshly-owned descriptor that nothing
        // else references; wrapping it transfers ownership to `File`.
        let file = unsafe { File::from_raw_fd(fd) };
        check_regular_not_world_writable(&file, rel)?;
        Ok(file)
    }

    /// Resolve `rel` to a raw descriptor, preferring openat2 and falling back on
    /// kernel/filesystem non-support.
    fn open_raw(&self, rel: &str) -> Result<RawFd, MicrovmError> {
        if self.allow_openat2 {
            match openat2_relative(self.dir.as_raw_fd(), rel) {
                Ok(fd) => return Ok(fd),
                Err(e) if openat2_unsupported(e) => {
                    // Fall through to the portable walk.
                }
                Err(e) => return Err(errno_to_error(e, rel)),
            }
        }
        openat_walk(self.dir.as_raw_fd(), rel).map_err(|e| errno_to_error(e, rel))
    }
}

/// Lexically validate a relative artifact path.
///
/// Rejects empty paths, absolute paths, remote URIs, NUL bytes, `..` components,
/// and empty (`//` or trailing-`/`) components. `.` components are permitted and
/// ignored during resolution.
pub fn validate_relative_path(rel: &str) -> Result<(), MicrovmError> {
    if rel.is_empty() {
        return Err(escape(rel, "path must not be empty"));
    }
    if rel.bytes().any(|b| b == 0) {
        return Err(escape(rel, "path must not contain NUL"));
    }
    if rel.starts_with('/') {
        return Err(escape(rel, "absolute paths are not permitted"));
    }
    if is_remote_uri(rel) {
        return Err(escape(rel, "remote URIs are not permitted"));
    }
    let mut saw_file_component = false;
    for component in rel.split('/') {
        match component {
            "" => return Err(escape(rel, "empty path component is not permitted")),
            ".." => return Err(escape(rel, "parent-directory traversal is not permitted")),
            "." => {}
            _ => saw_file_component = true,
        }
    }
    if !saw_file_component {
        return Err(escape(
            rel,
            "path does not name a file beneath the tenant root",
        ));
    }
    Ok(())
}

/// Detect RFC-3986-style URIs such as `https://…`, `oci://…`, `docker://…`,
/// `s3://…`, or `file://…`. Any `scheme://` form is rejected, as are bare
/// `scheme:` prefixes for well-known remote/local-escape schemes.
fn is_remote_uri(rel: &str) -> bool {
    if rel.contains("://") {
        return true;
    }
    const SCHEMES: &[&str] = &[
        "http:",
        "https:",
        "oci:",
        "docker:",
        "registry:",
        "s3:",
        "gs:",
        "ftp:",
        "ftps:",
        "ssh:",
        "git:",
        "file:",
        "unix:",
    ];
    let lower = rel.to_ascii_lowercase();
    SCHEMES.iter().any(|s| lower.starts_with(s))
}

/// openat2-based relative open. Returns the descriptor or the raw errno.
fn openat2_relative(dirfd: RawFd, rel: &str) -> Result<RawFd, i32> {
    let cpath = cstring(rel)?;
    // `libc::open_how` is `#[non_exhaustive]`, so build it from zeroed memory
    // and assign the public fields; the kernel requires reserved bytes to be
    // zero and the size to match `struct open_how`.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY) as u64;
    how.mode = 0;
    how.resolve = RESOLVE_FLAGS;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd as libc::c_long,
            cpath.as_ptr() as libc::c_long,
            &how as *const libc::open_how as libc::c_long,
            std::mem::size_of::<libc::open_how>() as libc::c_long,
        )
    };
    if ret < 0 {
        Err(last_errno())
    } else {
        Ok(ret as RawFd)
    }
}

/// Portable component-wise fallback. `rel` is already lexically validated (no
/// `..`, no absolute path, no empty components), so each hop is opened with
/// `O_NOFOLLOW` relative to the previous descriptor.
fn openat_walk(dirfd: RawFd, rel: &str) -> Result<RawFd, i32> {
    let components: Vec<&str> = rel.split('/').filter(|c| *c != ".").collect();
    debug_assert!(!components.is_empty(), "validated path has a component");
    let last = components.len() - 1;

    let mut cur = dirfd;
    let mut intermediates: Vec<RawFd> = Vec::new();
    let mut outcome: Result<RawFd, i32> = Err(libc::EINVAL);

    for (i, component) in components.iter().enumerate() {
        let cname = match cstring(component) {
            Ok(c) => c,
            Err(e) => {
                outcome = Err(e);
                break;
            }
        };
        let flags = if i == last { FILE_FLAGS } else { DIR_FLAGS };
        let fd = unsafe { libc::openat(cur, cname.as_ptr(), flags, 0) };
        if fd < 0 {
            outcome = Err(last_errno());
            break;
        }
        if i == last {
            outcome = Ok(fd);
        } else {
            intermediates.push(fd);
            cur = fd;
        }
    }

    for fd in intermediates {
        unsafe { libc::close(fd) };
    }
    outcome
}

/// fstat the opened descriptor and require a regular file that is not
/// world-writable. Returns the stat so callers can apply further owner checks.
pub(crate) fn check_regular_not_world_writable(
    file: &File,
    rel: &str,
) -> Result<libc::stat, MicrovmError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(file.as_raw_fd(), &mut stat) };
    if ret < 0 {
        return Err(
            MicrovmError::new(ErrorCode::InternalError, "failed to stat artifact")
                .with_context("path", rel)
                .with_context("errno", last_errno().to_string()),
        );
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(MicrovmError::new(
            ErrorCode::ArtifactNotFound,
            "artifact is not a regular file",
        )
        .with_context("path", rel));
    }
    if stat.st_mode & libc::S_IWOTH != 0 {
        return Err(
            MicrovmError::new(ErrorCode::PermissionDenied, "artifact is world-writable")
                .with_context("path", rel)
                .with_context("mode", format!("{:o}", stat.st_mode & 0o7777)),
        );
    }
    Ok(stat)
}

fn openat2_unsupported(errno: i32) -> bool {
    errno == libc::ENOSYS || errno == libc::EOPNOTSUPP
}

fn errno_to_error(errno: i32, rel: &str) -> MicrovmError {
    let base = match errno {
        // A genuinely absent file or directory component.
        libc::ENOENT => MicrovmError::new(ErrorCode::ArtifactNotFound, "artifact not found"),
        // ELOOP: a symlink (or magic link) was encountered despite NO_SYMLINKS /
        // O_NOFOLLOW. EXDEV: RESOLVE_BENEATH refused an escape attempt. ENOTDIR:
        // a non-directory (a refused symlink-to-dir, or a regular file) was used
        // as a path component. All are escape/malformation attempts -> fail closed.
        libc::ELOOP | libc::EXDEV | libc::ENOTDIR => {
            MicrovmError::new(ErrorCode::PathEscape, "path escape or symlink refused")
        }
        libc::EACCES | libc::EPERM => MicrovmError::new(
            ErrorCode::PermissionDenied,
            "permission denied opening artifact",
        ),
        _ => MicrovmError::new(ErrorCode::InternalError, "failed to open artifact"),
    };
    base.with_context("path", rel)
        .with_context("errno", errno.to_string())
}

fn root_open_error(e: io::Error, root: &Path) -> MicrovmError {
    let code = match e.raw_os_error() {
        // Missing root -> not found. A symlinked or non-directory root is refused
        // by O_NOFOLLOW|O_DIRECTORY as ELOOP/ENOTDIR -> treat as an escape attempt.
        Some(libc::ENOENT) => ErrorCode::ArtifactNotFound,
        Some(libc::ELOOP) | Some(libc::ENOTDIR) => ErrorCode::PathEscape,
        Some(libc::EACCES) | Some(libc::EPERM) => ErrorCode::PermissionDenied,
        _ => ErrorCode::InternalError,
    };
    MicrovmError::new(code, "failed to open tenant root")
        .with_context("root", root.display().to_string())
        .with_context(
            "errno",
            e.raw_os_error().map_or("-".into(), |n| n.to_string()),
        )
}

fn escape(rel: &str, reason: &str) -> MicrovmError {
    MicrovmError::new(ErrorCode::PathEscape, reason).with_context("path", rel)
}

fn cstring(s: &str) -> Result<CString, i32> {
    CString::new(s).map_err(|_| libc::EINVAL)
}

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::compute_sha256;
    use microvm_types::TenantId;
    use std::io::Write;
    use tempfile::TempDir;

    /// Build a tenant root containing a regular artifact `blobs/kernel.img`.
    fn fixture() -> (TempDir, std::path::PathBuf, Vec<u8>) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("tenants").join("tenant-1");
        let blobs = root.join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        let content = b"deterministic-kernel-image-bytes".to_vec();
        let mut f = std::fs::File::create(blobs.join("kernel.img")).unwrap();
        f.write_all(&content).unwrap();
        f.sync_all().unwrap();
        (tmp, root, content)
    }

    /// Run an assertion against both the openat2 fast path and the openat walk.
    fn both_modes<F>(root: &Path, mut check: F)
    where
        F: FnMut(&PathResolver),
    {
        let fast = PathResolver::open_root(root).unwrap();
        check(&fast);
        let slow = PathResolver::open_root(root)
            .unwrap()
            .with_openat2_disabled();
        check(&slow);
    }

    #[test]
    fn valid_digest_addressed_file() {
        let (_tmp, root, content) = fixture();
        both_modes(&root, |r| {
            let mut file = r.open("blobs/kernel.img").unwrap();
            let digest = compute_sha256(&mut file).unwrap();
            let expected = compute_sha256(&content[..]).unwrap();
            assert_eq!(digest, expected);
        });
    }

    #[test]
    fn opens_nested_relative_path() {
        let (_tmp, root, _) = fixture();
        both_modes(&root, |r| {
            assert!(r.open("./blobs/kernel.img").is_ok());
        });
    }

    #[test]
    fn rejects_dotdot_escape() {
        let (_tmp, root, _) = fixture();
        both_modes(&root, |r| {
            let err = r.open("../tenant-2/secret").unwrap_err();
            assert_eq!(err.code, ErrorCode::PathEscape);
            let err = r.open("blobs/../../tenant-1/blobs/kernel.img").unwrap_err();
            assert_eq!(err.code, ErrorCode::PathEscape);
        });
    }

    #[test]
    fn rejects_symlink_escape() {
        let (_tmp, root, _) = fixture();
        // Symlink inside the root that points outside of it.
        std::os::unix::fs::symlink("/etc/passwd", root.join("blobs/evil-link")).unwrap();
        // Symlinked directory component pointing outside.
        std::os::unix::fs::symlink("/etc", root.join("evil-dir")).unwrap();
        both_modes(&root, |r| {
            let err = r.open("blobs/evil-link").unwrap_err();
            assert_eq!(err.code, ErrorCode::PathEscape);
            // No file outside the tenant root was opened: the error is typed and
            // the resolver holds only the root descriptor.
            let err = r.open("evil-dir/passwd").unwrap_err();
            assert_eq!(err.code, ErrorCode::PathEscape);
        });
    }

    #[test]
    fn rejects_absolute_path() {
        let (_tmp, root, _) = fixture();
        both_modes(&root, |r| {
            let err = r.open("/etc/passwd").unwrap_err();
            assert_eq!(err.code, ErrorCode::PathEscape);
        });
    }

    #[test]
    fn rejects_world_writable() {
        let (_tmp, root, _) = fixture();
        let target = root.join("blobs/writable.img");
        std::fs::write(&target, b"x").unwrap();
        let mut perms = std::fs::metadata(&target).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o666);
        std::fs::set_permissions(&target, perms).unwrap();
        both_modes(&root, |r| {
            let err = r.open("blobs/writable.img").unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert!(err.message.contains("world-writable"));
        });
    }

    #[test]
    fn rejects_remote_uri() {
        let (_tmp, root, _) = fixture();
        both_modes(&root, |r| {
            for uri in [
                "https://example.com/kernel.img",
                "oci://registry.local/kernel@sha256:deadbeef",
                "docker://nginx:latest",
                "s3://bucket/key",
                "file:///etc/passwd",
            ] {
                let err = r.open(uri).unwrap_err();
                assert_eq!(err.code, ErrorCode::PathEscape, "uri={uri}");
            }
        });
    }

    #[test]
    fn rejects_missing_artifact() {
        let (_tmp, root, _) = fixture();
        both_modes(&root, |r| {
            let err = r.open("blobs/does-not-exist.img").unwrap_err();
            assert_eq!(err.code, ErrorCode::ArtifactNotFound);
        });
    }

    #[test]
    fn rejects_directory_target() {
        let (_tmp, root, _) = fixture();
        both_modes(&root, |r| {
            let err = r.open("blobs").unwrap_err();
            assert_eq!(err.code, ErrorCode::ArtifactNotFound);
        });
    }

    #[test]
    fn rejects_empty_and_malformed_components() {
        let (_tmp, root, _) = fixture();
        both_modes(&root, |r| {
            for bad in ["", "blobs//kernel.img", "blobs/", ".", "./."] {
                let err = r.open(bad).unwrap_err();
                assert_eq!(err.code, ErrorCode::PathEscape, "bad={bad:?}");
            }
        });
    }

    #[test]
    fn rejects_symlinked_tenant_root() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real-root");
        std::fs::create_dir_all(&real).unwrap();
        let link = tmp.path().join("link-root");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = PathResolver::open_root(&link).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape);
    }

    #[test]
    fn missing_tenant_root_is_artifact_not_found() {
        let tmp = TempDir::new().unwrap();
        let err = PathResolver::open_root(&tmp.path().join("nope")).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactNotFound);
    }

    #[test]
    fn validate_relative_path_unit_cases() {
        assert!(validate_relative_path("blobs/kernel.img").is_ok());
        assert!(validate_relative_path("./a/b").is_ok());
        assert!(validate_relative_path("a").is_ok());
        assert!(validate_relative_path("").is_err());
        assert!(validate_relative_path("/abs").is_err());
        assert!(validate_relative_path("a/../b").is_err());
        assert!(validate_relative_path("a//b").is_err());
        assert!(validate_relative_path("a\0b").is_err());
        assert!(validate_relative_path("https://x/y").is_err());
    }

    #[test]
    fn tenant_id_scopes_root() {
        // TenantId validation guarantees the root component itself cannot carry
        // slashes or `..`, so per-tenant roots stay disjoint.
        assert!(TenantId::new("tenant-1").is_ok());
        assert!(TenantId::new("../evil").is_err());
        assert!(TenantId::new("a/b").is_err());
    }
}
