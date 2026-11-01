//! Local-only reference validation for the constrained importer.
//!
//! `microvm run --image <ref>` must accept only a local, digest-pinned
//! layout reference. Remote registry references and tag-only references are
//! refused with [`ImportError::RemoteReference`] (which maps to
//! [`ErrorCode::LocalArtifactRequired`]) *before* any I/O or network activity.
//! The importer performs no network I/O by construction and has no remote
//! client dependency.
//!
//! Accepted forms:
//! - An absolute or relative local filesystem path to an OCI layout directory.
//! - A `file://` URI with an empty or `localhost` host.
//!
//! Refused forms (non-exhaustive): `https://…`, `http://…`, `oci://…`,
//! `docker://…`, `registry://…`, `s3://…`, `ssh://…`, `repo/img@sha256:…`,
//! `nginx:latest`, `ubuntu:22.04`, `file://remote-host/…`.

use crate::error::ImportError;
use std::path::{Path, PathBuf};

/// Bare `scheme:` prefixes that denote a remote or local-escape scheme. Only
/// the standard `file://` URI form is accepted (handled separately).
const REMOTE_SCHEME_PREFIXES: &[&str] = &[
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
    "containerd:",
    "file:",
];

/// Validate that `reference` is a local-only layout reference and resolve it to
/// a filesystem path.
///
/// This is a pure lexical/local check: it never touches the network. Existence
/// of the layout directory is verified later when the importer opens its root.
pub fn validate_local_reference(reference: &str) -> Result<PathBuf, ImportError> {
    if reference.is_empty() {
        return Err(remote(reference, "reference must not be empty"));
    }
    if reference.bytes().any(|b| b == 0) {
        return Err(remote(reference, "reference must not contain NUL"));
    }
    // Any `scheme://` form must be a local `file://` URI.
    if let Some((scheme, _)) = reference.split_once("://") {
        if scheme.eq_ignore_ascii_case("file") {
            return resolve_file_uri(reference);
        }
        return Err(remote(
            reference,
            "only local file:// references are permitted",
        ));
    }
    // Bare `scheme:` prefixes (docker:nginx, oci:img, https:…) are remote.
    if has_remote_scheme_prefix(reference) {
        return Err(remote(
            reference,
            "remote or local-escape scheme is not permitted",
        ));
    }
    // `@` denotes a digest-pinned registry reference (repo/img@sha256:…).
    if reference.contains('@') {
        return Err(remote(
            reference,
            "digest-pinned registry references are not permitted",
        ));
    }
    resolve_local_or_tag(reference)
}

/// Resolve a `file://` URI, requiring an empty or `localhost` host and an
/// absolute path.
fn resolve_file_uri(reference: &str) -> Result<PathBuf, ImportError> {
    let rest = &reference["file://".len()..];
    let path_part = if let Some(tail) = rest.strip_prefix('/') {
        // Empty host: file:///abs/path
        format!("/{tail}")
    } else {
        let (host, tail) = match rest.split_once('/') {
            Some(parts) => parts,
            None => {
                return Err(remote(
                    reference,
                    "file:// reference must include an absolute path",
                ))
            }
        };
        if !host.eq_ignore_ascii_case("localhost") {
            return Err(remote(
                reference,
                "file:// reference must use an empty or localhost host",
            ));
        }
        format!("/{tail}")
    };
    if path_part.len() <= 1 {
        return Err(remote(
            reference,
            "file:// reference must name a directory path",
        ));
    }
    Ok(PathBuf::from(path_part))
}

/// Resolve a reference with no `scheme://`: a local path if it is path-shaped,
/// otherwise a rejected tag-only reference.
fn resolve_local_or_tag(reference: &str) -> Result<PathBuf, ImportError> {
    let looks_like_path = reference.starts_with('/')
        || reference.starts_with("./")
        || reference.starts_with("../")
        || reference.contains('/');
    // A ':' outside a scheme denotes a registry tag (nginx:latest, repo/img:v1).
    if reference.contains(':') {
        return Err(remote(
            reference,
            "tag-only references are not permitted; provide a local path or file:// URI",
        ));
    }
    if looks_like_path {
        return Ok(absolutize(reference));
    }
    // A bare name with no path separators and no colon (e.g. "fedora") is
    // ambiguous with a tag; refuse it rather than guess.
    Err(remote(
        reference,
        "tag-only references are not permitted; provide a local path or file:// URI",
    ))
}

fn has_remote_scheme_prefix(reference: &str) -> bool {
    let lower = reference.to_ascii_lowercase();
    REMOTE_SCHEME_PREFIXES.iter().any(|s| lower.starts_with(s))
}

fn absolutize(reference: &str) -> PathBuf {
    let path = Path::new(reference);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    }
}

fn remote(reference: &str, reason: &str) -> ImportError {
    ImportError::RemoteReference {
        reference: reference.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_errors::ErrorCode;

    #[test]
    fn accepts_local_paths() {
        assert!(validate_local_reference("/var/lib/microvm/layouts/img").is_ok());
        assert!(validate_local_reference("./layouts/img").is_ok());
        assert!(validate_local_reference("../layouts/img").is_ok());
        assert!(validate_local_reference("layouts/img").is_ok());
    }

    #[test]
    fn accepts_local_file_uri() {
        let p = validate_local_reference("file:///var/lib/layouts/img").unwrap();
        assert_eq!(p, PathBuf::from("/var/lib/layouts/img"));
        let p = validate_local_reference("file://localhost/var/lib/layouts/img").unwrap();
        assert_eq!(p, PathBuf::from("/var/lib/layouts/img"));
    }

    #[test]
    fn rejects_remote_uris() {
        for bad in [
            "https://example.com/img",
            "http://example.com/img",
            "oci://registry.local/img",
            "docker://nginx:latest",
            "registry://local/img",
            "s3://bucket/img",
            "ssh://host/img",
            "file://remote-host/export/img",
        ] {
            let err = validate_local_reference(bad).unwrap_err();
            assert_eq!(err.code(), ErrorCode::LocalArtifactRequired, "bad={bad}");
            assert!(matches!(err, ImportError::RemoteReference { .. }));
        }
    }

    #[test]
    fn rejects_tag_only_and_digest_references() {
        for bad in [
            "nginx:latest",
            "ubuntu:22.04",
            "fedora",
            "repo/img:v1",
            "repo/img@sha256:abcdef0123456789",
            "docker:nginx",
        ] {
            let err = validate_local_reference(bad).unwrap_err();
            assert_eq!(err.code(), ErrorCode::LocalArtifactRequired, "bad={bad}");
        }
    }

    #[test]
    fn rejects_empty_and_nul() {
        assert!(validate_local_reference("").is_err());
        assert!(validate_local_reference("a\0b").is_err());
    }
}
