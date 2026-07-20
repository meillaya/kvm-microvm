//! Path-security adversarial suite.
//!
//! Drives the real descriptor-relative artifact resolver
//! ([`microvm_artifacts::PathResolver`]) and the lexical
//! [`microvm_artifacts::validate_relative_path`] gate against every known
//! path-escape trap: symlink escape, `..` traversal, absolute paths, magic
//! links, symlinked tenant roots, NUL bytes, remote URIs, world-writable
//! artifacts, and non-regular files. Both the `openat2` fast path and the
//! portable `O_NOFOLLOW` fallback walk are exercised independently.
//!
//! Every probe observes the **typed** [`ErrorCode`] the resolver returns; no
//! probe is a source-text scan.

mod common;

use common::{assert_no_bypass, run_battery, Probe};
use microvm_artifacts::{validate_relative_path, PathResolver};
use microvm_errors::ErrorCode;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

/// Build a tenant root containing one valid regular blob and return the root.
fn root_with_blob() -> (TempDir, String) {
    let tmp = TempDir::new().unwrap();
    let rel = "blobs/sha256/deadbeef".to_string();
    let full = tmp.path().join(&rel);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(&full, b"guest-artifact-bytes").unwrap();
    (tmp, rel)
}

/// The happy path must open a clean regular blob (the control that proves the
/// resolver works, so the rejections below are meaningful).
#[test]
fn happy_path_opens_clean_regular_blob() {
    let (tmp, rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let mut f = resolver.open(&rel).unwrap();
    use std::io::Read;
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    assert_eq!(s, "guest-artifact-bytes");
}

#[test]
fn symlink_escape_is_refused() {
    let (tmp, _rel) = root_with_blob();
    // A symlink whose lexical path is clean but whose target escapes the root.
    symlink("/etc/passwd", tmp.path().join("blobs/evil-link")).unwrap();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let err = resolver.open("blobs/evil-link").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

#[test]
fn symlinked_directory_component_is_refused() {
    let (tmp, _rel) = root_with_blob();
    symlink("/etc", tmp.path().join("evil-dir")).unwrap();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let err = resolver.open("evil-dir/passwd").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

#[test]
fn magic_link_target_is_refused() {
    let (tmp, _rel) = root_with_blob();
    // A symlink pointing at a procfs magic link (/proc/self/fd/0). The resolver
    // must refuse to follow it (NO_SYMLINKS / NO_MAGICLINKS) -> ELOOP -> escape.
    symlink("/proc/self/fd/0", tmp.path().join("blobs/magic")).unwrap();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let err = resolver.open("blobs/magic").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

#[test]
fn dotdot_traversal_is_refused_lexically() {
    let (tmp, _rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    for bad in [
        "../etc/passwd",
        "blobs/../../outside",
        "..",
        "blobs/../../../etc/shadow",
    ] {
        let err = resolver.open(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape, "bad={bad}");
    }
}

#[test]
fn absolute_path_is_refused() {
    let (tmp, _rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let err = resolver.open("/etc/passwd").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

#[test]
fn nul_byte_is_refused() {
    let (tmp, _rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let err = resolver.open("blobs\0/evil").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

#[test]
fn remote_uri_is_refused() {
    let (tmp, _rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    for bad in [
        "https://example.com/blob",
        "oci://registry/img",
        "file:///etc/passwd",
        "s3://bucket/key",
    ] {
        let err = resolver.open(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape, "bad={bad}");
    }
}

#[test]
fn empty_and_malformed_components_are_refused() {
    let (tmp, _rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    for bad in ["", "blobs//x", "blobs/", "/"] {
        let err = resolver.open(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape, "bad={bad:?}");
    }
}

#[test]
fn symlinked_tenant_root_is_refused() {
    let (tmp, _rel) = root_with_blob();
    let link = tmp.path().join("root-link");
    symlink(tmp.path().join("blobs"), &link).unwrap();
    // The root itself is a symlink -> O_NOFOLLOW|O_DIRECTORY refuses it.
    let err = PathResolver::open_root(&link).unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

#[test]
fn missing_tenant_root_is_not_found() {
    let tmp = TempDir::new().unwrap();
    let err = PathResolver::open_root(&tmp.path().join("does-not-exist")).unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);
}

#[test]
fn world_writable_artifact_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let (tmp, rel) = root_with_blob();
    let full = tmp.path().join(&rel);
    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o666)).unwrap();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let err = resolver.open(&rel).unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
}

#[test]
fn non_regular_file_is_refused() {
    let (tmp, _rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    // "blobs/sha256" is a directory, not a regular file.
    let err = resolver.open("blobs/sha256").unwrap_err();
    assert_eq!(err.code, ErrorCode::ArtifactNotFound);
}

/// The portable `O_NOFOLLOW` fallback walk (used on pre-5.6 kernels / filesystems
/// without openat2 resolve support) must be independently safe: the same traps
/// are refused with the same typed code when openat2 is disabled.
#[test]
fn fallback_walk_is_independently_safe() {
    let (tmp, rel) = root_with_blob();
    symlink("/etc/passwd", tmp.path().join("blobs/evil-link")).unwrap();
    let resolver = PathResolver::open_root(tmp.path())
        .unwrap()
        .with_openat2_disabled();
    // Happy path still works on the fallback.
    assert!(resolver.open(&rel).is_ok());
    // Symlink escape is still refused.
    let err = resolver.open("blobs/evil-link").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
    // `..` is still refused (lexically, before the walk).
    let err = resolver.open("../outside").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

/// `validate_relative_path` is the lexical gate the resolver applies first; it
/// must reject every escape shape before any descriptor is opened.
#[test]
fn lexical_gate_rejects_escape_shapes() {
    for bad in [
        "",
        "/abs",
        "../up",
        "a/../b",
        "a//b",
        "https://x/y",
        "file:///z",
        "a\0b",
        "..",
    ] {
        let err = validate_relative_path(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape, "bad={bad:?}");
    }
    // Clean relative paths pass the lexical gate.
    assert!(validate_relative_path("blobs/sha256/ab").is_ok());
    assert!(validate_relative_path("./blobs/x").is_ok());
}

/// The consolidated path-security battery: run every trap through the real
/// resolver, record the typed rejection, write the evidence artifact, and
/// assert no bypass. This is the artifact-producing proof for plan todo 31.
#[test]
fn path_security_battery_emits_evidence_and_detects_no_bypass() {
    let (tmp, rel) = root_with_blob();
    symlink("/etc/passwd", tmp.path().join("blobs/evil-link")).unwrap();
    symlink("/etc", tmp.path().join("evil-dir")).unwrap();
    symlink("/proc/self/fd/0", tmp.path().join("blobs/magic")).unwrap();
    let link_root = tmp.path().join("root-link");
    symlink(tmp.path().join("blobs"), &link_root).unwrap();

    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    let fallback = PathResolver::open_root(tmp.path())
        .unwrap()
        .with_openat2_disabled();

    let mut probes: Vec<Probe> = Vec::new();
    // Control: the clean blob opens (recorded as expected-OK via a synthetic
    // probe whose "expected" is the absence of error). We model the control by
    // asserting it here and not as a rejection probe.
    assert!(resolver.open(&rel).is_ok(), "control: clean blob must open");

    macro_rules! reject {
        ($name:expr, $trap:expr, $code:expr, $e:expr) => {
            probes.push(Probe::from_result($name, $trap, $code, $e))
        };
    }

    reject!(
        "symlink_escape",
        "path:symlink_escape",
        ErrorCode::PathEscape,
        resolver.open("blobs/evil-link")
    );
    reject!(
        "symlink_dir_component",
        "path:symlink_escape",
        ErrorCode::PathEscape,
        resolver.open("evil-dir/passwd")
    );
    reject!(
        "magic_link_target",
        "path:magic_link",
        ErrorCode::PathEscape,
        resolver.open("blobs/magic")
    );
    reject!(
        "dotdot_traversal",
        "path:dotdot_traversal",
        ErrorCode::PathEscape,
        resolver.open("../etc/passwd")
    );
    reject!(
        "dotdot_nested",
        "path:dotdot_traversal",
        ErrorCode::PathEscape,
        resolver.open("blobs/../../outside")
    );
    reject!(
        "absolute_path",
        "path:absolute_path",
        ErrorCode::PathEscape,
        resolver.open("/etc/passwd")
    );
    reject!(
        "nul_byte",
        "path:nul_byte",
        ErrorCode::PathEscape,
        resolver.open("blobs\0/x")
    );
    reject!(
        "remote_uri_https",
        "path:remote_uri",
        ErrorCode::PathEscape,
        resolver.open("https://example.com/b")
    );
    reject!(
        "remote_uri_file",
        "path:remote_uri",
        ErrorCode::PathEscape,
        resolver.open("file:///etc/passwd")
    );
    reject!(
        "empty_path",
        "path:empty",
        ErrorCode::PathEscape,
        resolver.open("")
    );
    reject!(
        "empty_component",
        "path:empty_component",
        ErrorCode::PathEscape,
        resolver.open("blobs//x")
    );
    reject!(
        "symlinked_root",
        "path:symlinked_root",
        ErrorCode::PathEscape,
        PathResolver::open_root(&link_root)
    );
    reject!(
        "missing_root",
        "path:missing_root",
        ErrorCode::ArtifactNotFound,
        PathResolver::open_root(&tmp.path().join("nope"))
    );
    reject!(
        "non_regular_file",
        "path:non_regular",
        ErrorCode::ArtifactNotFound,
        resolver.open("blobs/sha256")
    );
    // Fallback walk independence.
    reject!(
        "fallback_symlink_escape",
        "path:symlink_escape",
        ErrorCode::PathEscape,
        fallback.open("blobs/evil-link")
    );
    reject!(
        "fallback_dotdot",
        "path:dotdot_traversal",
        ErrorCode::PathEscape,
        fallback.open("../outside")
    );

    // World-writable artifact (PermissionDenied) needs its own fixture.
    let ww = root_with_world_writable();
    let ww_resolver = PathResolver::open_root(ww.0.path()).unwrap();
    reject!(
        "world_writable_artifact",
        "path:world_writable",
        ErrorCode::PermissionDenied,
        ww_resolver.open(&ww.1)
    );

    let evidence = run_battery("path_security", probes);
    assert_no_bypass(&evidence);
    assert!(
        evidence.summary.total >= 16,
        "battery must cover every path trap"
    );
}

fn root_with_world_writable() -> (TempDir, String) {
    use std::os::unix::fs::PermissionsExt;
    let (tmp, rel) = root_with_blob();
    let full = tmp.path().join(&rel);
    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o666)).unwrap();
    (tmp, rel)
}

/// A canary proving the harness itself detects a bypass: if a hostile input
/// were to *succeed* (operation returns `Ok`), the probe records `bypass` and
/// the battery fails. This is the "deliberate bypass fixture makes the suite
/// fail" property required by the plan's failure QA.
#[test]
fn harness_canary_flags_a_successful_bypass_as_failure() {
    let (tmp, rel) = root_with_blob();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    // A clean open succeeds; if we *expected* a rejection, that is a bypass.
    let bypass_probe = Probe::from_result(
        "canary_bypass",
        "path:canary",
        ErrorCode::PathEscape,
        resolver.open(&rel),
    );
    assert!(
        !bypass_probe.passed(),
        "a successful open must read as a bypass"
    );
    let evidence = common::SecurityEvidence::from_probes("path_security_canary", &[bypass_probe]);
    assert_eq!(evidence.summary.fail, 1);
}
