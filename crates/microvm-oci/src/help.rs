//! Canonical `microvm run` help/documentation text.
//!
//! The `microvm run` command is a **constrained local import** surface. These
//! constants are the single source of truth for its help output so the CLI
//! (todo 26) and the documentation always describe it accurately: it imports a
//! local, digest-pinned OCI-like layout into a typed microVM spec. It is **not**
//! an OCI runtime and does not claim OCI runtime compatibility.

/// One-line description for `microvm run --help`.
pub const RUN_SHORT_ABOUT: &str =
    "Import a constrained local OCI-like image and run it as a microVM";

/// Long-form description for `microvm run --help`.
///
/// Deliberately states the constrained-import contract and the explicit
/// non-goal of OCI runtime compatibility.
pub const RUN_LONG_ABOUT: &str = "\
Import a constrained local OCI-like image and run it as a microVM.

This is a CONSTRAINED LOCAL IMPORT interface, not an OCI runtime. It reads a
local, digest-pinned OCI-like layout (manifest.json plus blobs/sha256/<hex>),
verifies the SHA-256 of the config blob and of every layer, selects a supported
platform (linux/amd64 or linux/arm64), and translates the result into a typed
microVM specification (kernel, rootfs, and resource limits).

The image reference must be a local path or file:// URI to a layout directory.
Remote and tag-only references are rejected before any I/O: https://, docker://,
oci://, registry://, repo/img@sha256:..., and nginx:latest all fail with
local_artifact_required. This command performs no network I/O and has no remote
client dependency.

Constrained import refuses, with a typed rejection reason, any image that
requests host mounts, host network/PID/IPC sharing, privileged mode, capability
additions, or arbitrary host process controls. Container process metadata
(Cmd/Entrypoint/Env) is ignored, never applied to the host.

This tool does NOT provide OCI runtime compatibility and makes no claim of
general OCI runtime conformance; OCI input is only a constrained image/import
format.";

/// The full help body (short + long) used to render `microvm run --help`.
pub fn run_help_text() -> String {
    format!("{RUN_SHORT_ABOUT}\n\n{RUN_LONG_ABOUT}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_describes_constrained_import() {
        let text = run_help_text().to_ascii_lowercase();
        assert!(
            text.contains("constrained local import"),
            "must say constrained import"
        );
        assert!(text.contains("local"), "must emphasize local");
        assert!(text.contains("digest"), "must mention digest verification");
    }

    #[test]
    fn help_disclaims_oci_runtime_compatibility() {
        let text = run_help_text();
        let lower = text.to_ascii_lowercase();
        // Must explicitly state it is NOT an OCI runtime.
        assert!(
            lower.contains("not an oci runtime"),
            "must disclaim OCI runtime"
        );
        assert!(
            lower.contains("does not provide oci runtime compatibility")
                || lower.contains("no claim of general oci runtime"),
            "must disclaim OCI runtime compatibility"
        );
        // Must never positively claim OCI runtime compatibility/compliance.
        // (The disclaimer itself uses "conformance" in a negation, so we only
        // guard against affirmative-claim phrasings here.)
        assert!(!lower.contains("oci runtime compatible"));
        assert!(!lower.contains("oci runtime compliant"));
        assert!(!lower.contains("is an oci runtime"));
        assert!(!lower.contains("supports the oci runtime"));
    }

    #[test]
    fn help_documents_rejected_inputs() {
        let lower = run_help_text().to_ascii_lowercase();
        for token in [
            "https://",
            "docker://",
            "nginx:latest",
            "host mounts",
            "privileged",
        ] {
            assert!(lower.contains(token), "help should mention {token}");
        }
    }
}
