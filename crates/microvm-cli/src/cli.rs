//! Clap-based command-line interface for the `microvm` CLI.
//!
//! Defines the [`Cli`] parser and [`Command`] subcommands. The CLI talks
//! to the microvm daemon exclusively over a REST Unix socket; it exposes
//! **no** `--tcp`, `--rootless`, `--mount`, `--cap-add`, or remote
//! registry convenience flags. Those omissions are enforced by tests.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Default REST Unix socket path.
pub const DEFAULT_SOCKET: &str = "/run/microvm/api/rest.sock";

/// The `microvm` command-line interface.
///
/// Manages microVM lifecycle operations over a protected REST Unix
/// socket. No TCP endpoint is ever used.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "microvm",
    version,
    about = "Manage microVMs over a protected Unix socket",
    long_about = "Manage microVM lifecycle operations (create, start, stop, snapshot, \
restore, status, metrics, run) over a protected REST Unix domain socket.\n\n\
This CLI connects exclusively through a filesystem Unix socket; it has no \
TCP mode and no remote registry client. Image references for `run` must be \
local, digest-pinned OCI-like layouts."
)]
pub struct Cli {
    /// Path to the microvm daemon REST Unix socket.
    #[arg(long, global = true, default_value = DEFAULT_SOCKET, value_name = "PATH")]
    pub socket: PathBuf,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// The `microvm` subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Create a new microVM from a local digest-pinned image reference.
    Create {
        /// Local digest-pinned image reference (`sha256:<64 hex>`).
        ///
        /// Remote and tag-only references are rejected with exit code 4.
        #[arg(long, value_name = "DIGEST")]
        image: String,

        /// Number of virtual CPUs (minimum 1).
        #[arg(long, default_value_t = 1)]
        vcpu: u32,

        /// Memory allocation in MiB (minimum 1).
        #[arg(long, default_value_t = 512)]
        memory_mib: u64,

        /// Disk allocation in MiB (minimum 1).
        #[arg(long, default_value_t = 1024)]
        disk_mib: u64,

        /// Network egress policy: `none`, `nat-only`, or `egress-allowed`.
        #[arg(long, default_value = "none", value_name = "POLICY")]
        network_policy: String,
    },

    /// Start (or resume) a microVM.
    Start {
        /// Target VM identifier.
        #[arg(long, value_name = "ID")]
        vm_id: String,
    },

    /// Stop a running or paused microVM.
    Stop {
        /// Target VM identifier.
        #[arg(long, value_name = "ID")]
        vm_id: String,
    },

    /// Snapshot a running or paused microVM.
    Snapshot {
        /// Target VM identifier.
        #[arg(long, value_name = "ID")]
        vm_id: String,
    },

    /// Restore a microVM from an existing snapshot.
    Restore {
        /// Source snapshot identifier.
        #[arg(long, value_name = "ID")]
        snapshot_id: String,
    },

    /// Query the current lifecycle status of a microVM.
    Status {
        /// Target VM identifier.
        #[arg(long, value_name = "ID")]
        vm_id: String,
    },

    /// Query per-VM metrics.
    Metrics {
        /// Target VM identifier.
        #[arg(long, value_name = "ID")]
        vm_id: String,
    },

    /// Import a constrained local OCI-like image and run it as a microVM.
    ///
    /// This is a CONSTRAINED LOCAL IMPORT interface, not an OCI runtime.
    #[command(
        long_about = microvm_oci::RUN_LONG_ABOUT,
    )]
    Run {
        /// Local OCI-like image reference (local path or `file://` URI).
        ///
        /// Remote and tag-only references (`https://`, `docker://`,
        /// `nginx:latest`) are rejected with exit code 4 before any I/O.
        #[arg(long, value_name = "REF")]
        image: String,
    },
}

/// Validate a `create --image` digest reference.
///
/// Accepts only a well-formed `sha256:<64 hex>` digest. Remote URIs and
/// tag-only references are rejected with a local-artifact-required error;
/// malformed digests are rejected with a usage error.
pub fn validate_create_image(reference: &str) -> Result<(), crate::error::CliError> {
    // Reject remote schemes and tag-only references first, so the error
    // is local_artifact_required (exit 4) rather than a usage error.
    if let Some(reason) = classify_remote(reference) {
        return Err(crate::error::CliError::local_artifact_required(
            reference, reason,
        ));
    }

    // Must be a well-formed sha256:<64 hex> digest.
    if let Some(hex) = reference.strip_prefix("sha256:") {
        if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(());
        }
    }

    Err(crate::error::CliError::usage(format!(
        "invalid image digest '{}': expected sha256:<64 hex characters>",
        reference
    )))
}

/// If `reference` is a remote URI or tag-only reference, return the
/// rejection reason; otherwise return `None`.
fn classify_remote(reference: &str) -> Option<&'static str> {
    let lower = reference.to_ascii_lowercase();
    const SCHEMES: &[&str] = &[
        "https://",
        "http://",
        "docker://",
        "oci://",
        "registry://",
        "s3://",
        "ssh://",
        "file://",
    ];
    if SCHEMES.iter().any(|s| lower.starts_with(s)) {
        return Some("remote URI references are not permitted");
    }
    if reference.contains('@') {
        return Some("digest-pinned registry references are not permitted");
    }
    // A ':' outside a sha256: digest prefix denotes a registry tag.
    if reference.contains(':') && !reference.starts_with("sha256:") {
        return Some("tag-only references are not permitted");
    }
    // A bare name with no path separators and no sha256: prefix is
    // ambiguous with a tag (e.g. "nginx", "fedora").
    if !reference.starts_with("sha256:") && !reference.contains('/') && !reference.starts_with('.')
    {
        return Some("tag-only references are not permitted");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_create_with_defaults() {
        let cli = Cli::parse_from([
            "microvm",
            "create",
            "--image",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]);
        match cli.command {
            Command::Create {
                image,
                vcpu,
                memory_mib,
                disk_mib,
                network_policy,
            } => {
                assert!(image.starts_with("sha256:"));
                assert_eq!(vcpu, 1);
                assert_eq!(memory_mib, 512);
                assert_eq!(disk_mib, 1024);
                assert_eq!(network_policy, "none");
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn cli_parses_create_with_socket_and_overrides() {
        let cli = Cli::parse_from([
            "microvm",
            "create",
            "--image",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--socket",
            "runtime/api/rest.sock",
            "--vcpu",
            "4",
            "--memory-mib",
            "1024",
            "--disk-mib",
            "2048",
            "--network-policy",
            "nat-only",
        ]);
        assert_eq!(cli.socket, PathBuf::from("runtime/api/rest.sock"));
        match cli.command {
            Command::Create {
                vcpu,
                memory_mib,
                disk_mib,
                network_policy,
                ..
            } => {
                assert_eq!(vcpu, 4);
                assert_eq!(memory_mib, 1024);
                assert_eq!(disk_mib, 2048);
                assert_eq!(network_policy, "nat-only");
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn cli_parses_all_lifecycle_subcommands() {
        // start
        assert!(matches!(
            Cli::parse_from(["microvm", "start", "--vm-id", "vm-001"]).command,
            Command::Start { .. }
        ));
        // stop
        assert!(matches!(
            Cli::parse_from(["microvm", "stop", "--vm-id", "vm-001"]).command,
            Command::Stop { .. }
        ));
        // snapshot
        assert!(matches!(
            Cli::parse_from(["microvm", "snapshot", "--vm-id", "vm-001"]).command,
            Command::Snapshot { .. }
        ));
        // restore
        assert!(matches!(
            Cli::parse_from(["microvm", "restore", "--snapshot-id", "snap-001"]).command,
            Command::Restore { .. }
        ));
        // status
        assert!(matches!(
            Cli::parse_from(["microvm", "status", "--vm-id", "vm-001"]).command,
            Command::Status { .. }
        ));
        // metrics
        assert!(matches!(
            Cli::parse_from(["microvm", "metrics", "--vm-id", "vm-001"]).command,
            Command::Metrics { .. }
        ));
        // run
        assert!(matches!(
            Cli::parse_from(["microvm", "run", "--image", "./layouts/img"]).command,
            Command::Run { .. }
        ));
    }

    #[test]
    fn cli_default_socket_path() {
        let cli = Cli::parse_from(["microvm", "status", "--vm-id", "vm-001"]);
        assert_eq!(cli.socket, PathBuf::from(DEFAULT_SOCKET));
    }

    #[test]
    fn cli_socket_is_global_and_accepts_after_subcommand() {
        // --socket appears after the subcommand (as in the plan QA scenario).
        let cli = Cli::parse_from([
            "microvm",
            "create",
            "--image",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--socket",
            "runtime/api/rest.sock",
        ]);
        assert_eq!(cli.socket, PathBuf::from("runtime/api/rest.sock"));
    }

    #[test]
    fn cli_missing_required_arg_is_usage_error() {
        // create without --image should fail to parse.
        let result = Cli::try_parse_from(["microvm", "create"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // clap uses exit code 2 for usage errors.
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn cli_verify_command_debug_assert() {
        // Ensures the clap definition is internally consistent.
        Cli::command().debug_assert();
    }

    // -- validate_create_image tests ----------------------------------------

    #[test]
    fn validate_create_image_accepts_sha256_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(validate_create_image(&digest).is_ok());
        let digest = format!("sha256:{}", "0123456789abcdef".repeat(4));
        assert!(validate_create_image(&digest).is_ok());
    }

    #[test]
    fn validate_create_image_rejects_remote_uris() {
        for bad in [
            "https://example.com/img",
            "docker://nginx:latest",
            "oci://registry/img",
            "registry://local/img",
        ] {
            let err = validate_create_image(bad).unwrap_err();
            assert_eq!(
                err.exit_code,
                crate::exit_code::ExitCode::LocalArtifactRequired,
                "bad={bad}"
            );
        }
    }

    #[test]
    fn validate_create_image_rejects_tag_only() {
        for bad in ["nginx:latest", "ubuntu:22.04", "nginx", "fedora"] {
            let err = validate_create_image(bad).unwrap_err();
            assert_eq!(
                err.exit_code,
                crate::exit_code::ExitCode::LocalArtifactRequired,
                "bad={bad}"
            );
        }
    }

    #[test]
    fn validate_create_image_rejects_registry_digest_ref() {
        let bad =
            "repo/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let err = validate_create_image(bad).unwrap_err();
        assert_eq!(
            err.exit_code,
            crate::exit_code::ExitCode::LocalArtifactRequired
        );
    }

    #[test]
    fn validate_create_image_rejects_malformed_digest() {
        for bad in [
            "sha256:tooshort",
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            let err = validate_create_image(bad).unwrap_err();
            assert_eq!(
                err.exit_code,
                crate::exit_code::ExitCode::UsageError,
                "bad={bad}"
            );
        }
    }
}
