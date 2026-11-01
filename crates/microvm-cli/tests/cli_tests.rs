//! Deterministic CLI tests: command parsing, exit codes, forbidden flags,
//! and `run` help text.
//!
//! These tests are pure (no socket, no network, no `/dev/kvm`) and verify
//! the stable CLI contract named in plan todo 26:
//! - every subcommand parses,
//! - the forbidden flags (`--tcp`, `--rootless`, `--mount`, `--cap-add`,
//!   and remote registry convenience flags) do not exist,
//! - `microvm run --help` describes a constrained local import and
//!   disclaims OCI runtime compatibility,
//! - exit codes are stable.

use clap::{CommandFactory, Parser};
use microvm_cli::{Cli, Command, ExitCode};

/// Render the full `--help` output for the top-level CLI.
fn top_level_help() -> String {
    let mut cmd = Cli::command();
    cmd.render_help().to_string()
}

/// Render the `--help` output for a given subcommand.
fn subcommand_help(name: &str) -> String {
    let mut cmd = Cli::command();
    // Find the subcommand and render its help.
    let sub = cmd
        .find_subcommand_mut(name)
        .unwrap_or_else(|| panic!("subcommand {name} must exist"));
    sub.render_long_help().to_string()
}

// ---------------------------------------------------------------------------
// Subcommand presence
// ---------------------------------------------------------------------------

#[test]
fn all_required_subcommands_exist() {
    let cmd = Cli::command();
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for required in [
        "create", "start", "stop", "snapshot", "restore", "status", "metrics", "run",
    ] {
        assert!(
            names.iter().any(|n| n == required),
            "missing subcommand {required}; have {names:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Forbidden flags must not exist
// ---------------------------------------------------------------------------

/// The set of flags the plan forbids the CLI from exposing.
const FORBIDDEN_FLAGS: &[&str] = &[
    "--tcp",
    "--rootless",
    "--mount",
    "--cap-add",
    "--cap-add",
    "--registry",
    "--pull",
    "--host",
];

#[test]
fn no_forbidden_flags_in_top_level_help() {
    let help = top_level_help().to_ascii_lowercase();
    for flag in FORBIDDEN_FLAGS {
        assert!(
            !help.contains(flag),
            "forbidden flag {flag} must not appear in top-level help:\n{help}"
        );
    }
}

#[test]
fn no_forbidden_flags_in_any_subcommand_help() {
    let cmd = Cli::command();
    let sub_names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in sub_names {
        let help = subcommand_help(&name).to_ascii_lowercase();
        for flag in FORBIDDEN_FLAGS {
            assert!(
                !help.contains(flag),
                "forbidden flag {flag} must not appear in `{name} --help`:\n{help}"
            );
        }
    }
}

#[test]
fn forbidden_flags_are_rejected_at_parse_time() {
    // Each forbidden flag, if supplied, must cause a parse error (exit 2),
    // proving the flag is not silently accepted.
    for flag in ["--tcp", "--rootless", "--mount", "--cap-add", "--registry"] {
        let result =
            Cli::try_parse_from(["microvm", "create", flag, "x", "--image", "sha256:aaaa"]);
        assert!(
            result.is_err(),
            "forbidden flag {flag} must be rejected, but parse succeeded"
        );
    }
}

#[test]
fn create_has_no_mount_or_cap_add_flag() {
    // Attempting to use --mount or --cap-add on create must fail.
    assert!(Cli::try_parse_from([
        "microvm",
        "create",
        "--image",
        "sha256:aa",
        "--mount",
        "/host:/guest"
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "microvm",
        "create",
        "--image",
        "sha256:aa",
        "--cap-add",
        "NET_ADMIN"
    ])
    .is_err());
}

// ---------------------------------------------------------------------------
// `run` help text: constrained import, not OCI runtime
// ---------------------------------------------------------------------------

#[test]
fn run_help_describes_constrained_import() {
    let help = subcommand_help("run").to_ascii_lowercase();
    assert!(
        help.contains("constrained local import"),
        "run help must say constrained local import:\n{help}"
    );
    assert!(
        help.contains("digest"),
        "run help must mention digest verification"
    );
    assert!(help.contains("local"), "run help must emphasize local");
}

#[test]
fn run_help_disclaims_oci_runtime_compatibility() {
    let help = subcommand_help("run").to_ascii_lowercase();
    assert!(
        help.contains("not an oci runtime"),
        "run help must disclaim OCI runtime:\n{help}"
    );
    // Must never positively claim OCI runtime compatibility.
    assert!(!help.contains("oci runtime compatible"));
    assert!(!help.contains("oci runtime compliant"));
    assert!(!help.contains("is an oci runtime"));
}

#[test]
fn run_help_documents_rejected_inputs() {
    let help = subcommand_help("run").to_ascii_lowercase();
    for token in ["https://", "docker://", "nginx:latest", "privileged"] {
        assert!(
            help.contains(token),
            "run help should mention {token}:\n{help}"
        );
    }
}

#[test]
fn run_help_matches_oci_help_source_of_truth() {
    // The run subcommand long_about must be sourced from microvm_oci.
    let help = subcommand_help("run");
    assert!(
        help.contains(microvm_oci::RUN_SHORT_ABOUT),
        "run help must include the canonical microvm-oci short about"
    );
}

// ---------------------------------------------------------------------------
// Exit code stability
// ---------------------------------------------------------------------------

#[test]
fn exit_codes_are_stable_and_documented() {
    assert_eq!(ExitCode::Success.code(), 0);
    assert_eq!(ExitCode::GeneralError.code(), 1);
    assert_eq!(ExitCode::UsageError.code(), 2);
    assert_eq!(ExitCode::NotFound.code(), 3);
    assert_eq!(ExitCode::LocalArtifactRequired.code(), 4);
    assert_eq!(ExitCode::PermissionDenied.code(), 5);
}

// ---------------------------------------------------------------------------
// Command parsing details
// ---------------------------------------------------------------------------

#[test]
fn create_requires_image() {
    let result = Cli::try_parse_from(["microvm", "create"]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().exit_code(), 2);
}

#[test]
fn start_requires_vm_id() {
    let result = Cli::try_parse_from(["microvm", "start"]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().exit_code(), 2);
}

#[test]
fn restore_requires_snapshot_id() {
    let result = Cli::try_parse_from(["microvm", "restore"]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().exit_code(), 2);
}

#[test]
fn run_requires_image() {
    let result = Cli::try_parse_from(["microvm", "run"]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().exit_code(), 2);
}

#[test]
fn unknown_subcommand_is_usage_error() {
    let result = Cli::try_parse_from(["microvm", "frobnicate"]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().exit_code(), 2);
}

#[test]
fn create_image_flag_accepts_digest() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let cli = Cli::parse_from(["microvm", "create", "--image", &digest]);
    match cli.command {
        Command::Create { image, .. } => assert_eq!(image, digest),
        _ => panic!("expected Create"),
    }
}

#[test]
fn socket_flag_overrides_default() {
    let cli = Cli::parse_from([
        "microvm",
        "status",
        "--vm-id",
        "vm-001",
        "--socket",
        "runtime/api/rest.sock",
    ]);
    assert_eq!(cli.socket.to_string_lossy(), "runtime/api/rest.sock");
}
