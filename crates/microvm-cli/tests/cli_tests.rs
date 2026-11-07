//! Pure CLI contract tests: subcommands, flags, and exit codes.

use clap::{CommandFactory, Parser};
use microvm_cli::{Cli, Command, ExitCode};

fn help(name: Option<&str>) -> String {
    let mut cmd = Cli::command();
    match name {
        None => cmd.render_help().to_string(),
        Some(name) => cmd
            .find_subcommand_mut(name)
            .unwrap_or_else(|| panic!("missing subcommand {name}"))
            .render_long_help()
            .to_string(),
    }
}

#[test]
fn required_subcommands_exist() {
    let names: Vec<String> = Cli::command()
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for required in [
        "create", "start", "stop", "snapshot", "restore", "status", "metrics", "list", "delete",
        "run",
    ] {
        assert!(names.iter().any(|n| n == required), "missing {required}");
    }
}

#[test]
fn create_parses_resource_flags() {
    let cli = Cli::parse_from([
        "microvm",
        "create",
        "--vcpu",
        "2",
        "--memory-mib",
        "256",
        "--disk-mib",
        "128",
        "--network-policy",
        "nat-only",
    ]);
    match cli.command {
        Command::Create {
            vcpu,
            memory_mib,
            disk_mib,
            network_policy,
        } => {
            assert_eq!(vcpu, 2);
            assert_eq!(memory_mib, 256);
            assert_eq!(disk_mib, 128);
            assert_eq!(network_policy, "nat-only");
        }
        _ => panic!("expected create"),
    }
}

#[test]
fn list_and_delete_parse() {
    assert!(matches!(
        Cli::parse_from(["microvm", "list"]).command,
        Command::List
    ));
    assert!(matches!(
        Cli::parse_from(["microvm", "delete", "--vm-id", "vm-1"]).command,
        Command::Delete { .. }
    ));
}

#[test]
fn run_parses_json_and_socket() {
    let cli = Cli::parse_from([
        "microvm",
        "--json",
        "--socket",
        "/tmp/rest.sock",
        "run",
        "--vcpu",
        "1",
    ]);
    assert!(cli.json);
    assert_eq!(cli.socket, std::path::PathBuf::from("/tmp/rest.sock"));
    assert!(matches!(cli.command, Command::Run { .. }));
}

#[test]
fn forbidden_flags_are_rejected() {
    for flag in ["--tcp", "--rootless", "--mount", "--cap-add", "--registry"] {
        assert!(
            Cli::try_parse_from(["microvm", "create", flag, "x"]).is_err(),
            "{flag} must be rejected"
        );
    }
}

#[test]
fn no_forbidden_flags_in_help() {
    let text = format!("{} {}", help(None), help(Some("create"))).to_ascii_lowercase();
    for flag in ["--tcp", "--rootless", "--mount", "--cap-add", "--registry"] {
        assert!(!text.contains(flag), "{flag} leaked into help");
    }
}

#[test]
fn exit_codes_are_stable() {
    assert_eq!(ExitCode::Success.code(), 0);
    assert_eq!(ExitCode::GeneralError.code(), 1);
    assert_eq!(ExitCode::UsageError.code(), 2);
    assert_eq!(ExitCode::NotFound.code(), 3);
    assert_eq!(ExitCode::LocalArtifactRequired.code(), 4);
    assert_eq!(ExitCode::PermissionDenied.code(), 5);
}
