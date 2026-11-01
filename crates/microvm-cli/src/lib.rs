//! The `microvm` CLI: client-side lifecycle commands over a protected
//! REST Unix socket.
//!
//! This crate provides the [`Cli`] parser (clap-based), a stable
//! [`ExitCode`] contract, and a Unix-socket REST [`Client`]. It drives
//! the microvm daemon's OpenAPI lifecycle routes (todo 8) exclusively
//! through a filesystem Unix socket, never TCP, and maps every
//! outcome to a documented exit code.
//!
//! # Exit codes
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Success |
//! | 1 | General error |
//! | 2 | Usage error |
//! | 3 | Not found |
//! | 4 | Local artifact required |
//! | 5 | Permission denied |
//!
//! # Forbidden flags
//! The CLI deliberately exposes no `--tcp`, `--rootless`, `--mount`,
//! `--cap-add`, or remote registry convenience flags.
//!
//! # `microvm run`
//! The `run` subcommand is a constrained local import surface (not an
//! OCI runtime); its help text is sourced from [`microvm_oci::help`].

pub mod cli;
pub mod client;
pub mod error;
pub mod exit_code;
pub mod run;

pub use cli::{Cli, Command};
pub use client::Client;
pub use error::CliError;
pub use exit_code::ExitCode;

use clap::Parser;

/// Execute a parsed [`Command`] against the daemon and return the
/// process exit code plus a human-readable output line.
///
/// This is the transport-facing dispatch layer: it builds a [`Client`]
/// from the socket path and maps each subcommand to one or more REST
/// calls. It never panics on a service error; every failure becomes a
/// [`CliError`] with a stable [`ExitCode`].
pub async fn execute(cli: &Cli) -> (ExitCode, String) {
    let client = Client::new(cli.socket.clone());

    let result = match &cli.command {
        Command::Create {
            image,
            vcpu,
            memory_mib,
            disk_mib,
            network_policy,
        } => {
            // Validate the digest reference locally first (exit 4 for
            // remote/tag-only, exit 2 for malformed digest).
            match cli::validate_create_image(image) {
                Err(e) => Err(e),
                Ok(()) => {
                    let policy: client::NetworkPolicyArg = match network_policy.parse() {
                        Ok(p) => p,
                        Err(msg) => return (ExitCode::UsageError, msg),
                    };
                    let req = client::CreateVmRequest {
                        vcpu_count: *vcpu,
                        memory_mib: *memory_mib,
                        disk_mib: *disk_mib,
                        network_policy: policy,
                    };
                    match client.create_vm(&req).await {
                        Ok(resp) => Ok(format!("created vm {}", resp.vm_id)),
                        Err(e) => Err(e),
                    }
                }
            }
        }
        Command::Start { vm_id } => match client.start_vm(vm_id).await {
            Ok(()) => Ok(format!("started vm {vm_id}")),
            Err(e) => Err(e),
        },
        Command::Stop { vm_id } => match client.stop_vm(vm_id).await {
            Ok(()) => Ok(format!("stopped vm {vm_id}")),
            Err(e) => Err(e),
        },
        Command::Snapshot { vm_id } => match client.snapshot_vm(vm_id).await {
            Ok(resp) => Ok(format!("created snapshot {}", resp.snapshot_id)),
            Err(e) => Err(e),
        },
        Command::Restore { snapshot_id } => match client.restore_vm(snapshot_id).await {
            Ok(resp) => Ok(format!("restored vm {}", resp.vm_id)),
            Err(e) => Err(e),
        },
        Command::Status { vm_id } => match client.get_status(vm_id).await {
            Ok(resp) => Ok(format!(
                "vm {} state={} vcpu={} memory_mib={} disk_mib={} created_at={}",
                resp.vm_id,
                resp.state,
                resp.resource_spec.vcpu_count,
                resp.resource_spec.memory_mib,
                resp.resource_spec.disk_mib,
                resp.created_at
            )),
            Err(e) => Err(e),
        },
        Command::Metrics { vm_id } => match client.get_metrics(vm_id).await {
            Ok(value) => {
                Ok(serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()))
            }
            Err(e) => Err(e),
        },
        Command::Run { image } => match run::execute_run(&client, image).await {
            Ok(outcome) => Ok(format!("running vm {}", outcome.vm_id)),
            Err(e) => Err(e),
        },
    };

    match result {
        Ok(output) => (ExitCode::Success, output),
        Err(e) => (e.exit_code, e.to_string()),
    }
}

/// Parse arguments and run the CLI, returning the process exit code.
///
/// This is the top-level entry point used by `main`. Clap parse failures
/// (usage errors) are rendered by clap and map to exit code 2.
pub async fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // clap renders the error/usage to stderr; usage errors are 2.
            let code = err.exit_code();
            let _ = err.print();
            return if code == 2 {
                ExitCode::UsageError
            } else {
                ExitCode::GeneralError
            };
        }
    };

    let (exit_code, output) = execute(&cli).await;
    if exit_code == ExitCode::Success {
        println!("{output}");
    } else {
        eprintln!("error: {output}");
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lib_reexports_key_types() {
        // Compile-time check that the documented key types are exported.
        fn _assert_types() {
            let _: fn() -> ExitCode = || ExitCode::Success;
            // Cli and Client and CliError are referenced by path elsewhere.
        }
    }
}
