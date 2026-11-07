//! The `microvm` CLI: client-side lifecycle commands over a protected
//! REST Unix socket.
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

pub mod cli;
pub mod client;
pub mod error;
pub mod exit_code;

pub use cli::{Cli, Command};
pub use client::Client;
pub use error::CliError;
pub use exit_code::ExitCode;

use clap::Parser;
use client::CreateVmRequest;
use microvm_types::NetworkPolicy;

/// Execute a parsed [`Command`] and return the process exit code plus text.
pub async fn execute(cli: &Cli) -> (ExitCode, String) {
    let client = Client::new(cli.socket.clone());

    let result = match &cli.command {
        Command::Create {
            vcpu,
            memory_mib,
            disk_mib,
            network_policy,
        } => {
            let policy = match parse_policy(network_policy) {
                Ok(p) => p,
                Err(e) => return (ExitCode::UsageError, e),
            };
            let req = CreateVmRequest {
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
        Command::Run {
            vcpu,
            memory_mib,
            disk_mib,
            network_policy,
        } => {
            let policy = match parse_policy(network_policy) {
                Ok(p) => p,
                Err(e) => return (ExitCode::UsageError, e),
            };
            let req = CreateVmRequest {
                vcpu_count: *vcpu,
                memory_mib: *memory_mib,
                disk_mib: *disk_mib,
                network_policy: policy,
            };
            match client.create_vm(&req).await {
                Ok(created) => match client.start_vm(&created.vm_id).await {
                    Ok(()) => Ok(format!("running vm {}", created.vm_id)),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
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
            Ok(resp) => {
                if cli.json {
                    match serde_json::to_string_pretty(&resp) {
                        Ok(text) => Ok(text),
                        Err(e) => Err(CliError::usage(e.to_string())),
                    }
                } else {
                    Ok(format!(
                        "vm {} state={} vcpu={} memory_mib={} disk_mib={} network={} created_at={}",
                        resp.vm_id,
                        resp.state,
                        resp.resource_spec.vcpu_count,
                        resp.resource_spec.memory_mib,
                        resp.resource_spec.disk_mib,
                        resp.resource_spec.network_policy,
                        resp.created_at
                    ))
                }
            }
            Err(e) => Err(e),
        },
        Command::Metrics { vm_id } => match client.get_metrics(vm_id).await {
            Ok(value) => {
                Ok(serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()))
            }
            Err(e) => Err(e),
        },
        Command::List => match client.list_vms().await {
            Ok(resp) => {
                if cli.json {
                    match serde_json::to_string_pretty(&resp) {
                        Ok(text) => Ok(text),
                        Err(e) => Err(CliError::usage(e.to_string())),
                    }
                } else {
                    let mut out = String::new();
                    for vm in resp.vms {
                        out.push_str(&format!(
                            "{} {} vcpu={} memory_mib={} disk_mib={} network={} created_at={}\n",
                            vm.vm_id,
                            vm.state,
                            vm.resource_spec.vcpu_count,
                            vm.resource_spec.memory_mib,
                            vm.resource_spec.disk_mib,
                            vm.resource_spec.network_policy,
                            vm.created_at
                        ));
                    }
                    Ok(out.trim_end().to_string())
                }
            }
            Err(e) => Err(e),
        },
        Command::Delete { vm_id } => match client.delete_vm(vm_id).await {
            Ok(()) => Ok(format!("deleted vm {vm_id}")),
            Err(e) => Err(e),
        },
    };

    match result {
        Ok(output) => (ExitCode::Success, output),
        Err(e) => (e.exit_code, e.to_string()),
    }
}

fn parse_policy(value: &str) -> Result<NetworkPolicy, String> {
    value.parse::<NetworkPolicy>()
}

/// Parse arguments and run the CLI, returning the process exit code.
pub async fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
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
    fn parse_policy_accepts_known_values() {
        assert_eq!(parse_policy("none").unwrap(), NetworkPolicy::None);
        assert_eq!(parse_policy("nat-only").unwrap(), NetworkPolicy::NatOnly);
        assert_eq!(
            parse_policy("egress-allowed").unwrap(),
            NetworkPolicy::EgressAllowed
        );
        assert!(parse_policy("bridge").is_err());
    }
}
