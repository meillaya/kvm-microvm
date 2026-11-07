//! Clap-based command-line interface for the `microvm` CLI.
//!
//! The CLI talks to the daemon over one REST Unix socket. It has no TCP mode
//! and no remote registry client.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Default REST Unix socket path.
pub const DEFAULT_SOCKET: &str = "/run/microvm/rest.sock";

/// The `microvm` command-line interface.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "microvm",
    version,
    about = "Manage microVMs over a protected Unix socket"
)]
pub struct Cli {
    /// Path to the microvm daemon REST Unix socket.
    #[arg(long, global = true, default_value = DEFAULT_SOCKET, value_name = "PATH")]
    pub socket: PathBuf,

    /// Print JSON where the command supports it.
    #[arg(long, global = true)]
    pub json: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// The `microvm` subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Create a VM record from a resource specification.
    Create {
        /// Number of virtual CPUs.
        #[arg(long, default_value_t = 1)]
        vcpu: u32,
        /// Memory allocation in MiB.
        #[arg(long, default_value_t = 512)]
        memory_mib: u64,
        /// Disk allocation in MiB.
        #[arg(long, default_value_t = 1024)]
        disk_mib: u64,
        /// Network egress policy: none, nat-only, or egress-allowed.
        #[arg(long, default_value = "none", value_name = "POLICY")]
        network_policy: String,
    },

    /// Create and start a VM in one step.
    Run {
        /// Number of virtual CPUs.
        #[arg(long, default_value_t = 1)]
        vcpu: u32,
        /// Memory allocation in MiB.
        #[arg(long, default_value_t = 512)]
        memory_mib: u64,
        /// Disk allocation in MiB.
        #[arg(long, default_value_t = 1024)]
        disk_mib: u64,
        /// Network egress policy: none, nat-only, or egress-allowed.
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

    /// List every VM the caller may see.
    List,

    /// Delete a stopped or failed VM record.
    Delete {
        /// Target VM identifier.
        #[arg(long, value_name = "ID")]
        vm_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_create_with_defaults() {
        let cli = Cli::parse_from(["microvm", "create"]);
        match cli.command {
            Command::Create {
                vcpu,
                memory_mib,
                disk_mib,
                network_policy,
            } => {
                assert_eq!(vcpu, 1);
                assert_eq!(memory_mib, 512);
                assert_eq!(disk_mib, 1024);
                assert_eq!(network_policy, "none");
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn cli_parses_run_and_json() {
        let cli = Cli::parse_from([
            "microvm",
            "--json",
            "--socket",
            "/tmp/x.sock",
            "run",
            "--vcpu",
            "2",
            "--memory-mib",
            "256",
            "--network-policy",
            "nat-only",
        ]);
        assert!(cli.json);
        assert_eq!(cli.socket, PathBuf::from("/tmp/x.sock"));
        assert!(matches!(cli.command, Command::Run { .. }));
    }

    #[test]
    fn cli_parses_delete() {
        let cli = Cli::parse_from(["microvm", "delete", "--vm-id", "vm-1"]);
        assert!(matches!(cli.command, Command::Delete { .. }));
    }

    #[test]
    fn cli_rejects_unknown_flag() {
        assert!(Cli::try_parse_from(["microvm", "status", "--tcp"]).is_err());
    }

    #[test]
    fn cli_help_renders() {
        Cli::command().debug_assert();
    }
}
