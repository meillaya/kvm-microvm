//! `microvmd` command-line entry point.

use clap::Parser;
use microvm_daemon::config::DaemonConfig;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "microvmd",
    version,
    about = "Firecracker control-plane daemon over Unix sockets"
)]
struct Cli {
    /// Path to the TOML configuration.
    #[arg(long, default_value = "/etc/microvmd.toml")]
    config: PathBuf,

    /// Validate the configuration and host prerequisites, then exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = match DaemonConfig::load(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("microvmd: config error: {e}");
            return ExitCode::from(2);
        }
    };

    if cli.check {
        return match microvm_daemon::check(&config) {
            Ok(notes) => {
                for note in notes {
                    println!("{note}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("microvmd: check failed: {e}");
                ExitCode::from(1)
            }
        };
    }

    eprintln!(
        "microvmd: backend {:?}, REST {}, gRPC {}",
        config.backend,
        config.server.rest_socket.display(),
        config.server.grpc_socket.display()
    );
    match microvm_daemon::serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("microvmd: {e}");
            ExitCode::from(1)
        }
    }
}
