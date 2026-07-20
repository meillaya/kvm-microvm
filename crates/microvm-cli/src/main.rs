//! `microvm` CLI entry point.
//!
//! Parses arguments, dispatches to the lifecycle client over the REST
//! Unix socket, and exits with a stable [`microvm_cli::ExitCode`].

use microvm_cli::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let exit_code: ExitCode = microvm_cli::run().await;
    exit_code.to_process_exit_code()
}
