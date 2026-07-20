//! The `microvm-demo` binary: warm HTTP-function microVM demo with cold/warm
//! evidence (plan todo 28).
//!
//! The binary runs the demo against the in-process
//! [`microvm_demo::LocalFunctionRestorer`], which models the snapshot/restore
//! warm-function protocol locally with real monotonic timing, so it produces a
//! concrete cold/warm report on any host (no `/dev/kvm`, no Firecracker, no
//! network). Host substrate metadata is gathered for real via the benchmark
//! harness's [`HostProbe`].
//!
//! # Exit codes (stable contract)
//! | Code | Meaning |
//! |------|---------|
//! | 0  | the demo ran and produced measurements |
//! | 1  | an I/O error occurred |
//! | 2  | usage error (bad flags/arguments) |
//! | 77 | the demo was blocked (a prerequisite was unavailable) |
//!
//! A blocked demo is a *skip* (77), never a failure (1) and never a performance
//! pass (0): the demo emits no pass/fail verdict.

use clap::{Parser, Subcommand};
use microvm_artifacts::{compute_sha256, Digest};
use microvm_bench::host::HostProbe;
use microvm_bench::{HostMetadata, PageCachePolicy};
use microvm_demo::{
    DemoConfig, DemoReport, DemoRunner, HttpFunction, LocalFunctionRestorer, Rootfs,
};
use std::path::PathBuf;
use std::process::ExitCode;

/// The canonical pinned function/rootfs bytes the demo packages by default.
///
/// The rootfs is content-addressed by the SHA-256 of these exact bytes, so the
/// demo always serves the same pinned local function image.
const DEFAULT_FUNCTION_BYTES: &[u8] =
    b"microvm-demo/warm-http-function/v1: static rust http function rootfs";

/// The demo's reference warm-request target (metadata only, never a gate).
const WARM_TARGET_REFERENCE_MS: f64 = 200.0;

#[derive(Parser, Debug)]
#[command(
    name = "microvm-demo",
    version,
    about = "Warm HTTP-function microVM demo with cold first-call vs warm pool/request evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the warm HTTP-function demo and write a demo evidence report.
    Run(RunArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Warm request sample budget (the `N` in `N >= 100`).
    #[arg(long, default_value_t = 100)]
    samples: usize,

    /// Warm pool size (number of VMs pre-restored during warmup).
    #[arg(long, default_value_t = 8)]
    pool_size: usize,

    /// Function name.
    #[arg(long, default_value = "hello-http")]
    function: String,

    /// Rootfs content hash (64 hex chars). Defaults to the pinned built-in
    /// function image hash.
    #[arg(long)]
    rootfs: Option<String>,

    /// Output path for the demo evidence JSON.
    #[arg(
        long,
        default_value = ".omo/evidence/kvm-microvm-orchestrator/task-28-warm.json"
    )]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => match run(args).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("microvm-demo: error: {e}");
                ExitCode::from(1)
            }
        },
    }
}

async fn run(args: RunArgs) -> Result<ExitCode, String> {
    let rootfs_sha = match &args.rootfs {
        Some(hex) => Digest::from_hex(hex).map_err(|e| format!("--rootfs: {e}"))?,
        None => compute_sha256(DEFAULT_FUNCTION_BYTES).map_err(|e| format!("rootfs hash: {e}"))?,
    };
    let rootfs = Rootfs::new(format!("{}-rootfs", args.function), rootfs_sha)
        .map_err(|e| format!("rootfs: {e}"))?;
    let function =
        HttpFunction::new(args.function.clone(), rootfs).map_err(|e| format!("function: {e}"))?;

    let config = DemoConfig::new(function, args.samples, args.pool_size)
        .map_err(|e| format!("config: {e}"))?;
    if !config.meets_minimum_samples() {
        eprintln!(
            "microvm-demo: note: samples={} is below the N>={} reference floor",
            args.samples,
            DemoConfig::MIN_SAMPLES
        );
    }

    // Capture host substrate metadata for real (never lie about KVM/cgroup/nested).
    let probe = HostProbe::default();
    let host: HostMetadata = probe.gather(PageCachePolicy::Mixed);

    let mut restorer = LocalFunctionRestorer::new("local-in-process");
    let runner = DemoRunner::new(config);
    let report: DemoReport = runner.run(host, &mut restorer).await;

    write_report(&args.out, &report)?;
    summarise(&report);

    if report.is_blocked() {
        Ok(ExitCode::from(77))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn write_report(out: &std::path::Path, report: &DemoReport) -> Result<(), String> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create output dir {}: {e}", parent.display()))?;
        }
    }
    let json = report
        .to_json_pretty()
        .map_err(|e| format!("cannot serialize demo report: {e}"))?;
    std::fs::write(out, json + "\n").map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    eprintln!("microvm-demo: wrote {}", out.display());
    Ok(())
}

/// Print a short, verdict-free summary of the demo to stderr.
fn summarise(report: &DemoReport) {
    if let Some(reason) = &report.blocked_reason {
        eprintln!(
            "  warm_http_demo [BLOCKED: {}] {}",
            reason,
            report.blocked_detail.as_deref().unwrap_or("")
        );
        return;
    }
    eprintln!(
        "  warm_http_demo cold_first_call={}ms warm(p50/p95/p99 n={}): {}/{}/{}ms warmup={} restore_trials={} restore_failures={} (target {}ms is metadata only)",
        fmt_opt(report.cold_first_call_ms),
        report.warm.samples,
        fmt_opt(report.warm_p50_ms),
        fmt_opt(report.warm_p95_ms),
        fmt_opt(report.warm_p99_ms),
        report.warmup_count,
        report.restore_trials,
        report.restore_failures,
        WARM_TARGET_REFERENCE_MS,
    );
}

fn fmt_opt(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.3}"),
        None => "null".to_string(),
    }
}
