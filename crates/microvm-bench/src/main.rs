//! The `microvm-bench` binary: reproducible snapshot/boot benchmark harness and
//! Docker comparison (plan todo 27).
//!
//! # Commands
//! - `snapshot-restore` — measure Firecracker snapshot/restore and Docker start
//!   for the **same pinned payload**, under cold and warm page-cache conditions,
//!   writing a schema-conformant benchmark JSON.
//! - `warm-http` — reserved for plan todo 28 (warm HTTP-function microVM demo).
//!
//! # Exit codes (stable contract)
//! | Code | Meaning |
//! |------|---------|
//! | 0 | every requested lane ran and produced samples |
//! | 1 | a lane attempted and failed, or an I/O error occurred |
//! | 2 | usage error (bad flags/arguments) |
//! | 77 | a privileged lane was blocked (missing KVM/Docker/firecracker/…) |
//!
//! A blocked lane is a *skip* (77), never a failure (1) and never a pass (0):
//! the harness emits no pass/fail verdict (requirement 10).

use clap::{Parser, Subcommand};
use microvm_artifacts::{compute_sha256, Digest};
use microvm_bench::config::{
    BenchmarkConfig, Conditions, PageCachePolicy, RuntimeVersions, Workload, MIN_SAMPLES,
};
use microvm_bench::host::{probe_docker_version, probe_firecracker_version, HostProbe};
use microvm_bench::marker::BenchMarker;
use microvm_bench::result::{BenchmarkResult, HostMetadata};
use microvm_bench::runner::docker::DockerStartLane;
use microvm_bench::runner::firecracker::FirecrackerSnapshotLane;
use microvm_bench::{BenchExitCode, LaneRunner};
use std::path::PathBuf;

/// The canonical pinned payload bytes the benchmark measures by default.
///
/// Both the Firecracker and Docker lanes reference the SHA-256 of these exact
/// bytes, so the default run compares identical content across runtimes
/// (requirements 1, 7, 9). Operators measuring real artifacts pass
/// `--payload-hash` (and the per-artifact hashes) instead.
pub const DEFAULT_PAYLOAD: &[u8] =
    b"kvm-microvm-orchestrator benchmark payload v1: snapshot-restore\n";

/// SHA-256 of [`DEFAULT_PAYLOAD`]: the default pinned payload hash.
fn default_payload_hash() -> Digest {
    compute_sha256(DEFAULT_PAYLOAD).expect("in-memory payload hashes without error")
}

#[derive(Parser)]
#[command(
    name = "microvm-bench",
    about = "Reproducible snapshot/boot benchmark harness and Docker comparison",
    long_about = "Publishes p50/p95/p99 distributions (never a pass/fail gate) for Firecracker \
snapshot/restore versus Docker start, using the same pinned payload hash for both \
lanes, under cold/warm page-cache conditions, with full host metadata. An \
unavailable Docker/KVM/firecracker lane is blocked with evidence (exit 77)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Benchmark Firecracker snapshot/restore against Docker start.
    SnapshotRestore(Box<SnapshotRestoreArgs>),
    /// Warm HTTP-function microVM demo (implemented in plan todo 28).
    WarmHttp(WarmHttpArgs),
}

#[derive(Parser)]
struct SnapshotRestoreArgs {
    /// Measurements per condition (the plan requires N >= 100 for real runs).
    #[arg(long, default_value_t = 100)]
    samples: usize,

    /// Output path for the benchmark JSON artifact.
    #[arg(long)]
    out: PathBuf,

    /// Pinned payload SHA-256 (64 hex). Defaults to the canonical benchmark
    /// payload; both lanes always use this one hash.
    #[arg(long)]
    payload_hash: Option<String>,

    /// Guest kernel SHA-256 (64 hex), to pin the VM-side artifact.
    #[arg(long)]
    kernel: Option<String>,

    /// Rootfs SHA-256 (64 hex), to pin the VM-side artifact.
    #[arg(long)]
    rootfs: Option<String>,

    /// Docker image SHA-256 (64 hex), derived from the same payload.
    #[arg(long)]
    image: Option<String>,

    /// Docker image reference to run (built from the pinned payload).
    #[arg(long)]
    docker_image: Option<String>,

    /// Prepared microVM state file to restore.
    #[arg(long)]
    snapshot: Option<PathBuf>,

    /// Prepared guest memory file (the snapshot `mem_backend` source).
    #[arg(long)]
    memfile: Option<PathBuf>,

    /// Directory for per-sample Firecracker API sockets.
    #[arg(long)]
    socket_dir: Option<PathBuf>,

    /// Firecracker binary path/name.
    #[arg(long, default_value = "firecracker")]
    firecracker_bin: String,

    /// Reference restore-latency target in ms (metadata only, never a gate).
    #[arg(long)]
    target_ms: Option<f64>,
}

#[derive(Parser)]
struct WarmHttpArgs {
    /// Measurements per condition.
    #[arg(long, default_value_t = 100)]
    samples: usize,

    /// Output path for the warm-demo JSON artifact.
    #[arg(long)]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let exit = match cli.command {
        Commands::SnapshotRestore(args) => run_snapshot_restore(*args).await,
        Commands::WarmHttp(args) => run_warm_http(args),
    };
    match exit {
        Ok(code) => code.to_process_exit_code(),
        Err((code, message)) => {
            eprintln!("microvm-bench: error: {message}");
            code.to_process_exit_code()
        }
    }
}

/// A run error carrying the precise exit code it maps to.
///
/// Argument-validation failures map to [`BenchExitCode::UsageError`] (2);
/// runtime/I-O failures map to [`BenchExitCode::GeneralError`] (1).
type RunError = (BenchExitCode, String);

fn usage(message: impl Into<String>) -> RunError {
    (BenchExitCode::UsageError, message.into())
}

fn general(message: impl Into<String>) -> RunError {
    (BenchExitCode::GeneralError, message.into())
}

/// Run the snapshot/restore + Docker comparison benchmark.
async fn run_snapshot_restore(args: SnapshotRestoreArgs) -> Result<BenchExitCode, RunError> {
    if args.samples == 0 {
        return Err(usage("--samples must be at least 1"));
    }
    if args.samples < MIN_SAMPLES {
        eprintln!(
            "microvm-bench: warning: --samples {} is below the recommended minimum of {} \
             for an unblocked run",
            args.samples, MIN_SAMPLES
        );
    }

    // Pin the workload: one payload hash shared by both lanes.
    let payload = match &args.payload_hash {
        Some(hex) => Digest::from_hex(hex).map_err(|e| usage(format!("--payload-hash: {e}")))?,
        None => default_payload_hash(),
    };
    let mut workload =
        Workload::new("snapshot-restore", payload).map_err(|e| usage(format!("workload: {e}")))?;
    if let Some(hex) = &args.kernel {
        workload = workload
            .with_kernel(Digest::from_hex(hex).map_err(|e| usage(format!("--kernel: {e}")))?);
    }
    if let Some(hex) = &args.rootfs {
        workload = workload
            .with_rootfs(Digest::from_hex(hex).map_err(|e| usage(format!("--rootfs: {e}")))?);
    }
    if let Some(hex) = &args.image {
        workload =
            workload.with_image(Digest::from_hex(hex).map_err(|e| usage(format!("--image: {e}")))?);
    }

    let config = BenchmarkConfig::new(workload.clone(), args.samples, Conditions::default())
        .map_err(|e| usage(format!("config: {e}")))?;

    // Capture host substrate + runtime versions (never lie about KVM/cgroup/nested).
    let probe = HostProbe::default();
    let host: HostMetadata = probe.gather(PageCachePolicy::Mixed);
    let versions = RuntimeVersions {
        firecracker: probe_firecracker_version(),
        docker: probe_docker_version(),
    };

    // Build the two lanes pinned to the same payload.
    let socket_dir = args
        .socket_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("microvm-bench"));
    let snapshot_path = args
        .snapshot
        .clone()
        .unwrap_or_else(|| socket_dir.join("vmstate"));
    let memfile_path = args
        .memfile
        .clone()
        .unwrap_or_else(|| socket_dir.join("memfile"));

    let mut fc_lane =
        FirecrackerSnapshotLane::new(snapshot_path, memfile_path, socket_dir, probe.clone())
            .with_firecracker_bin(args.firecracker_bin.clone());
    if let Some(target) = args.target_ms {
        fc_lane = fc_lane.with_target_ms(target);
    }

    let docker_image = args.docker_image.clone().unwrap_or_else(|| {
        // Derive a deterministic, payload-pinned image reference.
        format!("microvm-bench/payload:{}", &payload.to_hex()[..12])
    });
    let docker_lane = DockerStartLane::new(docker_image, probe.proc_root.clone());

    let lanes: Vec<Box<dyn LaneRunner>> = vec![Box::new(fc_lane), Box::new(docker_lane)];

    let marker = BenchMarker::new(config);
    let result: BenchmarkResult = marker.run(host, versions, lanes).await;

    write_result(&args.out, &result)?;

    // Summarise to stderr for operators.
    summarise(&result);

    if result.has_blocked_lane() {
        Ok(BenchExitCode::Blocked)
    } else {
        Ok(BenchExitCode::Success)
    }
}

/// `warm-http` is owned by plan todo 28; this build reserves the command.
fn run_warm_http(args: WarmHttpArgs) -> Result<BenchExitCode, RunError> {
    let _ = args;
    eprintln!(
        "microvm-bench: `warm-http` is implemented in plan todo 28 (warm HTTP-function microVM \
         demo); this build provides `snapshot-restore`"
    );
    Ok(BenchExitCode::UsageError)
}

/// Write the benchmark JSON artifact, creating parent directories.
fn write_result(out: &std::path::Path, result: &BenchmarkResult) -> Result<(), RunError> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                general(format!(
                    "cannot create output dir {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    let json = result
        .to_json_pretty()
        .map_err(|e| general(format!("cannot serialize benchmark result: {e}")))?;
    std::fs::write(out, json + "\n")
        .map_err(|e| general(format!("cannot write {}: {e}", out.display())))?;
    eprintln!("microvm-bench: wrote {}", out.display());
    Ok(())
}

/// Print a short, verdict-free summary of each benchmark item to stderr.
fn summarise(result: &BenchmarkResult) {
    for item in &result.benchmarks {
        match &item.blocked_reason {
            Some(reason) => {
                eprintln!(
                    "  {} [BLOCKED: {}] target={}{} (metadata only)",
                    item.name,
                    reason,
                    item.target_ms,
                    item.unit.as_str()
                );
            }
            None => {
                eprintln!(
                    "  {} cold(p50/p95/p99 n={}): {}/{}/{}  warm(p50/p95/p99 n={}): {}/{}/{}  target={}{} (metadata only)",
                    item.name,
                    item.cold.samples,
                    fmt_opt(item.cold.p50),
                    fmt_opt(item.cold.p95),
                    fmt_opt(item.cold.p99),
                    item.warm.samples,
                    fmt_opt(item.warm.p50),
                    fmt_opt(item.warm.p95),
                    fmt_opt(item.warm.p99),
                    item.target_ms,
                    item.unit.as_str(),
                );
            }
        }
    }
}

fn fmt_opt(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.2}"),
        None => "null".to_string(),
    }
}
