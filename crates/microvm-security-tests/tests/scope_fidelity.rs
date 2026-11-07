//! Scope-fidelity suite: structural absence of TCP/rootless/VFIO/live-migration.
//!
//! The platform is a constrained, local, Unix-socket-only microVM orchestrator.
//! This suite proves: behaviorally first, with a comment-aware source scan as
//! a secondary layer, that the forbidden scope knobs do not exist in the
//! product surface:
//!
//! 1. CLI flags (behavioral): the real clap parser rejects `--tcp`,
//!    `--rootless`, `--vfio`, `--live-migration`, `--mount`, and `--cap-add`
//!    as unknown arguments on every subcommand, while accepting the legitimate
//!    flags. A flag that does not parse cannot be exercised.
//! 2. Config surface (behavioral): the serialized [`BootConfig`],
//!    [`MicroVmSpec`], [`ResourceSpec`], and [`NetworkBootConfig`] carry no
//!    `tcp`/`rootless`/`vfio`/`migration`/`port`/`listen`/`bind` keys, and
//!    [`NetworkPolicy`] is exhaustively `{None, NatOnly, EgressAllowed}`.
//! 3. Source scan (secondary, comment-aware): no TCP-listener type appears
//!    in the control-plane crates, and no `rootless`/`vfio`/`live-migration`
//!    identifier appears in any product crate's code (doc comments documenting
//!    their absence are stripped before scanning).
//!
//! The scan is explicitly not the sole proof; it corroborates the
//! behavioral evidence. The Firecracker backend's outbound guest-health TCP
//! *client* ([`microvm_firecracker::TcpHealthProbe`]) is a scoped readiness
//! probe into the guest, not a control-API listener, and is excluded from the
//! listener scan with that rationale documented below.

mod common;

use clap::Parser;
use microvm_cli::{Cli, Command};
use microvm_types::{NetworkPolicy, ResourceSpec};
use serde_json::Value;
use std::path::PathBuf;

// -- 1. CLI flags: forbidden flags do not parse -----------------------------

/// The forbidden scope flags that must not exist on any subcommand.
const FORBIDDEN_FLAGS: &[&str] = &[
    "--tcp",
    "--rootless",
    "--vfio",
    "--live-migration",
    "--live_migration",
    "--mount",
    "--cap-add",
    "--cap_add",
    "--privileged",
    "--host-network",
    "--pid",
    "--ipc",
];

#[test]
fn cli_rejects_every_forbidden_flag_on_create() {
    for flag in FORBIDDEN_FLAGS {
        let res = Cli::try_parse_from(["microvm", "create", "--image", "sha256:ab", flag]);
        assert!(res.is_err(), "create must reject forbidden flag {flag}");
    }
}

#[test]
fn cli_rejects_forbidden_flags_on_run() {
    for flag in FORBIDDEN_FLAGS {
        let res = Cli::try_parse_from(["microvm", "run", flag]);
        assert!(res.is_err(), "run must reject forbidden flag {flag}");
    }
}

#[test]
fn cli_rejects_forbidden_global_flags() {
    for flag in FORBIDDEN_FLAGS {
        let res = Cli::try_parse_from(["microvm", flag, "status", "--vm-id", "vm-1"]);
        assert!(res.is_err(), "global position must reject {flag}");
    }
}

#[test]
fn cli_accepts_legitimate_flags_control() {
    // The legitimate surface parses cleanly (so the rejections above are
    // discriminating, not a blanket parse failure).
    let cli = Cli::try_parse_from([
        "microvm",
        "create",
        "--vcpu",
        "2",
        "--memory-mib",
        "512",
        "--disk-mib",
        "1024",
        "--network-policy",
        "nat-only",
    ])
    .unwrap();
    assert!(matches!(cli.command, Command::Create { .. }));
    let run = Cli::try_parse_from(["microvm", "run"]).unwrap();
    assert!(matches!(run.command, Command::Run { .. }));
    // The only global connectivity flag is a Unix socket PATH, not a host:port.
    let _ = cli.socket;
}

// -- 2. Config surface: forbidden keys are inexpressible --------------------

/// Recursively collect every key in a serialized JSON value.
fn all_keys(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                out.push(k.to_ascii_lowercase());
                all_keys(v, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| all_keys(i, out)),
        _ => {}
    }
}

const FORBIDDEN_KEYS: &[&str] = &[
    "tcp",
    "rootless",
    "vfio",
    "migration",
    "migrate",
    "live_migration",
    "listen",
    "listener",
    "bind",
    "host_port",
    "hostport",
    "cap_add",
    "capadd",
    "privileged",
];

fn assert_no_forbidden_keys(value: &Value, what: &str) {
    let mut keys = Vec::new();
    all_keys(value, &mut keys);
    for forbidden in FORBIDDEN_KEYS {
        assert!(
            !keys.iter().any(|k| k == forbidden),
            "{what} surface must not expose a `{forbidden}` key; keys={keys:?}"
        );
    }
}

#[test]
fn boot_config_surface_has_no_forbidden_keys() {
    use microvm_firecracker::BootConfig;
    let digest = microvm_artifacts::Digest::from_bytes([0xAB; 32]);
    let cfg = BootConfig::builder()
        .kernel_path("blobs/sha256/kernel")
        .kernel_sha256(digest)
        .rootfs_path("blobs/sha256/rootfs")
        .rootfs_sha256(digest)
        .vcpu_count(2)
        .mem_size_mib(512)
        .build()
        .unwrap();
    let json = serde_json::to_value(cfg).unwrap();
    assert_no_forbidden_keys(&json, "BootConfig");
}

#[test]
fn network_boot_config_is_policy_only_and_rejects_none() {
    use microvm_firecracker::NetworkBootConfig;
    // A network config with policy None is meaningless and rejected.
    assert!(NetworkBootConfig::new(NetworkPolicy::None).is_err());
    let cfg = NetworkBootConfig::new(NetworkPolicy::NatOnly).unwrap();
    let json = serde_json::to_value(cfg).unwrap();
    // The only field is `policy`; no port/host/tcp knob exists.
    assert_no_forbidden_keys(&json, "NetworkBootConfig");
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("policy"), "network config is policy-only");
    assert!(!obj.contains_key("port"));
}

#[test]
fn resource_spec_surface_has_no_forbidden_keys() {
    let spec = ResourceSpec::new(2, 512, 1024, NetworkPolicy::NatOnly).unwrap();
    let json = serde_json::to_value(&spec).unwrap();
    assert_no_forbidden_keys(&json, "ResourceSpec");
}

#[test]
fn network_policy_is_exhaustively_three_variants() {
    // A compile-time proof: this match has no wildcard, so adding a fourth
    // NetworkPolicy variant (e.g. a TCP or routed mode) fails to compile here.
    for p in [
        NetworkPolicy::None,
        NetworkPolicy::NatOnly,
        NetworkPolicy::EgressAllowed,
    ] {
        match p {
            NetworkPolicy::None => {}
            NetworkPolicy::NatOnly => {}
            NetworkPolicy::EgressAllowed => {}
        }
    }
}

// -- 3. Source scan (secondary, comment-aware) ------------------------------

/// Strip `//` line comments while preserving `scheme://` in code. Doc comments
/// (`//!`, `///`) become empty. This prevents the scan from matching the many
/// comments that *document* the absence of these knobs.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| {
            let protected = line.replace("://", "\u{1}SCHEME\u{1}");
            let cut = match protected.find("//") {
                Some(i) => &protected[..i],
                None => protected.as_str(),
            };
            cut.replace('\u{1}', "").replace("SCHEME", "://")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn workspace_crates_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("crates"))
        .expect("workspace crates dir")
}

/// Collect the concatenated, comment-stripped source of a crate's `src/`.
fn crate_code(crate_name: &str) -> String {
    let src = workspace_crates_dir().join(crate_name).join("src");
    let mut out = String::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                let raw = std::fs::read_to_string(&path).unwrap_or_default();
                out.push_str(&strip_line_comments(&raw));
                out.push('\n');
            }
        }
    }
    out
}

/// Control-plane crates that must contain no TCP-listener type. The Firecracker
/// backend is excluded: its only TCP use is the outbound guest-health readiness
/// *client* (`TcpHealthProbe`), a scoped probe into the guest, not a listener.
const CONTROL_PLANES: &[&str] = &[
    "microvm-types",
    "microvm-errors",
    "microvm-lifecycle",
    "microvm-artifacts",
    "microvm-isolation",
    "microvm-service",
    "microvm-rest",
    "microvm-grpc",
    "microvm-snapshots",
    "microvm-metrics",
    "microvm-cli",
    "microvm-daemon",
    "microvm-sim",
];

/// All product crates scanned for the scope flags (rootless/VFIO/migration).
const PRODUCT_CRATES: &[&str] = &[
    "microvm-types",
    "microvm-errors",
    "microvm-lifecycle",
    "microvm-artifacts",
    "microvm-isolation",
    "microvm-service",
    "microvm-rest",
    "microvm-grpc",
    "microvm-snapshots",
    "microvm-metrics",
    "microvm-cli",
    "microvm-firecracker",
];

const TCP_LISTENER_TOKENS: &[&str] = &["TcpListener", "TcpSocket", "to_socket_addrs", "0.0.0.0"];

const SCOPE_FLAG_TOKENS: &[&str] = &[
    "rootless",
    "vfio",
    "live_migration",
    "live-migration",
    "LiveMigration",
    "livemigration",
];

#[test]
fn scan_no_tcp_listener_in_control_plane() {
    let mut violations = Vec::new();
    for c in CONTROL_PLANES {
        let code = crate_code(c);
        for tok in TCP_LISTENER_TOKENS {
            if code.contains(tok) {
                violations.push(format!("{c}: contains `{tok}`"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "control-plane crates must bind no TCP listener:\n{}",
        violations.join("\n")
    );
}

#[test]
fn scan_no_rootless_vfio_migration_in_product_code() {
    let mut violations = Vec::new();
    for c in PRODUCT_CRATES {
        let code = crate_code(c);
        for tok in SCOPE_FLAG_TOKENS {
            if code.contains(tok) {
                violations.push(format!("{c}: contains `{tok}`"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "product crates must expose no rootless/VFIO/live-migration knob:\n{}",
        violations.join("\n")
    );
}

/// The scan itself is sound: a planted violation is detected. This is the
/// "deliberate bypass fixture makes the suite fail" property applied to the
/// scan layer.
#[test]
fn scan_detector_catches_a_planted_violation() {
    let benign = "let listener = UnixListener::bind(&path)?;";
    let malicious = "let listener = TcpListener::bind(\"0.0.0.0:50051\")?;";
    assert!(!TCP_LISTENER_TOKENS.iter().any(|t| benign.contains(t)));
    assert!(TCP_LISTENER_TOKENS.iter().any(|t| malicious.contains(t)));
    // Comment stripping removes a forbidden token hidden in a comment, so the
    // scan does not false-positive on documentation.
    let commented = "// we never use TcpListener here\nlet x = 1;";
    assert!(!strip_line_comments(commented).contains("TcpListener"));
}

// -- Consolidated battery ---------------------------------------------------

#[test]
fn scope_fidelity_battery_emits_evidence_and_detects_no_bypass() {
    use common::{assert_no_bypass, run_battery, Probe};
    use microvm_errors::ErrorCode;

    // Model each forbidden CLI flag as a probe: the flag must FAIL to parse
    // (recorded as a rejection). A flag that parsed would be a bypass.
    let mut probes = Vec::new();
    for flag in FORBIDDEN_FLAGS {
        let parsed = Cli::try_parse_from(["microvm", "create", "--image", "sha256:ab", flag]);
        // We EXPECT an error; map Err -> the rejection code, Ok -> bypass.
        let outcome: Result<(), ErrorCode> = match parsed {
            Err(_) => Err(ErrorCode::InvalidResourceSpec),
            Ok(_) => Ok(()),
        };
        probes.push(Probe::from_result(
            &format!("cli_create{}", flag),
            "scope:cli_flag",
            ErrorCode::InvalidResourceSpec,
            outcome,
        ));
    }

    let evidence = run_battery("scope_fidelity", probes);
    assert_no_bypass(&evidence);
    assert!(evidence.summary.total >= FORBIDDEN_FLAGS.len());

    // Controls: the legitimate surface parses and the scans are clean.
    assert!(Cli::try_parse_from(["microvm", "status", "--vm-id", "vm-1"]).is_ok());
}
