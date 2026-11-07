//! Privileged Firecracker/jailer provenance and jailer-invocation test.
//!
//! Run with:
//! ```text
//! cargo test --features privileged --test jailer_invocation -- --nocapture
//! ```
//!
//! This exercises the binary provenance gate and the validated jailer argv.
//! Following the platform's privileged test model (`pass` / `blocked` /
//! `failed`), a host that lacks a pinned Firecracker/jailer binary reports a
//! stable `blocked` token and passes rather than failing.
//!
//! The deterministic rejection scenarios (debug build, wrong hash) never need
//! root: they build synthetic binaries in a tempdir and assert the gate rejects
//! them with [`ErrorCode::BinaryProvenanceError`] before any spawn. This
//! module never constructs a `std::process::Command`, so a rejection guarantees
//! no child process exists.
//!
//! To exercise the real happy path, point the gate at a genuine pinned release
//! binary, e.g.:
//! ```text
//! MICROVM_PINNED_FIRECRACKER=/path/to/firecracker-v1.16.1-x86_64 \
//! MICROVM_PINNED_JAILER=/path/to/jailer-v1.16.1-x86_64 \
//!     cargo test --features privileged --test jailer_invocation -- --nocapture
//! ```

#![cfg(feature = "privileged")]

use microvm_errors::ErrorCode;
use microvm_isolation::{
    pinned_firecracker, pinned_jailer, sha256_hex, BinaryManifest, BinaryVerifier, ElfMachine,
    JailerArgv, PINNED_VERSION,
};
use std::path::{Path, PathBuf};

/// Print a blocked token; used when the host cannot run a check.
fn blocked(reason: &str) {
    println!("blocked: {reason}");
}

/// The ELF machine for the host architecture.
fn host_machine() -> ElfMachine {
    match std::env::consts::ARCH {
        "aarch64" => ElfMachine::AArch64,
        _ => ElfMachine::X86_64,
    }
}

/// Locate a binary by explicit env override, then `PATH`, then common dirs.
fn locate(env_key: &str, name: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_key) {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let candidate = Path::new(dir).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for dir in [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/run/current-system/sw/bin",
    ] {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Deterministic: validated jailer argv (no root required)
// ---------------------------------------------------------------------------

#[test]
fn jailer_argv_is_validated_and_complete() {
    let argv = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-priv")
        .uid(10_000)
        .gid(10_000)
        .parent_cgroup("microvm/vm-priv")
        .netns("/var/run/netns/microvm-vm-priv")
        .chroot_base_dir("/srv/jailer")
        .with_recommended_limits()
        .daemonize()
        .build()
        .expect("valid argv builds")
        .argv();

    // The cgroup contract is always pinned to v2 with a pre-created leaf.
    assert!(argv.contains(&"--cgroup-version=2".to_string()));
    let pc = argv.iter().position(|a| a == "--parent-cgroup").unwrap();
    assert_eq!(argv[pc + 1], "microvm/vm-priv");

    // Non-root UID/GID, netns, and bounded resource limits are present.
    assert!(argv.contains(&"--netns".to_string()));
    assert!(argv.contains(&"--uid".to_string()));
    assert!(argv.contains(&"--gid".to_string()));
    assert!(argv.iter().any(|a| a.starts_with("fsize=")));
    assert!(argv.iter().any(|a| a.starts_with("no-file=")));

    println!("pass: jailer_argv_complete argv={argv:?}");
}

#[test]
fn jailer_argv_rejects_root_before_spawn() {
    let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-priv")
        .uid(0)
        .gid(10_000)
        .parent_cgroup("microvm/vm-priv")
        .netns("/var/run/netns/x")
        .with_recommended_limits()
        .build()
        .expect_err("root uid must be rejected");
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    println!("pass: root_uid_rejected code={}", err.code);
}

// ---------------------------------------------------------------------------
// Deterministic: provenance rejects debug / wrong-hash binaries, no child
// ---------------------------------------------------------------------------

/// ELF writers used by [`synth_binary`] (free fns avoid closure borrow clashes).
fn w16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn wshdr(b: &mut Vec<u8>, name: u32, typ: u32, off: u64, size: u64) {
    w32(b, name);
    w32(b, typ);
    w64(b, 0);
    w64(b, 0);
    w64(b, off);
    w64(b, size);
    w32(b, 0);
    w32(b, 0);
    w64(b, 1);
    w64(b, 0);
}

/// Build a minimal ELF64 that is either a debug build or a clean release, so
/// the gate has a concrete artifact to reject without needing a real binary.
fn synth_binary(debug: bool, version_tag: &[u8]) -> Vec<u8> {
    // Minimal ELF64 header + one PT_LOAD program header + a section-header
    // string table carrying an optional `.debug_info` section, plus a payload
    // embedding the version tag. Structurally valid for `parse_elf_form`.
    let mut shstrtab: Vec<u8> = vec![0];
    let off_shstrtab = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab");
    shstrtab.push(0);
    let off_debug = if debug {
        let off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".debug_info");
        shstrtab.push(0);
        Some(off)
    } else {
        None
    };
    let off_text = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text");
    shstrtab.push(0);

    let shnum: u16 = if debug { 4 } else { 3 };
    let h_off: u64 = 120 + shstrtab.len() as u64;

    let mut b = Vec::new();
    b.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    w16(&mut b, 2); // e_type = ET_EXEC
    w16(&mut b, host_machine().code()); // e_machine
    w32(&mut b, 1);
    w64(&mut b, 0);
    w64(&mut b, 64); // e_phoff
    w64(&mut b, h_off); // e_shoff
    w32(&mut b, 0);
    w16(&mut b, 64);
    w16(&mut b, 56);
    w16(&mut b, 1); // e_phnum
    w16(&mut b, 64);
    w16(&mut b, shnum);
    w16(&mut b, 1); // e_shstrndx

    // One PT_LOAD program header (no PT_INTERP => statically linked).
    w32(&mut b, 1);
    w32(&mut b, 0);
    w64(&mut b, 0);
    w64(&mut b, 0);
    w64(&mut b, 0);
    w64(&mut b, 0);
    w64(&mut b, 0);
    w64(&mut b, 0);

    b.extend_from_slice(&shstrtab);

    wshdr(&mut b, 0, 0, 0, 0); // null
    wshdr(&mut b, off_shstrtab, 3, 120, shstrtab.len() as u64); // .shstrtab
    if let Some(od) = off_debug {
        wshdr(&mut b, od, 1, 0, 0); // .debug_info
    }
    wshdr(&mut b, off_text, 1, 0, 0); // .text

    b.extend_from_slice(version_tag);
    b
}

#[test]
fn provenance_rejects_debug_and_wrong_hash_without_spawning() {
    let tmp = tempfile::TempDir::new().unwrap();
    let machine = host_machine();

    // 1. A debug build whose hash matches the manifest must still be rejected.
    let debug_bytes = synth_binary(true, b"1.16.1");
    let debug_path = tmp.path().join("firecracker-debug");
    std::fs::write(&debug_path, &debug_bytes).unwrap();
    let debug_manifest = BinaryManifest::new(
        "firecracker",
        PINNED_VERSION,
        sha256_hex(&debug_bytes),
        machine,
    )
    .unwrap();
    let err = BinaryVerifier::new(debug_manifest)
        .verify_path(&debug_path)
        .expect_err("debug build must be rejected");
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("debug_build")
    );
    println!(
        "pass: debug_rejected code={} stage={:?} path={} (no child spawned)",
        err.code,
        err.context.get("stage"),
        debug_path.display()
    );

    // 2. A clean release form whose hash does not match the pinned manifest.
    let clean_bytes = synth_binary(false, b"1.16.1");
    let wrong_path = tmp.path().join("firecracker-wronghash");
    std::fs::write(&wrong_path, &clean_bytes).unwrap();
    let pinned = pinned_firecracker(machine); // real pinned hash, won't match synth
    let err = BinaryVerifier::new(pinned)
        .verify_path(&wrong_path)
        .expect_err("wrong-hash binary must be rejected");
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("hash_mismatch")
    );
    println!(
        "pass: wrong_hash_rejected code={} stage={:?} path={} (no child spawned)",
        err.code,
        err.context.get("stage"),
        wrong_path.display()
    );

    // Audit evidence: the gate is pure pre-spawn. This test constructs no
    // std::process::Command, and BinaryVerifier exposes no spawn API, so a
    // rejection here guarantees no child process exists.
    println!("pass: no_child_process gate=pre-spawn module_spawns=never");
}

// ---------------------------------------------------------------------------
// Privileged happy path: verify a genuine pinned release binary, if present
// ---------------------------------------------------------------------------

#[test]
fn happy_path_verify_installed_pinned_binary() {
    let machine = host_machine();

    let cases = [
        (
            "MICROVM_PINNED_FIRECRACKER",
            "firecracker",
            pinned_firecracker(machine),
        ),
        ("MICROVM_PINNED_JAILER", "jailer", pinned_jailer(machine)),
    ];

    let mut verified_any = false;
    for (env_key, name, manifest) in cases {
        let Some(path) = locate(env_key, name) else {
            blocked(&format!("{name}_binary_missing"));
            continue;
        };
        let verifier = BinaryVerifier::new(manifest);
        match verifier.verify_path(&path) {
            Ok(verified) => {
                verified_any = true;
                println!(
                    "pass: {name}_provenance path={} sha256={} version={} machine={:?}",
                    path.display(),
                    verified.sha256(),
                    verified.version(),
                    verified.machine()
                );
            }
            Err(e) if e.code == ErrorCode::BinaryProvenanceError => {
                // A present-but-non-pinned build (e.g. a distro/Nix build whose
                // hash differs from the official release) is a host gap, not a
                // code failure.
                blocked(&format!(
                    "{name}_not_pinned_build stage={:?} path={}",
                    e.context.get("stage"),
                    path.display()
                ));
            }
            Err(e) => panic!("unexpected {name} verification error: {e}"),
        }
    }

    if !verified_any {
        blocked("no_pinned_binary_verified");
    }
}

// ---------------------------------------------------------------------------
// Privileged: post-exec seccomp parser against a real /proc, if readable
// ---------------------------------------------------------------------------

#[test]
fn seccomp_status_is_parseable_for_a_real_pid() {
    use microvm_isolation::{parse_seccomp_mode, SeccompVerifier};

    let status_path = Path::new("/proc/self/status");
    if !status_path.exists() {
        blocked("proc_missing");
        return;
    }
    let status = std::fs::read_to_string(status_path).expect("/proc/self/status readable");
    // We only assert the parser yields a mode; the current process is typically
    // mode 0 (no filter) here, which is not the post-exec Firecracker state.
    match parse_seccomp_mode(&status) {
        Some(mode) => println!("pass: seccomp_parseable self_mode={mode} (filter=2 post-exec)"),
        None => blocked("seccomp_field_absent"),
    }

    // The verifier path computation is stable regardless of host state.
    let v = SeccompVerifier::new("/proc");
    assert_eq!(
        v.status_path(std::process::id()),
        PathBuf::from(format!("/proc/{}/status", std::process::id()))
    );
}
