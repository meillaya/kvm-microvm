//! Binary-provenance adversarial suite.
//!
//! Drives the real pinned-binary provenance gate
//! ([`microvm_isolation::BinaryVerifier`]), the ELF release/static form parser
//! ([`microvm_isolation::parse_elf_form`]), the validated jailer argv contract
//! ([`microvm_isolation::JailerArgv`]), and the post-exec seccomp verifier
//! ([`microvm_isolation::verify_seccomp_status`]).
//!
//! Traps covered: SHA-256 mismatch, dynamically-linked (GNU/`PT_INTERP`)
//! binary, debug build (`.debug_*`), ELF machine mismatch, missing embedded
//! version string, non-pinned manifest, non-ELF / 32-bit / non-executable
//! input, on-disk tampering, jailer argv that drops to root or omits
//! `--cgroup-version=2` / `--netns` / bounded resource limits, and a seccomp
//! state that is not filter mode. Every probe observes the typed
//! [`ErrorCode`] (and provenance stage) the gate returns.

mod common;

use common::{
    assert_no_bypass, run_battery, synth_elf, ElfOpts, EM_AARCH64, EM_X86_64, ET_DYN, ET_EXEC,
};
use microvm_errors::ErrorCode;
use microvm_isolation::{
    binary_contains_version, parse_elf_form, parse_seccomp_mode, pinned_firecracker, sha256_hex,
    verify_seccomp_status, BinaryManifest, BinaryVerifier, ElfMachine, JailerArgv, ResourceKind,
    SeccompVerifier, MAX_FSIZE_BYTES, MAX_NO_FILE, PINNED_VERSION, SECCOMP_MODE_FILTER,
};

/// A manifest whose SHA-256 matches `bytes` (so the hash check passes and any
/// later rejection is about ELF form / version, not the hash).
fn matching_manifest(bytes: &[u8], machine: ElfMachine) -> BinaryManifest {
    BinaryManifest::new("firecracker", PINNED_VERSION, sha256_hex(bytes), machine).unwrap()
}

/// A static release ELF that the gate must accept for `machine`.
fn good_elf(machine: u16) -> Vec<u8> {
    common::static_release_elf(machine, PINNED_VERSION)
}

// -- Happy path (control) ---------------------------------------------------

#[test]
fn static_release_binary_verifies_for_both_machines() {
    for (machine, code) in [
        (ElfMachine::X86_64, EM_X86_64),
        (ElfMachine::AArch64, EM_AARCH64),
    ] {
        let bytes = good_elf(code);
        let verifier = BinaryVerifier::new(matching_manifest(&bytes, machine));
        let verified = verifier.verify_bytes(&bytes).unwrap();
        assert_eq!(verified.sha256(), sha256_hex(&bytes));
        assert_eq!(verified.version(), PINNED_VERSION);
        assert_eq!(verified.machine(), machine);
    }
}

#[test]
fn pie_et_dyn_release_is_accepted() {
    // The x86_64 release is a PIE (ET_DYN); it must be accepted when static.
    let bytes = synth_elf(&ElfOpts {
        elf_type: ET_DYN,
        machine: EM_X86_64,
        interp: false,
        debug: false,
        payload: b"Firecracker 1.16.1 pie".to_vec(),
    });
    let verifier = BinaryVerifier::new(matching_manifest(&bytes, ElfMachine::X86_64));
    assert!(verifier.verify_bytes(&bytes).is_ok());
}

// -- Provenance rejections --------------------------------------------------

#[test]
fn hash_mismatch_is_rejected() {
    let bytes = good_elf(EM_X86_64);
    // Manifest pins a different (well-formed) digest.
    let wrong = "0".repeat(64);
    let manifest =
        BinaryManifest::new("firecracker", PINNED_VERSION, wrong, ElfMachine::X86_64).unwrap();
    let verifier = BinaryVerifier::new(manifest);
    let err = verifier.verify_bytes(&bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("hash_mismatch")
    );
}

#[test]
fn dynamically_linked_binary_is_rejected() {
    let bytes = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: true, // PT_INTERP present -> GNU/dynamic
        debug: false,
        payload: b"Firecracker 1.16.1 gnu".to_vec(),
    });
    let verifier = BinaryVerifier::new(matching_manifest(&bytes, ElfMachine::X86_64));
    let err = verifier.verify_bytes(&bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("dynamic_binary")
    );
}

#[test]
fn debug_build_is_rejected() {
    let bytes = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: false,
        debug: true, // .debug_info present
        payload: b"Firecracker 1.16.1 debug".to_vec(),
    });
    let verifier = BinaryVerifier::new(matching_manifest(&bytes, ElfMachine::X86_64));
    let err = verifier.verify_bytes(&bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("debug_build")
    );
}

#[test]
fn elf_machine_mismatch_is_rejected() {
    // Bytes are an aarch64 ELF but the manifest pins x86_64.
    let bytes = good_elf(EM_AARCH64);
    let verifier = BinaryVerifier::new(matching_manifest(&bytes, ElfMachine::X86_64));
    let err = verifier.verify_bytes(&bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("machine_mismatch")
    );
}

#[test]
fn missing_version_string_is_rejected() {
    let bytes = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: false,
        debug: false,
        payload: b"no-version-here".to_vec(),
    });
    let verifier = BinaryVerifier::new(matching_manifest(&bytes, ElfMachine::X86_64));
    let err = verifier.verify_bytes(&bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("version_mismatch")
    );
}

#[test]
fn non_pinned_manifest_is_rejected() {
    let bytes = good_elf(EM_X86_64);
    // A well-formed manifest pinned to a DIFFERENT release.
    let manifest = BinaryManifest::new(
        "firecracker",
        "v1.15.0",
        sha256_hex(&bytes),
        ElfMachine::X86_64,
    )
    .unwrap();
    let verifier = BinaryVerifier::new(manifest);
    let err = verifier.verify_bytes(&bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("not_pinned")
    );
}

#[test]
fn non_elf_and_wrong_class_are_rejected() {
    let verifier = BinaryVerifier::new(pinned_firecracker(ElfMachine::X86_64));
    // Random non-ELF bytes.
    let err = verifier
        .verify_bytes(b"definitely not an elf binary")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    // A 32-bit ELF (ELFCLASS32) is rejected by the form parser.
    let mut elf32 = good_elf(EM_X86_64);
    elf32[4] = 1; // EI_CLASS = ELFCLASS32
    let err = parse_elf_form(&elf32).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    // A non-executable ELF type (ET_REL = 1) is rejected.
    let rel = synth_elf(&ElfOpts {
        elf_type: 1,
        machine: EM_X86_64,
        interp: false,
        debug: false,
        payload: b"Firecracker 1.16.1 rel".to_vec(),
    });
    let err = parse_elf_form(&rel).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
}

#[test]
fn manifest_format_validation_is_strict() {
    // SHA not 64 hex.
    assert!(BinaryManifest::new("firecracker", PINNED_VERSION, "abc", ElfMachine::X86_64).is_err());
    // Version not a pinned tag.
    assert!(
        BinaryManifest::new("firecracker", "latest", "0".repeat(64), ElfMachine::X86_64).is_err()
    );
    // Empty / unsafe name.
    assert!(BinaryManifest::new("", PINNED_VERSION, "0".repeat(64), ElfMachine::X86_64).is_err());
    assert!(BinaryManifest::new(
        "bad name",
        PINNED_VERSION,
        "0".repeat(64),
        ElfMachine::X86_64
    )
    .is_err());
}

// -- On-disk verification + tampering ---------------------------------------

#[test]
fn verify_path_accepts_clean_and_rejects_tampered_binary() {
    let tmp = tempfile::TempDir::new().unwrap();
    let bytes = good_elf(EM_X86_64);
    let path = tmp.path().join("firecracker");
    std::fs::write(&path, &bytes).unwrap();

    let verifier = BinaryVerifier::new(matching_manifest(&bytes, ElfMachine::X86_64));
    let verified = verifier.verify_path(&path).unwrap();
    assert_eq!(verified.path(), Some(path.as_path()));

    // Flip one byte on disk -> the hash no longer matches -> provenance error,
    // and (critically) no child process is spawned by this gate.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    std::fs::write(&path, &tampered).unwrap();
    let err = verifier.verify_path(&path).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("hash_mismatch")
    );

    // A missing binary is a provenance failure (io stage), not a pass.
    let err = verifier
        .verify_path(&tmp.path().join("absent"))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
}

#[test]
fn version_scan_is_exact() {
    assert!(binary_contains_version(b"prefix 1.16.1 suffix", "v1.16.1"));
    assert!(!binary_contains_version(b"1.16.0", "v1.16.1"));
    assert!(!binary_contains_version(b"", "v1.16.1"));
}

// -- Jailer argv contract ---------------------------------------------------

fn good_argv() -> JailerArgv {
    JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-1")
        .uid(10_000)
        .gid(10_000)
        .parent_cgroup("microvm/vm-1")
        .netns("/var/run/netns/microvm-vm-1")
        .with_recommended_limits()
        .build()
        .unwrap()
}

#[test]
fn jailer_argv_always_pins_cgroup_version_2() {
    let argv = good_argv().argv();
    assert!(
        argv.iter().any(|a| a == "--cgroup-version=2"),
        "jailer argv must pin --cgroup-version=2: {argv:?}"
    );
    // The jailer defaults to v1; the orchestrator must never emit v1.
    assert!(!argv.iter().any(|a| a.contains("cgroup-version=1")));
}

#[test]
fn jailer_argv_rejects_root_uid_and_gid() {
    let base = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-1")
        .parent_cgroup("microvm/vm-1")
        .netns("/var/run/netns/x")
        .with_recommended_limits();
    // root uid
    let err = base.clone().uid(0).gid(10_000).build().unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // root gid
    let err = base.clone().uid(10_000).gid(0).build().unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // missing uid/gid entirely
    let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-1")
        .parent_cgroup("microvm/vm-1")
        .netns("/var/run/netns/x")
        .with_recommended_limits()
        .build()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
}

#[test]
fn jailer_argv_requires_netns_parent_cgroup_and_limits() {
    // missing netns
    let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-1")
        .uid(10_000)
        .gid(10_000)
        .parent_cgroup("microvm/vm-1")
        .with_recommended_limits()
        .build()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // missing parent-cgroup
    let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-1")
        .uid(10_000)
        .gid(10_000)
        .netns("/var/run/netns/x")
        .with_recommended_limits()
        .build()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // no resource limits at all
    let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-1")
        .uid(10_000)
        .gid(10_000)
        .parent_cgroup("microvm/vm-1")
        .netns("/var/run/netns/x")
        .build()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
}

#[test]
fn jailer_argv_rejects_unbounded_resource_limits() {
    let base = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-1")
        .uid(10_000)
        .gid(10_000)
        .parent_cgroup("microvm/vm-1")
        .netns("/var/run/netns/x");
    // zero limit
    let err = base
        .clone()
        .resource_limit(ResourceKind::Fsize, 0)
        .build()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // over the maximum
    let err = base
        .clone()
        .resource_limit(ResourceKind::Fsize, MAX_FSIZE_BYTES + 1)
        .build()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    let err = base
        .resource_limit(ResourceKind::NoFile, MAX_NO_FILE + 1)
        .build()
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
}

#[test]
fn jailer_argv_rejects_unsafe_id() {
    for bad in ["", "vm 1", "vm\n1", "vm\t1"] {
        let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", bad)
            .uid(10_000)
            .gid(10_000)
            .parent_cgroup("microvm/vm-1")
            .netns("/var/run/netns/x")
            .with_recommended_limits()
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec, "bad id={bad:?}");
    }
}

// -- Post-exec seccomp ------------------------------------------------------

#[test]
fn seccomp_requires_filter_mode() {
    assert!(verify_seccomp_status("Name:\tfc\nSeccomp:\t2\n").is_ok());
    assert_eq!(SECCOMP_MODE_FILTER, 2);
    for mode in ["0", "1"] {
        let status = format!("Name:\tfc\nSeccomp:\t{mode}\n");
        let err = verify_seccomp_status(&status).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProcessSpawnError);
    }
    // Missing Seccomp field entirely.
    let err = verify_seccomp_status("Name:\tfc\nState:\tS\n").unwrap_err();
    assert_eq!(err.code, ErrorCode::ProcessSpawnError);
    assert_eq!(parse_seccomp_mode("Seccomp:\t2"), Some(2));
    assert_eq!(parse_seccomp_mode("no field"), None);
}

#[test]
fn seccomp_verifier_reads_proc_root() {
    let tmp = tempfile::TempDir::new().unwrap();
    let pid_dir = tmp.path().join("4242");
    std::fs::create_dir_all(&pid_dir).unwrap();
    std::fs::write(pid_dir.join("status"), "Name:\tfc\nSeccomp:\t2\n").unwrap();
    let verifier = SeccompVerifier::new(tmp.path());
    assert!(verifier.verify_pid(4242).is_ok());
    // A pid with no status file -> ProcessSpawnError, not a pass.
    let err = verifier.verify_pid(9999).unwrap_err();
    assert_eq!(err.code, ErrorCode::ProcessSpawnError);
}

// -- Consolidated battery ---------------------------------------------------

#[test]
fn binary_security_battery_emits_evidence_and_detects_no_bypass() {
    use common::Probe;
    let good = good_elf(EM_X86_64);
    let verifier = BinaryVerifier::new(matching_manifest(&good, ElfMachine::X86_64));

    let dynamic = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: true,
        debug: false,
        payload: b"Firecracker 1.16.1 gnu".to_vec(),
    });
    let debug = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: false,
        debug: true,
        payload: b"Firecracker 1.16.1 debug".to_vec(),
    });
    let no_version = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: false,
        debug: false,
        payload: b"nothing".to_vec(),
    });
    let aarch64 = good_elf(EM_AARCH64);

    let wrong_hash_manifest = BinaryManifest::new(
        "firecracker",
        PINNED_VERSION,
        "0".repeat(64),
        ElfMachine::X86_64,
    )
    .unwrap();
    let non_pinned_manifest = BinaryManifest::new(
        "firecracker",
        "v1.15.0",
        sha256_hex(&good),
        ElfMachine::X86_64,
    )
    .unwrap();

    let mut elf32 = good.clone();
    elf32[4] = 1; // ELFCLASS32

    let probes = vec![
        Probe::from_result(
            "hash_mismatch",
            "binary:hash_mismatch",
            ErrorCode::BinaryProvenanceError,
            BinaryVerifier::new(wrong_hash_manifest).verify_bytes(&good),
        ),
        Probe::from_result(
            "dynamic_binary",
            "binary:dynamic_binary",
            ErrorCode::BinaryProvenanceError,
            verifier.verify_bytes(&dynamic),
        ),
        Probe::from_result(
            "debug_build",
            "binary:debug_build",
            ErrorCode::BinaryProvenanceError,
            verifier.verify_bytes(&debug),
        ),
        Probe::from_result(
            "machine_mismatch",
            "binary:machine_mismatch",
            ErrorCode::BinaryProvenanceError,
            verifier.verify_bytes(&aarch64),
        ),
        Probe::from_result(
            "version_mismatch",
            "binary:version_mismatch",
            ErrorCode::BinaryProvenanceError,
            verifier.verify_bytes(&no_version),
        ),
        Probe::from_result(
            "not_pinned",
            "binary:not_pinned",
            ErrorCode::BinaryProvenanceError,
            BinaryVerifier::new(non_pinned_manifest).verify_bytes(&good),
        ),
        Probe::from_result(
            "non_elf",
            "binary:non_elf",
            ErrorCode::BinaryProvenanceError,
            verifier.verify_bytes(b"not an elf"),
        ),
        Probe::from_result(
            "elf32_class",
            "binary:wrong_class",
            ErrorCode::BinaryProvenanceError,
            parse_elf_form(&elf32),
        ),
        Probe::from_result(
            "jailer_root_uid",
            "binary:jailer_root_uid",
            ErrorCode::InvalidResourceSpec,
            JailerArgv::builder("/j", "/f", "vm-1")
                .uid(0)
                .gid(10000)
                .parent_cgroup("m/v")
                .netns("/n")
                .with_recommended_limits()
                .build(),
        ),
        Probe::from_result(
            "jailer_root_gid",
            "binary:jailer_root_gid",
            ErrorCode::InvalidResourceSpec,
            JailerArgv::builder("/j", "/f", "vm-1")
                .uid(10000)
                .gid(0)
                .parent_cgroup("m/v")
                .netns("/n")
                .with_recommended_limits()
                .build(),
        ),
        Probe::from_result(
            "jailer_no_netns",
            "binary:jailer_no_netns",
            ErrorCode::InvalidResourceSpec,
            JailerArgv::builder("/j", "/f", "vm-1")
                .uid(10000)
                .gid(10000)
                .parent_cgroup("m/v")
                .with_recommended_limits()
                .build(),
        ),
        Probe::from_result(
            "jailer_no_limits",
            "binary:jailer_no_limits",
            ErrorCode::InvalidResourceSpec,
            JailerArgv::builder("/j", "/f", "vm-1")
                .uid(10000)
                .gid(10000)
                .parent_cgroup("m/v")
                .netns("/n")
                .build(),
        ),
        Probe::from_result(
            "jailer_unbounded_limit",
            "binary:jailer_unbounded",
            ErrorCode::InvalidResourceSpec,
            JailerArgv::builder("/j", "/f", "vm-1")
                .uid(10000)
                .gid(10000)
                .parent_cgroup("m/v")
                .netns("/n")
                .resource_limit(ResourceKind::Fsize, MAX_FSIZE_BYTES + 1)
                .build(),
        ),
        Probe::from_result(
            "seccomp_not_filter",
            "binary:seccomp_not_filter",
            ErrorCode::ProcessSpawnError,
            verify_seccomp_status("Seccomp:\t0\n"),
        ),
        Probe::from_result(
            "seccomp_missing",
            "binary:seccomp_missing",
            ErrorCode::ProcessSpawnError,
            verify_seccomp_status("Name:\tfc\n"),
        ),
    ];

    let evidence = run_battery("binary_security", probes);
    assert_no_bypass(&evidence);
    assert!(evidence.summary.total >= 15);

    // Control: the genuine static release binary verifies (proves the
    // rejections above are discriminating, not blanket).
    assert!(verifier.verify_bytes(&good).is_ok());
    // The recommended defaults are accepted by the bounded argv builder.
    assert!(JailerArgv::builder("/j", "/f", "vm-ctl")
        .uid(10_000)
        .gid(10_000)
        .parent_cgroup("m/v")
        .netns("/n")
        .with_recommended_limits()
        .build()
        .is_ok());
}
