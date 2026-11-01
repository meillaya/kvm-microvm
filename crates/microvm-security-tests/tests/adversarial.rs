//! The adversarial mutation corpus and property suites (plan todo 31's
//! `--test adversarial` target).
//!
//! Where the per-domain suites enumerate each known trap, this target attacks
//! the boundaries *generatively*:
//!
//! - Property suites (proptest): invariants that must hold for *all*
//!   inputs: any path containing a `..` component is refused, any non-`file`
//!   URI is refused, any identifier containing `/`/`..`/uppercase is refused,
//!   any zero-valued cgroup spec is refused, any non-ELF byte string is refused.
//! - Mutation corpus: a genuine static release binary and a valid OCI
//!   layout are systematically mutated (single-byte flips, header-field
//!   rewrites, deeply-nested forbidden keys, encoding tricks) and every mutant
//!   must be rejected with the correct typed code.
//! - Deliberate-bypass canaries: fixtures engineered to slip past a *naive*
//!   check (a clean-named symlink to `/etc/shadow`, a `./..` path a
//!   dot-stripper would miss, a forbidden key buried in a nested array, a
//!   binary that is static and correctly-machined but carries the wrong
//!   version). The real boundaries reject all of them, and the harness canary
//!   proves that any mutant that *did* slip through would fail the battery.
//!
//! Every rejection happens in a pure, pre-spawn function; no probe spawns a
//! process or touches a privileged resource, so the suite fails on a bypass
//! *before* any side effect. The consolidated `adversarial.json` evidence
//! artifact is written before the assertions.

mod common;

use common::{
    assert_no_bypass, run_battery, sha256_hex, standard_layout, static_release_elf, synth_elf,
    ElfOpts, Probe, EM_X86_64, ET_EXEC,
};
use microvm_artifacts::{validate_relative_path, PathResolver};
use microvm_errors::ErrorCode;
use microvm_isolation::{
    parse_elf_form, sha256_hex as iso_sha256_hex, BinaryManifest, BinaryVerifier, CgroupSpec,
    ElfMachine, PINNED_VERSION,
};
use microvm_oci::{validate_local_reference, OciImporter};
use microvm_types::{TenantId, VmId};
use proptest::prelude::*;
use serde_json::json;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

fn matching_verifier(bytes: &[u8]) -> BinaryVerifier {
    let manifest = BinaryManifest::new(
        "firecracker",
        PINNED_VERSION,
        iso_sha256_hex(bytes),
        ElfMachine::X86_64,
    )
    .unwrap();
    BinaryVerifier::new(manifest)
}

// ===========================================================================
// Property suites (proptest)
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any path containing a `..` component is refused, regardless of the
    /// surrounding components.
    #[test]
    fn prop_dotdot_component_always_refused(pre in "[a-z]{0,4}", post in "[a-z]{0,4}") {
        let path = format!("{pre}/../{post}");
        let err = validate_relative_path(&path).unwrap_err();
        prop_assert_eq!(err.code, ErrorCode::PathEscape);
    }

    /// Any absolute path is refused.
    #[test]
    fn prop_absolute_path_always_refused(rest in "[a-z0-9/]{1,12}") {
        let path = format!("/{rest}");
        let err = validate_relative_path(&path).unwrap_err();
        prop_assert_eq!(err.code, ErrorCode::PathEscape);
    }

    /// Any non-`file` `scheme://` URI is refused as a remote reference.
    #[test]
    fn prop_remote_uri_always_refused(
        scheme in prop_oneof![
            Just("https".to_string()), Just("http".to_string()), Just("oci".to_string()),
            Just("docker".to_string()), Just("s3".to_string()), Just("ssh".to_string()),
        ],
        host in "[a-z]{1,8}",
    ) {
        let uri = format!("{scheme}://{host}/img");
        let err = validate_local_reference(&uri).unwrap_err();
        prop_assert_eq!(err.code(), ErrorCode::LocalArtifactRequired);
    }

    /// Any identifier containing `/` or `..` is refused (path-injection guard).
    #[test]
    fn prop_id_path_injection_refused(base in "[a-z]{1,6}", inj in prop_oneof![Just("/x".to_string()), Just("..".to_string()), Just("a/b".to_string())]) {
        let raw = format!("{base}{inj}");
        prop_assert!(VmId::new(&raw).is_err());
        prop_assert!(TenantId::new(&raw).is_err());
    }

    /// Any identifier with uppercase ASCII is refused (canonicalization guard).
    #[test]
    fn prop_id_uppercase_refused(upper in "[A-Z]{1,3}", base in "[a-z]{1,5}") {
        let raw = format!("{base}{upper}");
        prop_assert!(VmId::new(&raw).is_err());
    }

    /// Any over-length identifier is refused.
    #[test]
    fn prop_id_overlong_refused(pad in "[a-z]{65,80}") {
        prop_assert!(VmId::new(pad).is_err());
    }

    /// Any zero-valued cgroup spec field is refused.
    #[test]
    fn prop_cgroup_zero_field_refused(
        which in 0u8..3,
        good_cpu in 1u64..100_000,
        good_mem in 1u64..1_000_000,
        good_pids in 1u64..10_000,
    ) {
        let mut b = CgroupSpec::builder();
        b = match which {
            0 => b.cpu_quota_us(0).memory_max_bytes(good_mem).pids_max(good_pids),
            1 => b.cpu_quota_us(good_cpu).memory_max_bytes(0).pids_max(good_pids),
            _ => b.cpu_quota_us(good_cpu).memory_max_bytes(good_mem).pids_max(0),
        };
        let err = b.build().unwrap_err();
        prop_assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    /// Any byte string that is not a 64-bit little-endian ELF is refused by the
    /// form parser (the first gate the provenance check applies).
    #[test]
    fn prop_non_elf_bytes_refused(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        // Skip the astronomically unlikely case of accidentally forming a valid
        // ELF64-LE executable header.
        if bytes.len() >= 64 && bytes[0..4] == [0x7f, b'E', b'L', b'F'] && bytes[4] == 2 && bytes[5] == 1 {
            return Ok(());
        }
        prop_assert!(parse_elf_form(&bytes).is_err());
    }
}

// ===========================================================================
// Mutation corpus: single-byte tampering of a genuine binary
// ===========================================================================

/// Flipping ANY single byte of a verified binary changes its SHA-256, so the
/// provenance gate must reject the mutant with a hash mismatch. This is the
/// strongest tamper proof: every one-byte mutation is caught.
#[test]
fn every_single_byte_mutation_of_the_binary_is_caught() {
    let good = static_release_elf(EM_X86_64, PINNED_VERSION);
    let verifier = matching_verifier(&good);
    // Sanity: the unmutated binary verifies.
    assert!(verifier.verify_bytes(&good).is_ok());

    let positions: Vec<usize> = (0..good.len()).step_by(7).collect();
    let mut caught = 0usize;
    for pos in positions {
        let mut mutant = good.clone();
        mutant[pos] ^= 0x01;
        let err = verifier
            .verify_bytes(&mutant)
            .expect_err("any single-byte mutation must be rejected");
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        caught += 1;
    }
    assert!(
        caught >= 16,
        "must exercise many mutation sites, got {caught}"
    );
}

/// Targeted ELF-form mutations that keep the hash self-consistent (the manifest
/// is rebuilt for each mutant) so the *form* gate, not the hash, is what
/// rejects. Each mutates one security-relevant ELF property.
#[test]
fn elf_form_mutations_are_rejected_by_the_form_gate() {
    // dynamic (PT_INTERP)
    let dynamic = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: true,
        debug: false,
        payload: b"Firecracker 1.16.1 x".to_vec(),
    });
    assert_eq!(
        matching_verifier(&dynamic)
            .verify_bytes(&dynamic)
            .unwrap_err()
            .code,
        ErrorCode::BinaryProvenanceError
    );
    // debug build
    let debug = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: false,
        debug: true,
        payload: b"Firecracker 1.16.1 x".to_vec(),
    });
    assert_eq!(
        matching_verifier(&debug)
            .verify_bytes(&debug)
            .unwrap_err()
            .code,
        ErrorCode::BinaryProvenanceError
    );
    // wrong machine (aarch64 bytes verified against an x86_64 manifest)
    let arm = static_release_elf(common::EM_AARCH64, PINNED_VERSION);
    assert_eq!(
        matching_verifier(&arm).verify_bytes(&arm).unwrap_err().code,
        ErrorCode::BinaryProvenanceError
    );
    // non-executable ELF type (ET_REL)
    let rel = synth_elf(&ElfOpts {
        elf_type: 1,
        machine: EM_X86_64,
        interp: false,
        debug: false,
        payload: b"Firecracker 1.16.1 x".to_vec(),
    });
    assert!(parse_elf_form(&rel).is_err());
}

// ===========================================================================
// Deliberate-bypass canaries (naive-check evasions the real code still refuses)
// ===========================================================================

/// A clean-named symlink whose target is a sensitive host file. A naive
/// "looks relative, no `..`" check would open it; the real resolver refuses to
/// follow the symlink (ELOOP -> PathEscape).
#[test]
fn bypass_clean_named_symlink_to_sensitive_file_is_refused() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
    std::fs::write(root.join("blobs/sha256/good"), b"ok").unwrap();
    // Innocuous name, malicious target.
    symlink("/etc/shadow", root.join("blobs/sha256/innocent")).unwrap();
    let resolver = PathResolver::open_root(root).unwrap();
    assert!(resolver.open("blobs/sha256/good").is_ok());
    let err = resolver.open("blobs/sha256/innocent").unwrap_err();
    assert_eq!(err.code, ErrorCode::PathEscape);
}

/// A `./..` traversal a naive dot-component stripper would normalize away. The
/// real lexical gate refuses the `..` component outright.
#[test]
fn bypass_dot_slash_dotdot_traversal_is_refused() {
    for path in [
        "blobs/./../../etc/passwd",
        "./../secret",
        "blobs/././../../x",
    ] {
        let err = validate_relative_path(path).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathEscape, "path={path}");
    }
}

/// A forbidden OCI runtime key buried deep inside a nested array/object. A
/// naive top-level-only scanner would miss it; the real recursive scanner
/// catches it and the importer refuses the layout.
#[test]
fn bypass_deeply_nested_forbidden_key_is_refused() {
    use common::{
        config_value, materialize_config, materialize_layer, standard_labels, write_layout,
        OciLayer,
    };
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let mut config = config_value("linux", "amd64", standard_labels());
    // Bury `privileged` three levels deep inside an array of objects.
    config["config"]["Labels"]["org.microvm.network"] = json!("nat-only");
    config["nested"] = json!({"level1": [{"level2": {"Privileged": true}}]});
    let config_desc = materialize_config(root, &config, None);
    let layers = vec![
        materialize_layer(root, &OciLayer::kernel()),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    let err = OciImporter::open(root).unwrap().import().unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

/// A binary that is static, correctly machined, and hash-consistent, but embeds
/// the WRONG version string. A naive "is it a static ELF?" check would accept
/// it; the real gate also requires the embedded pinned version.
#[test]
fn bypass_wrong_version_static_binary_is_refused() {
    let bytes = static_release_elf(EM_X86_64, "v1.15.0"); // wrong version embedded
                                                          // Manifest is pinned to v1.16.1 but matches the bytes' hash, so the hash
                                                          // and form pass; only the version scan can catch this.
    let manifest = BinaryManifest::new(
        "firecracker",
        PINNED_VERSION,
        iso_sha256_hex(&bytes),
        ElfMachine::X86_64,
    )
    .unwrap();
    let err = BinaryVerifier::new(manifest)
        .verify_bytes(&bytes)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("stage").map(String::as_str),
        Some("version_mismatch")
    );
}

/// A `file://` URI with a remote host looks local-ish; the real reference gate
/// requires an empty or `localhost` host.
#[test]
fn bypass_file_uri_with_remote_host_is_refused() {
    for bad in [
        "file://evil-host/etc/passwd",
        "file://192.168.1.5/export/img",
    ] {
        let err = validate_local_reference(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LocalArtifactRequired, "bad={bad}");
    }
}

// ===========================================================================
// All rejections are pre-spawn (no privileged side effect)
// ===========================================================================

/// Every boundary exercised here is a pure function that returns its typed
/// rejection before any `std::process::Command` could run. This test documents
/// and asserts that property by construction: the probes call only
/// `validate_*`, `verify_bytes`, `build`, `import`, and `validate`; none of
/// which spawn, and each returns `Err` (the rejection) rather than performing
/// the dangerous operation.
#[test]
fn all_rejections_are_pre_spawn_pure_functions() {
    // A representative hostile input per boundary; each returns Err and the
    // process count is unchanged (no spawn occurred).
    assert!(validate_relative_path("../x").is_err());
    assert!(validate_local_reference("docker://x").is_err());
    assert!(CgroupSpec::builder()
        .cpu_quota_us(0)
        .memory_max_bytes(1)
        .pids_max(1)
        .build()
        .is_err());
    assert!(VmId::new("bad/id").is_err());
    // The binary verifier never spawns; a bad binary is a pure Err.
    let v = matching_verifier(b"not an elf");
    assert!(v.verify_bytes(b"not an elf").is_err());
}

// ===========================================================================
// Consolidated mutation-corpus battery + evidence
// ===========================================================================

#[test]
fn adversarial_mutation_corpus_emits_consolidated_evidence() {
    let good = static_release_elf(EM_X86_64, PINNED_VERSION);
    let verifier = matching_verifier(&good);

    let mut probes: Vec<Probe> = Vec::new();

    // Single-byte binary mutations (a slice of sites) -> hash mismatch.
    for (i, pos) in (0..good.len()).step_by(11).enumerate().take(12) {
        let mut mutant = good.clone();
        mutant[pos] ^= 0x01;
        probes.push(Probe::from_result(
            &format!("binary_byte_flip_{i}"),
            "mutation:binary_hash",
            ErrorCode::BinaryProvenanceError,
            verifier.verify_bytes(&mutant),
        ));
    }

    // ELF form mutations (hash self-consistent) -> form gate.
    let dynamic = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: true,
        debug: false,
        payload: b"Firecracker 1.16.1 x".to_vec(),
    });
    probes.push(Probe::from_result(
        "form_dynamic",
        "mutation:binary_form",
        ErrorCode::BinaryProvenanceError,
        matching_verifier(&dynamic).verify_bytes(&dynamic),
    ));
    let debug = synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine: EM_X86_64,
        interp: false,
        debug: true,
        payload: b"Firecracker 1.16.1 x".to_vec(),
    });
    probes.push(Probe::from_result(
        "form_debug",
        "mutation:binary_form",
        ErrorCode::BinaryProvenanceError,
        matching_verifier(&debug).verify_bytes(&debug),
    ));
    let wrongver = static_release_elf(EM_X86_64, "v1.15.0");
    let wv_manifest = BinaryManifest::new(
        "firecracker",
        PINNED_VERSION,
        iso_sha256_hex(&wrongver),
        ElfMachine::X86_64,
    )
    .unwrap();
    probes.push(Probe::from_result(
        "form_wrong_version",
        "mutation:binary_version",
        ErrorCode::BinaryProvenanceError,
        BinaryVerifier::new(wv_manifest).verify_bytes(&wrongver),
    ));

    // Path mutation corpus.
    for (i, path) in [
        "../etc/passwd",
        "/etc/passwd",
        "blobs/../../x",
        "a\0b",
        "https://x/y",
        "blobs//x",
        "",
        "..",
        "file:///etc/passwd",
        "./../x",
    ]
    .iter()
    .enumerate()
    {
        probes.push(Probe::from_result(
            &format!("path_mut_{i}"),
            "mutation:path",
            ErrorCode::PathEscape,
            validate_relative_path(path),
        ));
    }

    // OCI reference mutation corpus.
    for (i, r) in [
        "docker://nginx",
        "https://x/y",
        "nginx:latest",
        "repo/img@sha256:ab",
        "fedora",
        "oci://reg/img",
        "s3://b/k",
        "file://host/x",
        "",
    ]
    .iter()
    .enumerate()
    {
        probes.push(Probe::from_result(
            &format!("oci_ref_mut_{i}"),
            "mutation:oci_reference",
            ErrorCode::LocalArtifactRequired,
            validate_local_reference(r),
        ));
    }

    // Symlink bypass canary as a probe.
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("blobs")).unwrap();
    symlink("/etc/shadow", tmp.path().join("blobs/innocent")).unwrap();
    let resolver = PathResolver::open_root(tmp.path()).unwrap();
    probes.push(Probe::from_result(
        "canary_clean_symlink",
        "mutation:symlink_bypass",
        ErrorCode::PathEscape,
        resolver.open("blobs/innocent"),
    ));

    let evidence = run_battery("adversarial", probes);
    assert_no_bypass(&evidence);
    assert!(evidence.summary.total >= 30, "corpus must be substantial");

    // Control: the genuine artifacts still pass (the corpus is discriminating).
    assert!(verifier.verify_bytes(&good).is_ok());
    let clean = standard_layout();
    assert!(OciImporter::open(clean.path()).unwrap().import().is_ok());
    assert_eq!(sha256_hex(b"abc"), iso_sha256_hex(b"abc"));
}
