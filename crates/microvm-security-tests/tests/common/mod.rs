//! Shared harness for the adversarial security suites.
//!
//! Two responsibilities:
//! 1. A **typed-error probe recorder** that runs each security boundary against
//!    a hostile input, captures the [`ErrorCode`] the production code returns,
//!    and emits a per-domain machine-readable evidence artifact. The recorder
//!    writes the artifact *before* the caller asserts, so a detected bypass
//!    still leaves evidence behind.
//! 2. **Synthetic fixtures** — controllable ELF64 binaries, on-disk OCI
//!    layouts, and simulated cgroup-v2 hierarchies — so the real production
//!    gates can be driven deterministically without root, KVM, or a pinned
//!    Firecracker install.

#![allow(dead_code)]

use microvm_errors::ErrorCode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;

// ===========================================================================
// Typed-error probe recorder + evidence artifact
// ===========================================================================

/// Anything that carries a stable [`ErrorCode`] the security boundary produced.
pub trait SecCode {
    /// The stable code for this rejection.
    fn sec_code(&self) -> ErrorCode;
}

impl SecCode for microvm_errors::MicrovmError {
    fn sec_code(&self) -> ErrorCode {
        self.code
    }
}

impl SecCode for ErrorCode {
    fn sec_code(&self) -> ErrorCode {
        *self
    }
}

impl SecCode for microvm_oci::ImportError {
    fn sec_code(&self) -> ErrorCode {
        self.code()
    }
}

impl SecCode for microvm_snapshots::SnapshotError {
    fn sec_code(&self) -> ErrorCode {
        self.code()
    }
}

/// Extract the code a boundary produced, or `None` when the operation
/// **succeeded** — which, for a hostile input, means a bypass.
pub fn outcome<T, E: SecCode>(result: Result<T, E>) -> Option<ErrorCode> {
    result.err().map(|e| e.sec_code())
}

/// One adversarial probe: a hostile input applied to a real boundary.
#[derive(Clone, Debug)]
pub struct Probe {
    /// Stable probe identifier (e.g. `symlink_escape_relative`).
    pub name: String,
    /// The trap class (e.g. `path:symlink_escape`).
    pub trap: String,
    /// The code the boundary MUST produce to be considered secure.
    pub expected: ErrorCode,
    /// The code the boundary actually produced (`None` == it succeeded == bypass).
    pub actual: Option<ErrorCode>,
    /// Free-form evidence detail (paths, digests, argv fragments).
    pub detail: String,
}

impl Probe {
    /// Build a probe from a boundary call result.
    pub fn from_result<T, E: SecCode>(
        name: &str,
        trap: &str,
        expected: ErrorCode,
        result: Result<T, E>,
    ) -> Self {
        Self {
            name: name.to_string(),
            trap: trap.to_string(),
            expected,
            actual: outcome(result),
            detail: String::new(),
        }
    }

    /// Attach evidence detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// True iff the boundary produced exactly the expected typed rejection.
    pub fn passed(&self) -> bool {
        self.actual == Some(self.expected)
    }
}

/// A serialized probe record (one item in the evidence artifact).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeRecord {
    /// Stable probe identifier.
    pub name: String,
    /// The trap class exercised.
    pub trap: String,
    /// The code the boundary must produce.
    pub expected_code: String,
    /// The code actually produced (`"bypass"` when the operation succeeded).
    pub actual_code: String,
    /// True iff `actual_code == expected_code`.
    pub pass: bool,
    /// Wall-clock duration of the probe in milliseconds.
    pub duration_ms: u64,
    /// Free-form evidence detail.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// Aggregate counts for the evidence artifact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSummary {
    /// Total probes recorded.
    pub total: usize,
    /// Probes where the boundary produced the expected typed rejection.
    pub pass: usize,
    /// Probes where the boundary did NOT (a bypass or wrong code).
    pub fail: usize,
}

/// A per-domain security evidence artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEvidence {
    /// Lane discriminator; security probes are deterministic.
    pub class: String,
    /// Schema identifier for this artifact shape.
    pub schema: String,
    /// The security domain (e.g. `path_security`).
    pub domain: String,
    /// Per-probe records.
    pub items: Vec<ProbeRecord>,
    /// Aggregate counts (`total == items.len()`, `pass + fail == total`).
    pub summary: EvidenceSummary,
}

/// The schema identifier embedded in every security evidence artifact.
pub const SECURITY_EVIDENCE_SCHEMA: &str = "microvm-security-tests/evidence/v1";

impl SecurityEvidence {
    /// Build an artifact from probes, reconciling the summary.
    pub fn from_probes(domain: &str, probes: &[Probe]) -> Self {
        let items = probes
            .iter()
            .map(|p| ProbeRecord {
                name: p.name.clone(),
                trap: p.trap.clone(),
                expected_code: p.expected.as_str().to_string(),
                actual_code: p
                    .actual
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_else(|| "bypass".to_string()),
                pass: p.passed(),
                duration_ms: 0,
                detail: p.detail.clone(),
            })
            .collect::<Vec<_>>();
        let pass = items.iter().filter(|i| i.pass).count();
        let total = items.len();
        Self {
            class: "security".to_string(),
            schema: SECURITY_EVIDENCE_SCHEMA.to_string(),
            domain: domain.to_string(),
            summary: EvidenceSummary {
                total,
                pass,
                fail: total - pass,
            },
            items,
        }
    }

    /// The directory security evidence artifacts are written to.
    pub fn evidence_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("MICROVM_SECURITY_EVIDENCE_DIR") {
            return PathBuf::from(dir);
        }
        // CARGO_MANIFEST_DIR = <workspace>/crates/microvm-security-tests
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .parent()
            .and_then(|p| p.parent())
            .map(|root| root.join("target").join("security-evidence"))
            .unwrap_or_else(|| PathBuf::from("target/security-evidence"))
    }

    /// Write this artifact to `<evidence_dir>/<domain>.json`, creating the dir.
    pub fn write(&self) -> PathBuf {
        let dir = Self::evidence_dir();
        std::fs::create_dir_all(&dir).expect("create security-evidence dir");
        let path = dir.join(format!("{}.json", self.domain));
        let json = serde_json::to_string_pretty(self).expect("serialize evidence");
        std::fs::write(&path, json).expect("write evidence artifact");
        // Round-trip to prove the artifact is well-formed and self-consistent.
        let back: SecurityEvidence = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
            .expect("evidence artifact must round-trip");
        assert_eq!(
            back.summary.total,
            back.items.len(),
            "summary.total reconciles"
        );
        assert_eq!(
            back.summary.pass + back.summary.fail,
            back.summary.total,
            "summary pass+fail reconciles"
        );
        path
    }
}

/// Run a battery of probes for `domain`: build the evidence artifact, write it
/// to disk, and return it. The caller then asserts no bypass via
/// [`assert_no_bypass`]. Evidence is written **before** any assertion so a
/// detected bypass still leaves an artifact behind.
pub fn run_battery(domain: &str, probes: Vec<Probe>) -> SecurityEvidence {
    let evidence = SecurityEvidence::from_probes(domain, &probes);
    let path = evidence.write();
    eprintln!(
        "[security] {}: {} probes, {} pass, {} fail -> {}",
        domain,
        evidence.summary.total,
        evidence.summary.pass,
        evidence.summary.fail,
        path.display()
    );
    evidence
}

/// Assert every probe produced its expected typed rejection; panic with a
/// precise bypass report otherwise.
pub fn assert_no_bypass(evidence: &SecurityEvidence) {
    let failures: Vec<&ProbeRecord> = evidence.items.iter().filter(|i| !i.pass).collect();
    if failures.is_empty() {
        return;
    }
    let mut report = String::new();
    for f in &failures {
        report.push_str(&format!(
            "  - {} [trap {}]: expected `{}`, got `{}`{}\n",
            f.name,
            f.trap,
            f.expected_code,
            f.actual_code,
            if f.detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", f.detail)
            }
        ));
    }
    panic!(
        "SECURITY BYPASS in domain `{}`: {} of {} probes did not produce the expected typed rejection:\n{}",
        evidence.domain,
        failures.len(),
        evidence.summary.total,
        report
    );
}

/// Time a probe closure, recording its duration into the returned record set.
/// (Used by the adversarial corpus to add timing evidence.)
pub fn timed_probe<T, E: SecCode, F: FnOnce() -> Result<T, E>>(
    name: &str,
    trap: &str,
    expected: ErrorCode,
    f: F,
) -> (Probe, u64) {
    let start = Instant::now();
    let result = f();
    let ms = start.elapsed().as_millis() as u64;
    (Probe::from_result(name, trap, expected, result), ms)
}

// ===========================================================================
// Synthetic ELF64 builder (drives the real binary-provenance gate)
// ===========================================================================

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
/// `ET_EXEC` (a non-PIE executable; the aarch64 release form).
pub const ET_EXEC: u16 = 2;
/// `ET_DYN` (a PIE; the x86_64 release form).
pub const ET_DYN: u16 = 3;
const PT_INTERP: u32 = 3;
const PT_LOAD: u32 = 1;
/// `EM_X86_64`.
pub const EM_X86_64: u16 = 62;
/// `EM_AARCH64`.
pub const EM_AARCH64: u16 = 183;

/// Options controlling the synthetic ELF's form.
pub struct ElfOpts {
    /// `ET_EXEC` or `ET_DYN`.
    pub elf_type: u16,
    /// The `e_machine` code.
    pub machine: u16,
    /// Emit a `PT_INTERP` program header (makes the binary "dynamically linked").
    pub interp: bool,
    /// Emit a `.debug_info` section (makes the binary a "debug build").
    pub debug: bool,
    /// Trailing payload bytes (e.g. an embedded version string).
    pub payload: Vec<u8>,
}

fn pu16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn pu32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn pu64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_shdr(
    b: &mut Vec<u8>,
    name: u32,
    typ: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
) {
    pu32(b, name);
    pu32(b, typ);
    pu64(b, flags);
    pu64(b, addr);
    pu64(b, offset);
    pu64(b, size);
    pu32(b, link);
    pu32(b, info);
    pu64(b, align);
    pu64(b, entsize);
}

/// Build a minimal but structurally valid ELF64 with a controllable form.
pub fn synth_elf(o: &ElfOpts) -> Vec<u8> {
    let mut shstrtab: Vec<u8> = vec![0];
    let off_shstrtab = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab");
    shstrtab.push(0);
    let off_debug = if o.debug {
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

    let phoff: u64 = 64;
    let s_off: u64 = 120;
    let h_off: u64 = s_off + shstrtab.len() as u64;
    let shnum: u16 = if o.debug { 4 } else { 3 };
    let shstrndx: u16 = 1;

    let mut b = Vec::new();
    b.extend_from_slice(&[0x7f, b'E', b'L', b'F', ELFCLASS64, ELFDATA2LSB, 1, 0]);
    b.extend_from_slice(&[0u8; 8]);
    pu16(&mut b, o.elf_type);
    pu16(&mut b, o.machine);
    pu32(&mut b, 1);
    pu64(&mut b, 0);
    pu64(&mut b, phoff);
    pu64(&mut b, h_off);
    pu32(&mut b, 0);
    pu16(&mut b, 64);
    pu16(&mut b, 56);
    pu16(&mut b, 1);
    pu16(&mut b, 64);
    pu16(&mut b, shnum);
    pu16(&mut b, shstrndx);
    debug_assert_eq!(b.len(), 64);

    pu32(&mut b, if o.interp { PT_INTERP } else { PT_LOAD });
    pu32(&mut b, 0);
    pu64(&mut b, 0);
    pu64(&mut b, 0);
    pu64(&mut b, 0);
    pu64(&mut b, 0);
    pu64(&mut b, 0);
    pu64(&mut b, 0);
    debug_assert_eq!(b.len(), 120);

    b.extend_from_slice(&shstrtab);
    debug_assert_eq!(b.len() as u64, h_off);

    write_shdr(&mut b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    write_shdr(
        &mut b,
        off_shstrtab,
        3,
        0,
        0,
        s_off,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    if let Some(od) = off_debug {
        write_shdr(&mut b, od, 1, 0, 0, 0, 0, 0, 0, 1, 0);
    }
    write_shdr(&mut b, off_text, 1, 0, 0, 0, 0, 0, 0, 1, 0);

    b.extend_from_slice(&o.payload);
    b
}

/// A static release ELF for `machine` embedding the pinned `version` string
/// (release binaries embed `MAJOR.MINOR.PATCH`, no leading `v`).
pub fn static_release_elf(machine: u16, version: &str) -> Vec<u8> {
    let needle = version.strip_prefix('v').unwrap_or(version);
    synth_elf(&ElfOpts {
        elf_type: ET_EXEC,
        machine,
        interp: false,
        debug: false,
        payload: format!("Firecracker {needle} provenance-fixture").into_bytes(),
    })
}

// ===========================================================================
// Simulated cgroup-v2 hierarchy (drives the real CgroupManager)
// ===========================================================================

/// Build a simulated unified cgroup-v2 hierarchy under `root` whose parent
/// exposes `available` controllers (space-separated).
pub fn simulate_cgroup_root(root: &std::path::Path, parent: &str, available: &str) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("cgroup.controllers"), "cpu memory pids io").unwrap();
    std::fs::write(root.join("cgroup.subtree_control"), "").unwrap();
    let p = root.join(parent);
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("cgroup.controllers"), available).unwrap();
    std::fs::write(p.join("cgroup.subtree_control"), "").unwrap();
}

// ===========================================================================
// On-disk OCI layout builder (drives the real OciImporter)
// ===========================================================================

pub const KERNEL_BYTES: &[u8] = b"microvm-guest-kernel-bzimage-sec-v1";
pub const ROOTFS_BYTES: &[u8] = b"microvm-guest-rootfs-ext4-sec-v1-bytes";

/// Lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    microvm_artifacts::compute_sha256(bytes).unwrap().to_hex()
}

/// Write `bytes` to `<root>/blobs/sha256/<hex>`.
pub fn write_blob(root: &std::path::Path, hex: &str, bytes: &[u8]) {
    let dir = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(hex), bytes).unwrap();
}

/// A layer to materialize, with optional overrides to craft hostile scenarios.
pub struct OciLayer {
    /// The `org.microvm.media` role annotation (`kernel`/`rootfs`), if any.
    pub role: Option<&'static str>,
    /// The layer bytes.
    pub bytes: Vec<u8>,
    /// Override the declared digest (to craft a mismatch).
    pub declared_digest: Option<String>,
    /// Override the declared size (to craft a size mismatch).
    pub declared_size: Option<u64>,
    /// Remote `urls` to attach (to craft a remote-descriptor rejection).
    pub urls: Option<Vec<String>>,
}

impl OciLayer {
    /// A standard kernel layer.
    pub fn kernel() -> Self {
        Self {
            role: Some("kernel"),
            bytes: KERNEL_BYTES.to_vec(),
            declared_digest: None,
            declared_size: None,
            urls: None,
        }
    }
    /// A standard rootfs layer.
    pub fn rootfs() -> Self {
        Self {
            role: Some("rootfs"),
            bytes: ROOTFS_BYTES.to_vec(),
            declared_digest: None,
            declared_size: None,
            urls: None,
        }
    }
}

/// Materialize a layer blob, returning its manifest descriptor JSON.
pub fn materialize_layer(root: &std::path::Path, layer: &OciLayer) -> serde_json::Value {
    use serde_json::json;
    let actual_hex = sha256_hex(&layer.bytes);
    let declared = layer
        .declared_digest
        .clone()
        .unwrap_or_else(|| format!("sha256:{actual_hex}"));
    let declared_hex = declared.strip_prefix("sha256:").unwrap().to_string();
    let size = layer.declared_size.unwrap_or(layer.bytes.len() as u64);
    write_blob(root, &declared_hex, &layer.bytes);
    let mut descriptor = json!({
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "digest": declared,
        "size": size,
    });
    if let Some(role) = layer.role {
        descriptor["annotations"] = json!({ microvm_oci::MEDIA_ANNOTATION: role });
    }
    if let Some(urls) = &layer.urls {
        descriptor["urls"] = json!(urls);
    }
    descriptor
}

/// Materialize a config blob, returning its manifest descriptor JSON.
pub fn materialize_config(
    root: &std::path::Path,
    value: &serde_json::Value,
    declared_digest: Option<String>,
) -> serde_json::Value {
    use serde_json::json;
    let bytes = serde_json::to_vec(value).unwrap();
    let actual_hex = sha256_hex(&bytes);
    let declared = declared_digest.unwrap_or_else(|| format!("sha256:{actual_hex}"));
    let declared_hex = declared.strip_prefix("sha256:").unwrap().to_string();
    write_blob(root, &declared_hex, &bytes);
    json!({
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": declared,
        "size": bytes.len(),
    })
}

/// Standard `org.microvm.*` labels for a small NAT-only VM.
pub fn standard_labels() -> serde_json::Map<String, serde_json::Value> {
    use serde_json::{Map, Value};
    let mut labels = Map::new();
    labels.insert("org.microvm.vcpu".into(), Value::from("2"));
    labels.insert("org.microvm.memory-mib".into(), Value::from("512"));
    labels.insert("org.microvm.disk-mib".into(), Value::from("1024"));
    labels.insert("org.microvm.network".into(), Value::from("nat-only"));
    labels.insert(
        "org.microvm.boot-args".into(),
        Value::from("console=ttyS0 reboot=k"),
    );
    labels
}

/// Build an image-config JSON value for `os`/`arch` with the given labels and
/// optional extra top-level/nested keys (to craft forbidden-field scenarios).
pub fn config_value(
    os: &str,
    arch: &str,
    labels: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "architecture": arch,
        "os": os,
        "config": { "Labels": labels },
        "rootfs": { "type": "layers", "diff_ids": [] },
    })
}

/// Write a complete OCI layout (`manifest.json` + blobs) under `root`.
pub fn write_layout(
    root: &std::path::Path,
    config_descriptor: serde_json::Value,
    layers: Vec<serde_json::Value>,
) {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": config_descriptor,
        "layers": layers,
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// Build a standard valid `linux/amd64` layout in a fresh tempdir.
pub fn standard_layout() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path();
    let config = config_value("linux", "amd64", standard_labels());
    let config_desc = materialize_config(root, &config, None);
    let layers = vec![
        materialize_layer(root, &OciLayer::kernel()),
        materialize_layer(root, &OciLayer::rootfs()),
    ];
    write_layout(root, config_desc, layers);
    tmp
}
