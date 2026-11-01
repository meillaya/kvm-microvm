//! Pinned Firecracker/jailer binary provenance gate and validated jailer argv.
//!
//! This module owns the orchestrator's binary provenance boundary. Before
//! any microVM process is spawned, the exact Firecracker and jailer release
//! binaries are pinned by SHA-256 and verified on disk. A binary is accepted
//! only when *every* check passes; otherwise the gate fails closed with
//! [`ErrorCode::BinaryProvenanceError`] before any child process exists.
//!
//! # Provenance model
//! - A [`BinaryManifest`] pins one binary: a role name (`firecracker`/`jailer`),
//!   a release version (the pinned [`PINNED_VERSION`]), a lowercase-hex SHA-256,
//!   and an expected [`ElfMachine`].
//! - [`BinaryVerifier::verify_path`] reads the binary and, in order:
//!   1. confirms the manifest is pinned to [`PINNED_VERSION`],
//!   2. recomputes the SHA-256 and requires an exact match,
//!   3. parses the ELF header and requires the release/static form,
//!   4. confirms the binary embeds the pinned version string.
//!
//! # ELF release/static form
//! The genuine Firecracker/jailer release artifacts are statically linked musl
//! binaries. The form check requires:
//! - ELF64, little-endian,
//! - `e_type` is `ET_EXEC` or `ET_DYN` (the x86_64 release is a PIE/`ET_DYN`,
//!   the aarch64 release is `ET_EXEC`: both are accepted),
//! - `e_machine` matches the manifest,
//! - no `PT_INTERP` program header: a dynamically linked GNU/glibc binary
//!   carries an interpreter (`ld-linux-*.so`); a static musl binary has none,
//! - no `.debug_*` sections: a debug build carries DWARF; the stripped
//!   release does not (the release *does* keep `.symtab`, so `.symtab` alone is
//!   not a debug signal).
//!
//! # Jailer argv contract
//! [`JailerArgv`] is a validated launcher argument vector. The jailer defaults
//! `--cgroup-version` to v1, so the generated argv always pins
//! `--cgroup-version=2` and points `--parent-cgroup` at a pre-created leaf. It
//! also requires a `--netns`, a non-root `--uid`/`--gid`, and at least one
//! bounded `--resource-limit`. Invalid argv fails closed with
//! [`ErrorCode::InvalidResourceSpec`] before spawn.
//!
//! # Seccomp (post-exec)
//! The jailer performs chroot/cgroup/netns/UID-drop and exec, but does not
//! install seccomp; Firecracker installs per-thread seccomp *after* exec and
//! before guest code. [`SeccompVerifier`] is a post-exec stub that reads
//! `/proc/<pid>/status` and requires `Seccomp: 2` (filter mode) once the API is
//! ready. A missing/non-filter mode yields [`ErrorCode::ProcessSpawnError`].
//!
//! # Error contract
//! - [`ErrorCode::BinaryProvenanceError`]: binary hash/version/ELF-form failures
//!   and any condition that prevents establishing provenance (pre-spawn).
//! - [`ErrorCode::InvalidResourceSpec`]: invalid jailer argv configuration
//!   (non-root UID/GID, required flags, bounded resource limits) (pre-spawn).
//! - [`ErrorCode::ProcessSpawnError`]: post-exec seccomp-state assertion.
//!
//! # Determinism
//! Manifest validation, SHA-256 computation, ELF parsing, version scanning, argv
//! generation, and seccomp-status parsing are pure. [`BinaryVerifier::verify_path`]
//! and [`SeccompVerifier::verify_pid`] take configurable roots and are exercised
//! against temporary/synthetic inputs in the default test run; verifying a real
//! installed binary and reading a real `/proc` live behind the `privileged`
//! feature (`cargo test --features privileged --test jailer_invocation`). This
//! module never spawns a process: every rejection happens before any
//! `std::process::Command` could run.
//!
//! [`ErrorCode::BinaryProvenanceError`]: microvm_errors::ErrorCode::BinaryProvenanceError
//! [`ErrorCode::InvalidResourceSpec`]: microvm_errors::ErrorCode::InvalidResourceSpec
//! [`ErrorCode::ProcessSpawnError`]: microvm_errors::ErrorCode::ProcessSpawnError

use crate::manager::CGROUP_VERSION;
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The pinned Firecracker/jailer release version.
pub const PINNED_VERSION: &str = "v1.16.1";

// -- ELF constants ----------------------------------------------------------

const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_INTERP: u32 = 3;
const ELF_HEADER_LEN: usize = 64;
const ELF64_SHDR_LEN: usize = 64;

// -- Pinned binary SHA-256 (official v1.16.1 release artifacts) -------------
// Verified against the SHA256SUMS shipped inside each release tarball.

const FC_X86_64_SHA256: &str = "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7";
const JAILER_X86_64_SHA256: &str =
    "1f3a0c1fe86212d0001819bfe0819071c01208b3ccc9398c3b3bc1b84cf21edd";
const FC_AARCH64_SHA256: &str = "71ca0733576579a75cef268a8fd0ae0629b761b9844559c611f144132ac6038a";
const JAILER_AARCH64_SHA256: &str =
    "7db39d34991ccdd8d12aacab384b1dcbe35e79c27823e4e4d33725d4b504edd7";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a [`ErrorCode::BinaryProvenanceError`] tagged with a provenance stage.
fn provenance(stage: &str, message: &str) -> MicrovmError {
    MicrovmError::new(ErrorCode::BinaryProvenanceError, message).with_context("stage", stage)
}

/// Compute the lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut s, "{byte:02x}");
    }
    s
}

/// Best-effort: does `version` look like a pinned release tag (`vMAJOR.MINOR.PATCH`)?
fn valid_version(version: &str) -> bool {
    let rest = version.strip_prefix('v').unwrap_or("");
    let mut parts = rest.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    [a, b, c]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|x| x.is_ascii_digit()))
}

/// Is `s` a 64-character hex string (case-insensitive)?
fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Does `id` look like a safe jailer `--id` (non-empty, no whitespace/control)?
fn valid_id(id: &str) -> bool {
    !id.is_empty() && !id.chars().any(|c| c.is_whitespace() || c.is_control())
}

// ---------------------------------------------------------------------------
// ElfMachine
// ---------------------------------------------------------------------------

/// The ELF target machine a pinned binary must be built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElfMachine {
    /// `EM_X86_64` (62).
    X86_64,
    /// `EM_AARCH64` (183).
    AArch64,
}

impl ElfMachine {
    /// The ELF `e_machine` numeric code.
    pub fn code(self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::AArch64 => 183,
        }
    }

    /// Parse an ELF `e_machine` code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            62 => Some(Self::X86_64),
            183 => Some(Self::AArch64),
            _ => None,
        }
    }

    /// A stable human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::AArch64 => "aarch64",
        }
    }
}

// ---------------------------------------------------------------------------
// BinaryManifest
// ---------------------------------------------------------------------------

/// A pinned binary provenance record: role, version, SHA-256, and ELF machine.
///
/// All fields are validated at construction. The SHA-256 is stored lowercase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryManifest {
    name: String,
    version: String,
    sha256: String,
    machine: ElfMachine,
}

impl BinaryManifest {
    /// Create a manifest, validating the name, version, and SHA-256 format.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        sha256: impl Into<String>,
        machine: ElfMachine,
    ) -> Result<Self, MicrovmError> {
        let name = name.into();
        let version = version.into();
        let sha256 = sha256.into();

        if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(
                provenance("manifest", "binary name is empty or unsafe").with_context("name", name)
            );
        }
        if !valid_version(&version) {
            return Err(
                provenance("manifest", "version is not a pinned vMAJOR.MINOR.PATCH tag")
                    .with_context("version", version),
            );
        }
        if !valid_sha256(&sha256) {
            return Err(provenance("manifest", "sha256 is not 64 hex characters")
                .with_context("sha256", sha256));
        }
        Ok(Self {
            name,
            version,
            sha256: sha256.to_ascii_lowercase(),
            machine,
        })
    }

    /// The binary role name (`firecracker` or `jailer`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The pinned release version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The expected lowercase-hex SHA-256.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The expected ELF machine.
    pub fn machine(&self) -> ElfMachine {
        self.machine
    }

    /// True iff this manifest is pinned to [`PINNED_VERSION`].
    pub fn is_pinned(&self) -> bool {
        self.version == PINNED_VERSION
    }
}

/// The pinned Firecracker release manifest for `machine`.
pub fn pinned_firecracker(machine: ElfMachine) -> BinaryManifest {
    let sha = match machine {
        ElfMachine::X86_64 => FC_X86_64_SHA256,
        ElfMachine::AArch64 => FC_AARCH64_SHA256,
    };
    BinaryManifest::new("firecracker", PINNED_VERSION, sha, machine)
        .expect("pinned firecracker manifest is valid")
}

/// The pinned jailer release manifest for `machine`.
pub fn pinned_jailer(machine: ElfMachine) -> BinaryManifest {
    let sha = match machine {
        ElfMachine::X86_64 => JAILER_X86_64_SHA256,
        ElfMachine::AArch64 => JAILER_AARCH64_SHA256,
    };
    BinaryManifest::new("jailer", PINNED_VERSION, sha, machine)
        .expect("pinned jailer manifest is valid")
}

// ---------------------------------------------------------------------------
// ELF form parsing
// ---------------------------------------------------------------------------

/// A summary of the ELF form relevant to the release/static gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfForm {
    /// The ELF `e_machine` code.
    pub machine: u16,
    /// The ELF `e_type` (`ET_EXEC` or `ET_DYN`).
    pub elf_type: u16,
    /// True when no `PT_INTERP` program header is present (statically linked).
    pub statically_linked: bool,
    /// True when any section name begins with `.debug` (a debug build).
    pub has_debug_sections: bool,
    /// All section names (for diagnostics/evidence).
    pub section_names: Vec<String>,
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Compute `base + index * entsize` as a `usize`, failing on overflow.
fn table_offset(base: u64, index: usize, entsize: u16) -> Option<usize> {
    let base = usize::try_from(base).ok()?;
    let span = (entsize as usize).checked_mul(index)?;
    base.checked_add(span)
}

/// Read a NUL-terminated string from `table` starting at `start`.
fn cstr_at(table: &[u8], start: usize) -> Option<String> {
    let slice = table.get(start..)?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// True iff any program header is `PT_INTERP` (a dynamic interpreter is set).
fn has_interp(bytes: &[u8], phoff: u64, phentsize: u16, phnum: u16) -> Result<bool, MicrovmError> {
    if phnum == 0 {
        return Ok(false);
    }
    if (phentsize as usize) < 4 {
        return Err(provenance("elf_phdr", "program header entry too small"));
    }
    for i in 0..phnum as usize {
        let off = table_offset(phoff, i, phentsize)
            .ok_or_else(|| provenance("elf_phdr", "program header offset overflow"))?;
        let p_type = rd_u32(bytes, off)
            .ok_or_else(|| provenance("elf_phdr", "program header out of bounds"))?;
        if p_type == PT_INTERP {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Collect all section names via the section-header string table.
fn section_names(
    bytes: &[u8],
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
) -> Result<Vec<String>, MicrovmError> {
    if shnum == 0 {
        return Ok(Vec::new());
    }
    if (shentsize as usize) < ELF64_SHDR_LEN {
        return Err(provenance("elf_shdr", "section header entry too small"));
    }
    if shstrndx >= shnum {
        return Err(provenance(
            "elf_shdr",
            "section-header string index out of range",
        ));
    }
    let strhdr = table_offset(shoff, shstrndx as usize, shentsize)
        .ok_or_else(|| provenance("elf_shdr", "section header offset overflow"))?;
    let str_off = rd_u64(bytes, strhdr + 24)
        .ok_or_else(|| provenance("elf_shdr", "shstrtab offset out of bounds"))?;
    let str_size = rd_u64(bytes, strhdr + 32)
        .ok_or_else(|| provenance("elf_shdr", "shstrtab size out of bounds"))?;
    let start = usize::try_from(str_off)
        .ok()
        .and_then(|s| Some((s, s.checked_add(usize::try_from(str_size).ok()?)?)))
        .ok_or_else(|| provenance("elf_shdr", "shstrtab range overflow"))?;
    let table = bytes
        .get(start.0..start.1)
        .ok_or_else(|| provenance("elf_shdr", "shstrtab out of bounds"))?;

    let mut names = Vec::with_capacity(shnum as usize);
    for i in 0..shnum as usize {
        let off = table_offset(shoff, i, shentsize)
            .ok_or_else(|| provenance("elf_shdr", "section header offset overflow"))?;
        let sh_name = rd_u32(bytes, off)
            .ok_or_else(|| provenance("elf_shdr", "section header out of bounds"))?;
        names.push(cstr_at(table, sh_name as usize).unwrap_or_default());
    }
    Ok(names)
}

/// Parse the ELF form of `bytes`, rejecting non-ELF/non-ELF64/non-executable
/// input with [`ErrorCode::BinaryProvenanceError`].
pub fn parse_elf_form(bytes: &[u8]) -> Result<ElfForm, MicrovmError> {
    if bytes.len() < ELF_HEADER_LEN {
        return Err(provenance(
            "elf_header",
            "file smaller than an ELF64 header",
        ));
    }
    if bytes[0..4] != ELFMAG {
        return Err(provenance("elf_header", "missing ELF magic"));
    }
    if bytes[EI_CLASS] != ELFCLASS64 {
        return Err(provenance(
            "elf_header",
            "required a 64-bit ELF (ELFCLASS64)",
        ));
    }
    if bytes[EI_DATA] != ELFDATA2LSB {
        return Err(provenance("elf_header", "required a little-endian ELF"));
    }
    let elf_type = rd_u16(bytes, 16).expect("header bounds checked above");
    let machine = rd_u16(bytes, 18).expect("header bounds checked above");
    if elf_type != ET_EXEC && elf_type != ET_DYN {
        return Err(provenance(
            "elf_header",
            "required ET_EXEC or ET_DYN (PIE) executable",
        ));
    }
    let phoff = rd_u64(bytes, 32).expect("header bounds checked above");
    let shoff = rd_u64(bytes, 40).expect("header bounds checked above");
    let phentsize = rd_u16(bytes, 54).expect("header bounds checked above");
    let phnum = rd_u16(bytes, 56).expect("header bounds checked above");
    let shentsize = rd_u16(bytes, 58).expect("header bounds checked above");
    let shnum = rd_u16(bytes, 60).expect("header bounds checked above");
    let shstrndx = rd_u16(bytes, 62).expect("header bounds checked above");

    let statically_linked = !has_interp(bytes, phoff, phentsize, phnum)?;
    let section_names = section_names(bytes, shoff, shentsize, shnum, shstrndx)?;
    let has_debug_sections = section_names.iter().any(|n| n.starts_with(".debug"));
    Ok(ElfForm {
        machine,
        elf_type,
        statically_linked,
        has_debug_sections,
        section_names,
    })
}

/// Enforce the release/static ELF form against the manifest's machine.
fn require_release_static(form: &ElfForm, expected: ElfMachine) -> Result<(), MicrovmError> {
    if form.machine != expected.code() {
        return Err(provenance(
            "machine_mismatch",
            "ELF machine does not match the manifest",
        )
        .with_context("expected", expected.as_str())
        .with_context("actual", format!("0x{:x}", form.machine)));
    }
    if !form.statically_linked {
        return Err(provenance(
            "dynamic_binary",
            "binary is dynamically linked (PT_INTERP present); required a static/musl release, not GNU",
        ));
    }
    if form.has_debug_sections {
        return Err(provenance(
            "debug_build",
            "binary contains .debug_* sections; required a stripped release build",
        ));
    }
    Ok(())
}

/// Does `bytes` contain the pinned version string?
///
/// Release binaries embed the numeric `MAJOR.MINOR.PATCH` (e.g. `1.16.1`), not
/// the `v`-prefixed tag, so a leading `v` is stripped before scanning.
pub fn binary_contains_version(bytes: &[u8], version: &str) -> bool {
    let needle = version.strip_prefix('v').unwrap_or(version).as_bytes();
    if needle.is_empty() {
        return false;
    }
    bytes.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// VerifiedBinary + BinaryVerifier
// ---------------------------------------------------------------------------

/// A binary that passed every provenance check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBinary {
    path: Option<PathBuf>,
    sha256: String,
    version: String,
    machine: ElfMachine,
}

impl VerifiedBinary {
    /// The on-disk path, when verified via [`BinaryVerifier::verify_path`].
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The verified lowercase-hex SHA-256.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The verified pinned version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The verified ELF machine.
    pub fn machine(&self) -> ElfMachine {
        self.machine
    }
}

/// Verifies binaries against a pinned [`BinaryManifest`] before spawn.
#[derive(Clone, Debug)]
pub struct BinaryVerifier {
    manifest: BinaryManifest,
}

impl BinaryVerifier {
    /// Create a verifier for `manifest`.
    pub fn new(manifest: BinaryManifest) -> Self {
        Self { manifest }
    }

    /// The manifest this verifier checks against.
    pub fn manifest(&self) -> &BinaryManifest {
        &self.manifest
    }

    /// Verify in-memory `bytes` against the manifest (pure; no filesystem).
    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<VerifiedBinary, MicrovmError> {
        // 1. The manifest itself must be pinned to the release.
        if !self.manifest.is_pinned() {
            return Err(
                provenance("not_pinned", "manifest version is not the pinned release")
                    .with_context("version", self.manifest.version())
                    .with_context("pinned", PINNED_VERSION),
            );
        }
        // 2. Cryptographic hash match.
        let actual = sha256_hex(bytes);
        if actual != self.manifest.sha256() {
            return Err(provenance(
                "hash_mismatch",
                "binary sha256 does not match the pinned manifest",
            )
            .with_context("name", self.manifest.name())
            .with_context("expected", self.manifest.sha256())
            .with_context("actual", &actual));
        }
        // 3. ELF release/static form.
        let form = parse_elf_form(bytes)?;
        require_release_static(&form, self.manifest.machine())?;
        // 4. The binary self-reports the pinned version.
        if !binary_contains_version(bytes, self.manifest.version()) {
            return Err(provenance(
                "version_mismatch",
                "binary does not embed the pinned version string",
            )
            .with_context("version", self.manifest.version()));
        }
        Ok(VerifiedBinary {
            path: None,
            sha256: actual,
            version: self.manifest.version().to_string(),
            machine: self.manifest.machine(),
        })
    }

    /// Verify a binary file on disk before spawn.
    ///
    /// Reads the file and runs [`BinaryVerifier::verify_bytes`]. Any failure
    /// (including an unreadable file) yields [`ErrorCode::BinaryProvenanceError`]
    /// and no child process is spawned.
    pub fn verify_path(&self, path: &Path) -> Result<VerifiedBinary, MicrovmError> {
        let bytes = fs::read(path).map_err(|e| {
            provenance("io", "failed to read binary for provenance verification")
                .with_context("path", path.display().to_string())
                .with_context("io_error", e.to_string())
        })?;
        let mut verified = self.verify_bytes(&bytes)?;
        verified.path = Some(path.to_path_buf());
        Ok(verified)
    }
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

/// Upper bound for `RLIMIT_FSIZE` (bytes): 1 TiB.
pub const MAX_FSIZE_BYTES: u64 = 1 << 40;
/// Upper bound for `RLIMIT_NOFILE` (file descriptors): 1,048,576.
pub const MAX_NO_FILE: u64 = 1 << 20;
/// Recommended default `fsize` bound (matches the jailer documentation example).
pub const DEFAULT_FSIZE_BYTES: u64 = 250_000_000;
/// Recommended default `no-file` bound.
pub const DEFAULT_NO_FILE: u64 = 1024;

/// A jailer `--resource-limit` resource kind.
///
/// Firecracker v1.16.1 supports exactly `fsize` and `no-file`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ResourceKind {
    /// `RLIMIT_FSIZE`: maximum size in bytes of files the process may create.
    Fsize,
    /// `RLIMIT_NOFILE`: one greater than the maximum open file descriptor.
    NoFile,
}

impl ResourceKind {
    /// The jailer `--resource-limit` key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fsize => "fsize",
            Self::NoFile => "no-file",
        }
    }

    /// The maximum allowed value for this resource.
    pub fn max_value(self) -> u64 {
        match self {
            Self::Fsize => MAX_FSIZE_BYTES,
            Self::NoFile => MAX_NO_FILE,
        }
    }

    /// Parse a jailer resource key.
    pub fn parse(key: &str) -> Option<Self> {
        match key {
            "fsize" => Some(Self::Fsize),
            "no-file" => Some(Self::NoFile),
            _ => None,
        }
    }

    /// All supported resource kinds.
    pub fn all() -> &'static [ResourceKind] {
        &[Self::Fsize, Self::NoFile]
    }
}

// ---------------------------------------------------------------------------
// JailerArgv
// ---------------------------------------------------------------------------

/// A validated jailer launch argument vector.
///
/// Built via [`JailerArgv::builder`]; `build()` fails closed with
/// [`ErrorCode::InvalidResourceSpec`] when any required field is missing, the
/// UID/GID is root, or a resource limit is out of bounds. The rendered argv
/// always contains `--cgroup-version=2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailerArgv {
    jailer_binary: String,
    id: String,
    exec_file: String,
    uid: u32,
    gid: u32,
    parent_cgroup: String,
    netns: String,
    chroot_base_dir: Option<String>,
    resource_limits: BTreeMap<ResourceKind, u64>,
    daemonize: bool,
}

impl JailerArgv {
    /// Start building a jailer argv for `id`, exec-ing `exec_file`.
    pub fn builder(
        jailer_binary: impl Into<String>,
        exec_file: impl Into<String>,
        id: impl Into<String>,
    ) -> JailerArgvBuilder {
        JailerArgvBuilder {
            jailer_binary: jailer_binary.into(),
            exec_file: exec_file.into(),
            id: id.into(),
            uid: None,
            gid: None,
            parent_cgroup: None,
            netns: None,
            chroot_base_dir: None,
            resource_limits: BTreeMap::new(),
            daemonize: false,
        }
    }

    /// Render the full argv. Always contains `--cgroup-version=2`.
    pub fn argv(&self) -> Vec<String> {
        let mut a = Vec::with_capacity(16 + self.resource_limits.len() * 2);
        a.push(self.jailer_binary.clone());
        a.push("--id".to_string());
        a.push(self.id.clone());
        a.push("--exec-file".to_string());
        a.push(self.exec_file.clone());
        a.push("--uid".to_string());
        a.push(self.uid.to_string());
        a.push("--gid".to_string());
        a.push(self.gid.to_string());
        a.push(format!("--cgroup-version={CGROUP_VERSION}"));
        a.push("--parent-cgroup".to_string());
        a.push(self.parent_cgroup.clone());
        a.push("--netns".to_string());
        a.push(self.netns.clone());
        if let Some(dir) = &self.chroot_base_dir {
            a.push("--chroot-base-dir".to_string());
            a.push(dir.clone());
        }
        // BTreeMap iterates in key order, so this is deterministic.
        for (kind, value) in &self.resource_limits {
            a.push("--resource-limit".to_string());
            a.push(format!("{}={}", kind.as_str(), value));
        }
        if self.daemonize {
            a.push("--daemonize".to_string());
        }
        a
    }

    /// The non-root UID the jailer drops to.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The non-root GID the jailer drops to.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// The pre-created parent cgroup path.
    pub fn parent_cgroup(&self) -> &str {
        &self.parent_cgroup
    }

    /// The network namespace handle path.
    pub fn netns(&self) -> &str {
        &self.netns
    }

    /// The bounded resource limits.
    pub fn resource_limits(&self) -> &BTreeMap<ResourceKind, u64> {
        &self.resource_limits
    }
}

/// Builder for a validated [`JailerArgv`].
#[derive(Clone, Debug)]
pub struct JailerArgvBuilder {
    jailer_binary: String,
    exec_file: String,
    id: String,
    uid: Option<u32>,
    gid: Option<u32>,
    parent_cgroup: Option<String>,
    netns: Option<String>,
    chroot_base_dir: Option<String>,
    resource_limits: BTreeMap<ResourceKind, u64>,
    daemonize: bool,
}

impl JailerArgvBuilder {
    /// Set the UID the jailer drops to (must be non-root).
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Set the GID the jailer drops to (must be non-root).
    pub fn gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    /// Set the pre-created parent cgroup path.
    pub fn parent_cgroup(mut self, path: impl Into<String>) -> Self {
        self.parent_cgroup = Some(path.into());
        self
    }

    /// Set the network namespace handle path.
    pub fn netns(mut self, path: impl Into<String>) -> Self {
        self.netns = Some(path.into());
        self
    }

    /// Set the chroot base directory.
    pub fn chroot_base_dir(mut self, path: impl Into<String>) -> Self {
        self.chroot_base_dir = Some(path.into());
        self
    }

    /// Add a resource limit (validated against its bound at `build`).
    pub fn resource_limit(mut self, kind: ResourceKind, value: u64) -> Self {
        self.resource_limits.insert(kind, value);
        self
    }

    /// Add the recommended bounded resource limits.
    pub fn with_recommended_limits(mut self) -> Self {
        self.resource_limits
            .insert(ResourceKind::Fsize, DEFAULT_FSIZE_BYTES);
        self.resource_limits
            .insert(ResourceKind::NoFile, DEFAULT_NO_FILE);
        self
    }

    /// Request that the jailer daemonize.
    pub fn daemonize(mut self) -> Self {
        self.daemonize = true;
        self
    }

    /// Validate and build the argv, failing closed before spawn.
    pub fn build(self) -> Result<JailerArgv, MicrovmError> {
        let invalid = |message: &str| MicrovmError::new(ErrorCode::InvalidResourceSpec, message);

        if self.jailer_binary.is_empty() {
            return Err(
                invalid("jailer binary path is empty").with_context("field", "jailer_binary")
            );
        }
        if self.exec_file.is_empty() {
            return Err(invalid("exec-file path is empty").with_context("field", "exec_file"));
        }
        if !valid_id(&self.id) {
            return Err(
                invalid("id is empty or contains whitespace/control characters")
                    .with_context("field", "id"),
            );
        }
        let uid = self
            .uid
            .ok_or_else(|| invalid("uid is required").with_context("field", "uid"))?;
        let gid = self
            .gid
            .ok_or_else(|| invalid("gid is required").with_context("field", "gid"))?;
        if uid == 0 {
            return Err(invalid("uid must be non-root").with_context("uid", "0"));
        }
        if gid == 0 {
            return Err(invalid("gid must be non-root").with_context("gid", "0"));
        }
        let parent_cgroup = self
            .parent_cgroup
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                invalid("parent-cgroup is required").with_context("field", "parent_cgroup")
            })?;
        let netns = self
            .netns
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("netns is required").with_context("field", "netns"))?;
        if let Some(dir) = &self.chroot_base_dir {
            if dir.is_empty() {
                return Err(
                    invalid("chroot-base-dir is empty").with_context("field", "chroot_base_dir")
                );
            }
        }
        if self.resource_limits.is_empty() {
            return Err(invalid("at least one bounded --resource-limit is required"));
        }
        for (kind, value) in &self.resource_limits {
            if *value == 0 || *value > kind.max_value() {
                return Err(invalid("resource-limit out of bounds")
                    .with_context("resource", kind.as_str())
                    .with_context("value", value.to_string())
                    .with_context("max", kind.max_value().to_string()));
            }
        }

        Ok(JailerArgv {
            jailer_binary: self.jailer_binary,
            id: self.id,
            exec_file: self.exec_file,
            uid,
            gid,
            parent_cgroup,
            netns,
            chroot_base_dir: self.chroot_base_dir,
            resource_limits: self.resource_limits,
            daemonize: self.daemonize,
        })
    }
}

// ---------------------------------------------------------------------------
// Post-exec seccomp verification (stub)
// ---------------------------------------------------------------------------

/// `Seccomp:` value in `/proc/<pid>/status` when a seccomp filter is active.
pub const SECCOMP_MODE_FILTER: u8 = 2;

/// Default procfs root.
pub const DEFAULT_PROC_ROOT: &str = "/proc";

/// Parse the `Seccomp:` mode from a `/proc/<pid>/status` document.
pub fn parse_seccomp_mode(status: &str) -> Option<u8> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("Seccomp:")?;
        rest.trim().parse::<u8>().ok()
    })
}

/// Verify a parsed status document reports seccomp filter mode (`Seccomp: 2`).
///
/// The jailer does not install seccomp; Firecracker installs it after exec.
/// Call this only after API readiness. A missing or non-filter mode yields
/// [`ErrorCode::ProcessSpawnError`].
pub fn verify_seccomp_status(status: &str) -> Result<(), MicrovmError> {
    match parse_seccomp_mode(status) {
        Some(SECCOMP_MODE_FILTER) => Ok(()),
        Some(mode) => Err(MicrovmError::new(
            ErrorCode::ProcessSpawnError,
            "seccomp filter not active after exec",
        )
        .with_context("seccomp_mode", mode.to_string())
        .with_context("expected", SECCOMP_MODE_FILTER.to_string())),
        None => Err(MicrovmError::new(
            ErrorCode::ProcessSpawnError,
            "no Seccomp field in process status",
        )
        .with_context("expected", SECCOMP_MODE_FILTER.to_string())),
    }
}

/// Reads `/proc/<pid>/status` and requires seccomp filter mode after exec.
#[derive(Clone, Debug)]
pub struct SeccompVerifier {
    proc_root: PathBuf,
}

impl Default for SeccompVerifier {
    fn default() -> Self {
        Self::new(DEFAULT_PROC_ROOT)
    }
}

impl SeccompVerifier {
    /// Create a verifier rooted at `proc_root` (e.g. `/proc`).
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    /// The status file path for `pid`.
    pub fn status_path(&self, pid: u32) -> PathBuf {
        self.proc_root.join(pid.to_string()).join("status")
    }

    /// Read `<proc_root>/<pid>/status` and require `Seccomp: 2`.
    pub fn verify_pid(&self, pid: u32) -> Result<(), MicrovmError> {
        let path = self.status_path(pid);
        let status = fs::read_to_string(&path).map_err(|e| {
            MicrovmError::new(
                ErrorCode::ProcessSpawnError,
                "failed to read process status",
            )
            .with_context("path", path.display().to_string())
            .with_context("io_error", e.to_string())
        })?;
        verify_seccomp_status(&status)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Synthetic ELF builder ---------------------------------------------

    struct Opts {
        elf_type: u16,
        machine: u16,
        interp: bool,
        debug: bool,
        payload: Vec<u8>,
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

    /// Build a minimal but structurally valid ELF64 with controllable form.
    fn synth_elf(o: &Opts) -> Vec<u8> {
        // Section-header string table and name offsets.
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
        let s_off: u64 = 120; // shstrtab data offset (after 64B header + 56B phdr)
        let h_off: u64 = s_off + shstrtab.len() as u64; // section header table offset
        let shnum: u16 = if o.debug { 4 } else { 3 };
        let shstrndx: u16 = 1;

        let mut b = Vec::new();
        // e_ident (16 bytes).
        b.extend_from_slice(&[0x7f, b'E', b'L', b'F', ELFCLASS64, ELFDATA2LSB, 1, 0]);
        b.extend_from_slice(&[0u8; 8]);
        pu16(&mut b, o.elf_type); // e_type
        pu16(&mut b, o.machine); // e_machine
        pu32(&mut b, 1); // e_version
        pu64(&mut b, 0); // e_entry
        pu64(&mut b, phoff); // e_phoff
        pu64(&mut b, h_off); // e_shoff
        pu32(&mut b, 0); // e_flags
        pu16(&mut b, 64); // e_ehsize
        pu16(&mut b, 56); // e_phentsize
        pu16(&mut b, 1); // e_phnum
        pu16(&mut b, 64); // e_shentsize
        pu16(&mut b, shnum); // e_shnum
        pu16(&mut b, shstrndx); // e_shstrndx
        debug_assert_eq!(b.len(), 64);

        // One program header: PT_INTERP for dynamic, PT_LOAD otherwise.
        pu32(&mut b, if o.interp { PT_INTERP } else { 1 });
        pu32(&mut b, 0);
        pu64(&mut b, 0);
        pu64(&mut b, 0);
        pu64(&mut b, 0);
        pu64(&mut b, 0);
        pu64(&mut b, 0);
        pu64(&mut b, 0);
        debug_assert_eq!(b.len(), 120);

        // shstrtab data.
        b.extend_from_slice(&shstrtab);
        debug_assert_eq!(b.len() as u64, h_off);

        // Section headers.
        write_shdr(&mut b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); // null
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

        // Arbitrary payload (e.g. an embedded version string).
        b.extend_from_slice(&o.payload);
        b
    }

    /// A static release ELF for `machine` embedding the pinned version string.
    fn static_release_elf(machine: u16) -> Vec<u8> {
        synth_elf(&Opts {
            elf_type: ET_EXEC,
            machine,
            interp: false,
            debug: false,
            payload: b"Firecracker 1.16.1 provenance-test".to_vec(),
        })
    }

    /// A manifest whose hash matches `bytes` for `machine`.
    fn manifest_for(bytes: &[u8], machine: ElfMachine) -> BinaryManifest {
        BinaryManifest::new("firecracker", PINNED_VERSION, sha256_hex(bytes), machine).unwrap()
    }

    // -- BinaryManifest -----------------------------------------------------

    #[test]
    fn manifest_accepts_valid_record() {
        let m = BinaryManifest::new(
            "firecracker",
            "v1.16.1",
            "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7",
            ElfMachine::X86_64,
        )
        .unwrap();
        assert_eq!(m.name(), "firecracker");
        assert_eq!(m.version(), "v1.16.1");
        assert_eq!(m.machine(), ElfMachine::X86_64);
        assert!(m.is_pinned());
    }

    #[test]
    fn manifest_normalizes_sha256_to_lowercase() {
        let upper = "2FD0171309AF7E24CF8DAFC8A6F921C1434C49B5F9349BB996B7ED0A4DEB8AA7";
        let m = BinaryManifest::new("jailer", "v1.16.1", upper, ElfMachine::X86_64).unwrap();
        assert_eq!(m.sha256(), upper.to_ascii_lowercase());
    }

    #[test]
    fn manifest_rejects_bad_sha256() {
        for bad in [
            "",
            "abc",
            "zzz0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7",
        ] {
            let err =
                BinaryManifest::new("firecracker", "v1.16.1", bad, ElfMachine::X86_64).unwrap_err();
            assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        }
    }

    #[test]
    fn manifest_rejects_bad_version() {
        for bad in ["", "1.16.1", "v1.16", "v1.16.1.2", "va.b.c", "v1..1"] {
            let err = BinaryManifest::new(
                "firecracker",
                bad,
                "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7",
                ElfMachine::X86_64,
            )
            .unwrap_err();
            assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        }
    }

    #[test]
    fn manifest_rejects_empty_name() {
        let err = BinaryManifest::new(
            "",
            "v1.16.1",
            "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7",
            ElfMachine::X86_64,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    }

    #[test]
    fn pinned_manifests_are_well_formed() {
        for m in [
            pinned_firecracker(ElfMachine::X86_64),
            pinned_firecracker(ElfMachine::AArch64),
            pinned_jailer(ElfMachine::X86_64),
            pinned_jailer(ElfMachine::AArch64),
        ] {
            assert!(m.is_pinned());
            assert_eq!(m.version(), PINNED_VERSION);
            assert!(valid_sha256(m.sha256()));
        }
        assert_eq!(
            pinned_firecracker(ElfMachine::X86_64).sha256(),
            FC_X86_64_SHA256
        );
        assert_eq!(
            pinned_jailer(ElfMachine::AArch64).sha256(),
            JAILER_AARCH64_SHA256
        );
    }

    // -- sha256 / version scan ---------------------------------------------

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn version_scan_strips_v_prefix() {
        assert!(binary_contains_version(b"xx1.16.1yy", "v1.16.1"));
        assert!(binary_contains_version(b"xx1.16.1yy", "1.16.1"));
        assert!(binary_contains_version(b"v1.16.1", "v1.16.1")); // "v1.16.1" contains the bare "1.16.1"
        assert!(!binary_contains_version(b"nothing", "v1.16.1"));
        assert!(!binary_contains_version(b"anything", ""));
    }

    // -- ELF form parsing ---------------------------------------------------

    #[test]
    fn elf_static_release_is_accepted() {
        let bytes = static_release_elf(ElfMachine::X86_64.code());
        let form = parse_elf_form(&bytes).unwrap();
        assert_eq!(form.machine, ElfMachine::X86_64.code());
        assert_eq!(form.elf_type, ET_EXEC);
        assert!(form.statically_linked);
        assert!(!form.has_debug_sections);
    }

    #[test]
    fn elf_pie_static_is_accepted() {
        let bytes = synth_elf(&Opts {
            elf_type: ET_DYN,
            machine: ElfMachine::X86_64.code(),
            interp: false,
            debug: false,
            payload: b"1.16.1".to_vec(),
        });
        let form = parse_elf_form(&bytes).unwrap();
        assert_eq!(form.elf_type, ET_DYN);
        assert!(form.statically_linked);
    }

    #[test]
    fn elf_dynamic_interpreter_is_detected() {
        let bytes = synth_elf(&Opts {
            elf_type: ET_EXEC,
            machine: ElfMachine::X86_64.code(),
            interp: true,
            debug: false,
            payload: Vec::new(),
        });
        let form = parse_elf_form(&bytes).unwrap();
        assert!(!form.statically_linked);
    }

    #[test]
    fn elf_debug_section_is_detected() {
        let bytes = synth_elf(&Opts {
            elf_type: ET_EXEC,
            machine: ElfMachine::X86_64.code(),
            interp: false,
            debug: true,
            payload: Vec::new(),
        });
        let form = parse_elf_form(&bytes).unwrap();
        assert!(form.has_debug_sections);
        assert!(form.section_names.iter().any(|n| n == ".debug_info"));
    }

    #[test]
    fn elf_rejects_non_elf_and_truncated() {
        assert_eq!(
            parse_elf_form(b"not an elf at all").unwrap_err().code,
            ErrorCode::BinaryProvenanceError
        );
        assert_eq!(
            parse_elf_form(&[0x7f, b'E', b'L']).unwrap_err().code,
            ErrorCode::BinaryProvenanceError
        );
    }

    #[test]
    fn elf_rejects_wrong_class_and_endianness() {
        let mut bytes = static_release_elf(ElfMachine::X86_64.code());
        bytes[EI_CLASS] = 1; // ELFCLASS32
        assert_eq!(
            parse_elf_form(&bytes).unwrap_err().code,
            ErrorCode::BinaryProvenanceError
        );

        let mut bytes = static_release_elf(ElfMachine::X86_64.code());
        bytes[EI_DATA] = 2; // big-endian
        assert_eq!(
            parse_elf_form(&bytes).unwrap_err().code,
            ErrorCode::BinaryProvenanceError
        );
    }

    #[test]
    fn elf_rejects_non_executable_type() {
        let bytes = synth_elf(&Opts {
            elf_type: 1, // ET_REL
            machine: ElfMachine::X86_64.code(),
            interp: false,
            debug: false,
            payload: Vec::new(),
        });
        assert_eq!(
            parse_elf_form(&bytes).unwrap_err().code,
            ErrorCode::BinaryProvenanceError
        );
    }

    // -- BinaryVerifier -----------------------------------------------------

    #[test]
    fn verifier_accepts_matching_static_release() {
        let bytes = static_release_elf(ElfMachine::X86_64.code());
        let v = BinaryVerifier::new(manifest_for(&bytes, ElfMachine::X86_64));
        let verified = v.verify_bytes(&bytes).unwrap();
        assert_eq!(verified.sha256(), sha256_hex(&bytes));
        assert_eq!(verified.version(), PINNED_VERSION);
        assert_eq!(verified.machine(), ElfMachine::X86_64);
        assert!(verified.path().is_none());
    }

    #[test]
    fn verifier_rejects_hash_mismatch() {
        let bytes = static_release_elf(ElfMachine::X86_64.code());
        // Manifest with the correct format but a different (valid) hash.
        let other = static_release_elf(ElfMachine::AArch64.code());
        let m = BinaryManifest::new(
            "firecracker",
            PINNED_VERSION,
            sha256_hex(&other),
            ElfMachine::X86_64,
        )
        .unwrap();
        let err = BinaryVerifier::new(m).verify_bytes(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(
            err.context.get("stage").map(String::as_str),
            Some("hash_mismatch")
        );
    }

    #[test]
    fn verifier_rejects_debug_binary_even_with_matching_hash() {
        let bytes = synth_elf(&Opts {
            elf_type: ET_EXEC,
            machine: ElfMachine::X86_64.code(),
            interp: false,
            debug: true,
            payload: b"1.16.1".to_vec(),
        });
        let v = BinaryVerifier::new(manifest_for(&bytes, ElfMachine::X86_64));
        let err = v.verify_bytes(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(
            err.context.get("stage").map(String::as_str),
            Some("debug_build")
        );
    }

    #[test]
    fn verifier_rejects_gnu_dynamic_binary_even_with_matching_hash() {
        let bytes = synth_elf(&Opts {
            elf_type: ET_EXEC,
            machine: ElfMachine::X86_64.code(),
            interp: true,
            debug: false,
            payload: b"1.16.1".to_vec(),
        });
        let v = BinaryVerifier::new(manifest_for(&bytes, ElfMachine::X86_64));
        let err = v.verify_bytes(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(
            err.context.get("stage").map(String::as_str),
            Some("dynamic_binary")
        );
    }

    #[test]
    fn verifier_rejects_machine_mismatch() {
        let bytes = static_release_elf(ElfMachine::AArch64.code());
        // Hash matches the bytes, but the manifest claims x86_64.
        let v = BinaryVerifier::new(manifest_for(&bytes, ElfMachine::X86_64));
        let err = v.verify_bytes(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(
            err.context.get("stage").map(String::as_str),
            Some("machine_mismatch")
        );
    }

    #[test]
    fn verifier_rejects_missing_version_string() {
        let bytes = synth_elf(&Opts {
            elf_type: ET_EXEC,
            machine: ElfMachine::X86_64.code(),
            interp: false,
            debug: false,
            payload: b"no version here".to_vec(),
        });
        let v = BinaryVerifier::new(manifest_for(&bytes, ElfMachine::X86_64));
        let err = v.verify_bytes(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(
            err.context.get("stage").map(String::as_str),
            Some("version_mismatch")
        );
    }

    #[test]
    fn verifier_rejects_non_pinned_manifest() {
        let bytes = static_release_elf(ElfMachine::X86_64.code());
        let m = BinaryManifest::new(
            "firecracker",
            "v1.15.0",
            sha256_hex(&bytes),
            ElfMachine::X86_64,
        )
        .unwrap();
        let err = BinaryVerifier::new(m).verify_bytes(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(
            err.context.get("stage").map(String::as_str),
            Some("not_pinned")
        );
    }

    #[test]
    fn verifier_path_roundtrip_and_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bytes = static_release_elf(ElfMachine::X86_64.code());
        let path = tmp.path().join("firecracker");
        fs::write(&path, &bytes).unwrap();

        let v = BinaryVerifier::new(manifest_for(&bytes, ElfMachine::X86_64));
        let verified = v.verify_path(&path).unwrap();
        assert_eq!(verified.path(), Some(path.as_path()));

        // Missing file fails closed with provenance error, no spawn.
        let missing = tmp.path().join("does-not-exist");
        let err = v.verify_path(&missing).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(err.context.get("stage").map(String::as_str), Some("io"));
    }

    #[test]
    fn verifier_path_rejects_tampered_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bytes = static_release_elf(ElfMachine::X86_64.code());
        let path = tmp.path().join("firecracker");
        fs::write(&path, &bytes).unwrap();

        let v = BinaryVerifier::new(manifest_for(&bytes, ElfMachine::X86_64));
        // Tamper after the manifest was pinned.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        fs::write(&path, &tampered).unwrap();

        let err = v.verify_path(&path).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    }

    // -- JailerArgv ---------------------------------------------------------

    fn full_builder() -> JailerArgvBuilder {
        JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-001")
            .uid(10_000)
            .gid(10_000)
            .parent_cgroup("microvm/vm-001")
            .netns("/var/run/netns/microvm-vm-001")
            .with_recommended_limits()
    }

    #[test]
    fn argv_contains_required_flags() {
        let argv = full_builder().build().unwrap().argv();
        assert_eq!(argv[0], "/usr/bin/jailer");
        assert!(argv.contains(&"--cgroup-version=2".to_string()));
        assert!(argv.contains(&"--exec-file".to_string()));
        assert!(argv.contains(&"/usr/bin/firecracker".to_string()));
        assert!(argv.contains(&"--netns".to_string()));
        assert!(argv.contains(&"/var/run/netns/microvm-vm-001".to_string()));
        assert!(argv.contains(&"--uid".to_string()));
        assert!(argv.contains(&"10000".to_string()));
        assert!(argv.contains(&"--gid".to_string()));

        let idx = argv.iter().position(|a| a == "--parent-cgroup").unwrap();
        assert_eq!(argv[idx + 1], "microvm/vm-001");

        // Bounded resource limits rendered as key=value.
        assert!(argv.contains(&"--resource-limit".to_string()));
        assert!(argv.contains(&format!("fsize={DEFAULT_FSIZE_BYTES}")));
        assert!(argv.contains(&format!("no-file={DEFAULT_NO_FILE}")));
    }

    #[test]
    fn argv_is_deterministic() {
        let a = full_builder().daemonize().build().unwrap().argv();
        let b = full_builder().daemonize().build().unwrap().argv();
        assert_eq!(a, b);
        assert_eq!(a.last().map(String::as_str), Some("--daemonize"));
    }

    #[test]
    fn argv_rejects_root_uid_and_gid() {
        let err = full_builder().uid(0).build().unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        let err = full_builder().gid(0).build().unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn argv_rejects_missing_required_fields() {
        // Missing uid.
        let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-001")
            .gid(1000)
            .parent_cgroup("microvm/vm-001")
            .netns("/var/run/netns/x")
            .with_recommended_limits()
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);

        // Missing netns.
        let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-001")
            .uid(1000)
            .gid(1000)
            .parent_cgroup("microvm/vm-001")
            .with_recommended_limits()
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);

        // Missing parent-cgroup.
        let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-001")
            .uid(1000)
            .gid(1000)
            .netns("/var/run/netns/x")
            .with_recommended_limits()
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn argv_rejects_empty_id() {
        let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "bad id")
            .uid(1000)
            .gid(1000)
            .parent_cgroup("microvm/x")
            .netns("/var/run/netns/x")
            .with_recommended_limits()
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn argv_rejects_unbounded_resource_limits() {
        // Zero is not a valid bound.
        let err = full_builder()
            .resource_limit(ResourceKind::NoFile, 0)
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);

        // Above the maximum.
        let err = full_builder()
            .resource_limit(ResourceKind::NoFile, MAX_NO_FILE + 1)
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);

        let err = full_builder()
            .resource_limit(ResourceKind::Fsize, MAX_FSIZE_BYTES + 1)
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn argv_rejects_no_resource_limits() {
        let err = JailerArgv::builder("/usr/bin/jailer", "/usr/bin/firecracker", "vm-001")
            .uid(1000)
            .gid(1000)
            .parent_cgroup("microvm/vm-001")
            .netns("/var/run/netns/x")
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn resource_kind_roundtrip() {
        for kind in ResourceKind::all() {
            assert_eq!(ResourceKind::parse(kind.as_str()), Some(*kind));
            assert!(kind.max_value() > 0);
        }
        assert_eq!(ResourceKind::parse("bogus"), None);
    }

    // -- Seccomp stub -------------------------------------------------------

    const STATUS_FILTER: &str = "Name:\tfirecracker\nPid:\t4242\nSeccomp:\t2\n";
    const STATUS_DISABLED: &str = "Name:\tfirecracker\nPid:\t4242\nSeccomp:\t0\n";
    const STATUS_NO_FIELD: &str = "Name:\tfirecracker\nPid:\t4242\n";

    #[test]
    fn seccomp_parse_mode() {
        assert_eq!(parse_seccomp_mode(STATUS_FILTER), Some(2));
        assert_eq!(parse_seccomp_mode(STATUS_DISABLED), Some(0));
        assert_eq!(parse_seccomp_mode(STATUS_NO_FIELD), None);
    }

    #[test]
    fn seccomp_verify_requires_filter_mode() {
        assert!(verify_seccomp_status(STATUS_FILTER).is_ok());

        let err = verify_seccomp_status(STATUS_DISABLED).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProcessSpawnError);
        assert_eq!(
            err.context.get("seccomp_mode").map(String::as_str),
            Some("0")
        );

        let err = verify_seccomp_status(STATUS_NO_FIELD).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProcessSpawnError);
    }

    #[test]
    fn seccomp_verifier_reads_configurable_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_dir = tmp.path().join("4242");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("status"), STATUS_FILTER).unwrap();

        let v = SeccompVerifier::new(tmp.path());
        assert_eq!(v.status_path(4242), pid_dir.join("status"));
        assert!(v.verify_pid(4242).is_ok());

        // A pid with no status file fails with ProcessSpawnError.
        let err = v.verify_pid(9999).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProcessSpawnError);
    }
}
