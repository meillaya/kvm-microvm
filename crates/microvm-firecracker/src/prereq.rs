//! Host prerequisite verification, run **before** any child process is created.
//!
//! The boot adapter must fail closed when the host lacks the capabilities a
//! Firecracker VM needs: a KVM device, a TUN device (when networking is
//! requested), present and provenance-verified Firecracker/jailer binaries, and
//! an available cgroup-v2 root. Every check here runs synchronously and returns
//! a typed [`MicrovmError`] before the backend spawns anything.
//!
//! The [`PrerequisiteCheck`] trait lets deterministic tests inject a scripted
//! checker; [`HostPrerequisiteChecker`] performs the real filesystem and binary
//! checks. Binary *presence* is always required; full SHA-256/ELF provenance
//! verification runs when a [`BinaryVerifier`] is supplied (production wires the
//! pinned manifests from [`microvm_isolation`]).

use microvm_errors::{ErrorCode, MicrovmError};
use microvm_isolation::{BinaryVerifier, CgroupManager};
use std::path::{Path, PathBuf};

/// Checks host prerequisites for booting a VM.
pub trait PrerequisiteCheck: Send + Sync {
    /// Verify all prerequisites.
    ///
    /// `net_required` selects whether the TUN device is mandatory (it is only
    /// needed when the VM attaches a network interface).
    ///
    /// # Errors
    /// Returns a typed [`MicrovmError`] for the first unmet prerequisite.
    fn check(&self, net_required: bool) -> Result<(), MicrovmError>;
}

/// Real host prerequisite checker.
///
/// Checks, in order (fail-fast, all before spawn):
/// 1. KVM device present.
/// 2. TUN device present (only when `net_required`).
/// 3. Firecracker binary present (and provenance-verified if a verifier is set).
/// 4. Jailer binary present (and provenance-verified if a verifier is set).
/// 5. cgroup-v2 root available.
#[derive(Clone)]
pub struct HostPrerequisiteChecker {
    kvm_device: PathBuf,
    tun_device: PathBuf,
    firecracker_binary: PathBuf,
    jailer_binary: PathBuf,
    firecracker_verifier: Option<BinaryVerifier>,
    jailer_verifier: Option<BinaryVerifier>,
    cgroup: CgroupManager,
}

impl HostPrerequisiteChecker {
    /// Start building a checker.
    pub fn builder() -> HostPrerequisiteCheckerBuilder {
        HostPrerequisiteCheckerBuilder::default()
    }

    /// The KVM device path checked.
    pub fn kvm_device(&self) -> &Path {
        &self.kvm_device
    }

    /// The cgroup manager used for the root-availability check.
    pub fn cgroup(&self) -> &CgroupManager {
        &self.cgroup
    }
}

impl PrerequisiteCheck for HostPrerequisiteChecker {
    fn check(&self, net_required: bool) -> Result<(), MicrovmError> {
        // 1. KVM device.
        if !self.kvm_device.exists() {
            return Err(MicrovmError::new(
                ErrorCode::InternalError,
                "host prerequisite missing: KVM device",
            )
            .with_context("prerequisite", "kvm")
            .with_context("path", self.kvm_device.display().to_string()));
        }

        // 2. TUN device (only when networking is requested).
        if net_required && !self.tun_device.exists() {
            return Err(MicrovmError::new(
                ErrorCode::InternalError,
                "host prerequisite missing: TUN device",
            )
            .with_context("prerequisite", "tun")
            .with_context("path", self.tun_device.display().to_string()));
        }

        // 3. Firecracker binary.
        verify_binary(
            "firecracker",
            &self.firecracker_binary,
            self.firecracker_verifier.as_ref(),
        )?;

        // 4. Jailer binary.
        verify_binary("jailer", &self.jailer_binary, self.jailer_verifier.as_ref())?;

        // 5. cgroup-v2 root.
        self.cgroup.require_root()?;

        Ok(())
    }
}

/// Verify a binary is present and, when a verifier is supplied, that its bytes
/// pass provenance verification.
fn verify_binary(
    role: &str,
    path: &Path,
    verifier: Option<&BinaryVerifier>,
) -> Result<(), MicrovmError> {
    if !path.is_file() {
        return Err(MicrovmError::new(
            ErrorCode::BinaryProvenanceError,
            format!("{} binary is missing", role),
        )
        .with_context("prerequisite", "binary")
        .with_context("role", role)
        .with_context("path", path.display().to_string()));
    }

    if let Some(verifier) = verifier {
        // verify_path reads the file and checks SHA-256 + ELF form, failing
        // closed with BinaryProvenanceError on any mismatch.
        verifier.verify_path(path).map_err(|e| {
            MicrovmError::new(
                ErrorCode::BinaryProvenanceError,
                format!("{} binary failed provenance verification", role),
            )
            .with_context("prerequisite", "binary")
            .with_context("role", role)
            .with_context("path", path.display().to_string())
            .with_context("cause", e.message)
        })?;
    }
    Ok(())
}

/// Builder for [`HostPrerequisiteChecker`].
#[derive(Clone, Default)]
pub struct HostPrerequisiteCheckerBuilder {
    kvm_device: Option<PathBuf>,
    tun_device: Option<PathBuf>,
    firecracker_binary: Option<PathBuf>,
    jailer_binary: Option<PathBuf>,
    firecracker_verifier: Option<BinaryVerifier>,
    jailer_verifier: Option<BinaryVerifier>,
    cgroup: Option<CgroupManager>,
}

impl HostPrerequisiteCheckerBuilder {
    /// Set the KVM device path (default `/dev/kvm`).
    pub fn kvm_device(mut self, path: impl Into<PathBuf>) -> Self {
        self.kvm_device = Some(path.into());
        self
    }

    /// Set the TUN device path (default `/dev/net/tun`).
    pub fn tun_device(mut self, path: impl Into<PathBuf>) -> Self {
        self.tun_device = Some(path.into());
        self
    }

    /// Set the Firecracker binary path.
    pub fn firecracker_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.firecracker_binary = Some(path.into());
        self
    }

    /// Set the jailer binary path.
    pub fn jailer_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.jailer_binary = Some(path.into());
        self
    }

    /// Attach a provenance verifier for the Firecracker binary.
    pub fn firecracker_verifier(mut self, verifier: BinaryVerifier) -> Self {
        self.firecracker_verifier = Some(verifier);
        self
    }

    /// Attach a provenance verifier for the jailer binary.
    pub fn jailer_verifier(mut self, verifier: BinaryVerifier) -> Self {
        self.jailer_verifier = Some(verifier);
        self
    }

    /// Set the cgroup manager (default root `/sys/fs/cgroup`).
    pub fn cgroup(mut self, cgroup: CgroupManager) -> Self {
        self.cgroup = Some(cgroup);
        self
    }

    /// Build the checker, applying defaults for unset paths.
    pub fn build(self) -> HostPrerequisiteChecker {
        HostPrerequisiteChecker {
            kvm_device: self.kvm_device.unwrap_or_else(|| PathBuf::from("/dev/kvm")),
            tun_device: self
                .tun_device
                .unwrap_or_else(|| PathBuf::from("/dev/net/tun")),
            firecracker_binary: self
                .firecracker_binary
                .unwrap_or_else(|| PathBuf::from("/usr/bin/firecracker")),
            jailer_binary: self
                .jailer_binary
                .unwrap_or_else(|| PathBuf::from("/usr/bin/jailer")),
            firecracker_verifier: self.firecracker_verifier,
            jailer_verifier: self.jailer_verifier,
            cgroup: self.cgroup.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Build a checker whose device/binary paths point into `dir` so each can be
    /// created or omitted independently. `cgroup_root` is the cgroup root dir.
    fn checker_in(
        dir: &Path,
        cgroup_root: &Path,
        with_kvm: bool,
        with_tun: bool,
        with_fc: bool,
        with_jailer: bool,
    ) -> HostPrerequisiteChecker {
        let kvm = dir.join("kvm");
        let tun = dir.join("tun");
        let fc = dir.join("firecracker");
        let jailer = dir.join("jailer");
        if with_kvm {
            fs::write(&kvm, b"").unwrap();
        }
        if with_tun {
            fs::write(&tun, b"").unwrap();
        }
        if with_fc {
            fs::write(&fc, b"").unwrap();
        }
        if with_jailer {
            fs::write(&jailer, b"").unwrap();
        }
        HostPrerequisiteChecker::builder()
            .kvm_device(kvm)
            .tun_device(tun)
            .firecracker_binary(fc)
            .jailer_binary(jailer)
            .cgroup(CgroupManager::new(cgroup_root))
            .build()
    }

    #[test]
    fn all_present_passes() {
        let tmp = TempDir::new().unwrap();
        let cgroup = tmp.path().join("cgroup");
        fs::create_dir_all(&cgroup).unwrap();
        let chk = checker_in(tmp.path(), &cgroup, true, true, true, true);
        assert!(chk.check(true).is_ok());
    }

    #[test]
    fn missing_kvm_fails_first() {
        let tmp = TempDir::new().unwrap();
        let cgroup = tmp.path().join("cgroup");
        fs::create_dir_all(&cgroup).unwrap();
        // Everything present except KVM.
        let chk = checker_in(tmp.path(), &cgroup, false, true, true, true);
        let err = chk.check(false).unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("prerequisite").map(String::as_str),
            Some("kvm")
        );
    }

    #[test]
    fn missing_tun_fails_only_when_net_required() {
        let tmp = TempDir::new().unwrap();
        let cgroup = tmp.path().join("cgroup");
        fs::create_dir_all(&cgroup).unwrap();
        let chk = checker_in(tmp.path(), &cgroup, true, false, true, true);
        // Without network, TUN is not required.
        assert!(chk.check(false).is_ok());
        // With network, missing TUN fails.
        let err = chk.check(true).unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("prerequisite").map(String::as_str),
            Some("tun")
        );
    }

    #[test]
    fn missing_firecracker_binary_fails() {
        let tmp = TempDir::new().unwrap();
        let cgroup = tmp.path().join("cgroup");
        fs::create_dir_all(&cgroup).unwrap();
        let chk = checker_in(tmp.path(), &cgroup, true, true, false, true);
        let err = chk.check(false).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(
            err.context.get("role").map(String::as_str),
            Some("firecracker")
        );
    }

    #[test]
    fn missing_jailer_binary_fails() {
        let tmp = TempDir::new().unwrap();
        let cgroup = tmp.path().join("cgroup");
        fs::create_dir_all(&cgroup).unwrap();
        let chk = checker_in(tmp.path(), &cgroup, true, true, true, false);
        let err = chk.check(false).unwrap_err();
        assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
        assert_eq!(err.context.get("role").map(String::as_str), Some("jailer"));
    }

    #[test]
    fn missing_cgroup_root_fails() {
        let tmp = TempDir::new().unwrap();
        // Point cgroup at a directory that does not exist.
        let cgroup = tmp.path().join("no-such-cgroup");
        let chk = checker_in(tmp.path(), &cgroup, true, true, true, true);
        let err = chk.check(false).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
    }

    #[test]
    fn check_order_kvm_before_binary() {
        let tmp = TempDir::new().unwrap();
        let cgroup = tmp.path().join("cgroup");
        fs::create_dir_all(&cgroup).unwrap();
        // KVM and binary both missing: KVM error wins (checked first).
        let chk = checker_in(tmp.path(), &cgroup, false, true, false, true);
        let err = chk.check(false).unwrap_err();
        assert_eq!(
            err.context.get("prerequisite").map(String::as_str),
            Some("kvm")
        );
    }

    #[test]
    fn builder_defaults() {
        let chk = HostPrerequisiteChecker::builder().build();
        assert_eq!(chk.kvm_device(), Path::new("/dev/kvm"));
    }
}
