//! Host-substrate metadata gathering and lane-availability probing.
//!
//! This is the harness's I/O shell. Every reader degrades gracefully: a missing
//! or unreadable source yields a documented fallback (e.g. `kvm_api_version =
//! -1`) rather than a panic, so a benchmark artifact is always producible and
//! never lies about nested/cgroup-v2/KVM.
//!
//! Readers take configurable roots ([`HostProbe`]) so deterministic tests can
//! point them at fixture directories; the [`Default`] probe uses the real
//! `/proc`, `/sys`, `/dev/kvm`, and `/sys/fs/cgroup` paths.

use crate::config::PageCachePolicy;
use crate::outcome::BlockedReason;
use crate::result::HostMetadata;
use microvm_errors::{ErrorCode, MicrovmError};
use std::path::{Path, PathBuf};
use std::process::Command;

/// `KVM_GET_API_VERSION` ioctl request code (`_IO(KVMIO=0xAE, 0x00)`).
pub const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;

/// The stable KVM API version Linux has returned since KVM was merged.
pub const EXPECTED_KVM_API_VERSION: i64 = 12;

/// Probes the host substrate from configurable roots.
#[derive(Clone, Debug)]
pub struct HostProbe {
    /// Root of procfs (default `/proc`).
    pub proc_root: PathBuf,
    /// Root of sysfs (default `/sys`).
    pub sys_root: PathBuf,
    /// KVM device path (default `/dev/kvm`).
    pub kvm_device: PathBuf,
    /// cgroup root (default `/sys/fs/cgroup`).
    pub cgroup_root: PathBuf,
}

impl Default for HostProbe {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            sys_root: PathBuf::from("/sys"),
            kvm_device: PathBuf::from("/dev/kvm"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
        }
    }
}

impl HostProbe {
    /// Build a probe rooted at fixture directories (for tests).
    pub fn with_roots(
        proc_root: PathBuf,
        sys_root: PathBuf,
        kvm_device: PathBuf,
        cgroup_root: PathBuf,
    ) -> Self {
        Self {
            proc_root,
            sys_root,
            kvm_device,
            cgroup_root,
        }
    }

    /// Gather a complete [`HostMetadata`] snapshot.
    pub fn gather(&self, page_cache: PageCachePolicy) -> HostMetadata {
        HostMetadata {
            cpu: self.cpu_model(),
            kernel: self.kernel_release(),
            kvm_api_version: self.kvm_api_version(),
            page_cache_state: page_cache,
            memory_size_mib: self.memory_mib(),
            vcpu_count: self.vcpu_count(),
            cgroup_v2: self.cgroup_v2_available(),
            nested: self.nested_available(),
        }
    }

    /// CPU model string from `cpuinfo` "model name"; `unknown` if unreadable.
    pub fn cpu_model(&self) -> String {
        let path = self.proc_root.join("cpuinfo");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return "unknown".to_string();
        };
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("model name") {
                if let Some((_, value)) = rest.split_once(':') {
                    let value = value.trim();
                    if !value.is_empty() {
                        return value.to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    /// Kernel release (`uname -r` equivalent via `/proc/sys/kernel/osrelease`).
    pub fn kernel_release(&self) -> String {
        let path = self.proc_root.join("sys/kernel/osrelease");
        if let Ok(content) = std::fs::read_to_string(&path) {
            let value = content.trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
        uname_release().unwrap_or_else(|| "unknown".to_string())
    }

    /// `KVM_GET_API_VERSION`, or `-1` when `/dev/kvm` is inaccessible.
    pub fn kvm_api_version(&self) -> i64 {
        kvm_api_version_at(&self.kvm_device)
    }

    /// Total host RAM in MiB from `meminfo` "MemTotal"; `0` if unreadable.
    pub fn memory_mib(&self) -> u64 {
        let path = self.proc_root.join("meminfo");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return 0;
        };
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                // Format: "MemTotal:       65536000 kB"
                let mut parts = rest.split_whitespace();
                if let (Some(num), Some(unit)) = (parts.next(), parts.next()) {
                    if let Ok(kb) = num.parse::<u64>() {
                        return if unit == "kB" { kb / 1024 } else { kb };
                    }
                }
            }
        }
        0
    }

    /// Logical CPU count (`nproc`); `1` if undeterminable.
    pub fn vcpu_count(&self) -> u64 {
        nproc()
    }

    /// True iff the cgroup root exposes a unified v2 hierarchy with cpu, memory,
    /// and pids controllers available.
    pub fn cgroup_v2_available(&self) -> bool {
        let path = self.cgroup_root.join("cgroup.controllers");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return false;
        };
        let controllers: Vec<&str> = content.split_whitespace().collect();
        controllers.contains(&"cpu")
            && controllers.contains(&"memory")
            && controllers.contains(&"pids")
    }

    /// True iff nested virtualization is enabled (kvm_intel or kvm_amd `nested`).
    pub fn nested_available(&self) -> bool {
        for module in ["kvm_intel", "kvm_amd"] {
            let path = self
                .sys_root
                .join("module")
                .join(module)
                .join("parameters")
                .join("nested");
            if let Ok(content) = std::fs::read_to_string(&path) {
                let value = content.trim();
                if value == "Y" || value == "1" {
                    return true;
                }
            }
        }
        false
    }
}

/// `KVM_GET_API_VERSION` at a specific device path; `-1` when inaccessible.
pub fn kvm_api_version_at(device: &Path) -> i64 {
    let c_path = match std::ffi::CString::new(device.display().to_string()) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    // SAFETY: open(2) with a valid C string; the fd is closed before return.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return -1;
    }
    // SAFETY: ioctl on a valid open fd with the KVM_GET_API_VERSION request,
    // which takes no argument pointer.
    let version = unsafe { libc::ioctl(fd, KVM_GET_API_VERSION) };
    // SAFETY: close the fd we opened.
    unsafe { libc::close(fd) };
    if version < 0 {
        -1
    } else {
        version as i64
    }
}

/// Kernel release via `uname(2)`, if available.
fn uname_release() -> Option<String> {
    // SAFETY: uname writes into a zeroed utsname struct.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::uname(&mut uts) };
    if rc != 0 {
        return None;
    }
    // SAFETY: uname populated NUL-terminated arrays.
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    release.to_str().ok().map(|s| s.to_string())
}

/// Logical online CPU count via `sysconf`; `1` if undeterminable.
fn nproc() -> u64 {
    // SAFETY: sysconf with a valid constant; returns -1 on error.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n < 1 {
        1
    } else {
        n as u64
    }
}

/// True iff `name` is found as an executable on `PATH`.
pub fn binary_in_path(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return true;
        }
    }
    false
}

/// Probe the Firecracker version (`firecracker --version`); `None` if absent.
pub fn probe_firecracker_version() -> Option<String> {
    let output = Command::new("firecracker").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Expected: "Firecracker v1.16.1": take the last whitespace token, strip a
    // leading 'v'.
    stdout
        .lines()
        .next()?
        .split_whitespace()
        .last()
        .map(|tok| tok.trim_start_matches('v').to_string())
}

/// Probe the Docker Engine version; `None` if the binary or daemon is unavailable.
pub fn probe_docker_version() -> Option<String> {
    let output = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// The blocked reason for the Firecracker lane, or `None` if it can run.
///
/// Requires `/dev/kvm` and an installed `firecracker` binary.
pub fn firecracker_lane_block(probe: &HostProbe) -> Option<BlockedReason> {
    if probe.kvm_api_version() < 0 {
        return Some(BlockedReason::KvmUnavailable);
    }
    if !binary_in_path("firecracker") {
        return Some(BlockedReason::FirecrackerMissing);
    }
    None
}

/// The blocked reason for the Docker lane, or `None` if it can run.
pub fn docker_lane_block() -> Option<BlockedReason> {
    if !binary_in_path("docker") {
        return Some(BlockedReason::DockerMissing);
    }
    if probe_docker_version().is_none() {
        return Some(BlockedReason::DockerMissing);
    }
    None
}

/// Drop the host page cache (`echo 3 > /proc/sys/vm/drop_caches`).
///
/// Requires `CAP_SYS_ADMIN`; an unprivileged caller gets an error, which the
/// harness reports as [`BlockedReason::PageCacheDropUnsupported`] for the cold
/// condition rather than measuring cold under a warm cache.
///
/// # Errors
/// Returns [`ErrorCode::InternalError`] when the write fails.
pub fn drop_page_cache(proc_root: &Path) -> Result<(), MicrovmError> {
    let path = proc_root.join("sys/vm/drop_caches");
    std::fs::write(&path, "3").map_err(|e| {
        MicrovmError::new(ErrorCode::InternalError, "failed to drop page cache")
            .with_context("path", path.display().to_string())
            .with_context("io", e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a fixture proc/sys/cgroup tree and a probe rooted at it.
    fn fixture_probe(tmp: &Path) -> HostProbe {
        let proc = tmp.join("proc");
        let sys = tmp.join("sys");
        let cgroup = tmp.join("cgroup");
        fs::create_dir_all(proc.join("sys/kernel")).unwrap();
        fs::create_dir_all(proc.join("sys/vm")).unwrap();
        fs::create_dir_all(&cgroup).unwrap();
        fs::create_dir_all(&sys).unwrap();

        fs::write(
            proc.join("cpuinfo"),
            "processor\t: 0\nmodel name\t: Fixture CPU 9000\n",
        )
        .unwrap();
        fs::write(proc.join("sys/kernel/osrelease"), "7.1.3-fixture\n").unwrap();
        fs::write(proc.join("meminfo"), "MemTotal:       67108864 kB\n").unwrap();
        fs::write(cgroup.join("cgroup.controllers"), "cpu memory pids io\n").unwrap();

        HostProbe::with_roots(proc, sys, tmp.join("dev-kvm"), cgroup)
    }

    #[test]
    fn cpu_model_is_parsed_from_cpuinfo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path());
        assert_eq!(probe.cpu_model(), "Fixture CPU 9000");
    }

    #[test]
    fn kernel_release_is_read_from_proc() {
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path());
        assert_eq!(probe.kernel_release(), "7.1.3-fixture");
    }

    #[test]
    fn memory_mib_converts_kib() {
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path());
        assert_eq!(probe.memory_mib(), 67108864 / 1024);
    }

    #[test]
    fn cgroup_v2_detection() {
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path());
        assert!(probe.cgroup_v2_available());

        // A v1-style root without the unified controllers file is not v2.
        let v1 = tmp.path().join("v1cgroup");
        fs::create_dir_all(&v1).unwrap();
        let probe_v1 = HostProbe::with_roots(
            probe.proc_root.clone(),
            probe.sys_root.clone(),
            probe.kvm_device.clone(),
            v1,
        );
        assert!(!probe_v1.cgroup_v2_available());
    }

    #[test]
    fn nested_detection_reads_module_parameter() {
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path());
        assert!(!probe.nested_available());

        let nested_dir = probe.sys_root.join("module/kvm_amd/parameters");
        fs::create_dir_all(&nested_dir).unwrap();
        fs::write(nested_dir.join("nested"), "Y\n").unwrap();
        assert!(probe.nested_available());
    }

    #[test]
    fn kvm_api_version_is_minus_one_for_missing_device() {
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path()); // dev-kvm path does not exist
        assert_eq!(probe.kvm_api_version(), -1);
    }

    #[test]
    fn vcpu_count_is_at_least_one() {
        assert!(nproc() >= 1);
    }

    #[test]
    fn drop_page_cache_fails_without_privilege_on_fixture() {
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path());
        // The fixture drop_caches file is a regular file we own, so the write
        // succeeds; point at a read-only path to assert the error surface.
        let ro = tmp.path().join("ro");
        fs::create_dir_all(&ro).unwrap();
        let file = ro.join("sys");
        fs::write(&file, "").unwrap();
        // Writing to a path whose parent is a file must fail.
        assert!(drop_page_cache(&file).is_err());
        let _ = probe;
    }

    #[test]
    fn binary_in_path_finds_a_real_binary() {
        // `sh` exists on every POSIX host this crate targets.
        assert!(binary_in_path("sh"));
        assert!(!binary_in_path("definitely-not-a-real-binary-xyz"));
    }

    #[test]
    fn firecracker_lane_blocks_when_binary_absent() {
        // On a host without firecracker on PATH, the lane must block. We cannot
        // assume firecracker is absent, so assert the function returns a
        // well-formed Option without panicking.
        let tmp = tempfile::TempDir::new().unwrap();
        let probe = fixture_probe(tmp.path());
        // kvm is -1 in the fixture, so the lane blocks on KVM regardless of PATH.
        assert_eq!(
            firecracker_lane_block(&probe),
            Some(BlockedReason::KvmUnavailable)
        );
    }
}
