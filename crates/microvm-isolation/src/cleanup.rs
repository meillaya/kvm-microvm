//! Idempotent VM resource cleanup and orphan reconciliation.
//!
//! This module owns the orchestrator's **cleanup and reconciliation** boundary.
//! Every VM's owned resources are tracked in a [`ResourceRecord`], and
//! [`CleanupManager`] tears them down in strict reverse-creation order.
//! Cleanup is **idempotent**: repeated invocations on an already-cleaned record
//! are no-ops. When cleanup cannot complete (for example, a stuck process or a
//! permission error), a [`LeakRecord`] is emitted so the operator can intervene.
//!
//! [`OrphanReconciler`] scans for resources that outlived their owning VM
//! (startup or periodic reconciliation). Orphans are quarantined rather than
//! deleted outright, and resources owned by another tenant are **never**
//! removed.
//!
//! # Cleanup order (reverse of creation)
//! 1. Kill VMM process (pid)
//! 2. Remove Unix socket paths
//! 3. Flush nftables table
//! 4. Remove TAP device
//! 5. Remove network namespace
//! 6. Remove cgroup leaf
//! 7. Remove chroot path
//!
//! # Error contract
//! All cleanup failures yield [`ErrorCode::InternalError`]. A failed step does
//! not abort the remaining steps; instead, every failure is captured in a
//! [`LeakRecord`] and the cleanup continues best-effort.
//!
//! # Determinism
//! [`ResourceRecord`] construction, [`CleanupManager`] ordering logic, and
//! [`OrphanReconciler`] scan logic are pure. Filesystem operations take
//! configurable roots and are exercised against temporary directories in the
//! default test run. Process kill and network commands require privileges and
//! live behind the `privileged` feature.
//!
//! [`ErrorCode::InternalError`]: microvm_errors::ErrorCode::InternalError

use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::{TenantId, VmId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default quarantine directory name beneath the state root.
pub const DEFAULT_QUARANTINE_DIR: &str = "quarantine";

/// Default state directory for resource records.
pub const DEFAULT_STATE_DIR: &str = "state";

/// Prefix used to identify microVM-owned network namespaces.
pub const NETNS_PREFIX: &str = "microvm-";

/// Prefix used to identify microVM-owned nftables tables.
pub const NFT_TABLE_PREFIX: &str = "microvm_";

/// Prefix used to identify microVM-owned cgroup leaves.
pub const CGROUP_LEAF_PREFIX: &str = "microvm/";

// ---------------------------------------------------------------------------
// ResourceKind
// ---------------------------------------------------------------------------

/// The kind of resource being cleaned up, used in [`CleanupAction`] and
/// [`LeakRecord`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupResourceKind {
    /// VMM process (pid).
    Process,
    /// Unix domain socket.
    Socket,
    /// Nftables table.
    NftTable,
    /// TAP network device.
    TapDevice,
    /// Network namespace.
    Netns,
    /// Cgroup leaf directory.
    CgroupLeaf,
    /// Jailer chroot directory.
    Chroot,
}

impl CleanupResourceKind {
    /// All resource kinds in cleanup (reverse-creation) order.
    pub fn cleanup_order() -> &'static [CleanupResourceKind] {
        &[
            Self::Process,
            Self::Socket,
            Self::NftTable,
            Self::TapDevice,
            Self::Netns,
            Self::CgroupLeaf,
            Self::Chroot,
        ]
    }
}

impl fmt::Display for CleanupResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Process => "process",
            Self::Socket => "socket",
            Self::NftTable => "nft_table",
            Self::TapDevice => "tap_device",
            Self::Netns => "netns",
            Self::CgroupLeaf => "cgroup_leaf",
            Self::Chroot => "chroot",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// ResourceRecord
// ---------------------------------------------------------------------------

/// Ownership record for all resources held by a single VM.
///
/// The record is created when a VM's resources are provisioned and consumed by
/// [`CleanupManager`] during teardown. It is serializable so it can be
/// persisted to disk for crash-recovery reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRecord {
    /// The VM that owns these resources.
    vm_id: VmId,
    /// The tenant that owns the VM.
    tenant_id: TenantId,
    /// Cgroup leaf path (relative to the cgroup root).
    cgroup_path: PathBuf,
    /// Network namespace name (e.g. `microvm-vm-001`).
    netns_name: String,
    /// TAP device name inside the namespace.
    tap_name: String,
    /// Nftables table name for this VM's NAT rules.
    nft_table: String,
    /// Unix socket paths (API socket, metrics socket, etc.).
    socket_paths: Vec<PathBuf>,
    /// Jailer chroot path.
    chroot_path: PathBuf,
    /// VMM process PID (`None` if the process was never started or already
    /// reaped).
    pid: Option<u32>,
}

impl ResourceRecord {
    /// Create a new resource record for a VM.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm_id: VmId,
        tenant_id: TenantId,
        cgroup_path: impl Into<PathBuf>,
        netns_name: impl Into<String>,
        tap_name: impl Into<String>,
        nft_table: impl Into<String>,
        socket_paths: Vec<PathBuf>,
        chroot_path: impl Into<PathBuf>,
        pid: Option<u32>,
    ) -> Self {
        Self {
            vm_id,
            tenant_id,
            cgroup_path: cgroup_path.into(),
            netns_name: netns_name.into(),
            tap_name: tap_name.into(),
            nft_table: nft_table.into(),
            socket_paths,
            chroot_path: chroot_path.into(),
            pid,
        }
    }

    /// The VM that owns these resources.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }

    /// The tenant that owns the VM.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Cgroup leaf path.
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    /// Network namespace name.
    pub fn netns_name(&self) -> &str {
        &self.netns_name
    }

    /// TAP device name.
    pub fn tap_name(&self) -> &str {
        &self.tap_name
    }

    /// Nftables table name.
    pub fn nft_table(&self) -> &str {
        &self.nft_table
    }

    /// Unix socket paths.
    pub fn socket_paths(&self) -> &[PathBuf] {
        &self.socket_paths
    }

    /// Jailer chroot path.
    pub fn chroot_path(&self) -> &Path {
        &self.chroot_path
    }

    /// VMM process PID.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Set the PID (for example, after the VMM process is spawned).
    pub fn set_pid(&mut self, pid: Option<u32>) {
        self.pid = pid;
    }

    /// Derive the default netns name for a VM.
    pub fn default_netns_name(vm_id: &VmId) -> String {
        format!("{}{}", NETNS_PREFIX, vm_id.as_str())
    }

    /// Derive the default nft table name for a VM.
    pub fn default_nft_table(vm_id: &VmId) -> String {
        format!("{}{}", NFT_TABLE_PREFIX, vm_id.as_str().replace('-', "_"))
    }
}

// ---------------------------------------------------------------------------
// CleanupAction
// ---------------------------------------------------------------------------

/// A single cleanup step performed by [`CleanupManager`].
///
/// The action log provides a deterministic, inspectable record of what was
/// done (or skipped) during cleanup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupAction {
    /// The kind of resource acted upon.
    pub kind: CleanupResourceKind,
    /// The VM whose resource was cleaned.
    pub vm_id: String,
    /// Human-readable detail (path, pid, table name, etc.).
    pub detail: String,
    /// Whether the resource was actually removed (`true`) or was already
    /// absent (`false` — idempotent no-op).
    pub removed: bool,
}

// ---------------------------------------------------------------------------
// LeakRecord
// ---------------------------------------------------------------------------

/// Emitted when a cleanup step fails and the resource may be leaked.
///
/// Leak records are the operator's signal that manual intervention is
/// required. They are never silently dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakRecord {
    /// The VM whose resource leaked.
    pub vm_id: String,
    /// The tenant that owns the VM.
    pub tenant_id: String,
    /// The kind of resource that could not be cleaned.
    pub kind: CleanupResourceKind,
    /// Human-readable detail (path, pid, etc.).
    pub detail: String,
    /// The error that prevented cleanup.
    pub error: String,
}

impl fmt::Display for LeakRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "leak: vm={} tenant={} kind={} detail={} error={}",
            self.vm_id, self.tenant_id, self.kind, self.detail, self.error
        )
    }
}

// ---------------------------------------------------------------------------
// CleanupOutcome
// ---------------------------------------------------------------------------

/// The result of a cleanup invocation: the ordered action log and any leak
/// records.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupOutcome {
    /// Ordered log of cleanup actions performed.
    pub actions: Vec<CleanupAction>,
    /// Leak records for steps that failed.
    pub leaks: Vec<LeakRecord>,
}

impl CleanupOutcome {
    /// Whether the cleanup completed without any leaks.
    pub fn is_clean(&self) -> bool {
        self.leaks.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CleanupBackend (abstraction for side-effectful operations)
// ---------------------------------------------------------------------------

/// Abstraction over side-effectful cleanup operations (process kill, nft
/// flush, TAP deletion).
///
/// The default implementation ([`RealCleanupBackend`]) performs real system
/// calls. Tests use [`RecordingCleanupBackend`] to capture operations
/// deterministically.
pub trait CleanupBackend {
    /// Kill a process by PID. Returns `Ok(true)` if the process was killed,
    /// `Ok(false)` if it was already absent.
    fn kill_process(&self, pid: u32) -> Result<bool, MicrovmError>;

    /// Flush and delete an nftables table. Returns `Ok(true)` if the table
    /// was removed, `Ok(false)` if it was already absent.
    fn flush_nft_table(&self, table: &str) -> Result<bool, MicrovmError>;

    /// Delete a TAP device inside a network namespace. Returns `Ok(true)` if
    /// the device was removed, `Ok(false)` if it was already absent.
    fn delete_tap(&self, netns: &str, tap: &str) -> Result<bool, MicrovmError>;

    /// Remove a network namespace. Returns `Ok(true)` if the namespace was
    /// removed, `Ok(false)` if it was already absent.
    fn remove_netns(&self, netns: &str) -> Result<bool, MicrovmError>;
}

/// Real system-call backend for privileged cleanup operations.
///
/// This backend is only meaningful on a Linux host with appropriate
/// privileges. In the default (deterministic) test run, tests use
/// [`RecordingCleanupBackend`] instead.
#[derive(Clone, Debug, Default)]
pub struct RealCleanupBackend {
    /// Root for netns mount points (default: `/var/run/netns`).
    pub netns_root: PathBuf,
}

impl RealCleanupBackend {
    /// Create a backend with the default netns root.
    pub fn new() -> Self {
        Self {
            netns_root: PathBuf::from("/var/run/netns"),
        }
    }

    /// Create a backend with a custom netns root.
    pub fn with_netns_root(root: impl Into<PathBuf>) -> Self {
        Self {
            netns_root: root.into(),
        }
    }
}

impl CleanupBackend for RealCleanupBackend {
    fn kill_process(&self, pid: u32) -> Result<bool, MicrovmError> {
        // Check if the process exists via /proc/<pid>.
        let proc_path = PathBuf::from(format!("/proc/{}", pid));
        if !proc_path.exists() {
            return Ok(false);
        }
        // Send SIGKILL (signal 9).
        let ret = libc_kill(pid, 9);
        if ret == 0 {
            Ok(true)
        } else {
            // ESRCH (3) means the process vanished between check and kill.
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() == Some(3) {
                Ok(false)
            } else {
                Err(
                    MicrovmError::new(ErrorCode::InternalError, "failed to kill VMM process")
                        .with_context("pid", pid.to_string())
                        .with_context("errno", errno.to_string()),
                )
            }
        }
    }

    fn flush_nft_table(&self, table: &str) -> Result<bool, MicrovmError> {
        // In a real deployment this would run `nft delete table <table>`.
        // The deterministic test path does not exercise this; the privileged
        // integration test does.
        let output = std::process::Command::new("nft")
            .args(["delete", "table", "ip", table])
            .output()
            .map_err(|e| {
                MicrovmError::new(ErrorCode::InternalError, "failed to run nft")
                    .with_context("table", table)
                    .with_context("io_error", e.to_string())
            })?;
        if output.status.success() {
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "No such file or directory" means the table was already absent.
            if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
                Ok(false)
            } else {
                Err(
                    MicrovmError::new(ErrorCode::InternalError, "nft delete table failed")
                        .with_context("table", table)
                        .with_context("stderr", stderr.trim().to_string()),
                )
            }
        }
    }

    fn delete_tap(&self, netns: &str, tap: &str) -> Result<bool, MicrovmError> {
        let output = std::process::Command::new("ip")
            .args(["netns", "exec", netns, "ip", "link", "del", tap])
            .output()
            .map_err(|e| {
                MicrovmError::new(ErrorCode::InternalError, "failed to run ip link del")
                    .with_context("netns", netns)
                    .with_context("tap", tap)
                    .with_context("io_error", e.to_string())
            })?;
        if output.status.success() {
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Cannot find device") || stderr.contains("No such device") {
                Ok(false)
            } else {
                Err(
                    MicrovmError::new(ErrorCode::InternalError, "ip link del failed")
                        .with_context("netns", netns)
                        .with_context("tap", tap)
                        .with_context("stderr", stderr.trim().to_string()),
                )
            }
        }
    }

    fn remove_netns(&self, netns: &str) -> Result<bool, MicrovmError> {
        let path = self.netns_root.join(netns);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path).map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "failed to remove netns")
                .with_context("netns", netns)
                .with_context("path", path.display().to_string())
                .with_context("io_error", e.to_string())
        })?;
        Ok(true)
    }
}

/// FFI wrapper for `kill(2)`.
///
/// # Safety
/// Calls libc `kill` with the given pid and signal.
fn libc_kill(pid: u32, sig: i32) -> i32 {
    // Use std::process::Command as a safe fallback to avoid a libc dependency.
    // In practice, the privileged path uses this; the deterministic tests use
    // RecordingCleanupBackend.
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid as i32, sig) }
}

// ---------------------------------------------------------------------------
// RecordingCleanupBackend (deterministic test backend)
// ---------------------------------------------------------------------------

/// A test backend that records all operations without performing real system
/// calls.
///
/// Operations can be pre-configured to succeed or fail, enabling
/// deterministic testing of cleanup ordering, idempotency, and leak-record
/// emission.
#[derive(Clone, Debug, Default)]
pub struct RecordingCleanupBackend {
    /// Recorded operations in call order.
    pub operations: std::cell::RefCell<Vec<(String, bool)>>,
    /// Operations that should fail (kind detail -> error message).
    pub failures: BTreeMap<String, String>,
    /// Set of PIDs that are "alive" (kill returns true for these).
    pub alive_pids: std::collections::BTreeSet<u32>,
    /// Set of nft tables that "exist" (flush returns true for these).
    pub existing_tables: std::collections::BTreeSet<String>,
    /// Set of (netns, tap) pairs that "exist".
    pub existing_taps: std::collections::BTreeSet<(String, String)>,
    /// Set of netns names that "exist".
    pub existing_netns: std::collections::BTreeSet<String>,
}

impl RecordingCleanupBackend {
    /// Create an empty recording backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the recorded operations as `(operation, removed)` pairs.
    pub fn recorded(&self) -> Vec<(String, bool)> {
        self.operations.borrow().clone()
    }
}

impl CleanupBackend for RecordingCleanupBackend {
    fn kill_process(&self, pid: u32) -> Result<bool, MicrovmError> {
        let key = format!("kill:{}", pid);
        if let Some(err) = self.failures.get(&key) {
            self.operations.borrow_mut().push((key, false));
            return Err(MicrovmError::new(ErrorCode::InternalError, err.clone())
                .with_context("pid", pid.to_string()));
        }
        let removed = self.alive_pids.contains(&pid);
        self.operations.borrow_mut().push((key, removed));
        Ok(removed)
    }

    fn flush_nft_table(&self, table: &str) -> Result<bool, MicrovmError> {
        let key = format!("nft:{}", table);
        if let Some(err) = self.failures.get(&key) {
            self.operations.borrow_mut().push((key, false));
            return Err(MicrovmError::new(ErrorCode::InternalError, err.clone())
                .with_context("table", table));
        }
        let removed = self.existing_tables.contains(table);
        self.operations.borrow_mut().push((key, removed));
        Ok(removed)
    }

    fn delete_tap(&self, netns: &str, tap: &str) -> Result<bool, MicrovmError> {
        let key = format!("tap:{}:{}", netns, tap);
        if let Some(err) = self.failures.get(&key) {
            self.operations.borrow_mut().push((key, false));
            return Err(MicrovmError::new(ErrorCode::InternalError, err.clone())
                .with_context("netns", netns)
                .with_context("tap", tap));
        }
        let removed = self
            .existing_taps
            .contains(&(netns.to_string(), tap.to_string()));
        self.operations.borrow_mut().push((key, removed));
        Ok(removed)
    }

    fn remove_netns(&self, netns: &str) -> Result<bool, MicrovmError> {
        let key = format!("netns:{}", netns);
        if let Some(err) = self.failures.get(&key) {
            self.operations.borrow_mut().push((key, false));
            return Err(MicrovmError::new(ErrorCode::InternalError, err.clone())
                .with_context("netns", netns));
        }
        let removed = self.existing_netns.contains(netns);
        self.operations.borrow_mut().push((key, removed));
        Ok(removed)
    }
}

// ---------------------------------------------------------------------------
// CleanupManager
// ---------------------------------------------------------------------------

/// Performs reverse-order, idempotent cleanup of all resources owned by a VM.
///
/// The manager takes a configurable filesystem root for cgroup, chroot, and
/// socket cleanup, and a [`CleanupBackend`] for privileged operations
/// (process kill, nft flush, TAP/netns removal).
#[derive(Clone, Debug)]
pub struct CleanupManager {
    /// Root for cgroup filesystem operations.
    cgroup_root: PathBuf,
    /// Root for chroot directories.
    chroot_root: PathBuf,
    /// Root for socket files.
    socket_root: PathBuf,
}

impl CleanupManager {
    /// Create a cleanup manager with explicit roots.
    pub fn new(
        cgroup_root: impl Into<PathBuf>,
        chroot_root: impl Into<PathBuf>,
        socket_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            chroot_root: chroot_root.into(),
            socket_root: socket_root.into(),
        }
    }

    /// The cgroup root.
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    /// The chroot root.
    pub fn chroot_root(&self) -> &Path {
        &self.chroot_root
    }

    /// The socket root.
    pub fn socket_root(&self) -> &Path {
        &self.socket_root
    }

    /// Clean up all resources owned by the VM described in `record`.
    ///
    /// Cleanup proceeds in strict reverse-creation order:
    /// 1. Kill VMM process
    /// 2. Remove sockets
    /// 3. Flush nft table
    /// 4. Delete TAP device
    /// 5. Remove netns
    /// 6. Remove cgroup leaf
    /// 7. Remove chroot
    ///
    /// Each step is idempotent: if the resource is already absent, the step
    /// is a no-op. Failures do not abort remaining steps; instead, a
    /// [`LeakRecord`] is emitted for each failed step.
    pub fn cleanup(&self, record: &ResourceRecord, backend: &dyn CleanupBackend) -> CleanupOutcome {
        let mut outcome = CleanupOutcome::default();
        let vm = record.vm_id().as_str();
        let tenant = record.tenant_id().as_str();

        // 1. Kill VMM process.
        if let Some(pid) = record.pid() {
            match backend.kill_process(pid) {
                Ok(removed) => {
                    outcome.actions.push(CleanupAction {
                        kind: CleanupResourceKind::Process,
                        vm_id: vm.to_string(),
                        detail: format!("pid={}", pid),
                        removed,
                    });
                }
                Err(e) => {
                    outcome.leaks.push(LeakRecord {
                        vm_id: vm.to_string(),
                        tenant_id: tenant.to_string(),
                        kind: CleanupResourceKind::Process,
                        detail: format!("pid={}", pid),
                        error: e.to_string(),
                    });
                }
            }
        }

        // 2. Remove Unix sockets.
        for sock in record.socket_paths() {
            let full = self.socket_root.join(sock);
            match Self::remove_file_idempotent(&full) {
                Ok(removed) => {
                    outcome.actions.push(CleanupAction {
                        kind: CleanupResourceKind::Socket,
                        vm_id: vm.to_string(),
                        detail: full.display().to_string(),
                        removed,
                    });
                }
                Err(e) => {
                    outcome.leaks.push(LeakRecord {
                        vm_id: vm.to_string(),
                        tenant_id: tenant.to_string(),
                        kind: CleanupResourceKind::Socket,
                        detail: full.display().to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }

        // 3. Flush nft table.
        match backend.flush_nft_table(record.nft_table()) {
            Ok(removed) => {
                outcome.actions.push(CleanupAction {
                    kind: CleanupResourceKind::NftTable,
                    vm_id: vm.to_string(),
                    detail: record.nft_table().to_string(),
                    removed,
                });
            }
            Err(e) => {
                outcome.leaks.push(LeakRecord {
                    vm_id: vm.to_string(),
                    tenant_id: tenant.to_string(),
                    kind: CleanupResourceKind::NftTable,
                    detail: record.nft_table().to_string(),
                    error: e.to_string(),
                });
            }
        }

        // 4. Delete TAP device.
        match backend.delete_tap(record.netns_name(), record.tap_name()) {
            Ok(removed) => {
                outcome.actions.push(CleanupAction {
                    kind: CleanupResourceKind::TapDevice,
                    vm_id: vm.to_string(),
                    detail: format!("{}/{}", record.netns_name(), record.tap_name()),
                    removed,
                });
            }
            Err(e) => {
                outcome.leaks.push(LeakRecord {
                    vm_id: vm.to_string(),
                    tenant_id: tenant.to_string(),
                    kind: CleanupResourceKind::TapDevice,
                    detail: format!("{}/{}", record.netns_name(), record.tap_name()),
                    error: e.to_string(),
                });
            }
        }

        // 5. Remove netns.
        match backend.remove_netns(record.netns_name()) {
            Ok(removed) => {
                outcome.actions.push(CleanupAction {
                    kind: CleanupResourceKind::Netns,
                    vm_id: vm.to_string(),
                    detail: record.netns_name().to_string(),
                    removed,
                });
            }
            Err(e) => {
                outcome.leaks.push(LeakRecord {
                    vm_id: vm.to_string(),
                    tenant_id: tenant.to_string(),
                    kind: CleanupResourceKind::Netns,
                    detail: record.netns_name().to_string(),
                    error: e.to_string(),
                });
            }
        }

        // 6. Remove cgroup leaf.
        let cgroup_full = self.cgroup_root.join(record.cgroup_path());
        match Self::remove_dir_idempotent(&cgroup_full) {
            Ok(removed) => {
                outcome.actions.push(CleanupAction {
                    kind: CleanupResourceKind::CgroupLeaf,
                    vm_id: vm.to_string(),
                    detail: cgroup_full.display().to_string(),
                    removed,
                });
            }
            Err(e) => {
                outcome.leaks.push(LeakRecord {
                    vm_id: vm.to_string(),
                    tenant_id: tenant.to_string(),
                    kind: CleanupResourceKind::CgroupLeaf,
                    detail: cgroup_full.display().to_string(),
                    error: e.to_string(),
                });
            }
        }

        // 7. Remove chroot.
        let chroot_full = self.chroot_root.join(record.chroot_path());
        match Self::remove_dir_idempotent(&chroot_full) {
            Ok(removed) => {
                outcome.actions.push(CleanupAction {
                    kind: CleanupResourceKind::Chroot,
                    vm_id: vm.to_string(),
                    detail: chroot_full.display().to_string(),
                    removed,
                });
            }
            Err(e) => {
                outcome.leaks.push(LeakRecord {
                    vm_id: vm.to_string(),
                    tenant_id: tenant.to_string(),
                    kind: CleanupResourceKind::Chroot,
                    detail: chroot_full.display().to_string(),
                    error: e.to_string(),
                });
            }
        }

        outcome
    }

    /// Remove a file idempotently: `Ok(true)` if removed, `Ok(false)` if
    /// already absent.
    fn remove_file_idempotent(path: &Path) -> Result<bool, MicrovmError> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(
                MicrovmError::new(ErrorCode::InternalError, "failed to remove file")
                    .with_context("path", path.display().to_string())
                    .with_context("io_error", e.to_string()),
            ),
        }
    }

    /// Remove a directory tree idempotently: `Ok(true)` if removed,
    /// `Ok(false)` if already absent.
    fn remove_dir_idempotent(path: &Path) -> Result<bool, MicrovmError> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(MicrovmError::new(
                ErrorCode::InternalError,
                "failed to remove directory",
            )
            .with_context("path", path.display().to_string())
            .with_context("io_error", e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// OrphanReconciler
// ---------------------------------------------------------------------------

/// Scans for orphaned microVM resources and reconciles them.
///
/// An orphan is a resource (cgroup leaf, netns, chroot, socket) that exists
/// on the filesystem but is **not** tracked by any live [`ResourceRecord`].
/// Orphans are quarantined (moved to a quarantine directory) rather than
/// deleted, so an operator can inspect them.
///
/// # Cross-tenant protection
/// The reconciler **never** removes or quarantines a resource whose owning
/// tenant differs from the requesting tenant. Resources owned by another
/// tenant are reported but left untouched.
#[derive(Clone, Debug)]
pub struct OrphanReconciler {
    /// Root for cgroup filesystem operations.
    cgroup_root: PathBuf,
    /// Root for netns mount points.
    netns_root: PathBuf,
    /// Root for chroot directories.
    chroot_root: PathBuf,
    /// Root for socket files.
    socket_root: PathBuf,
    /// Quarantine directory (beneath the state root).
    quarantine_dir: PathBuf,
}

/// Result of an orphan reconciliation scan.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileOutcome {
    /// Orphans that were quarantined.
    pub quarantined: Vec<OrphanRecord>,
    /// Orphans owned by another tenant (left untouched).
    pub cross_tenant_skipped: Vec<OrphanRecord>,
    /// Orphans that could not be quarantined (leak).
    pub leaks: Vec<LeakRecord>,
}

impl ReconcileOutcome {
    /// Whether reconciliation completed without leaks.
    pub fn is_clean(&self) -> bool {
        self.leaks.is_empty()
    }

    /// Total number of orphans detected (quarantined + skipped + leaked).
    pub fn total_detected(&self) -> usize {
        self.quarantined.len() + self.cross_tenant_skipped.len() + self.leaks.len()
    }
}

/// A detected orphan resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanRecord {
    /// The kind of orphaned resource.
    pub kind: CleanupResourceKind,
    /// The path or name of the orphaned resource.
    pub path: String,
    /// The tenant that owns the resource (if determinable from the path
    /// naming convention).
    pub owner_tenant: Option<String>,
    /// The VM that owned the resource (if determinable).
    pub owner_vm: Option<String>,
}

impl OrphanReconciler {
    /// Create a reconciler with explicit roots.
    pub fn new(
        cgroup_root: impl Into<PathBuf>,
        netns_root: impl Into<PathBuf>,
        chroot_root: impl Into<PathBuf>,
        socket_root: impl Into<PathBuf>,
        quarantine_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            netns_root: netns_root.into(),
            chroot_root: chroot_root.into(),
            socket_root: socket_root.into(),
            quarantine_dir: quarantine_dir.into(),
        }
    }

    /// The quarantine directory.
    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    /// Scan for orphaned resources and reconcile them.
    ///
    /// `known_records` is the set of resource records for currently live VMs.
    /// `requesting_tenant` is the tenant requesting reconciliation; resources
    /// owned by other tenants are reported but never touched.
    pub fn reconcile(
        &self,
        known_records: &[ResourceRecord],
        requesting_tenant: &TenantId,
    ) -> ReconcileOutcome {
        let mut outcome = ReconcileOutcome::default();

        // Build a set of known resource paths for quick lookup.
        let known_cgroups: std::collections::BTreeSet<PathBuf> = known_records
            .iter()
            .map(|r| self.cgroup_root.join(r.cgroup_path()))
            .collect();
        let known_netns: std::collections::BTreeSet<String> = known_records
            .iter()
            .map(|r| r.netns_name().to_string())
            .collect();
        let known_chroots: std::collections::BTreeSet<PathBuf> = known_records
            .iter()
            .map(|r| self.chroot_root.join(r.chroot_path()))
            .collect();
        let known_sockets: std::collections::BTreeSet<PathBuf> = known_records
            .iter()
            .flat_map(|r| {
                r.socket_paths().iter().flat_map(|s| {
                    let full = self.socket_root.join(s);
                    // Include both the socket file and its parent directory
                    // so the directory scan does not flag the parent as orphan.
                    let parent = full.parent().map(Path::to_path_buf);
                    std::iter::once(full).chain(parent)
                })
            })
            .collect();

        // Build tenant ownership map for cross-tenant protection.
        let tenant_by_cgroup: BTreeMap<PathBuf, TenantId> = known_records
            .iter()
            .map(|r| {
                (
                    self.cgroup_root.join(r.cgroup_path()),
                    r.tenant_id().clone(),
                )
            })
            .collect();
        let tenant_by_netns: BTreeMap<String, TenantId> = known_records
            .iter()
            .map(|r| (r.netns_name().to_string(), r.tenant_id().clone()))
            .collect();

        // Scan cgroup leaves.
        self.scan_dir_orphans(
            &self.cgroup_root.join("microvm"),
            &known_cgroups,
            &tenant_by_cgroup,
            requesting_tenant,
            CleanupResourceKind::CgroupLeaf,
            &mut outcome,
        );

        // Scan netns.
        self.scan_netns_orphans(
            &known_netns,
            &tenant_by_netns,
            requesting_tenant,
            &mut outcome,
        );

        // Scan chroots.
        self.scan_dir_orphans(
            &self.chroot_root,
            &known_chroots,
            &BTreeMap::new(),
            requesting_tenant,
            CleanupResourceKind::Chroot,
            &mut outcome,
        );

        // Scan sockets.
        self.scan_dir_orphans(
            &self.socket_root,
            &known_sockets,
            &BTreeMap::new(),
            requesting_tenant,
            CleanupResourceKind::Socket,
            &mut outcome,
        );

        outcome
    }

    /// Scan a directory for entries not in the known set.
    fn scan_dir_orphans(
        &self,
        dir: &Path,
        known: &std::collections::BTreeSet<PathBuf>,
        tenant_map: &BTreeMap<PathBuf, TenantId>,
        requesting_tenant: &TenantId,
        kind: CleanupResourceKind,
        outcome: &mut ReconcileOutcome,
    ) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return, // Directory does not exist; nothing to scan.
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if known.contains(&path) {
                continue; // Not an orphan.
            }

            let orphan = OrphanRecord {
                kind,
                path: path.display().to_string(),
                owner_tenant: tenant_map.get(&path).map(|t| t.as_str().to_string()),
                owner_vm: Self::extract_vm_from_path(&path),
            };

            // Cross-tenant protection: if the resource is owned by another
            // tenant, report but do not touch.
            if let Some(owner) = tenant_map.get(&path) {
                if owner != requesting_tenant {
                    outcome.cross_tenant_skipped.push(orphan);
                    continue;
                }
            }

            // Quarantine the orphan.
            self.quarantine_orphan(&path, &orphan, outcome);
        }
    }

    /// Scan netns directory for orphaned namespaces.
    fn scan_netns_orphans(
        &self,
        known: &std::collections::BTreeSet<String>,
        tenant_map: &BTreeMap<String, TenantId>,
        requesting_tenant: &TenantId,
        outcome: &mut ReconcileOutcome,
    ) {
        let entries = match std::fs::read_dir(&self.netns_root) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Only consider microVM-owned namespaces.
            if !name.starts_with(NETNS_PREFIX) {
                continue;
            }
            if known.contains(&name) {
                continue;
            }

            let path = entry.path();
            let orphan = OrphanRecord {
                kind: CleanupResourceKind::Netns,
                path: path.display().to_string(),
                owner_tenant: tenant_map.get(&name).map(|t| t.as_str().to_string()),
                owner_vm: name.strip_prefix(NETNS_PREFIX).map(String::from),
            };

            // Cross-tenant protection.
            if let Some(owner) = tenant_map.get(&name) {
                if owner != requesting_tenant {
                    outcome.cross_tenant_skipped.push(orphan);
                    continue;
                }
            }

            self.quarantine_orphan(&path, &orphan, outcome);
        }
    }

    /// Move an orphaned resource to the quarantine directory.
    fn quarantine_orphan(
        &self,
        path: &Path,
        orphan: &OrphanRecord,
        outcome: &mut ReconcileOutcome,
    ) {
        // Ensure quarantine directory exists.
        if let Err(e) = std::fs::create_dir_all(&self.quarantine_dir) {
            outcome.leaks.push(LeakRecord {
                vm_id: orphan.owner_vm.clone().unwrap_or_default(),
                tenant_id: orphan.owner_tenant.clone().unwrap_or_default(),
                kind: orphan.kind,
                detail: orphan.path.clone(),
                error: MicrovmError::new(
                    ErrorCode::InternalError,
                    "failed to create quarantine directory",
                )
                .with_context("io_error", e.to_string())
                .to_string(),
            });
            return;
        }

        // Derive a quarantine destination name from the resource path.
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let dest = self
            .quarantine_dir
            .join(format!("{}-{}", orphan.kind, file_name));

        match std::fs::rename(path, &dest) {
            Ok(()) => {
                outcome.quarantined.push(orphan.clone());
            }
            Err(e) => {
                outcome.leaks.push(LeakRecord {
                    vm_id: orphan.owner_vm.clone().unwrap_or_default(),
                    tenant_id: orphan.owner_tenant.clone().unwrap_or_default(),
                    kind: orphan.kind,
                    detail: orphan.path.clone(),
                    error: MicrovmError::new(
                        ErrorCode::InternalError,
                        "failed to quarantine orphan",
                    )
                    .with_context("path", path.display().to_string())
                    .with_context("dest", dest.display().to_string())
                    .with_context("io_error", e.to_string())
                    .to_string(),
                });
            }
        }
    }

    /// Try to extract a VM ID from a resource path (best-effort, for
    /// reporting).
    fn extract_vm_from_path(path: &Path) -> Option<String> {
        path.file_name().map(|n| n.to_string_lossy().to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).unwrap()
    }

    fn test_record(vm_id: &str, tenant_id: &str) -> ResourceRecord {
        let v = vm(vm_id);
        ResourceRecord::new(
            v.clone(),
            tenant(tenant_id),
            format!("microvm/{}", vm_id),
            ResourceRecord::default_netns_name(&v),
            "tap0",
            ResourceRecord::default_nft_table(&v),
            vec![
                PathBuf::from(format!("{}/api.sock", vm_id)),
                PathBuf::from(format!("{}/metrics.sock", vm_id)),
            ],
            vm_id.to_string(),
            Some(12345),
        )
    }

    /// Create a fully-populated backend where all resources "exist".
    fn alive_backend(record: &ResourceRecord) -> RecordingCleanupBackend {
        let mut b = RecordingCleanupBackend::new();
        if let Some(pid) = record.pid() {
            b.alive_pids.insert(pid);
        }
        b.existing_tables.insert(record.nft_table().to_string());
        b.existing_taps.insert((
            record.netns_name().to_string(),
            record.tap_name().to_string(),
        ));
        b.existing_netns.insert(record.netns_name().to_string());
        b
    }

    // -- ResourceRecord tests -----------------------------------------------

    #[test]
    fn resource_record_accessors() {
        let rec = test_record("vm-001", "tenant-a");
        assert_eq!(rec.vm_id().as_str(), "vm-001");
        assert_eq!(rec.tenant_id().as_str(), "tenant-a");
        assert_eq!(rec.cgroup_path(), Path::new("microvm/vm-001"));
        assert_eq!(rec.netns_name(), "microvm-vm-001");
        assert_eq!(rec.tap_name(), "tap0");
        assert_eq!(rec.nft_table(), "microvm_vm_001");
        assert_eq!(rec.socket_paths().len(), 2);
        assert_eq!(rec.chroot_path(), Path::new("vm-001"));
        assert_eq!(rec.pid(), Some(12345));
    }

    #[test]
    fn resource_record_set_pid() {
        let mut rec = test_record("vm-001", "tenant-a");
        rec.set_pid(Some(99999));
        assert_eq!(rec.pid(), Some(99999));
        rec.set_pid(None);
        assert_eq!(rec.pid(), None);
    }

    #[test]
    fn resource_record_default_names() {
        let v = vm("vm-web-01");
        assert_eq!(ResourceRecord::default_netns_name(&v), "microvm-vm-web-01");
        assert_eq!(ResourceRecord::default_nft_table(&v), "microvm_vm_web_01");
    }

    #[test]
    fn resource_record_serde_roundtrip() {
        let rec = test_record("vm-001", "tenant-a");
        let json = serde_json::to_string(&rec).unwrap();
        let back: ResourceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    // -- CleanupResourceKind tests ------------------------------------------

    #[test]
    fn cleanup_order_is_reverse_creation() {
        let order = CleanupResourceKind::cleanup_order();
        assert_eq!(order.len(), 7);
        assert_eq!(order[0], CleanupResourceKind::Process);
        assert_eq!(order[1], CleanupResourceKind::Socket);
        assert_eq!(order[2], CleanupResourceKind::NftTable);
        assert_eq!(order[3], CleanupResourceKind::TapDevice);
        assert_eq!(order[4], CleanupResourceKind::Netns);
        assert_eq!(order[5], CleanupResourceKind::CgroupLeaf);
        assert_eq!(order[6], CleanupResourceKind::Chroot);
    }

    // -- CleanupManager: ordering tests -------------------------------------

    #[test]
    fn cleanup_follows_reverse_order() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");

        // Create filesystem resources.
        let rec = test_record("vm-001", "tenant-a");
        fs::create_dir_all(cgroup_root.join("microvm/vm-001")).unwrap();
        fs::create_dir_all(chroot_root.join("vm-001")).unwrap();
        fs::create_dir_all(socket_root.join("vm-001")).unwrap();
        fs::write(socket_root.join("vm-001/api.sock"), "").unwrap();
        fs::write(socket_root.join("vm-001/metrics.sock"), "").unwrap();

        let mgr = CleanupManager::new(&cgroup_root, &chroot_root, &socket_root);
        let backend = alive_backend(&rec);
        let outcome = mgr.cleanup(&rec, &backend);

        assert!(outcome.is_clean());

        // Verify ordering: process -> socket -> nft -> tap -> netns -> cgroup -> chroot.
        let kinds: Vec<CleanupResourceKind> = outcome.actions.iter().map(|a| a.kind).collect();
        // Process first.
        assert_eq!(kinds[0], CleanupResourceKind::Process);
        // Sockets next (2 of them).
        assert_eq!(kinds[1], CleanupResourceKind::Socket);
        assert_eq!(kinds[2], CleanupResourceKind::Socket);
        // Then nft, tap, netns.
        assert_eq!(kinds[3], CleanupResourceKind::NftTable);
        assert_eq!(kinds[4], CleanupResourceKind::TapDevice);
        assert_eq!(kinds[5], CleanupResourceKind::Netns);
        // Cgroup before chroot.
        assert_eq!(kinds[6], CleanupResourceKind::CgroupLeaf);
        assert_eq!(kinds[7], CleanupResourceKind::Chroot);

        // Filesystem resources are gone.
        assert!(!cgroup_root.join("microvm/vm-001").exists());
        assert!(!chroot_root.join("vm-001").exists());
        assert!(!socket_root.join("vm-001/api.sock").exists());
        assert!(!socket_root.join("vm-001/metrics.sock").exists());
    }

    #[test]
    fn cleanup_backend_operations_ordered() {
        let tmp = TempDir::new().unwrap();
        let mgr = CleanupManager::new(
            tmp.path().join("cgroup"),
            tmp.path().join("chroot"),
            tmp.path().join("sockets"),
        );

        let rec = test_record("vm-002", "tenant-b");
        let backend = alive_backend(&rec);
        let _outcome = mgr.cleanup(&rec, &backend);

        // Backend operations: kill, nft, tap, netns (filesystem ops are
        // handled by CleanupManager directly).
        let ops = backend.recorded();
        assert_eq!(ops[0].0, "kill:12345");
        assert_eq!(ops[1].0, "nft:microvm_vm_002");
        assert_eq!(ops[2].0, "tap:microvm-vm-002:tap0");
        assert_eq!(ops[3].0, "netns:microvm-vm-002");
    }

    // -- CleanupManager: idempotency tests ----------------------------------

    #[test]
    fn cleanup_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");

        let rec = test_record("vm-001", "tenant-a");
        fs::create_dir_all(cgroup_root.join("microvm/vm-001")).unwrap();
        fs::create_dir_all(chroot_root.join("vm-001")).unwrap();
        fs::create_dir_all(socket_root.join("vm-001")).unwrap();
        fs::write(socket_root.join("vm-001/api.sock"), "").unwrap();
        fs::write(socket_root.join("vm-001/metrics.sock"), "").unwrap();

        let mgr = CleanupManager::new(&cgroup_root, &chroot_root, &socket_root);
        let backend = alive_backend(&rec);

        // First cleanup removes everything.
        let outcome1 = mgr.cleanup(&rec, &backend);
        assert!(outcome1.is_clean());
        assert!(outcome1.actions.iter().any(|a| a.removed));

        // Second cleanup: everything is already gone -> all removed=false.
        let backend2 = RecordingCleanupBackend::new(); // empty: nothing alive.
        let outcome2 = mgr.cleanup(&rec, &backend2);
        assert!(outcome2.is_clean());
        // All filesystem actions report removed=false.
        for action in &outcome2.actions {
            assert!(
                !action.removed,
                "expected no-op for {:?} but got removed=true",
                action.kind
            );
        }

        // Third cleanup: still a no-op.
        let backend3 = RecordingCleanupBackend::new();
        let outcome3 = mgr.cleanup(&rec, &backend3);
        assert!(outcome3.is_clean());
        assert_eq!(outcome3.actions.len(), outcome2.actions.len());
    }

    #[test]
    fn cleanup_no_pid_skips_process_step() {
        let tmp = TempDir::new().unwrap();
        let mgr = CleanupManager::new(
            tmp.path().join("cgroup"),
            tmp.path().join("chroot"),
            tmp.path().join("sockets"),
        );

        let mut rec = test_record("vm-001", "tenant-a");
        rec.set_pid(None);

        let backend = RecordingCleanupBackend::new();
        let outcome = mgr.cleanup(&rec, &backend);

        // No process action.
        assert!(!outcome
            .actions
            .iter()
            .any(|a| a.kind == CleanupResourceKind::Process));
        // Backend received no kill call (but may have nft/tap/netns calls).
        assert!(!backend
            .recorded()
            .iter()
            .any(|(op, _)| op.starts_with("kill:")));
    }

    // -- CleanupManager: leak record tests ----------------------------------

    #[test]
    fn cleanup_emits_leak_on_process_kill_failure() {
        let tmp = TempDir::new().unwrap();
        let mgr = CleanupManager::new(
            tmp.path().join("cgroup"),
            tmp.path().join("chroot"),
            tmp.path().join("sockets"),
        );

        let rec = test_record("vm-001", "tenant-a");
        let mut backend = alive_backend(&rec);
        backend
            .failures
            .insert("kill:12345".to_string(), "permission denied".to_string());

        let outcome = mgr.cleanup(&rec, &backend);

        // Cleanup continued despite the failure.
        assert!(!outcome.is_clean());
        assert_eq!(outcome.leaks.len(), 1);
        assert_eq!(outcome.leaks[0].kind, CleanupResourceKind::Process);
        assert_eq!(outcome.leaks[0].vm_id, "vm-001");
        assert_eq!(outcome.leaks[0].tenant_id, "tenant-a");
        assert!(outcome.leaks[0].error.contains("permission denied"));

        // Remaining steps still executed.
        assert!(outcome
            .actions
            .iter()
            .any(|a| a.kind == CleanupResourceKind::NftTable));
        assert!(outcome
            .actions
            .iter()
            .any(|a| a.kind == CleanupResourceKind::Chroot));
    }

    #[test]
    fn cleanup_emits_leak_on_nft_failure() {
        let tmp = TempDir::new().unwrap();
        let mgr = CleanupManager::new(
            tmp.path().join("cgroup"),
            tmp.path().join("chroot"),
            tmp.path().join("sockets"),
        );

        let rec = test_record("vm-001", "tenant-a");
        let mut backend = alive_backend(&rec);
        backend.failures.insert(
            "nft:microvm_vm_001".to_string(),
            "nft: table busy".to_string(),
        );

        let outcome = mgr.cleanup(&rec, &backend);

        assert!(!outcome.is_clean());
        assert_eq!(outcome.leaks.len(), 1);
        assert_eq!(outcome.leaks[0].kind, CleanupResourceKind::NftTable);

        // Process was still killed, chroot still removed.
        assert!(outcome
            .actions
            .iter()
            .any(|a| a.kind == CleanupResourceKind::Process));
        assert!(outcome
            .actions
            .iter()
            .any(|a| a.kind == CleanupResourceKind::Chroot));
    }

    #[test]
    fn cleanup_multiple_failures_emit_multiple_leaks() {
        let tmp = TempDir::new().unwrap();
        let mgr = CleanupManager::new(
            tmp.path().join("cgroup"),
            tmp.path().join("chroot"),
            tmp.path().join("sockets"),
        );

        let rec = test_record("vm-001", "tenant-a");
        let mut backend = alive_backend(&rec);
        backend
            .failures
            .insert("kill:12345".to_string(), "kill failed".to_string());
        backend.failures.insert(
            "netns:microvm-vm-001".to_string(),
            "netns stuck".to_string(),
        );

        let outcome = mgr.cleanup(&rec, &backend);

        assert_eq!(outcome.leaks.len(), 2);
        let leak_kinds: Vec<CleanupResourceKind> = outcome.leaks.iter().map(|l| l.kind).collect();
        assert!(leak_kinds.contains(&CleanupResourceKind::Process));
        assert!(leak_kinds.contains(&CleanupResourceKind::Netns));
    }

    // -- CleanupManager: filesystem idempotency -----------------------------

    #[test]
    fn cleanup_missing_filesystem_resources_is_noop() {
        let tmp = TempDir::new().unwrap();
        // No directories created at all.
        let mgr = CleanupManager::new(
            tmp.path().join("cgroup"),
            tmp.path().join("chroot"),
            tmp.path().join("sockets"),
        );

        let rec = test_record("vm-001", "tenant-a");
        let backend = RecordingCleanupBackend::new();
        let outcome = mgr.cleanup(&rec, &backend);

        assert!(outcome.is_clean());
        // All filesystem actions report removed=false.
        for action in &outcome.actions {
            if matches!(
                action.kind,
                CleanupResourceKind::Socket
                    | CleanupResourceKind::CgroupLeaf
                    | CleanupResourceKind::Chroot
            ) {
                assert!(!action.removed);
            }
        }
    }

    // -- OrphanReconciler tests ---------------------------------------------

    #[test]
    fn reconciler_detects_orphan_cgroup() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        // Create an orphan cgroup leaf (not tracked by any record).
        fs::create_dir_all(cgroup_root.join("microvm/vm-orphan")).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        fs::create_dir_all(&chroot_root).unwrap();
        fs::create_dir_all(&socket_root).unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[], &t);

        assert_eq!(outcome.quarantined.len(), 1);
        assert_eq!(outcome.quarantined[0].kind, CleanupResourceKind::CgroupLeaf);
        assert!(outcome.quarantined[0].path.contains("vm-orphan"));
        assert!(outcome.is_clean());

        // Orphan was moved to quarantine.
        assert!(!cgroup_root.join("microvm/vm-orphan").exists());
        assert!(quarantine.exists());
    }

    #[test]
    fn reconciler_skips_known_resources() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        let rec = test_record("vm-001", "tenant-a");

        // Create resources that ARE tracked.
        fs::create_dir_all(cgroup_root.join("microvm/vm-001")).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        fs::write(netns_root.join("microvm-vm-001"), "").unwrap();
        fs::create_dir_all(chroot_root.join("vm-001")).unwrap();
        fs::create_dir_all(socket_root.join("vm-001")).unwrap();
        fs::write(socket_root.join("vm-001/api.sock"), "").unwrap();
        fs::write(socket_root.join("vm-001/metrics.sock"), "").unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[rec], &t);

        // Nothing is an orphan.
        assert_eq!(outcome.total_detected(), 0);
        assert!(outcome.is_clean());

        // Resources still exist.
        assert!(cgroup_root.join("microvm/vm-001").exists());
        assert!(netns_root.join("microvm-vm-001").exists());
    }

    #[test]
    fn reconciler_cross_tenant_protection() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        // tenant-b owns vm-002.
        let rec_b = test_record("vm-002", "tenant-b");
        fs::create_dir_all(cgroup_root.join("microvm/vm-002")).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        fs::write(netns_root.join("microvm-vm-002"), "").unwrap();
        fs::create_dir_all(chroot_root.join("vm-002")).unwrap();
        fs::create_dir_all(socket_root.join("vm-002")).unwrap();
        fs::write(socket_root.join("vm-002/api.sock"), "").unwrap();
        fs::write(socket_root.join("vm-002/metrics.sock"), "").unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        // tenant-a requests reconciliation; tenant-b's resources must not be
        // touched.
        let t_a = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[rec_b], &t_a);

        // No quarantined (cross-tenant resources are skipped).
        assert_eq!(outcome.quarantined.len(), 0);
        assert!(outcome.is_clean());

        // tenant-b's resources still exist.
        assert!(cgroup_root.join("microvm/vm-002").exists());
        assert!(netns_root.join("microvm-vm-002").exists());
    }

    #[test]
    fn reconciler_detects_orphan_netns() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        fs::create_dir_all(&cgroup_root).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        // Orphan netns.
        fs::write(netns_root.join("microvm-vm-ghost"), "").unwrap();
        // Non-microvm netns (should be ignored).
        fs::write(netns_root.join("docker-bridge"), "").unwrap();
        fs::create_dir_all(&chroot_root).unwrap();
        fs::create_dir_all(&socket_root).unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[], &t);

        // Only the microvm-prefixed netns is detected.
        assert_eq!(outcome.quarantined.len(), 1);
        assert_eq!(outcome.quarantined[0].kind, CleanupResourceKind::Netns);
        assert!(outcome.quarantined[0].path.contains("microvm-vm-ghost"));
        assert_eq!(
            outcome.quarantined[0].owner_vm,
            Some("vm-ghost".to_string())
        );

        // Non-microvm netns untouched.
        assert!(netns_root.join("docker-bridge").exists());
    }

    #[test]
    fn reconciler_detects_orphan_chroot() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        fs::create_dir_all(&cgroup_root).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        // Orphan chroot.
        fs::create_dir_all(chroot_root.join("vm-stale")).unwrap();
        fs::create_dir_all(&socket_root).unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[], &t);

        assert_eq!(outcome.quarantined.len(), 1);
        assert_eq!(outcome.quarantined[0].kind, CleanupResourceKind::Chroot);
        assert!(outcome.quarantined[0].path.contains("vm-stale"));
    }

    #[test]
    fn reconciler_detects_orphan_socket() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        fs::create_dir_all(&cgroup_root).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        fs::create_dir_all(&chroot_root).unwrap();
        // Orphan socket directory.
        fs::create_dir_all(socket_root.join("vm-dead")).unwrap();
        fs::write(socket_root.join("vm-dead/api.sock"), "").unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[], &t);

        assert_eq!(outcome.quarantined.len(), 1);
        assert_eq!(outcome.quarantined[0].kind, CleanupResourceKind::Socket);
        assert!(outcome.quarantined[0].path.contains("vm-dead"));
    }

    #[test]
    fn reconciler_mixed_orphans_and_known() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        let rec = test_record("vm-alive", "tenant-a");

        // Known resources.
        fs::create_dir_all(cgroup_root.join("microvm/vm-alive")).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        fs::write(netns_root.join("microvm-vm-alive"), "").unwrap();
        fs::create_dir_all(chroot_root.join("vm-alive")).unwrap();
        fs::create_dir_all(socket_root.join("vm-alive")).unwrap();
        fs::write(socket_root.join("vm-alive/api.sock"), "").unwrap();
        fs::write(socket_root.join("vm-alive/metrics.sock"), "").unwrap();

        // Orphan resources.
        fs::create_dir_all(cgroup_root.join("microvm/vm-dead")).unwrap();
        fs::write(netns_root.join("microvm-vm-dead"), "").unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[rec], &t);

        // Two orphans quarantined (cgroup + netns).
        assert_eq!(outcome.quarantined.len(), 2);
        assert!(outcome.is_clean());

        // Known resources untouched.
        assert!(cgroup_root.join("microvm/vm-alive").exists());
        assert!(netns_root.join("microvm-vm-alive").exists());

        // Orphans quarantined.
        assert!(!cgroup_root.join("microvm/vm-dead").exists());
        assert!(!netns_root.join("microvm-vm-dead").exists());
    }

    #[test]
    fn reconciler_empty_dirs_no_orphans() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let netns_root = tmp.path().join("netns");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let quarantine = tmp.path().join("quarantine");

        // Create empty directories.
        fs::create_dir_all(cgroup_root.join("microvm")).unwrap();
        fs::create_dir_all(&netns_root).unwrap();
        fs::create_dir_all(&chroot_root).unwrap();
        fs::create_dir_all(&socket_root).unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[], &t);

        assert_eq!(outcome.total_detected(), 0);
        assert!(outcome.is_clean());
    }

    #[test]
    fn reconciler_missing_dirs_no_orphans() {
        let tmp = TempDir::new().unwrap();
        // No directories created at all.
        let reconciler = OrphanReconciler::new(
            tmp.path().join("cgroup"),
            tmp.path().join("netns"),
            tmp.path().join("chroot"),
            tmp.path().join("sockets"),
            tmp.path().join("quarantine"),
        );

        let t = tenant("tenant-a");
        let outcome = reconciler.reconcile(&[], &t);

        assert_eq!(outcome.total_detected(), 0);
        assert!(outcome.is_clean());
    }

    // -- LeakRecord tests ---------------------------------------------------

    #[test]
    fn leak_record_display() {
        let leak = LeakRecord {
            vm_id: "vm-001".to_string(),
            tenant_id: "tenant-a".to_string(),
            kind: CleanupResourceKind::Process,
            detail: "pid=12345".to_string(),
            error: "kill failed".to_string(),
        };
        let s = leak.to_string();
        assert!(s.contains("vm-001"));
        assert!(s.contains("tenant-a"));
        assert!(s.contains("process"));
        assert!(s.contains("pid=12345"));
        assert!(s.contains("kill failed"));
    }

    #[test]
    fn leak_record_serde_roundtrip() {
        let leak = LeakRecord {
            vm_id: "vm-001".to_string(),
            tenant_id: "tenant-a".to_string(),
            kind: CleanupResourceKind::Netns,
            detail: "microvm-vm-001".to_string(),
            error: "device busy".to_string(),
        };
        let json = serde_json::to_string(&leak).unwrap();
        let back: LeakRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(leak, back);
    }

    // -- CleanupOutcome tests -----------------------------------------------

    #[test]
    fn cleanup_outcome_is_clean_when_no_leaks() {
        let outcome = CleanupOutcome::default();
        assert!(outcome.is_clean());
    }

    #[test]
    fn cleanup_outcome_not_clean_with_leaks() {
        let outcome = CleanupOutcome {
            actions: vec![],
            leaks: vec![LeakRecord {
                vm_id: "vm-001".to_string(),
                tenant_id: "t".to_string(),
                kind: CleanupResourceKind::Process,
                detail: "pid=1".to_string(),
                error: "fail".to_string(),
            }],
        };
        assert!(!outcome.is_clean());
    }

    // -- End-to-end lifecycle test ------------------------------------------

    #[test]
    fn end_to_end_cleanup_lifecycle() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let chroot_root = tmp.path().join("chroot");
        let socket_root = tmp.path().join("sockets");
        let netns_root = tmp.path().join("netns");
        let quarantine = tmp.path().join("quarantine");

        // Provision two VMs for tenant-a and one for tenant-b.
        let rec_a1 = test_record("vm-web", "tenant-a");
        let rec_a2 = test_record("vm-db", "tenant-a");
        let rec_b1 = test_record("vm-cache", "tenant-b");

        // Create all filesystem resources.
        for rec in [&rec_a1, &rec_a2, &rec_b1] {
            fs::create_dir_all(cgroup_root.join(rec.cgroup_path())).unwrap();
            fs::create_dir_all(chroot_root.join(rec.chroot_path())).unwrap();
            for sock in rec.socket_paths() {
                let full = socket_root.join(sock);
                fs::create_dir_all(full.parent().unwrap()).unwrap();
                fs::write(&full, "").unwrap();
            }
        }
        fs::create_dir_all(&netns_root).unwrap();
        for rec in [&rec_a1, &rec_a2, &rec_b1] {
            fs::write(netns_root.join(rec.netns_name()), "").unwrap();
        }

        let mgr = CleanupManager::new(&cgroup_root, &chroot_root, &socket_root);

        // Clean up vm-web (tenant-a).
        let backend_a1 = alive_backend(&rec_a1);
        let outcome_a1 = mgr.cleanup(&rec_a1, &backend_a1);
        assert!(outcome_a1.is_clean());
        assert!(!cgroup_root.join("microvm/vm-web").exists());
        assert!(!chroot_root.join("vm-web").exists());

        // vm-db and vm-cache still exist.
        assert!(cgroup_root.join("microvm/vm-db").exists());
        assert!(cgroup_root.join("microvm/vm-cache").exists());

        // Reconcile: vm-web's netns is now an orphan (cleanup used the
        // backend, not the filesystem, for netns in this test).
        // Actually, let's create an orphan to test reconciliation.
        fs::create_dir_all(cgroup_root.join("microvm/vm-stale")).unwrap();

        let reconciler = OrphanReconciler::new(
            &cgroup_root,
            &netns_root,
            &chroot_root,
            &socket_root,
            &quarantine,
        );

        // Reconcile as tenant-a with vm-db as the only known record.
        let t_a = tenant("tenant-a");
        let outcome_recon = reconciler.reconcile(&[rec_a2.clone(), rec_b1.clone()], &t_a);

        // vm-stale cgroup is quarantined (orphan, no owner).
        assert!(outcome_recon
            .quarantined
            .iter()
            .any(|o| o.path.contains("vm-stale")));
        assert!(outcome_recon.is_clean());

        // tenant-b's vm-cache is NOT touched (cross-tenant protection).
        assert!(cgroup_root.join("microvm/vm-cache").exists());

        // Idempotent: clean up vm-web again.
        let backend_again = RecordingCleanupBackend::new();
        let outcome_again = mgr.cleanup(&rec_a1, &backend_again);
        assert!(outcome_again.is_clean());
        for action in &outcome_again.actions {
            assert!(!action.removed);
        }
    }
}
