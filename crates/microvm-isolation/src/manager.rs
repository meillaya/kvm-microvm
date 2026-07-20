//! Cgroup-v2 hierarchy management and jailer argv construction.
//!
//! [`CgroupManager`] owns the orchestrator's cgroup-v2 boundary. It creates a
//! single parent cgroup, delegates the required controllers top-down, and
//! creates one **leaf** cgroup per VM with explicit resource limits. The jailer
//! is only ever handed a **pre-created** leaf path; it never creates the
//! hierarchy itself.
//!
//! # Layout
//! ```text
//! <root>/                       <- cgroup-v2 mount (e.g. /sys/fs/cgroup)
//!   cgroup.subtree_control      <- "+cpu +memory +pids +io" (delegates down)
//!   microvm/                    <- parent cgroup
//!     cgroup.subtree_control    <- "+cpu +memory +pids +io" (delegates to leaves)
//!     <vm-id>/                  <- per-VM leaf (no children, empty subtree_control)
//!       cpu.max memory.max memory.swap.max pids.max [io.max]
//! ```
//!
//! # Determinism
//! Path computation, controller checks, leaf-constraint validation, and jailer
//! argv generation are pure and run without root. The filesystem operations
//! take a configurable root, so they are exercised against a temporary
//! directory in the default test run; a real `/sys/fs/cgroup` run lives behind
//! the `privileged` feature.

use crate::spec::{
    check_required_controllers, parse_controllers, validate_no_children,
    validate_subtree_control_empty, CgroupSpec, Controller,
};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::VmId;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Default cgroup-v2 mount point on a unified hierarchy host.
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Default parent cgroup name beneath the root.
pub const DEFAULT_PARENT_NAME: &str = "microvm";

/// The cgroup-version the jailer must always be launched with.
pub const CGROUP_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// JailerCommand
// ---------------------------------------------------------------------------

/// A deterministic jailer launch command.
///
/// The cgroup contract is fixed: `--cgroup-version=2` is always present and
/// `--parent-cgroup` always points at a **pre-created** leaf path (relative to
/// the cgroup root) so the jailer never creates the hierarchy itself. Extra
/// flags (netns, uid/gid, resource limits) are appended by later waves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailerCommand {
    jailer_binary: String,
    id: String,
    parent_cgroup: String,
    extra: Vec<String>,
}

impl JailerCommand {
    /// Create a command for a VM whose leaf cgroup already exists at
    /// `parent_cgroup` (a root-relative path such as `microvm/vm-001`).
    pub fn new(
        jailer_binary: impl Into<String>,
        id: impl Into<String>,
        parent_cgroup: impl Into<String>,
    ) -> Self {
        Self {
            jailer_binary: jailer_binary.into(),
            id: id.into(),
            parent_cgroup: parent_cgroup.into(),
            extra: Vec::new(),
        }
    }

    /// Append an extra flag/value pair (for example `--netns`, `--uid`).
    pub fn with_arg(mut self, flag: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push(flag.into());
        self.extra.push(value.into());
        self
    }

    /// The pre-created leaf cgroup path passed to the jailer.
    pub fn parent_cgroup(&self) -> &str {
        &self.parent_cgroup
    }

    /// Render the full argv. Always contains `--cgroup-version=2` and
    /// `--parent-cgroup <leaf>`.
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(6 + self.extra.len());
        argv.push(self.jailer_binary.clone());
        argv.push("--id".to_string());
        argv.push(self.id.clone());
        argv.push(format!("--cgroup-version={}", CGROUP_VERSION));
        argv.push("--parent-cgroup".to_string());
        argv.push(self.parent_cgroup.clone());
        argv.extend(self.extra.iter().cloned());
        argv
    }
}

// ---------------------------------------------------------------------------
// CgroupManager
// ---------------------------------------------------------------------------

/// Manages the parent/leaf cgroup-v2 hierarchy for VM isolation.
#[derive(Clone, Debug)]
pub struct CgroupManager {
    root: PathBuf,
    parent_name: String,
}

impl Default for CgroupManager {
    fn default() -> Self {
        Self::new(DEFAULT_CGROUP_ROOT)
    }
}

impl CgroupManager {
    /// Create a manager rooted at the given cgroup-v2 mount point, using the
    /// default parent name [`DEFAULT_PARENT_NAME`].
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            parent_name: DEFAULT_PARENT_NAME.to_string(),
        }
    }

    /// Override the parent cgroup name beneath the root.
    pub fn with_parent_name(mut self, name: impl Into<String>) -> Self {
        self.parent_name = name.into();
        self
    }

    /// The cgroup-v2 root mount point.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The parent cgroup name.
    pub fn parent_name(&self) -> &str {
        &self.parent_name
    }

    /// Absolute path to the parent cgroup.
    pub fn parent_path(&self) -> PathBuf {
        self.root.join(&self.parent_name)
    }

    /// Absolute path to a per-VM leaf cgroup.
    pub fn leaf_path(&self, vm_id: &VmId) -> PathBuf {
        self.parent_path().join(vm_id.as_str())
    }

    /// Root-relative leaf path (for example `microvm/vm-001`), suitable for the
    /// jailer's `--parent-cgroup` argument.
    pub fn relative_leaf_path(&self, vm_id: &VmId) -> String {
        format!("{}/{}", self.parent_name, vm_id.as_str())
    }

    /// Build the deterministic jailer command for a VM, pointing at its
    /// pre-created leaf cgroup.
    pub fn jailer_command(&self, vm_id: &VmId, jailer_binary: impl Into<String>) -> JailerCommand {
        JailerCommand::new(
            jailer_binary,
            vm_id.as_str(),
            self.relative_leaf_path(vm_id),
        )
    }

    // -- Pure checks --------------------------------------------------------

    /// Confirm the cgroup root exists and is a directory.
    ///
    /// Returns [`ErrorCode::CgroupUnavailable`] when the root is missing, so
    /// callers fail closed **before** any process spawn.
    pub fn require_root(&self) -> Result<(), MicrovmError> {
        if self.root.is_dir() {
            Ok(())
        } else {
            Err(MicrovmError::new(
                ErrorCode::CgroupUnavailable,
                "cgroup-v2 root is not an available directory",
            )
            .with_context("root", self.root.display().to_string()))
        }
    }

    /// Read the controllers exposed by a cgroup directory from its
    /// `cgroup.controllers` file.
    pub fn read_available_controllers(dir: &Path) -> Result<Vec<Controller>, MicrovmError> {
        let path = dir.join("cgroup.controllers");
        let contents = fs::read_to_string(&path)
            .map_err(|e| cgroup_error(e, "failed to read cgroup.controllers", &path))?;
        Ok(parse_controllers(&contents))
    }

    /// Verify the parent cgroup exposes every controller `spec` requires.
    ///
    /// Returns [`ErrorCode::CgroupUnavailable`] (with the missing/available
    /// controller sets in context) when any required controller is absent.
    pub fn check_parent_controllers(&self, spec: &CgroupSpec) -> Result<(), MicrovmError> {
        self.require_root()?;
        let parent = self.parent_path();
        let available = Self::read_available_controllers(&parent)?;
        check_required_controllers(&available, spec)
    }

    /// Validate that a leaf directory satisfies the leaf contract: it exists,
    /// has no child cgroups, and its `cgroup.subtree_control` is empty.
    pub fn verify_leaf(&self, vm_id: &VmId) -> Result<(), MicrovmError> {
        let leaf = self.leaf_path(vm_id);
        if !leaf.is_dir() {
            return Err(MicrovmError::new(
                ErrorCode::CgroupUnavailable,
                "leaf cgroup does not exist",
            )
            .with_context("leaf", leaf.display().to_string()));
        }

        let children = list_child_cgroups(&leaf)?;
        validate_no_children(&children)?;

        let subtree = leaf.join("cgroup.subtree_control");
        let contents = fs::read_to_string(&subtree).unwrap_or_default();
        validate_subtree_control_empty(&contents)
    }

    // -- Filesystem operations ---------------------------------------------

    /// Create the parent cgroup and delegate the required controllers
    /// top-down.
    ///
    /// Writes `+cpu +memory +pids +io` to the root's and the parent's
    /// `cgroup.subtree_control` so the controllers are available in every leaf.
    pub fn create_parent(&self) -> Result<(), MicrovmError> {
        self.require_root()?;
        let enable = "+cpu +memory +pids +io";

        // Delegate from the root down to the parent.
        write_cgroup_file(&self.root.join("cgroup.subtree_control"), enable)?;

        let parent = self.parent_path();
        fs::create_dir_all(&parent)
            .map_err(|e| cgroup_error(e, "failed to create parent cgroup", &parent))?;

        // Delegate from the parent down to the leaves.
        write_cgroup_file(&parent.join("cgroup.subtree_control"), enable)?;
        Ok(())
    }

    /// Create a per-VM leaf cgroup beneath the parent.
    ///
    /// The parent must already exist ([`CgroupManager::create_parent`]). The
    /// leaf is created with an empty `cgroup.subtree_control`.
    pub fn create_leaf(&self, vm_id: &VmId) -> Result<PathBuf, MicrovmError> {
        self.require_root()?;
        let parent = self.parent_path();
        if !parent.is_dir() {
            return Err(MicrovmError::new(
                ErrorCode::CgroupUnavailable,
                "parent cgroup does not exist; call create_parent first",
            )
            .with_context("parent", parent.display().to_string()));
        }

        let leaf = self.leaf_path(vm_id);
        fs::create_dir_all(&leaf)
            .map_err(|e| cgroup_error(e, "failed to create leaf cgroup", &leaf))?;
        Ok(leaf)
    }

    /// Validate `spec`, confirm the parent exposes the required controllers,
    /// create the leaf, and write every resource-limit file.
    ///
    /// This is the single entry point used before handing the leaf to the
    /// jailer. It fails closed with [`ErrorCode::InvalidResourceSpec`] or
    /// [`ErrorCode::CgroupUnavailable`] before writing anything when the spec
    /// or hierarchy is invalid.
    pub fn apply_spec(&self, vm_id: &VmId, spec: &CgroupSpec) -> Result<PathBuf, MicrovmError> {
        spec.validate()?;
        self.check_parent_controllers(spec)?;

        let leaf = self.create_leaf(vm_id)?;
        write_cgroup_file(&leaf.join("cpu.max"), &spec.cpu_max_value())?;
        write_cgroup_file(&leaf.join("memory.max"), &spec.memory_max_value())?;
        write_cgroup_file(&leaf.join("memory.swap.max"), &spec.memory_swap_max_value())?;
        write_cgroup_file(&leaf.join("pids.max"), &spec.pids_max_value())?;
        if let Some(io_line) = spec.io_max_value() {
            write_cgroup_file(&leaf.join("io.max"), &io_line)?;
        }
        Ok(leaf)
    }

    /// Read back the configured limit files for a leaf, for round-trip
    /// verification.
    pub fn read_back(&self, vm_id: &VmId) -> Result<AppliedLimits, MicrovmError> {
        let leaf = self.leaf_path(vm_id);
        let cpu_max = read_cgroup_file(&leaf.join("cpu.max"))?;
        let memory_max = read_cgroup_file(&leaf.join("memory.max"))?;
        let memory_swap_max = read_cgroup_file(&leaf.join("memory.swap.max"))?;
        let pids_max = read_cgroup_file(&leaf.join("pids.max"))?;
        let io_max = match read_cgroup_file(&leaf.join("io.max")) {
            // An empty io.max means no I/O limit was applied — treat as None.
            Ok(v) if v.is_empty() => None,
            Ok(v) => Some(v),
            // io.max is optional; a missing file means no I/O limit was set.
            Err(e) if e.code == ErrorCode::CgroupUnavailable => None,
            Err(e) => return Err(e),
        };
        Ok(AppliedLimits {
            cpu_max,
            memory_max,
            memory_swap_max,
            pids_max,
            io_max,
        })
    }

    /// Remove a per-VM leaf cgroup (idempotent cleanup).
    pub fn teardown_leaf(&self, vm_id: &VmId) -> Result<(), MicrovmError> {
        let leaf = self.leaf_path(vm_id);
        if !leaf.exists() {
            return Ok(());
        }
        // In cgroup v2, a cgroup is removed with rmdir(2), not by deleting
        // its pseudo-files. Try rmdir first (works on real cgroups); fall
        // back to remove_dir_all for simulated/tempdir hierarchies that
        // contain regular files.
        match fs::remove_dir(&leaf) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => fs::remove_dir_all(&leaf)
                .map_err(|e| cgroup_error(e, "failed to remove leaf cgroup", &leaf)),
        }
    }
}

// ---------------------------------------------------------------------------
// AppliedLimits
// ---------------------------------------------------------------------------

/// Resource-limit values read back from a leaf cgroup's files (trimmed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedLimits {
    /// Contents of `cpu.max` (`<quota> <period>`).
    pub cpu_max: String,
    /// Contents of `memory.max`.
    pub memory_max: String,
    /// Contents of `memory.swap.max`.
    pub memory_swap_max: String,
    /// Contents of `pids.max`.
    pub pids_max: String,
    /// Contents of `io.max`, if present.
    pub io_max: Option<String>,
}

impl AppliedLimits {
    /// Confirm the read-back values match what `spec` would have written.
    pub fn matches_spec(&self, spec: &CgroupSpec) -> bool {
        self.cpu_max == spec.cpu_max_value()
            && self.memory_max == spec.memory_max_value()
            && self.memory_swap_max == spec.memory_swap_max_value()
            && self.pids_max == spec.pids_max_value()
            && self.io_max == spec.io_max_value()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// List the child cgroup directory names directly beneath `dir`.
fn list_child_cgroups(dir: &Path) -> Result<Vec<String>, MicrovmError> {
    let mut children = Vec::new();
    let entries =
        fs::read_dir(dir).map_err(|e| cgroup_error(e, "failed to read cgroup directory", dir))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| cgroup_error(e, "failed to read cgroup directory entry", dir))?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Some(name) = entry.file_name().to_str() {
                children.push(name.to_string());
            }
        }
    }
    children.sort();
    Ok(children)
}

/// Write a single cgroup control file.
fn write_cgroup_file(path: &Path, contents: &str) -> Result<(), MicrovmError> {
    fs::write(path, contents).map_err(|e| cgroup_error(e, "failed to write cgroup file", path))
}

/// Read and trim a single cgroup control file.
fn read_cgroup_file(path: &Path) -> Result<String, MicrovmError> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| cgroup_error(e, "failed to read cgroup file", path))
}

/// Map an I/O error on a cgroup path to a typed [`ErrorCode::CgroupUnavailable`].
fn cgroup_error(e: io::Error, op: &str, path: &Path) -> MicrovmError {
    MicrovmError::new(ErrorCode::CgroupUnavailable, op)
        .with_context("path", path.display().to_string())
        .with_context("io_error", e.kind().to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::IoMax;
    use tempfile::TempDir;

    fn vm() -> VmId {
        VmId::new("vm-001").unwrap()
    }

    /// Build a simulated cgroup hierarchy in a tempdir: a root that exposes
    /// `controllers` and a parent whose `cgroup.controllers` lists `available`.
    fn simulated_hierarchy(mgr: &CgroupManager, available: &str) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cgroup");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("cgroup.controllers"), "cpu memory pids io").unwrap();
        fs::write(root.join("cgroup.subtree_control"), "").unwrap();

        let parent = root.join(mgr.parent_name());
        fs::create_dir_all(&parent).unwrap();
        fs::write(parent.join("cgroup.controllers"), available).unwrap();
        fs::write(parent.join("cgroup.subtree_control"), "").unwrap();
        tmp
    }

    fn spec() -> CgroupSpec {
        CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .build()
            .unwrap()
    }

    // -- Paths --------------------------------------------------------------

    #[test]
    fn default_paths() {
        let mgr = CgroupManager::default();
        assert_eq!(mgr.root(), Path::new(DEFAULT_CGROUP_ROOT));
        assert_eq!(mgr.parent_path(), PathBuf::from("/sys/fs/cgroup/microvm"));
        assert_eq!(
            mgr.leaf_path(&vm()),
            PathBuf::from("/sys/fs/cgroup/microvm/vm-001")
        );
        assert_eq!(mgr.relative_leaf_path(&vm()), "microvm/vm-001");
    }

    #[test]
    fn custom_root_and_parent() {
        let mgr = CgroupManager::new("/tmp/cg").with_parent_name("orch");
        assert_eq!(mgr.parent_path(), PathBuf::from("/tmp/cg/orch"));
        assert_eq!(mgr.relative_leaf_path(&vm()), "orch/vm-001");
    }

    // -- require_root -------------------------------------------------------

    #[test]
    fn missing_root_returns_unavailable() {
        let mgr = CgroupManager::new("/definitely/not/a/real/cgroup/root");
        let err = mgr.require_root().unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
        assert!(err.context.contains_key("root"));
    }

    #[test]
    fn present_root_is_ok() {
        let mgr = CgroupManager::new("/tmp");
        assert!(mgr.require_root().is_ok());
    }

    // -- apply_spec / read_back round-trip ---------------------------------

    #[test]
    fn apply_spec_writes_and_reads_back() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));

        mgr.create_parent().unwrap();
        let leaf = mgr.apply_spec(&vm(), &spec()).unwrap();
        assert!(leaf.is_dir());

        let limits = mgr.read_back(&vm()).unwrap();
        assert!(limits.matches_spec(&spec()));
        assert_eq!(limits.cpu_max, "50000 100000");
        assert_eq!(limits.memory_max, "134217728");
        assert_eq!(limits.memory_swap_max, "0");
        assert_eq!(limits.pids_max, "64");
        assert!(limits.io_max.is_none());
    }

    #[test]
    fn apply_spec_with_io_writes_io_max() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));

        let spec = CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .io_max(IoMax::new(8, 0))
            .build()
            .unwrap();

        mgr.create_parent().unwrap();
        mgr.apply_spec(&vm(), &spec).unwrap();
        let limits = mgr.read_back(&vm()).unwrap();
        assert_eq!(
            limits.io_max.as_deref(),
            Some("8:0 rbps=max wbps=max riops=max wiops=max")
        );
        assert!(limits.matches_spec(&spec));
    }

    #[test]
    fn apply_spec_invalid_spec_rejected_before_write() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        mgr.create_parent().unwrap();

        let bad = CgroupSpec {
            pids_max: 0,
            ..spec()
        };
        let err = mgr.apply_spec(&vm(), &bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        // No leaf was created for the invalid spec.
        assert!(!mgr.leaf_path(&vm()).exists());
    }

    #[test]
    fn apply_spec_missing_controller_rejected_before_write() {
        let mgr = CgroupManager::new("/placeholder");
        // Parent exposes cpu+pids but NOT memory.
        let tmp = simulated_hierarchy(&mgr, "cpu pids");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        mgr.create_parent().unwrap();

        let err = mgr.apply_spec(&vm(), &spec()).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
        assert_eq!(
            err.context.get("missing").map(String::as_str),
            Some("memory")
        );
        assert!(!mgr.leaf_path(&vm()).exists());
    }

    #[test]
    fn apply_spec_missing_root_rejected() {
        let mgr = CgroupManager::new("/definitely/not/a/real/cgroup/root");
        let err = mgr.apply_spec(&vm(), &spec()).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
    }

    // -- create_parent / create_leaf ---------------------------------------

    #[test]
    fn create_parent_delegates_controllers_top_down() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));

        mgr.create_parent().unwrap();
        let root_sc = fs::read_to_string(mgr.root().join("cgroup.subtree_control")).unwrap();
        let parent_sc =
            fs::read_to_string(mgr.parent_path().join("cgroup.subtree_control")).unwrap();
        assert_eq!(root_sc, "+cpu +memory +pids +io");
        assert_eq!(parent_sc, "+cpu +memory +pids +io");
    }

    #[test]
    fn create_leaf_requires_parent() {
        let tmp = TempDir::new().unwrap();
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        fs::create_dir_all(mgr.root()).unwrap();
        // No parent created.
        let err = mgr.create_leaf(&vm()).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
    }

    // -- verify_leaf --------------------------------------------------------

    #[test]
    fn verify_leaf_ok_for_empty_leaf() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        mgr.create_parent().unwrap();
        mgr.create_leaf(&vm()).unwrap();
        // A freshly created leaf has no subtree_control file -> treated empty.
        assert!(mgr.verify_leaf(&vm()).is_ok());
    }

    #[test]
    fn verify_leaf_rejects_children() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        mgr.create_parent().unwrap();
        let leaf = mgr.create_leaf(&vm()).unwrap();
        fs::create_dir_all(leaf.join("child")).unwrap();

        let err = mgr.verify_leaf(&vm()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert_eq!(
            err.context.get("children").map(String::as_str),
            Some("child")
        );
    }

    #[test]
    fn verify_leaf_rejects_nonempty_subtree_control() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        mgr.create_parent().unwrap();
        let leaf = mgr.create_leaf(&vm()).unwrap();
        fs::write(leaf.join("cgroup.subtree_control"), "cpu").unwrap();

        let err = mgr.verify_leaf(&vm()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn verify_leaf_missing_leaf_unavailable() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        mgr.create_parent().unwrap();
        let err = mgr.verify_leaf(&vm()).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
    }

    // -- teardown -----------------------------------------------------------

    #[test]
    fn teardown_leaf_is_idempotent() {
        let mgr = CgroupManager::new("/placeholder");
        let tmp = simulated_hierarchy(&mgr, "cpu memory pids io");
        let mgr = CgroupManager::new(tmp.path().join("cgroup"));
        mgr.create_parent().unwrap();
        mgr.create_leaf(&vm()).unwrap();

        mgr.teardown_leaf(&vm()).unwrap();
        assert!(!mgr.leaf_path(&vm()).exists());
        // Second teardown of an already-removed leaf is a no-op.
        mgr.teardown_leaf(&vm()).unwrap();
    }

    // -- JailerCommand ------------------------------------------------------

    #[test]
    fn jailer_argv_always_includes_cgroup_version_2_and_parent() {
        let mgr = CgroupManager::new("/sys/fs/cgroup");
        let cmd = mgr.jailer_command(&vm(), "/usr/bin/jailer");
        let argv = cmd.argv();

        assert_eq!(argv[0], "/usr/bin/jailer");
        assert!(argv.contains(&"--cgroup-version=2".to_string()));
        let idx = argv
            .iter()
            .position(|a| a == "--parent-cgroup")
            .expect("--parent-cgroup present");
        assert_eq!(argv[idx + 1], "microvm/vm-001");
    }

    #[test]
    fn jailer_argv_appends_extra_args_after_cgroup_flags() {
        let cmd = JailerCommand::new("/usr/bin/jailer", "vm-001", "microvm/vm-001")
            .with_arg("--uid", "10000")
            .with_arg("--gid", "10000");
        let argv = cmd.argv();
        assert!(argv.contains(&"--cgroup-version=2".to_string()));
        assert!(argv.contains(&"--uid".to_string()));
        assert!(argv.contains(&"--gid".to_string()));
        // cgroup flags come before extra args.
        let cg = argv.iter().position(|a| a == "--parent-cgroup").unwrap();
        let uid = argv.iter().position(|a| a == "--uid").unwrap();
        assert!(cg < uid);
    }

    #[test]
    fn jailer_command_uses_precreated_relative_leaf() {
        let mgr = CgroupManager::new("/sys/fs/cgroup").with_parent_name("orch");
        let cmd = mgr.jailer_command(&vm(), "jailer");
        assert_eq!(cmd.parent_cgroup(), "orch/vm-001");
    }
}
