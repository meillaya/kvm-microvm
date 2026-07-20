//! Explicit cgroup-v2 hierarchy management and resource limits for the
//! kvm-microvm-orchestrator platform.
//!
//! This crate owns the platform's cgroup-v2 isolation boundary. Firecracker's
//! jailer historically defaulted to cgroup v1 and is willing to create cgroups
//! itself, so the orchestrator instead builds a **unified cgroup-v2** hierarchy
//! explicitly and hands the jailer only a pre-created leaf path.
//!
//! # Model
//! - One **parent** cgroup (`<root>/microvm`) delegates `cpu`, `memory`,
//!   `pids`, and `io` top-down via `cgroup.subtree_control`.
//! - One **leaf** cgroup per VM (`<root>/microvm/<vm-id>`) carries the explicit
//!   limits (`cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`, and an
//!   optional `io.max`). A leaf has **no children** and an **empty**
//!   `cgroup.subtree_control` — no domain controllers live in a leaf subtree.
//! - The generated jailer argv **always** includes `--cgroup-version=2` and a
//!   `--parent-cgroup` pointing at the pre-created leaf.
//!
//! # Error contract
//! All failures are typed [`MicrovmError`]s. A missing cgroup root or a missing
//! required controller yields [`ErrorCode::CgroupUnavailable`] **before** any
//! process spawn; an invalid [`CgroupSpec`] or a leaf-contract violation yields
//! [`ErrorCode::InvalidResourceSpec`].
//!
//! # Determinism
//! Specification validation, controller checks, leaf-constraint validation, and
//! jailer argv generation are pure. The filesystem layer takes a configurable
//! root and is exercised against a temporary directory in the default test run;
//! a real `/sys/fs/cgroup` run lives behind the `privileged` feature
//! (`cargo test --features privileged --test cgroup_v2`).
//!
//! [`MicrovmError`]: microvm_errors::MicrovmError
//! [`ErrorCode::CgroupUnavailable`]: microvm_errors::ErrorCode::CgroupUnavailable
//! [`ErrorCode::InvalidResourceSpec`]: microvm_errors::ErrorCode::InvalidResourceSpec

pub mod firecracker;
pub mod manager;
pub mod net;
pub mod spec;

pub use manager::{
    AppliedLimits, CgroupManager, JailerCommand, CGROUP_VERSION, DEFAULT_CGROUP_ROOT,
    DEFAULT_PARENT_NAME,
};
pub use net::{
    nft_ruleset, AddressAllocator, NetConfig, NetManager, DEFAULT_NETNS_ROOT, DEFAULT_PREFIX_LEN,
    DEFAULT_SUBNET_OCTETS, IFNAMSIZ, MAX_SLOTS, NFT_TABLE,
};
pub use spec::{
    check_required_controllers, parse_controllers, validate_no_children,
    validate_subtree_control_empty, CgroupSpec, CgroupSpecBuilder, Controller, IoMax,
    DEFAULT_CPU_PERIOD_US, DEFAULT_MEMORY_SWAP_MAX_BYTES,
};

pub use firecracker::{
    binary_contains_version, parse_elf_form, parse_seccomp_mode, pinned_firecracker, pinned_jailer,
    sha256_hex, verify_seccomp_status, BinaryManifest, BinaryVerifier, ElfForm, ElfMachine,
    JailerArgv, JailerArgvBuilder, ResourceKind, SeccompVerifier, VerifiedBinary,
    DEFAULT_FSIZE_BYTES, DEFAULT_NO_FILE, DEFAULT_PROC_ROOT, MAX_FSIZE_BYTES, MAX_NO_FILE,
    PINNED_VERSION, SECCOMP_MODE_FILTER,
};

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_errors::ErrorCode;
    use microvm_types::VmId;
    use std::fs;
    use tempfile::TempDir;

    /// Build a simulated hierarchy whose parent exposes `available`.
    fn simulated(root: &std::path::Path, parent: &str, available: &str) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("cgroup.controllers"), "cpu memory pids io").unwrap();
        fs::write(root.join("cgroup.subtree_control"), "").unwrap();
        let p = root.join(parent);
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("cgroup.controllers"), available).unwrap();
        fs::write(p.join("cgroup.subtree_control"), "").unwrap();
    }

    /// End-to-end (deterministic): build a hierarchy in a tempdir, apply a
    /// spec, verify the leaf contract, read the limits back, and confirm the
    /// jailer argv references the pre-created leaf.
    #[test]
    fn end_to_end_isolation_lifecycle() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cgroup");
        simulated(&root, "microvm", "cpu memory pids io");

        let mgr = CgroupManager::new(&root);
        let vm = VmId::new("vm-e2e").unwrap();
        let spec = CgroupSpec::builder()
            .cpu_quota_us(75_000)
            .memory_max_bytes(256 * 1024 * 1024)
            .pids_max(128)
            .build()
            .unwrap();

        // Parent delegates controllers top-down.
        mgr.create_parent().unwrap();

        // Apply the spec: validates, checks controllers, creates the leaf,
        // and writes every limit file.
        let leaf = mgr.apply_spec(&vm, &spec).unwrap();
        assert!(leaf.is_dir());

        // Leaf contract holds: no children, empty subtree_control.
        mgr.verify_leaf(&vm).unwrap();

        // Configured values round-trip from the files.
        let limits = mgr.read_back(&vm).unwrap();
        assert!(limits.matches_spec(&spec));

        // Jailer argv references the pre-created leaf and cgroup v2.
        let argv = mgr.jailer_command(&vm, "/usr/bin/jailer").argv();
        assert!(argv.contains(&"--cgroup-version=2".to_string()));
        assert!(argv.contains(&"microvm/vm-e2e".to_string()));

        // Cleanup removes the leaf.
        mgr.teardown_leaf(&vm).unwrap();
        assert!(!leaf.exists());
    }

    /// A spec requiring `io` fails closed when the parent does not expose the
    /// `io` controller, before any leaf is created.
    #[test]
    fn end_to_end_missing_io_controller_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cgroup");
        simulated(&root, "microvm", "cpu memory pids"); // no io

        let mgr = CgroupManager::new(&root);
        mgr.create_parent().unwrap();

        let vm = VmId::new("vm-io").unwrap();
        let spec = CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .io_max(IoMax::new(8, 0))
            .build()
            .unwrap();

        let err = mgr.apply_spec(&vm, &spec).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
        assert_eq!(err.context.get("missing").map(String::as_str), Some("io"));
        assert!(!mgr.leaf_path(&vm).exists());
    }
}
