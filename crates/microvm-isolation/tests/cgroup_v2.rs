//! Privileged cgroup-v2 integration test.
//!
//! Run with:
//! ```text
//! cargo test --features privileged --test cgroup_v2 -- --nocapture
//! ```
//!
//! This exercises a **real** unified cgroup-v2 hierarchy on a capable host.
//! When the host cannot support it (no cgroup2 mount, missing controllers, or
//! insufficient privilege to delegate), the test reports a stable `blocked`
//! token and passes rather than failing — matching the platform's privileged
//! evidence model (`pass` / `blocked` / `failed`). It never spawns Firecracker
//! and always tears down any cgroup it creates.

#![cfg(feature = "privileged")]

use microvm_errors::ErrorCode;
use microvm_isolation::{CgroupManager, CgroupSpec};
use microvm_types::VmId;
use std::fs;
use std::path::Path;

const CG_ROOT: &str = "/sys/fs/cgroup";

/// Print a blocked token and return; used when the host cannot run the test.
fn blocked(reason: &str) {
    println!("blocked: {reason}");
}

/// True iff `/sys/fs/cgroup` looks like a unified cgroup-v2 mount.
fn cgroup2_available() -> bool {
    Path::new(CG_ROOT).join("cgroup.controllers").exists()
}

#[test]
fn enforce_cpu_memory_pids_on_real_hierarchy() {
    if !cgroup2_available() {
        blocked("cgroup_v2_missing");
        return;
    }

    // Unique test parent so concurrent/previous runs do not collide.
    let parent = format!("microvm-isolation-test-{}", std::process::id());
    let mgr = CgroupManager::new(CG_ROOT).with_parent_name(&parent);
    let vm = VmId::new("vm-priv").unwrap();
    let spec = CgroupSpec::builder()
        .cpu_quota_us(50_000)
        .memory_max_bytes(128 * 1024 * 1024)
        .pids_max(64)
        .build()
        .unwrap();

    // Delegate controllers top-down. This requires privilege; treat failure as
    // a host gap (blocked), not a code failure.
    if let Err(e) = mgr.create_parent() {
        if e.code == ErrorCode::CgroupUnavailable {
            blocked(&format!("cgroup_delegate_failed: {e}"));
            return;
        }
        panic!("unexpected create_parent error: {e}");
    }

    // From here on we must clean up the parent no matter what.
    let result = run_leaf_checks(&mgr, &vm, &spec);

    // Best-effort teardown of the parent (only succeeds once empty).
    let _ = fs::remove_dir(mgr.parent_path());

    if let Err(e) = result {
        panic!("privileged cgroup check failed: {e}");
    }
    println!("pass: cgroup-v2 cpu/memory/pids limits enforced and read back");
}

fn run_leaf_checks(
    mgr: &CgroupManager,
    vm: &VmId,
    spec: &CgroupSpec,
) -> Result<(), microvm_errors::MicrovmError> {
    // Confirm the parent exposes the required controllers on the real host.
    mgr.check_parent_controllers(spec)?;

    // Apply the spec: creates the leaf and writes cpu.max/memory.max/etc.
    let leaf = mgr.apply_spec(vm, spec)?;
    assert!(leaf.is_dir(), "leaf cgroup must exist after apply_spec");

    // Leaf contract: no children, empty subtree_control.
    mgr.verify_leaf(vm)?;

    // Configured values round-trip from the kernel's cgroup files.
    let limits = mgr.read_back(vm)?;
    assert!(
        limits.matches_spec(spec),
        "read-back limits must match the applied spec: {limits:?}"
    );

    // The jailer argv references cgroup v2 and the pre-created leaf.
    let argv = mgr.jailer_command(vm, "/usr/bin/jailer").argv();
    assert!(argv.contains(&"--cgroup-version=2".to_string()));
    assert!(argv.iter().any(|a| a == "--parent-cgroup"));

    // Teardown the leaf.
    mgr.teardown_leaf(vm)?;
    assert!(!leaf.exists(), "leaf must be removed after teardown");
    Ok(())
}
