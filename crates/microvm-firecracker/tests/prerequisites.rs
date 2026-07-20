//! Deterministic prerequisite tests: missing host capabilities fail **before**
//! any child process is created, both at the checker level and wired into the
//! backend.

mod common;

use common::{PrereqMode, Rig, RigOptions};
use microvm_errors::ErrorCode;
use microvm_firecracker::prereq::{HostPrerequisiteChecker, PrerequisiteCheck};
use microvm_isolation::CgroupManager;
use microvm_lifecycle::{LifecycleService, VmState};
use std::fs;
use tempfile::TempDir;

/// Build a checker whose paths point into `dir`; each resource is created or
/// omitted per the flags.
fn checker(
    dir: &std::path::Path,
    cgroup_root: &std::path::Path,
    kvm: bool,
    tun: bool,
    fc: bool,
    jailer: bool,
) -> HostPrerequisiteChecker {
    if kvm {
        fs::write(dir.join("kvm"), b"").unwrap();
    }
    if tun {
        fs::write(dir.join("tun"), b"").unwrap();
    }
    if fc {
        fs::write(dir.join("firecracker"), b"").unwrap();
    }
    if jailer {
        fs::write(dir.join("jailer"), b"").unwrap();
    }
    HostPrerequisiteChecker::builder()
        .kvm_device(dir.join("kvm"))
        .tun_device(dir.join("tun"))
        .firecracker_binary(dir.join("firecracker"))
        .jailer_binary(dir.join("jailer"))
        .cgroup(CgroupManager::new(cgroup_root))
        .build()
}

#[test]
fn checker_passes_when_all_present() {
    let tmp = TempDir::new().unwrap();
    let cgroup = tmp.path().join("cgroup");
    fs::create_dir_all(&cgroup).unwrap();
    let chk = checker(tmp.path(), &cgroup, true, true, true, true);
    assert!(chk.check(true).is_ok());
}

#[test]
fn checker_missing_kvm_fails_before_binary_checks() {
    let tmp = TempDir::new().unwrap();
    let cgroup = tmp.path().join("cgroup");
    fs::create_dir_all(&cgroup).unwrap();
    // KVM missing AND binaries missing: KVM error must win (checked first).
    let chk = checker(tmp.path(), &cgroup, false, true, false, false);
    let err = chk.check(false).unwrap_err();
    assert_eq!(err.code, ErrorCode::InternalError);
    assert_eq!(
        err.context.get("prerequisite").map(String::as_str),
        Some("kvm")
    );
}

#[test]
fn checker_missing_binary_is_provenance_error() {
    let tmp = TempDir::new().unwrap();
    let cgroup = tmp.path().join("cgroup");
    fs::create_dir_all(&cgroup).unwrap();
    let chk = checker(tmp.path(), &cgroup, true, true, false, true);
    let err = chk.check(false).unwrap_err();
    assert_eq!(err.code, ErrorCode::BinaryProvenanceError);
    assert_eq!(
        err.context.get("role").map(String::as_str),
        Some("firecracker")
    );
}

#[test]
fn checker_missing_cgroup_root_fails() {
    let tmp = TempDir::new().unwrap();
    let cgroup = tmp.path().join("absent");
    let chk = checker(tmp.path(), &cgroup, true, true, true, true);
    let err = chk.check(false).unwrap_err();
    assert_eq!(err.code, ErrorCode::CgroupUnavailable);
}

#[tokio::test]
async fn backend_runs_prereq_before_spawning_child() {
    // A real HostPrerequisiteChecker with a missing KVM device must stop the
    // boot before the launcher is ever invoked.
    let rig = Rig::new(RigOptions {
        prereq: PrereqMode::RealMissingKvm,
        ..RigOptions::default()
    })
    .await;

    let err = rig.backend.start(&rig.vm_id, &rig.owner).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InternalError);
    assert_eq!(
        err.context.get("prerequisite").map(String::as_str),
        Some("kvm")
    );

    // The decisive guarantee: no child process was created.
    assert!(
        rig.launcher.spawned().is_empty(),
        "prereq must fail before child creation"
    );
    assert!(rig.api.calls().is_empty());
    // State remains Created (host problem, retryable on a capable host).
    assert_eq!(rig.backend.vm_state(&rig.vm_id), Some(VmState::Created));
}
