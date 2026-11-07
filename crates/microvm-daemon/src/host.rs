//! Host probing, guest image preparation, and snapshot compatibility data.

use crate::config::ImageConfig;
use microvm_artifacts::{compute_sha256, GuestArch, ImageBuilder};
use microvm_firecracker::{BackendConfig, BootConfig, SnapshotHostInfo};
use microvm_snapshots::{CgroupVersion, CpuCompatibility, FirecrackerBinary, HostEnvironment};
use microvm_types::TenantId;
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::config::{BackendKind, DaemonConfig};

/// The KVM API version call used by Firecracker.
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;

/// Prepared image and snapshot data for the Firecracker backend.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// Boot configuration derived from the configured image.
    pub boot: Option<BootConfig>,
    /// Host and binary data recorded in snapshot manifests.
    pub snapshot_host: Option<SnapshotHostInfo>,
}

/// Read the KVM API version from `/dev/kvm`.
pub fn kvm_api_version(path: &Path) -> Result<u32, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let version = unsafe { libc::ioctl(file.as_raw_fd(), KVM_GET_API_VERSION, 0) };
    if version < 0 {
        return Err(format!(
            "KVM_GET_API_VERSION failed on {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(version as u32)
}

/// Parse the CPU model and virtualization flag from `/proc/cpuinfo`.
fn cpu_compatibility() -> Result<CpuCompatibility, String> {
    let text = std::fs::read_to_string("/proc/cpuinfo")
        .map_err(|e| format!("cannot read /proc/cpuinfo: {e}"))?;
    let mut model = String::new();
    let mut flags = BTreeSet::new();
    for line in text.lines() {
        if model.is_empty() {
            if let Some(value) = line.strip_prefix("model name") {
                if let Some(value) = value.split_once(':') {
                    model = value.1.trim().to_string();
                }
            }
        }
        if let Some(value) = line.strip_prefix("flags") {
            if let Some(value) = value.split_once(':') {
                for flag in value.1.split_whitespace() {
                    flags.insert(flag.to_string());
                }
            }
        }
    }
    if model.is_empty() {
        model = "unknown".to_string();
    }
    let required = if flags.contains("svm") {
        BTreeSet::from(["svm".to_string()])
    } else if flags.contains("vmx") {
        BTreeSet::from(["vmx".to_string()])
    } else {
        return Err("host CPU exposes neither svm nor vmx".to_string());
    };
    let arch = std::env::consts::ARCH.to_string();
    CpuCompatibility::new(arch, model, required).map_err(|e| e.to_string())
}

/// Build the host compatibility envelope used by snapshot manifests.
pub fn host_environment(cgroup_root: &Path) -> Result<HostEnvironment, String> {
    let controllers = cgroup_root.join("cgroup.controllers");
    if !controllers.is_file() {
        return Err(format!("{} is not a cgroup v2 root", cgroup_root.display()));
    }
    let kvm_api_version = kvm_api_version(Path::new("/dev/kvm"))?;
    Ok(HostEnvironment {
        cpu: cpu_compatibility()?,
        kvm_api_version,
        cgroup_version: CgroupVersion::V2,
    })
}

/// Read the Firecracker binary version and SHA-256.
pub fn firecracker_binary(path: &Path, version: &str) -> Result<FirecrackerBinary, String> {
    if !path.is_file() {
        return Err(format!(
            "Firecracker binary does not exist: {}",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let digest = compute_sha256(file).map_err(|e| e.to_string())?;
    FirecrackerBinary::new(version.to_string(), digest).map_err(|e| e.to_string())
}

/// Prepare the configured guest image and host snapshot data.
pub fn prepare(config: &DaemonConfig) -> Result<Prepared, String> {
    if config.backend == BackendKind::Sim {
        return Ok(Prepared {
            boot: None,
            snapshot_host: None,
        });
    }

    let image = config
        .image
        .as_ref()
        .ok_or_else(|| "image is required for the firecracker backend".to_string())?;
    let tenant = config.tenant();
    let tenant_root = config.paths.artifact_dir.join(tenant.as_str());
    std::fs::create_dir_all(&tenant_root)
        .map_err(|e| format!("cannot create {}: {e}", tenant_root.display()))?;

    let boot = build_boot_config(image, &tenant_root)?;
    let host = host_environment(&config.isolation.cgroup_root)?;
    let binary = firecracker_binary(
        &config.runtime.firecracker,
        &config.runtime.firecracker_version,
    )?;
    Ok(Prepared {
        boot: Some(boot),
        snapshot_host: Some(SnapshotHostInfo { host, binary }),
    })
}

fn build_boot_config(image: &ImageConfig, tenant_root: &Path) -> Result<BootConfig, String> {
    let builder =
        ImageBuilder::new(GuestArch::X86_64, image.boot_args.clone()).map_err(|e| e.to_string())?;
    let output = builder
        .build(
            &image.kernel.to_string_lossy(),
            &image.rootfs.to_string_lossy(),
            tenant_root,
        )
        .map_err(|e| e.to_string())?;
    let kernel = output.manifest.kernel.clone();
    let rootfs = output.manifest.rootfs.clone();
    BootConfig::builder()
        .kernel_path(kernel.path)
        .kernel_sha256(kernel.sha256)
        .rootfs_path(rootfs.path)
        .rootfs_sha256(rootfs.sha256)
        .vcpu_count(1)
        .mem_size_mib(128)
        .boot_args(image.boot_args.clone())
        .build()
        .map_err(|e| e.to_string())
}

/// Validate a config without writing anything or serving.
pub fn check(config: &DaemonConfig) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    if config.backend == BackendKind::Sim {
        notes.push("backend sim: no KVM, cgroup, or image checks".to_string());
        return Ok(notes);
    }

    config
        .image
        .as_ref()
        .ok_or_else(|| "image is required for the firecracker backend".to_string())?;
    let api = kvm_api_version(Path::new("/dev/kvm"))?;
    notes.push(format!("KVM API version {api}"));
    host_environment(&config.isolation.cgroup_root)?;
    notes.push(format!(
        "cgroup v2 root {}",
        config.isolation.cgroup_root.display()
    ));
    firecracker_binary(
        &config.runtime.firecracker,
        &config.runtime.firecracker_version,
    )?;
    notes.push(format!(
        "Firecracker {} at {}",
        config.runtime.firecracker_version,
        config.runtime.firecracker.display()
    ));
    if config.runtime.use_jailer {
        let jailer = config
            .runtime
            .jailer
            .as_ref()
            .ok_or_else(|| "runtime.jailer is required when use_jailer is true".to_string())?;
        if !jailer.is_file() {
            return Err(format!("jailer does not exist: {}", jailer.display()));
        }
        notes.push(format!("jailer at {}", jailer.display()));
    }
    notes.push("config OK".to_string());
    Ok(notes)
}

/// Build the Firecracker backend configuration from the daemon config.
pub fn backend_config(config: &DaemonConfig, prepared: &Prepared) -> BackendConfig {
    BackendConfig {
        socket_root: config.paths.socket_dir.clone(),
        log_dir: config.paths.log_dir.clone(),
        snapshot_root: config.paths.snapshot_dir.clone(),
        firecracker_binary: config.runtime.firecracker.display().to_string(),
        jailer_binary: config
            .runtime
            .jailer
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        chroot_base_dir: config.paths.chroot_dir.clone(),
        uid: config.isolation.jailer_uid,
        gid: config.isolation.jailer_gid,
        pids_max: config.isolation.pids_max,
        socket_timeout: std::time::Duration::from_millis(config.runtime.socket_timeout_ms),
        readiness_timeout: std::time::Duration::from_millis(config.runtime.readiness_timeout_ms),
        use_jailer: config.runtime.use_jailer,
        snapshot_host: prepared.snapshot_host.clone(),
        ..BackendConfig::default()
    }
}

/// The tenant root used by the artifact store.
pub fn tenant_id(config: &DaemonConfig) -> TenantId {
    config.tenant()
}

/// The per-VM serial log path.
pub fn serial_log_path(config: &DaemonConfig, vm_id: &microvm_types::VmId) -> PathBuf {
    config
        .paths
        .log_dir
        .join(format!("{}.serial.log", vm_id.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kvm_api_version_is_readable_on_this_host() {
        if Path::new("/dev/kvm").exists() {
            let version = kvm_api_version(Path::new("/dev/kvm")).unwrap();
            assert!(version >= 12);
        }
    }
}
