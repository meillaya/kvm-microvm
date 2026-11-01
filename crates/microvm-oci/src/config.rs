//! Image-config parsing, forbidden-field rejection, and resource extraction.
//!
//! The constrained importer reads the OCI image config blob to select the
//! platform and to derive a typed microVM resource specification from
//! `org.microvm.*` labels. It then refuses any config that carries OCI
//! runtime knobs the platform will not apply to the host: mounts, capability
//! additions, privileged mode, host network/PID/IPC sharing, and arbitrary host
//! process controls. The refusal is a recursive key scan over the raw JSON, so
//! it is independent of where the knob is nested and fails closed.
//!
//! Guest-container metadata that the microVM does not apply (`Env`, `Cmd`,
//! `Entrypoint`, `WorkingDir`, `User`) is ignored rather than applied; it is the
//! forbidden runtime knobs, not inert metadata, that trigger rejection.

use crate::error::{ForbiddenField, ImportError};
use microvm_types::{NetworkPolicy, ResourceSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Label carrying the guest vCPU count.
pub const LABEL_VCPU: &str = "org.microvm.vcpu";
/// Label carrying the guest memory in MiB.
pub const LABEL_MEMORY_MIB: &str = "org.microvm.memory-mib";
/// Label carrying the guest disk allocation in MiB.
pub const LABEL_DISK_MIB: &str = "org.microvm.disk-mib";
/// Label carrying the network egress policy (`none`, `nat-only`, `egress-allowed`).
pub const LABEL_NETWORK: &str = "org.microvm.network";
/// Label carrying the kernel boot arguments (cmdline).
pub const LABEL_BOOT_ARGS: &str = "org.microvm.boot-args";

/// Default guest vCPU count when [`LABEL_VCPU`] is absent.
pub const DEFAULT_VCPU: u32 = 1;
/// Default guest memory (MiB) when [`LABEL_MEMORY_MIB`] is absent.
pub const DEFAULT_MEMORY_MIB: u64 = 512;
/// Default guest disk (MiB) when [`LABEL_DISK_MIB`] is absent.
pub const DEFAULT_DISK_MIB: u64 = 1024;
/// Default kernel boot arguments when [`LABEL_BOOT_ARGS`] is absent.
pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";

/// Lowercased exact key names the constrained importer refuses, mapped to their
/// rejection category. Matching is exact (not substring) on the lowercased key.
const FORBIDDEN_KEYS: &[(&str, ForbiddenField)] = &[
    ("mount", ForbiddenField::Mounts),
    ("mounts", ForbiddenField::Mounts),
    ("capabilities", ForbiddenField::Capabilities),
    ("capability", ForbiddenField::Capabilities),
    ("capadd", ForbiddenField::Capabilities),
    ("cap_add", ForbiddenField::Capabilities),
    ("capdrop", ForbiddenField::Capabilities),
    ("cap_drop", ForbiddenField::Capabilities),
    ("privileged", ForbiddenField::Privileged),
    ("hostnetwork", ForbiddenField::HostNetwork),
    ("host_network", ForbiddenField::HostNetwork),
    ("networkmode", ForbiddenField::HostNetwork),
    ("network_mode", ForbiddenField::HostNetwork),
    ("hostpid", ForbiddenField::HostPid),
    ("host_pid", ForbiddenField::HostPid),
    ("pidmode", ForbiddenField::HostPid),
    ("pid_mode", ForbiddenField::HostPid),
    ("hostipc", ForbiddenField::HostIpc),
    ("host_ipc", ForbiddenField::HostIpc),
    ("ipcmode", ForbiddenField::HostIpc),
    ("ipc_mode", ForbiddenField::HostIpc),
    ("process", ForbiddenField::HostProcessControl),
    ("rlimits", ForbiddenField::HostProcessControl),
    ("oomscoreadj", ForbiddenField::HostProcessControl),
    ("oom_score_adj", ForbiddenField::HostProcessControl),
    ("devices", ForbiddenField::HostProcessControl),
    ("sysctls", ForbiddenField::HostProcessControl),
    ("selinuxoptions", ForbiddenField::HostProcessControl),
    ("apparmorprofile", ForbiddenField::HostProcessControl),
];

/// Recursively scan a JSON document for a forbidden runtime key.
///
/// Returns the first offending `(field, key)` in deterministic order
/// (`serde_json::Map` iterates keys in sorted order). Object keys are matched
/// case-insensitively; the scan descends into nested objects and arrays.
pub fn scan_forbidden(value: &Value) -> Option<(ForbiddenField, String)> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if let Some((_, field)) = FORBIDDEN_KEYS
                    .iter()
                    .find(|(name, _)| *name == lower.as_str())
                {
                    return Some((*field, key.clone()));
                }
                if let Some(found) = scan_forbidden(child) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(scan_forbidden),
        _ => None,
    }
}

/// The constrained view of an OCI image config blob.
///
/// Only the fields the importer needs are typed; inert guest-container metadata
/// is ignored. Dangerous runtime knobs are caught by [`scan_forbidden`] before
/// this struct is built.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciImageConfig {
    /// CPU architecture token (`amd64`, `arm64`, or a synonym).
    #[serde(default)]
    pub architecture: String,
    /// Operating system token (`linux`).
    #[serde(default)]
    pub os: String,
    /// Optional container config carrying `org.microvm.*` labels.
    #[serde(default, rename = "config")]
    pub container: Option<OciContainerConfig>,
    /// Optional rootfs diff-id list (informational; not applied to the host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<OciRootfs>,
}

/// The image config's `config` object; only labels are read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciContainerConfig {
    /// Image labels (`org.microvm.*` carry the microVM resource spec).
    #[serde(default, rename = "Labels")]
    pub labels: Option<BTreeMap<String, String>>,
}

/// The image config's `rootfs` object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciRootfs {
    /// Rootfs type (OCI requires `layers`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Ordered layer diff-ids.
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

impl OciImageConfig {
    /// Parse the constrained image config from a JSON value.
    pub fn from_value(value: &Value) -> Result<Self, ImportError> {
        serde_json::from_value(value.clone()).map_err(|e| ImportError::ConfigInvalid {
            reason: format!("image config did not parse: {e}"),
        })
    }

    /// The `org.microvm.*` labels (empty map if none are present).
    pub fn labels(&self) -> BTreeMap<String, String> {
        self.container
            .as_ref()
            .and_then(|c| c.labels.clone())
            .unwrap_or_default()
    }
}

/// The microVM resource specification derived from image labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MicroVmResources {
    /// Guest vCPU count.
    pub vcpu: u32,
    /// Guest memory in MiB.
    pub memory_mib: u64,
    /// Guest disk allocation in MiB.
    pub disk_mib: u64,
    /// Network egress policy.
    pub network: NetworkPolicy,
    /// Kernel boot arguments.
    pub boot_args: String,
}

impl MicroVmResources {
    /// Derive resources from `org.microvm.*` labels, applying documented
    /// defaults for absent labels.
    pub fn from_labels(labels: &BTreeMap<String, String>) -> Result<Self, ImportError> {
        let vcpu = parse_label(labels, LABEL_VCPU, DEFAULT_VCPU)?;
        let memory_mib = parse_label(labels, LABEL_MEMORY_MIB, DEFAULT_MEMORY_MIB)?;
        let disk_mib = parse_label(labels, LABEL_DISK_MIB, DEFAULT_DISK_MIB)?;
        let network = parse_network(labels)?;
        let boot_args = labels
            .get(LABEL_BOOT_ARGS)
            .cloned()
            .unwrap_or_else(|| DEFAULT_BOOT_ARGS.to_string());
        if boot_args.bytes().any(|b| b == 0) {
            return Err(ImportError::InvalidResources {
                reason: "boot args must not contain NUL".to_string(),
            });
        }
        Ok(Self {
            vcpu,
            memory_mib,
            disk_mib,
            network,
            boot_args,
        })
    }

    /// Build the validated [`ResourceSpec`], mapping validation failure to a
    /// typed [`ImportError::InvalidResources`].
    pub fn to_resource_spec(&self) -> Result<ResourceSpec, ImportError> {
        ResourceSpec::new(self.vcpu, self.memory_mib, self.disk_mib, self.network).map_err(|e| {
            ImportError::InvalidResources {
                reason: e.to_string(),
            }
        })
    }
}

fn parse_label<T>(
    labels: &BTreeMap<String, String>,
    key: &str,
    default: T,
) -> Result<T, ImportError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match labels.get(key) {
        Some(raw) => raw.parse::<T>().map_err(|e| ImportError::InvalidResources {
            reason: format!("label {key}={raw:?} is not a valid number: {e}"),
        }),
        None => Ok(default),
    }
}

fn parse_network(labels: &BTreeMap<String, String>) -> Result<NetworkPolicy, ImportError> {
    let Some(raw) = labels.get(LABEL_NETWORK) else {
        return Ok(NetworkPolicy::None);
    };
    match raw.to_ascii_lowercase().replace('_', "-").as_str() {
        "none" => Ok(NetworkPolicy::None),
        "nat-only" => Ok(NetworkPolicy::NatOnly),
        "egress-allowed" => Ok(NetworkPolicy::EgressAllowed),
        other => Err(ImportError::InvalidResources {
            reason: format!(
                "label {LABEL_NETWORK}={other:?} is not one of none, nat-only, egress-allowed"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scan_detects_forbidden_keys_at_any_depth() {
        let cases = [
            (json!({"mounts": []}), ForbiddenField::Mounts),
            (json!({"linux": {"mounts": []}}), ForbiddenField::Mounts),
            (
                json!({"process": {"args": ["sh"]}}),
                ForbiddenField::HostProcessControl,
            ),
            (
                json!({"process": {"capabilities": {"bounding": ["CAP_NET_ADMIN"]}}}),
                // "capabilities" sorts before "process" alphabetically, but
                // "process" is the top-level key scanned first.
                ForbiddenField::HostProcessControl,
            ),
            (
                json!({"cap_add": ["NET_ADMIN"]}),
                ForbiddenField::Capabilities,
            ),
            (json!({"privileged": true}), ForbiddenField::Privileged),
            (json!({"host_network": true}), ForbiddenField::HostNetwork),
            (json!({"network_mode": "host"}), ForbiddenField::HostNetwork),
            (json!({"host_pid": true}), ForbiddenField::HostPid),
            (json!({"host_ipc": true}), ForbiddenField::HostIpc),
            (json!({"sysctls": {}}), ForbiddenField::HostProcessControl),
            (json!({"devices": []}), ForbiddenField::HostProcessControl),
        ];
        for (doc, field) in cases {
            let (found, _key) = scan_forbidden(&doc).unwrap_or_else(|| panic!("missed {doc}"));
            assert_eq!(found, field, "doc={doc}");
        }
    }

    #[test]
    fn scan_is_case_insensitive_on_keys() {
        let doc = json!({"Privileged": true});
        let (field, key) = scan_forbidden(&doc).unwrap();
        assert_eq!(field, ForbiddenField::Privileged);
        assert_eq!(key, "Privileged");
    }

    #[test]
    fn scan_accepts_benign_image_config() {
        let doc = json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/bin"],
                "Cmd": ["/sbin/init"],
                "WorkingDir": "/",
                "Labels": {"org.microvm.vcpu": "2"}
            },
            "rootfs": {"type": "layers", "diff_ids": ["sha256:aa"]}
        });
        assert_eq!(scan_forbidden(&doc), None);
    }

    #[test]
    fn scan_finds_forbidden_inside_arrays() {
        let doc = json!([{"ok": 1}, {"mounts": []}]);
        assert_eq!(
            scan_forbidden(&doc).map(|(f, _)| f),
            Some(ForbiddenField::Mounts)
        );
    }

    #[test]
    fn resources_apply_defaults_when_labels_absent() {
        let r = MicroVmResources::from_labels(&BTreeMap::new()).unwrap();
        assert_eq!(r.vcpu, DEFAULT_VCPU);
        assert_eq!(r.memory_mib, DEFAULT_MEMORY_MIB);
        assert_eq!(r.disk_mib, DEFAULT_DISK_MIB);
        assert_eq!(r.network, NetworkPolicy::None);
        assert_eq!(r.boot_args, DEFAULT_BOOT_ARGS);
    }

    #[test]
    fn resources_parse_labels() {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_VCPU.to_string(), "4".to_string());
        labels.insert(LABEL_MEMORY_MIB.to_string(), "2048".to_string());
        labels.insert(LABEL_DISK_MIB.to_string(), "4096".to_string());
        labels.insert(LABEL_NETWORK.to_string(), "nat-only".to_string());
        labels.insert(LABEL_BOOT_ARGS.to_string(), "console=ttyS0".to_string());
        let r = MicroVmResources::from_labels(&labels).unwrap();
        assert_eq!(r.vcpu, 4);
        assert_eq!(r.memory_mib, 2048);
        assert_eq!(r.disk_mib, 4096);
        assert_eq!(r.network, NetworkPolicy::NatOnly);
        assert_eq!(r.boot_args, "console=ttyS0");
        let spec = r.to_resource_spec().unwrap();
        assert_eq!(spec.vcpu_count(), 4);
        assert_eq!(spec.network_policy(), NetworkPolicy::NatOnly);
    }

    #[test]
    fn resources_reject_bad_number_and_network() {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_VCPU.to_string(), "not-a-number".to_string());
        assert!(matches!(
            MicroVmResources::from_labels(&labels).unwrap_err(),
            ImportError::InvalidResources { .. }
        ));

        let mut labels = BTreeMap::new();
        labels.insert(LABEL_NETWORK.to_string(), "bridge".to_string());
        assert!(matches!(
            MicroVmResources::from_labels(&labels).unwrap_err(),
            ImportError::InvalidResources { .. }
        ));
    }

    #[test]
    fn resources_reject_zero_via_resource_spec() {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_VCPU.to_string(), "0".to_string());
        let r = MicroVmResources::from_labels(&labels).unwrap();
        assert!(matches!(
            r.to_resource_spec().unwrap_err(),
            ImportError::InvalidResources { .. }
        ));
    }

    #[test]
    fn image_config_reads_labels() {
        let doc = json!({
            "architecture": "arm64",
            "os": "linux",
            "config": {"Labels": {"org.microvm.vcpu": "2"}}
        });
        let cfg = OciImageConfig::from_value(&doc).unwrap();
        assert_eq!(cfg.architecture, "arm64");
        assert_eq!(cfg.os, "linux");
        assert_eq!(cfg.labels().get(LABEL_VCPU).map(String::as_str), Some("2"));
    }
}
