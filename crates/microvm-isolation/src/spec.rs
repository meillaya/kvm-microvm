//! Cgroup-v2 resource specifications and controller model.
//!
//! This module is pure: it contains no filesystem or host calls. Every
//! type here can be validated, serialized, and rendered to the exact cgroup-v2
//! file contents and `io.max` line the kernel expects, which keeps the
//! specification logic fully deterministic and testable without root.

use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Default CPU period in microseconds (100ms), the kernel's conventional
/// scheduling window for `cpu.max`.
pub const DEFAULT_CPU_PERIOD_US: u64 = 100_000;

/// Default swap limit: `0` disables swap for the cgroup (`memory.swap.max`).
pub const DEFAULT_MEMORY_SWAP_MAX_BYTES: u64 = 0;

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// A cgroup-v2 controller the orchestrator delegates top-down from the parent
/// cgroup to each per-VM leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Controller {
    /// CPU bandwidth control (`cpu.max`).
    Cpu,
    /// Memory accounting and limits (`memory.max`, `memory.swap.max`).
    Memory,
    /// Process/thread count limit (`pids.max`).
    Pids,
    /// Block I/O bandwidth/IOPS limits (`io.max`).
    Io,
}

impl Controller {
    /// The kernel's controller name as it appears in `cgroup.controllers` and
    /// `cgroup.subtree_control`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Pids => "pids",
            Self::Io => "io",
        }
    }

    /// All controllers the orchestrator knows how to delegate.
    pub fn all() -> &'static [Controller] {
        &[Self::Cpu, Self::Memory, Self::Pids, Self::Io]
    }
}

/// Error returned when a controller name is not recognized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseControllerError;

impl fmt::Display for ParseControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown cgroup-v2 controller")
    }
}

impl std::error::Error for ParseControllerError {}

impl std::str::FromStr for Controller {
    type Err = ParseControllerError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "cpu" => Ok(Self::Cpu),
            "memory" => Ok(Self::Memory),
            "pids" => Ok(Self::Pids),
            "io" => Ok(Self::Io),
            _ => Err(ParseControllerError),
        }
    }
}

impl fmt::Display for Controller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse the space-separated contents of a `cgroup.controllers` (or
/// `cgroup.subtree_control`) file into the set of known controllers.
///
/// Unknown controller names (for example `cpuset`, `hugetlb`) are ignored: the
/// orchestrator only manages the controllers in [`Controller`].
pub fn parse_controllers(contents: &str) -> Vec<Controller> {
    let mut out = Vec::new();
    for tok in contents.split_whitespace() {
        if let Ok(c) = tok.parse::<Controller>() {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// IoMax
// ---------------------------------------------------------------------------

/// Per-block-device I/O limits rendered into a single `io.max` line.
///
/// Any unset field is written as `max` (unlimited), matching the cgroup-v2
/// `io.max` format: `MAJ:MIN rbps=<n|max> wbps=<n|max> riops=<n|max>
/// wiops=<n|max>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoMax {
    /// Block device major number.
    pub major: u32,
    /// Block device minor number.
    pub minor: u32,
    /// Read bandwidth limit in bytes/sec (`rbps`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_bytes_per_sec: Option<u64>,
    /// Write bandwidth limit in bytes/sec (`wbps`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_bytes_per_sec: Option<u64>,
    /// Read IOPS limit (`riops`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_iops: Option<u64>,
    /// Write IOPS limit (`wiops`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_iops: Option<u64>,
}

impl IoMax {
    /// Create an `io.max` entry for a device with all limits unset.
    pub fn new(major: u32, minor: u32) -> Self {
        Self {
            major,
            minor,
            ..Default::default()
        }
    }

    /// Render the exact line written to `io.max` for this device.
    pub fn to_io_max_line(&self) -> String {
        fn field(v: Option<u64>) -> String {
            match v {
                Some(n) => n.to_string(),
                None => "max".to_string(),
            }
        }
        format!(
            "{}:{} rbps={} wbps={} riops={} wiops={}",
            self.major,
            self.minor,
            field(self.read_bytes_per_sec),
            field(self.write_bytes_per_sec),
            field(self.read_iops),
            field(self.write_iops),
        )
    }
}

// ---------------------------------------------------------------------------
// CgroupSpec
// ---------------------------------------------------------------------------

/// Resource limits applied to a per-VM leaf cgroup.
///
/// Construct through [`CgroupSpec::builder`] (which enforces defaults and
/// validation) or validate an instance produced by deserialization with
/// [`CgroupSpec::validate`]. The manager always validates a spec before writing
/// any cgroup file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupSpec {
    /// CPU quota in microseconds per period (`cpu.max` quota). Must be > 0.
    pub cpu_quota_us: u64,
    /// CPU period in microseconds (`cpu.max` period). Defaults to
    /// [`DEFAULT_CPU_PERIOD_US`]. Must be > 0.
    pub cpu_period_us: u64,
    /// Hard memory limit in bytes (`memory.max`). Must be > 0.
    pub memory_max_bytes: u64,
    /// Swap limit in bytes (`memory.swap.max`). Defaults to `0` (no swap).
    pub memory_swap_max_bytes: u64,
    /// Maximum number of processes/threads (`pids.max`). Must be > 0.
    pub pids_max: u64,
    /// Optional per-device block I/O limit (`io.max`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_max: Option<IoMax>,
}

impl CgroupSpec {
    /// Start building a spec. `cpu_quota_us`, `memory_max_bytes`, and
    /// `pids_max` are required; `cpu_period_us` and `memory_swap_max_bytes`
    /// default to [`DEFAULT_CPU_PERIOD_US`] and `0` respectively.
    pub fn builder() -> CgroupSpecBuilder {
        CgroupSpecBuilder::default()
    }

    /// Validate the spec's invariants.
    ///
    /// Returns [`ErrorCode::InvalidResourceSpec`] when any required limit is
    /// zero. A zero `memory_swap_max_bytes` is valid (it disables swap).
    pub fn validate(&self) -> Result<(), MicrovmError> {
        if self.cpu_quota_us == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "cpu_quota_us must be greater than zero",
            )
            .with_context("field", "cpu_quota_us"));
        }
        if self.cpu_period_us == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "cpu_period_us must be greater than zero",
            )
            .with_context("field", "cpu_period_us"));
        }
        if self.memory_max_bytes == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "memory_max_bytes must be greater than zero",
            )
            .with_context("field", "memory_max_bytes"));
        }
        if self.pids_max == 0 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "pids_max must be greater than zero",
            )
            .with_context("field", "pids_max"));
        }
        Ok(())
    }

    /// The controllers this spec requires the parent cgroup to expose.
    ///
    /// `cpu`, `memory`, and `pids` are always required; `io` is required only
    /// when an [`IoMax`] limit is present.
    pub fn required_controllers(&self) -> Vec<Controller> {
        let mut v = vec![Controller::Cpu, Controller::Memory, Controller::Pids];
        if self.io_max.is_some() {
            v.push(Controller::Io);
        }
        v.sort();
        v
    }

    /// The exact `cpu.max` file contents: `<quota> <period>`.
    pub fn cpu_max_value(&self) -> String {
        format!("{} {}", self.cpu_quota_us, self.cpu_period_us)
    }

    /// The exact `memory.max` file contents.
    pub fn memory_max_value(&self) -> String {
        self.memory_max_bytes.to_string()
    }

    /// The exact `memory.swap.max` file contents.
    pub fn memory_swap_max_value(&self) -> String {
        self.memory_swap_max_bytes.to_string()
    }

    /// The exact `pids.max` file contents.
    pub fn pids_max_value(&self) -> String {
        self.pids_max.to_string()
    }

    /// The exact `io.max` file contents, if an I/O limit is configured.
    pub fn io_max_value(&self) -> Option<String> {
        self.io_max.map(|io| io.to_io_max_line())
    }
}

/// Builder for [`CgroupSpec`] that applies defaults and validates on
/// [`CgroupSpecBuilder::build`].
#[derive(Clone, Debug)]
pub struct CgroupSpecBuilder {
    cpu_quota_us: Option<u64>,
    cpu_period_us: u64,
    memory_max_bytes: Option<u64>,
    memory_swap_max_bytes: u64,
    pids_max: Option<u64>,
    io_max: Option<IoMax>,
}

impl Default for CgroupSpecBuilder {
    fn default() -> Self {
        Self {
            cpu_quota_us: None,
            cpu_period_us: DEFAULT_CPU_PERIOD_US,
            memory_max_bytes: None,
            memory_swap_max_bytes: DEFAULT_MEMORY_SWAP_MAX_BYTES,
            pids_max: None,
            io_max: None,
        }
    }
}

impl CgroupSpecBuilder {
    /// Set the CPU quota in microseconds per period (required).
    pub fn cpu_quota_us(mut self, v: u64) -> Self {
        self.cpu_quota_us = Some(v);
        self
    }

    /// Override the CPU period in microseconds (default 100000).
    pub fn cpu_period_us(mut self, v: u64) -> Self {
        self.cpu_period_us = v;
        self
    }

    /// Set the hard memory limit in bytes (required).
    pub fn memory_max_bytes(mut self, v: u64) -> Self {
        self.memory_max_bytes = Some(v);
        self
    }

    /// Override the swap limit in bytes (default 0 = no swap).
    pub fn memory_swap_max_bytes(mut self, v: u64) -> Self {
        self.memory_swap_max_bytes = v;
        self
    }

    /// Set the maximum process/thread count (required).
    pub fn pids_max(mut self, v: u64) -> Self {
        self.pids_max = Some(v);
        self
    }

    /// Attach a per-device block I/O limit (optional).
    pub fn io_max(mut self, v: IoMax) -> Self {
        self.io_max = Some(v);
        self
    }

    /// Build and validate the spec.
    ///
    /// Missing required fields and zero-valued limits both yield
    /// [`ErrorCode::InvalidResourceSpec`].
    pub fn build(self) -> Result<CgroupSpec, MicrovmError> {
        let cpu_quota_us = self.cpu_quota_us.ok_or_else(|| {
            MicrovmError::new(ErrorCode::InvalidResourceSpec, "cpu_quota_us is required")
                .with_context("field", "cpu_quota_us")
        })?;
        let memory_max_bytes = self.memory_max_bytes.ok_or_else(|| {
            MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "memory_max_bytes is required",
            )
            .with_context("field", "memory_max_bytes")
        })?;
        let pids_max = self.pids_max.ok_or_else(|| {
            MicrovmError::new(ErrorCode::InvalidResourceSpec, "pids_max is required")
                .with_context("field", "pids_max")
        })?;

        let spec = CgroupSpec {
            cpu_quota_us,
            cpu_period_us: self.cpu_period_us,
            memory_max_bytes,
            memory_swap_max_bytes: self.memory_swap_max_bytes,
            pids_max,
            io_max: self.io_max,
        };
        spec.validate()?;
        Ok(spec)
    }
}

// ---------------------------------------------------------------------------
// Controller availability check
// ---------------------------------------------------------------------------

/// Verify that every controller required by `spec` is present in `available`.
///
/// Returns [`ErrorCode::CgroupUnavailable`] listing the missing controllers
/// when the parent cgroup does not expose the full required set. This check is
/// intended to run before any process spawn.
pub fn check_required_controllers(
    available: &[Controller],
    spec: &CgroupSpec,
) -> Result<(), MicrovmError> {
    let required = spec.required_controllers();
    let missing: Vec<Controller> = required
        .into_iter()
        .filter(|c| !available.contains(c))
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    let missing_str: Vec<&str> = missing.iter().map(|c| c.as_str()).collect();
    let available_str: Vec<&str> = available.iter().map(|c| c.as_str()).collect();
    Err(MicrovmError::new(
        ErrorCode::CgroupUnavailable,
        "parent cgroup does not expose all required controllers",
    )
    .with_context("missing", missing_str.join(","))
    .with_context("available", available_str.join(",")))
}

// ---------------------------------------------------------------------------
// Leaf structural constraints
// ---------------------------------------------------------------------------

/// Validate that a leaf cgroup's `cgroup.subtree_control` is empty.
///
/// A leaf must not delegate any domain controllers to children (it has none).
/// A non-empty value yields [`ErrorCode::InvalidResourceSpec`].
pub fn validate_subtree_control_empty(contents: &str) -> Result<(), MicrovmError> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        Ok(())
    } else {
        Err(MicrovmError::new(
            ErrorCode::InvalidResourceSpec,
            "leaf cgroup.subtree_control must be empty",
        )
        .with_context("subtree_control", trimmed))
    }
}

/// Validate that a leaf cgroup has no child cgroups.
///
/// `child_names` is the set of subdirectory names beneath the leaf. Any child
/// yields [`ErrorCode::InvalidResourceSpec`].
pub fn validate_no_children(child_names: &[String]) -> Result<(), MicrovmError> {
    if child_names.is_empty() {
        Ok(())
    } else {
        Err(MicrovmError::new(
            ErrorCode::InvalidResourceSpec,
            "leaf cgroup must have no children",
        )
        .with_context("children", child_names.join(",")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> CgroupSpec {
        CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .build()
            .unwrap()
    }

    // -- Builder / defaults -------------------------------------------------

    #[test]
    fn builder_applies_defaults() {
        let spec = valid_spec();
        assert_eq!(spec.cpu_period_us, DEFAULT_CPU_PERIOD_US);
        assert_eq!(spec.memory_swap_max_bytes, 0);
        assert!(spec.io_max.is_none());
    }

    #[test]
    fn builder_overrides_defaults() {
        let spec = CgroupSpec::builder()
            .cpu_quota_us(25_000)
            .cpu_period_us(50_000)
            .memory_max_bytes(64 * 1024 * 1024)
            .memory_swap_max_bytes(1024)
            .pids_max(32)
            .build()
            .unwrap();
        assert_eq!(spec.cpu_period_us, 50_000);
        assert_eq!(spec.memory_swap_max_bytes, 1024);
    }

    #[test]
    fn builder_missing_required_fields_rejected() {
        // No fields at all.
        let err = CgroupSpec::builder().build().unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);

        // Missing memory and pids.
        let err = CgroupSpec::builder()
            .cpu_quota_us(1000)
            .build()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    // -- Validation ---------------------------------------------------------

    #[test]
    fn valid_spec_passes_validation() {
        assert!(valid_spec().validate().is_ok());
    }

    #[test]
    fn zero_cpu_quota_rejected() {
        let spec = CgroupSpec {
            cpu_quota_us: 0,
            ..valid_spec()
        };
        let err = spec.validate().unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert_eq!(
            err.context.get("field").map(String::as_str),
            Some("cpu_quota_us")
        );
    }

    #[test]
    fn zero_cpu_period_rejected() {
        let spec = CgroupSpec {
            cpu_period_us: 0,
            ..valid_spec()
        };
        assert_eq!(
            spec.validate().unwrap_err().code,
            ErrorCode::InvalidResourceSpec
        );
    }

    #[test]
    fn zero_memory_max_rejected() {
        let spec = CgroupSpec {
            memory_max_bytes: 0,
            ..valid_spec()
        };
        assert_eq!(
            spec.validate().unwrap_err().code,
            ErrorCode::InvalidResourceSpec
        );
    }

    #[test]
    fn zero_pids_max_rejected() {
        let spec = CgroupSpec {
            pids_max: 0,
            ..valid_spec()
        };
        assert_eq!(
            spec.validate().unwrap_err().code,
            ErrorCode::InvalidResourceSpec
        );
    }

    #[test]
    fn zero_swap_is_valid() {
        let spec = CgroupSpec {
            memory_swap_max_bytes: 0,
            ..valid_spec()
        };
        assert!(spec.validate().is_ok());
    }

    // -- Rendered cgroup file values ---------------------------------------

    #[test]
    fn rendered_file_values_match_kernel_format() {
        let spec = CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .cpu_period_us(100_000)
            .memory_max_bytes(134_217_728)
            .memory_swap_max_bytes(0)
            .pids_max(64)
            .build()
            .unwrap();
        assert_eq!(spec.cpu_max_value(), "50000 100000");
        assert_eq!(spec.memory_max_value(), "134217728");
        assert_eq!(spec.memory_swap_max_value(), "0");
        assert_eq!(spec.pids_max_value(), "64");
        assert!(spec.io_max_value().is_none());
    }

    #[test]
    fn io_max_line_uses_max_for_unset_fields() {
        let io = IoMax {
            major: 8,
            minor: 0,
            read_bytes_per_sec: Some(1_048_576),
            write_iops: Some(500),
            ..Default::default()
        };
        assert_eq!(
            io.to_io_max_line(),
            "8:0 rbps=1048576 wbps=max riops=max wiops=500"
        );
    }

    #[test]
    fn io_max_value_present_when_configured() {
        let spec = CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .io_max(IoMax::new(259, 1))
            .build()
            .unwrap();
        assert_eq!(
            spec.io_max_value().unwrap(),
            "259:1 rbps=max wbps=max riops=max wiops=max"
        );
    }

    // -- Required controllers ----------------------------------------------

    #[test]
    fn required_controllers_without_io() {
        let spec = valid_spec();
        assert_eq!(
            spec.required_controllers(),
            vec![Controller::Cpu, Controller::Memory, Controller::Pids]
        );
    }

    #[test]
    fn required_controllers_with_io() {
        let spec = CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .io_max(IoMax::new(8, 0))
            .build()
            .unwrap();
        assert_eq!(
            spec.required_controllers(),
            vec![
                Controller::Cpu,
                Controller::Memory,
                Controller::Pids,
                Controller::Io
            ]
        );
    }

    #[test]
    fn controller_name_roundtrip() {
        for c in Controller::all() {
            assert_eq!(c.as_str().parse::<Controller>(), Ok(*c));
            assert_eq!(c.to_string(), c.as_str());
        }
        assert!("cpuset".parse::<Controller>().is_err());
    }

    #[test]
    fn parse_controllers_ignores_unknown_and_dedups() {
        let parsed = parse_controllers("cpuset cpu io memory pids cpu hugetlb");
        assert_eq!(
            parsed,
            vec![
                Controller::Cpu,
                Controller::Memory,
                Controller::Pids,
                Controller::Io
            ]
        );
        assert!(parse_controllers("").is_empty());
        assert!(parse_controllers("   \n").is_empty());
    }

    // -- Controller availability check -------------------------------------

    #[test]
    fn controller_check_passes_when_all_present() {
        let spec = valid_spec();
        let available = vec![Controller::Cpu, Controller::Memory, Controller::Pids];
        assert!(check_required_controllers(&available, &spec).is_ok());
    }

    #[test]
    fn controller_check_passes_with_extra_controllers() {
        let spec = valid_spec();
        let available = Controller::all().to_vec();
        assert!(check_required_controllers(&available, &spec).is_ok());
    }

    #[test]
    fn controller_check_fails_on_missing_controller() {
        let spec = valid_spec();
        // Missing `memory`.
        let available = vec![Controller::Cpu, Controller::Pids];
        let err = check_required_controllers(&available, &spec).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
        assert_eq!(
            err.context.get("missing").map(String::as_str),
            Some("memory")
        );
    }

    #[test]
    fn controller_check_requires_io_when_spec_has_io() {
        let spec = CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .io_max(IoMax::new(8, 0))
            .build()
            .unwrap();
        // cpu+memory+pids present but io missing.
        let available = vec![Controller::Cpu, Controller::Memory, Controller::Pids];
        let err = check_required_controllers(&available, &spec).unwrap_err();
        assert_eq!(err.code, ErrorCode::CgroupUnavailable);
        assert_eq!(err.context.get("missing").map(String::as_str), Some("io"));
    }

    // -- Leaf structural constraints ---------------------------------------

    #[test]
    fn empty_subtree_control_is_valid() {
        assert!(validate_subtree_control_empty("").is_ok());
        assert!(validate_subtree_control_empty("   \n").is_ok());
    }

    #[test]
    fn nonempty_subtree_control_rejected() {
        let err = validate_subtree_control_empty("cpu memory").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn leaf_with_no_children_is_valid() {
        assert!(validate_no_children(&[]).is_ok());
    }

    #[test]
    fn leaf_with_children_rejected() {
        let children = vec!["child-a".to_string()];
        let err = validate_no_children(&children).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert_eq!(
            err.context.get("children").map(String::as_str),
            Some("child-a")
        );
    }

    // -- Serde --------------------------------------------------------------

    #[test]
    fn cgroup_spec_serde_roundtrip() {
        let spec = CgroupSpec::builder()
            .cpu_quota_us(50_000)
            .memory_max_bytes(128 * 1024 * 1024)
            .pids_max(64)
            .io_max(IoMax::new(8, 0))
            .build()
            .unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        let back: CgroupSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn cgroup_spec_serde_omits_absent_io() {
        let spec = valid_spec();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(!json.contains("io_max"));
    }

    #[test]
    fn deserialized_spec_can_be_validated() {
        // A spec produced by deserialization is not auto-validated; validate()
        // is the gate the manager applies before writing any file.
        let bad: CgroupSpec = serde_json::from_str(
            r#"{"cpu_quota_us":0,"cpu_period_us":100000,"memory_max_bytes":1024,"memory_swap_max_bytes":0,"pids_max":1}"#,
        )
        .unwrap();
        assert_eq!(
            bad.validate().unwrap_err().code,
            ErrorCode::InvalidResourceSpec
        );
    }
}
