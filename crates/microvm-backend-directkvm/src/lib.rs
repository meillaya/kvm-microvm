//! Educational direct-KVM microvm backend contract types.
//!
//! This crate is not a production Firecracker replacement. It exists solely
//! to teach the KVM API surface used by the kvm-microvm-orchestrator platform.
//!
//! The contract pins exactly:
//! - One host architecture: x86_64
//! - One vCPU
//! - One 16 MiB memory slot (identity-mapped from GPA 0)
//! - Serial output via I/O port 0x3F8 (16550 UART data register)
//! - Four allowed VM exits: IO, HLT, FAIL_ENTRY, INTERNAL_ERROR
//! - Three stop behaviors: HLT, HostStop, Failure
//!
//! # Feature gate
//!
//! The `direct-kvm` Cargo feature is off by default. Contract types and
//! validation are always available without the feature. The feature gates the
//! real KVM ioctl path implemented in the [`runner`] module: an API-version /
//! capability probe, one identity-mapped 16 MiB memory slot, one vCPU programmed
//! into 64-bit long mode, a bounded `KVM_RUN` loop feeding the pure exit
//! dispatcher, and clean shutdown. The default workspace build never compiles,
//! links, or launches this path, and it is never presented as a production VMM
//! or reported using TCG/QEMU/Firecracker as KVM evidence.
//!
//! # Determinism
//!
//! All contract validation is pure and requires no host access, no `/dev/kvm`,
//! and no privileged operations. Tests run in the default (no-feature) lane.
//!
//! # Scope lock
//!
//! This subset must not be expanded without a formal scope-change decision.
//! See `docs/design/direct-kvm-subset.md` for the authoritative scope definition.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Subset implementation modules
// ---------------------------------------------------------------------------
//
// The pure modules (serial, outcome, dispatch, probe validation, guest layout)
// are always compiled and deterministically tested without `/dev/kvm`. The
// `runner` module is the sole KVM-ioctl surface and is gated behind the
// `direct-kvm` feature so the default build never links it.

mod dispatch;
mod outcome;
mod probe;
mod serial;

/// The tiny marker guest and its x86_64 long-mode boot layout.
pub mod guest;

#[cfg(feature = "direct-kvm")]
pub mod runner;

pub use dispatch::{DispatchAction, ExitDispatcher, GuestExit};
pub use guest::{guest_code, write_boot_layout};
pub use outcome::{BlockedReason, FailureReason, RunOutcome, StopReason};
pub use probe::{
    probe_blocked_outcome, validate_api_version, validate_capabilities, ProbeError, ProbeReport,
    DEFAULT_KVM_DEVICE,
};
pub use serial::SerialOutput;

#[cfg(feature = "direct-kvm")]
pub use probe::open_and_probe;
#[cfg(feature = "direct-kvm")]
pub use runner::{
    blocked_reason_for_device, run_subset_boot, run_subset_boot_at, VmRunner, MAX_RUN_ITERATIONS,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The single supported architecture.
pub const SUPPORTED_ARCH: &str = "x86_64";

/// Exactly one vCPU.
pub const VCPU_COUNT: u8 = 1;

/// Guest memory size: 16 MiB.
pub const MEMORY_SIZE_BYTES: u64 = 16 * 1024 * 1024;

/// Guest physical address of the single memory slot.
pub const MEMORY_GUEST_PHYS_ADDR: u64 = 0x0;

/// KVM memory slot index (only one slot).
pub const MEMORY_SLOT: u32 = 0;

/// 16550 UART data register I/O port.
pub const SERIAL_PORT: u16 = 0x3F8;

/// The guest marker byte written to the serial port by the tiny test guest.
pub const GUEST_MARKER_BYTE: u8 = 0x4B; // 'K'

/// KVM stable ABI version.
pub const KVM_API_VERSION: i32 = 12;

/// Educational label required on all public surfaces.
pub const EDUCATIONAL_LABEL: &str = "educational";

// ---------------------------------------------------------------------------
// Arch
// ---------------------------------------------------------------------------

/// Supported host architecture for the direct-KVM educational subset.
///
/// Pinned to x86_64 only. No other architecture is supported or planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    /// x86_64 (AMD64 / Intel 64). The only supported architecture.
    X86_64,
}

impl Arch {
    /// Returns the string representation of the architecture.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::X86_64 => SUPPORTED_ARCH,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MemoryLayout
// ---------------------------------------------------------------------------

/// Descriptor for the single guest memory slot.
///
/// The educational subset allows exactly one contiguous, identity-mapped
/// memory region starting at guest physical address 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryLayout {
    /// Guest physical address of the slot start.
    pub guest_phys_addr: u64,
    /// Size of the slot in bytes.
    pub size_bytes: u64,
}

impl MemoryLayout {
    /// Creates the canonical educational-subset memory layout (16 MiB at GPA 0).
    #[must_use]
    pub fn educational_default() -> Self {
        Self {
            guest_phys_addr: MEMORY_GUEST_PHYS_ADDR,
            size_bytes: MEMORY_SIZE_BYTES,
        }
    }

    /// Validates that this layout matches the educational subset contract.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if the layout deviates from the pinned contract.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.guest_phys_addr != MEMORY_GUEST_PHYS_ADDR {
            return Err(ContractError::InvalidMemoryLayout(format!(
                "guest_phys_addr must be {MEMORY_GUEST_PHYS_ADDR:#x}, got {:#x}",
                self.guest_phys_addr
            )));
        }
        if self.size_bytes != MEMORY_SIZE_BYTES {
            return Err(ContractError::InvalidMemoryLayout(format!(
                "size_bytes must be {MEMORY_SIZE_BYTES} (16 MiB), got {}",
                self.size_bytes
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AllowedExit
// ---------------------------------------------------------------------------

/// VM exit reasons handled by the educational direct-KVM backend.
///
/// Any exit reason not in this set is treated as unexpected and causes a
/// transition to the `Failed` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedExit {
    /// `KVM_EXIT_IO` on port 0x3F8, direction OUT, size 1.
    /// Records the byte as serial output; resumes the vCPU.
    Io,
    /// `KVM_EXIT_HLT`. Stops the vCPU loop; state → Stopped.
    Hlt,
    /// `KVM_EXIT_FAIL_ENTRY`. Records hardware_entry_failure_reason; state → Failed.
    FailEntry,
    /// `KVM_EXIT_INTERNAL_ERROR`. Records internal_error_suberror; state → Failed.
    InternalError,
}

impl AllowedExit {
    /// Returns all allowed exits in canonical order.
    #[must_use]
    pub fn all() -> &'static [AllowedExit] {
        &[
            AllowedExit::Io,
            AllowedExit::Hlt,
            AllowedExit::FailEntry,
            AllowedExit::InternalError,
        ]
    }

    /// Returns the KVM exit reason constant name for documentation.
    #[must_use]
    pub fn kvm_reason_name(&self) -> &'static str {
        match self {
            AllowedExit::Io => "KVM_EXIT_IO",
            AllowedExit::Hlt => "KVM_EXIT_HLT",
            AllowedExit::FailEntry => "KVM_EXIT_FAIL_ENTRY",
            AllowedExit::InternalError => "KVM_EXIT_INTERNAL_ERROR",
        }
    }
}

impl fmt::Display for AllowedExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kvm_reason_name())
    }
}

// ---------------------------------------------------------------------------
// StopBehavior
// ---------------------------------------------------------------------------

/// How the vCPU loop terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopBehavior {
    /// Guest executed HLT; vCPU loop exits normally.
    Hlt,
    /// Host called `stop()`; stop flag checked between KVM_RUN iterations.
    HostStop,
    /// Unexpected exit or entry failure; vCPU loop exits with error.
    Failure,
}

impl StopBehavior {
    /// Returns all stop behaviors in canonical order.
    #[must_use]
    pub fn all() -> &'static [StopBehavior] {
        &[
            StopBehavior::Hlt,
            StopBehavior::HostStop,
            StopBehavior::Failure,
        ]
    }
}

impl fmt::Display for StopBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopBehavior::Hlt => f.write_str("hlt"),
            StopBehavior::HostStop => f.write_str("host_stop"),
            StopBehavior::Failure => f.write_str("failure"),
        }
    }
}

// ---------------------------------------------------------------------------
// EducationalLabel
// ---------------------------------------------------------------------------

/// Newtype asserting the "educational" label is present on all public surfaces.
///
/// This type exists to make the educational designation structurally enforced
/// rather than relying on documentation alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EducationalLabel(String);

impl EducationalLabel {
    /// Creates the canonical educational label.
    #[must_use]
    pub fn new() -> Self {
        Self(EDUCATIONAL_LABEL.to_string())
    }

    /// Returns the label string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates that the label is exactly "educational".
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidLabel`] if the label is not exactly
    /// `"educational"`.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.0 != EDUCATIONAL_LABEL {
            return Err(ContractError::InvalidLabel(format!(
                "label must be {EDUCATIONAL_LABEL:?}, got {:?}",
                self.0
            )));
        }
        Ok(())
    }
}

impl Default for EducationalLabel {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EducationalLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// KvmContract
// ---------------------------------------------------------------------------

/// Top-level contract descriptor for the educational direct-KVM backend.
///
/// This struct pins the exact subset: architecture, vCPU count, memory layout,
/// allowed exits, and stop behavior. It is the single source of truth for what
/// the educational backend supports.
///
/// # Invariants
///
/// - `arch` is always [`Arch::X86_64`].
/// - `vcpu_count` is always 1.
/// - `memory_layout` is the canonical 16 MiB slot at GPA 0.
/// - `allowed_exits` contains exactly the four handled exit reasons.
/// - `stop_behavior` lists all three termination paths.
/// - `label` is always "educational".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvmContract {
    /// Supported host architecture (pinned to x86_64).
    pub arch: Arch,
    /// Number of vCPUs (pinned to 1).
    pub vcpu_count: u8,
    /// Guest memory layout (single 16 MiB slot at GPA 0).
    pub memory_layout: MemoryLayout,
    /// Allowed VM exit reasons.
    pub allowed_exits: Vec<AllowedExit>,
    /// Stop behaviors.
    pub stop_behavior: Vec<StopBehavior>,
    /// Educational label (must be "educational").
    pub label: EducationalLabel,
}

impl KvmContract {
    /// Creates the canonical educational direct-KVM contract.
    #[must_use]
    pub fn educational() -> Self {
        Self {
            arch: Arch::X86_64,
            vcpu_count: VCPU_COUNT,
            memory_layout: MemoryLayout::educational_default(),
            allowed_exits: AllowedExit::all().to_vec(),
            stop_behavior: StopBehavior::all().to_vec(),
            label: EducationalLabel::new(),
        }
    }

    /// Validates that this contract matches the pinned educational subset.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if any field deviates from the contract.
    pub fn validate(&self) -> Result<(), ContractError> {
        // Architecture must be x86_64.
        if self.arch != Arch::X86_64 {
            return Err(ContractError::UnsupportedArch(format!(
                "only {SUPPORTED_ARCH} is supported, got {}",
                self.arch
            )));
        }

        // Exactly one vCPU.
        if self.vcpu_count != VCPU_COUNT {
            return Err(ContractError::InvalidVcpuCount(format!(
                "vcpu_count must be {VCPU_COUNT}, got {}",
                self.vcpu_count
            )));
        }

        // Memory layout must match.
        self.memory_layout.validate()?;

        // Allowed exits must be exactly the four canonical exits.
        let expected_exits = AllowedExit::all();
        if self.allowed_exits.len() != expected_exits.len() {
            return Err(ContractError::InvalidAllowedExits(format!(
                "expected exactly {} allowed exits, got {}",
                expected_exits.len(),
                self.allowed_exits.len()
            )));
        }
        for (i, exit) in self.allowed_exits.iter().enumerate() {
            if *exit != expected_exits[i] {
                return Err(ContractError::InvalidAllowedExits(format!(
                    "allowed_exits[{i}] must be {:?}, got {exit:?}",
                    expected_exits[i]
                )));
            }
        }

        // Stop behavior must be exactly the three canonical behaviors.
        let expected_stops = StopBehavior::all();
        if self.stop_behavior.len() != expected_stops.len() {
            return Err(ContractError::InvalidStopBehavior(format!(
                "expected exactly {} stop behaviors, got {}",
                expected_stops.len(),
                self.stop_behavior.len()
            )));
        }
        for (i, stop) in self.stop_behavior.iter().enumerate() {
            if *stop != expected_stops[i] {
                return Err(ContractError::InvalidStopBehavior(format!(
                    "stop_behavior[{i}] must be {:?}, got {stop:?}",
                    expected_stops[i]
                )));
            }
        }

        // Label must be "educational".
        self.label.validate()?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ContractError
// ---------------------------------------------------------------------------

/// Error returned when a contract field fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// Architecture is not x86_64.
    UnsupportedArch(String),
    /// vCPU count is not 1.
    InvalidVcpuCount(String),
    /// Memory layout deviates from the pinned contract.
    InvalidMemoryLayout(String),
    /// Allowed exits do not match the canonical set.
    InvalidAllowedExits(String),
    /// Stop behavior does not match the canonical set.
    InvalidStopBehavior(String),
    /// Label is not "educational".
    InvalidLabel(String),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::UnsupportedArch(msg) => write!(f, "unsupported architecture: {msg}"),
            ContractError::InvalidVcpuCount(msg) => write!(f, "invalid vcpu count: {msg}"),
            ContractError::InvalidMemoryLayout(msg) => {
                write!(f, "invalid memory layout: {msg}")
            }
            ContractError::InvalidAllowedExits(msg) => {
                write!(f, "invalid allowed exits: {msg}")
            }
            ContractError::InvalidStopBehavior(msg) => {
                write!(f, "invalid stop behavior: {msg}")
            }
            ContractError::InvalidLabel(msg) => write!(f, "invalid label: {msg}"),
        }
    }
}

impl std::error::Error for ContractError {}

// ---------------------------------------------------------------------------
// Feature gate marker
// ---------------------------------------------------------------------------

/// Returns `true` if the `direct-kvm` feature is enabled at compile time.
///
/// This is a compile-time constant that tests can use to verify the feature
/// gate without requiring `/dev/kvm`.
#[must_use]
pub const fn direct_kvm_feature_enabled() -> bool {
    cfg!(feature = "direct-kvm")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Contract validation ------------------------------------------------

    #[test]
    fn canonical_contract_validates() {
        let contract = KvmContract::educational();
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn contract_arch_is_x86_64() {
        let contract = KvmContract::educational();
        assert_eq!(contract.arch, Arch::X86_64);
        assert_eq!(contract.arch.as_str(), "x86_64");
    }

    #[test]
    fn contract_vcpu_count_is_one() {
        let contract = KvmContract::educational();
        assert_eq!(contract.vcpu_count, 1);
    }

    #[test]
    fn contract_memory_layout_is_16mib_at_gpa_zero() {
        let contract = KvmContract::educational();
        assert_eq!(contract.memory_layout.guest_phys_addr, 0);
        assert_eq!(contract.memory_layout.size_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn contract_allowed_exits_are_canonical() {
        let contract = KvmContract::educational();
        assert_eq!(contract.allowed_exits, AllowedExit::all().to_vec());
        assert_eq!(contract.allowed_exits.len(), 4);
    }

    #[test]
    fn contract_stop_behavior_is_canonical() {
        let contract = KvmContract::educational();
        assert_eq!(contract.stop_behavior, StopBehavior::all().to_vec());
        assert_eq!(contract.stop_behavior.len(), 3);
    }

    #[test]
    fn contract_label_is_educational() {
        let contract = KvmContract::educational();
        assert_eq!(contract.label.as_str(), "educational");
    }

    // -- Validation failures ------------------------------------------------

    #[test]
    fn rejects_wrong_vcpu_count() {
        let mut contract = KvmContract::educational();
        contract.vcpu_count = 2;
        let err = contract.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidVcpuCount(_)));
    }

    #[test]
    fn rejects_wrong_memory_size() {
        let mut contract = KvmContract::educational();
        contract.memory_layout.size_bytes = 32 * 1024 * 1024;
        let err = contract.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidMemoryLayout(_)));
    }

    #[test]
    fn rejects_wrong_memory_base() {
        let mut contract = KvmContract::educational();
        contract.memory_layout.guest_phys_addr = 0x1000;
        let err = contract.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidMemoryLayout(_)));
    }

    #[test]
    fn rejects_extra_allowed_exit() {
        let mut contract = KvmContract::educational();
        contract.allowed_exits.push(AllowedExit::Io);
        let err = contract.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidAllowedExits(_)));
    }

    #[test]
    fn rejects_missing_allowed_exit() {
        let mut contract = KvmContract::educational();
        contract.allowed_exits.pop();
        let err = contract.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidAllowedExits(_)));
    }

    #[test]
    fn rejects_extra_stop_behavior() {
        let mut contract = KvmContract::educational();
        contract.stop_behavior.push(StopBehavior::Hlt);
        let err = contract.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidStopBehavior(_)));
    }

    #[test]
    fn rejects_wrong_label() {
        let mut contract = KvmContract::educational();
        contract.label = EducationalLabel("production".to_string());
        let err = contract.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidLabel(_)));
    }

    // -- Feature gate -------------------------------------------------------

    // The default build (no features) must not enable the KVM ioctl path.
    #[test]
    #[cfg(not(feature = "direct-kvm"))]
    fn feature_gate_is_off_by_default() {
        // In the default test run (--no-default-features), the feature must be off.
        assert!(!direct_kvm_feature_enabled());
    }

    // When the feature is explicitly enabled, the marker reflects that.
    #[test]
    #[cfg(feature = "direct-kvm")]
    fn feature_gate_is_on_when_enabled() {
        assert!(direct_kvm_feature_enabled());
    }

    // -- Educational label --------------------------------------------------

    #[test]
    fn educational_label_validates() {
        let label = EducationalLabel::new();
        assert!(label.validate().is_ok());
        assert_eq!(label.as_str(), EDUCATIONAL_LABEL);
    }

    #[test]
    fn educational_label_rejects_non_educational() {
        let label = EducationalLabel("production".to_string());
        assert!(label.validate().is_err());
    }

    // -- Serialization round-trip -------------------------------------------

    #[test]
    fn contract_serialization_round_trip() {
        let contract = KvmContract::educational();
        let json = serde_json::to_string(&contract).unwrap();
        let deserialized: KvmContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract, deserialized);
    }

    #[test]
    fn contract_json_contains_educational_label() {
        let contract = KvmContract::educational();
        let json = serde_json::to_string(&contract).unwrap();
        assert!(json.contains("\"educational\""));
    }

    // -- Constants ----------------------------------------------------------

    #[test]
    fn constants_are_pinned() {
        assert_eq!(SUPPORTED_ARCH, "x86_64");
        assert_eq!(VCPU_COUNT, 1);
        assert_eq!(MEMORY_SIZE_BYTES, 16 * 1024 * 1024);
        assert_eq!(MEMORY_GUEST_PHYS_ADDR, 0);
        assert_eq!(MEMORY_SLOT, 0);
        assert_eq!(SERIAL_PORT, 0x3F8);
        assert_eq!(GUEST_MARKER_BYTE, 0x4B);
        assert_eq!(KVM_API_VERSION, 12);
        assert_eq!(EDUCATIONAL_LABEL, "educational");
    }

    // -- AllowedExit display ------------------------------------------------

    #[test]
    fn allowed_exit_display_names() {
        assert_eq!(AllowedExit::Io.to_string(), "KVM_EXIT_IO");
        assert_eq!(AllowedExit::Hlt.to_string(), "KVM_EXIT_HLT");
        assert_eq!(AllowedExit::FailEntry.to_string(), "KVM_EXIT_FAIL_ENTRY");
        assert_eq!(
            AllowedExit::InternalError.to_string(),
            "KVM_EXIT_INTERNAL_ERROR"
        );
    }

    // -- StopBehavior display -----------------------------------------------

    #[test]
    fn stop_behavior_display_names() {
        assert_eq!(StopBehavior::Hlt.to_string(), "hlt");
        assert_eq!(StopBehavior::HostStop.to_string(), "host_stop");
        assert_eq!(StopBehavior::Failure.to_string(), "failure");
    }
}
