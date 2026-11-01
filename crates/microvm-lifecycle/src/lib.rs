//! Transport-neutral lifecycle state machine and service contract for the
//! kvm-microvm-orchestrator platform.
//!
//! This crate defines:
//! - [`VmState`]: the finite set of VM lifecycle states.
//! - [`transition`]: a pure function that validates state transitions.
//! - [`LifecycleService`]: an async trait that any backend (Firecracker,
//!   mock, direct-KVM) can implement without embedding transport or
//!   runtime-specific details.
//! - [`VmStatus`] / [`VmMetrics`]: read-only views returned by the service.
//!
//! No REST, gRPC, or Firecracker-specific JSON lives here.
//!
//! # Policy
//! - [`policy`]: tenant authorization, ownership, quotas, and audit events.

pub mod policy;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_metrics::{MetricsPhase, VmMetricsRecord};
use microvm_types::{Principal, ResourceSpec, SnapshotId, VmId};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// VmState
// ---------------------------------------------------------------------------

/// Finite set of VM lifecycle states.
///
/// The state machine is validated by [`transition`]; it serializes to
/// `snake_case` strings for stable wire representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    /// VM record exists but has not been configured with boot parameters.
    Created,
    /// Boot parameters are set; the VM is ready to start.
    Configured,
    /// The VM is actively running.
    Running,
    /// The VM is paused (vCPUs halted, memory retained).
    Paused,
    /// A snapshot operation is in progress.
    Snapshotting,
    /// A restore-from-snapshot operation is in progress.
    Restoring,
    /// The VM has been stopped; resources are released.
    Stopped,
    /// The VM entered an unrecoverable error state.
    Failed,
}

impl VmState {
    /// Return all state variants.
    pub fn all() -> &'static [VmState] {
        &[
            Self::Created,
            Self::Configured,
            Self::Running,
            Self::Paused,
            Self::Snapshotting,
            Self::Restoring,
            Self::Stopped,
            Self::Failed,
        ]
    }

    /// Stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Configured => "configured",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Snapshotting => "snapshotting",
            Self::Restoring => "restoring",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl VmState {
    /// Map a lifecycle state to the monotonic metrics phase used by
    /// [`VmMetricsRecord`] (plan todo 23).
    ///
    /// - `Created`/`Configured` have not reached service-ready => [`Booting`].
    /// - `Running`/`Paused`/`Snapshotting` are service-ready => [`Running`].
    /// - `Restoring` => [`Restoring`].
    /// - `Stopped`/`Failed` are terminal => [`Stopped`].
    ///
    /// [`Booting`]: MetricsPhase::Booting
    /// [`Running`]: MetricsPhase::Running
    /// [`Restoring`]: MetricsPhase::Restoring
    /// [`Stopped`]: MetricsPhase::Stopped
    pub fn metrics_phase(self) -> MetricsPhase {
        match self {
            Self::Created | Self::Configured => MetricsPhase::Booting,
            Self::Running | Self::Paused | Self::Snapshotting => MetricsPhase::Running,
            Self::Restoring => MetricsPhase::Restoring,
            Self::Stopped | Self::Failed => MetricsPhase::Stopped,
        }
    }
}

// ---------------------------------------------------------------------------
// State transition validation
// ---------------------------------------------------------------------------

/// Validate a state transition and return the target state on success.
///
/// # Legal transitions
///
/// | From | To |
/// |---|---|
/// | Created | Configured |
/// | Configured | Running |
/// | Running | Paused, Stopped, Snapshotting |
/// | Paused | Running, Stopped, Snapshotting |
/// | Snapshotting | Paused |
/// | Restoring | Running |
/// | *(any)* | Failed |
///
/// Every other combination returns [`ErrorCode::InvalidTransition`].
pub fn transition(from: VmState, to: VmState) -> Result<VmState, MicrovmError> {
    // any → Failed is always legal.
    if to == VmState::Failed {
        return Ok(to);
    }

    let legal = matches!(
        (from, to),
        (VmState::Created, VmState::Configured)
            | (VmState::Configured, VmState::Running)
            | (VmState::Running, VmState::Paused)
            | (VmState::Running, VmState::Stopped)
            | (VmState::Running, VmState::Snapshotting)
            | (VmState::Paused, VmState::Running)
            | (VmState::Paused, VmState::Stopped)
            | (VmState::Paused, VmState::Snapshotting)
            | (VmState::Snapshotting, VmState::Paused)
            | (VmState::Restoring, VmState::Running)
    );

    if legal {
        Ok(to)
    } else {
        Err(MicrovmError::new(
            ErrorCode::InvalidTransition,
            format!("cannot transition from {} to {}", from, to),
        )
        .with_context("from", from.as_str())
        .with_context("to", to.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Read-only views
// ---------------------------------------------------------------------------

/// Immutable status snapshot for a VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmStatus {
    /// The VM this status describes.
    pub vm_id: VmId,
    /// Current lifecycle state.
    pub state: VmState,
    /// When the VM record was created.
    pub created_at: DateTime<Utc>,
    /// Resource allocation for this VM.
    pub resource_spec: ResourceSpec,
}

/// Per-VM metrics view returned by the service (plan todo 23).
///
/// Wraps the full, wire-stable [`VmMetricsRecord`] (host cgroup/TAP metrics,
/// monotonic boot/restore phases, and optional guest-agent metrics, all
/// availability-flagged) together with the lifecycle [`VmState`] observed at
/// collection time. The record is produced by `microvm-metrics`; this view
/// adds only the lifecycle state, which is a lifecycle concern rather than a
/// measurement.
///
/// Note: this type is `PartialEq` but not `Eq` because the embedded record
/// may carry fractional guest metrics (`f64`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmMetrics {
    /// The VM these metrics describe.
    pub vm_id: VmId,
    /// Current lifecycle state at time of collection.
    pub state: VmState,
    /// The full measurement snapshot (availability-flagged, never zero-filled).
    pub record: VmMetricsRecord,
}

// ---------------------------------------------------------------------------
// Service trait
// ---------------------------------------------------------------------------

/// Transport-neutral, backend-neutral lifecycle service contract.
///
/// Implementors manage VM state and resources. Callers interact through
/// this trait without knowing whether the backend is Firecracker, a mock,
/// or a direct-KVM adapter, and without knowing whether the transport is
/// REST, gRPC, or an in-process call.
#[async_trait]
pub trait LifecycleService: Send + Sync {
    /// Create a new VM from a resource specification.
    ///
    /// Returns the assigned [`VmId`]. The VM starts in [`VmState::Created`].
    async fn create(&self, spec: ResourceSpec, owner: Principal) -> Result<VmId, MicrovmError>;

    /// Start (or resume) a VM.
    ///
    /// Transitions through Created→Configured→Running on first start, or
    /// Paused→Running on resume.
    async fn start(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError>;

    /// Stop a running or paused VM, releasing its resources.
    async fn stop(&self, vm_id: &VmId, principal: &Principal) -> Result<(), MicrovmError>;

    /// Snapshot a running or paused VM.
    ///
    /// Returns the [`SnapshotId`] of the created snapshot.
    async fn snapshot(
        &self,
        vm_id: &VmId,
        principal: &Principal,
    ) -> Result<SnapshotId, MicrovmError>;

    /// Restore a VM from a snapshot, returning the new [`VmId`].
    async fn restore(
        &self,
        snapshot_id: &SnapshotId,
        principal: &Principal,
    ) -> Result<VmId, MicrovmError>;

    /// Query the current status of a VM.
    async fn status(&self, vm_id: &VmId, principal: &Principal) -> Result<VmStatus, MicrovmError>;

    /// Query placeholder metrics for a VM.
    async fn metrics(&self, vm_id: &VmId, principal: &Principal)
        -> Result<VmMetrics, MicrovmError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- VmState basics -----------------------------------------------------

    #[test]
    fn all_states_count() {
        assert_eq!(VmState::all().len(), 8);
    }

    #[test]
    fn state_display_matches_as_str() {
        for state in VmState::all() {
            assert_eq!(state.to_string(), state.as_str());
        }
    }

    #[test]
    fn state_serde_roundtrip() {
        for state in VmState::all() {
            let json = serde_json::to_string(state).unwrap();
            let back: VmState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }

    #[test]
    fn state_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&VmState::Created).unwrap(),
            r#""created""#
        );
        assert_eq!(
            serde_json::to_string(&VmState::Snapshotting).unwrap(),
            r#""snapshotting""#
        );
    }

    // -- VmStatus / VmMetrics serde -----------------------------------------

    #[test]
    fn vm_status_serde_roundtrip() {
        let status = VmStatus {
            vm_id: VmId::new("vm-001").unwrap(),
            state: VmState::Running,
            created_at: Utc::now(),
            resource_spec: ResourceSpec::new(2, 512, 1024, Default::default()).unwrap(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: VmStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn vm_metrics_serde_roundtrip() {
        let metrics = VmMetrics {
            vm_id: VmId::new("vm-002").unwrap(),
            state: VmState::Paused,
            record: VmMetricsRecord::not_collected(
                VmId::new("vm-002").unwrap(),
                VmState::Paused.metrics_phase(),
                Utc::now(),
                0,
            ),
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let back: VmMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(metrics, back);
    }

    #[test]
    fn state_maps_to_metrics_phase() {
        use microvm_metrics::MetricsPhase;
        assert_eq!(VmState::Created.metrics_phase(), MetricsPhase::Booting);
        assert_eq!(VmState::Configured.metrics_phase(), MetricsPhase::Booting);
        assert_eq!(VmState::Running.metrics_phase(), MetricsPhase::Running);
        assert_eq!(VmState::Paused.metrics_phase(), MetricsPhase::Running);
        assert_eq!(VmState::Snapshotting.metrics_phase(), MetricsPhase::Running);
        assert_eq!(VmState::Restoring.metrics_phase(), MetricsPhase::Restoring);
        assert_eq!(VmState::Stopped.metrics_phase(), MetricsPhase::Stopped);
        assert_eq!(VmState::Failed.metrics_phase(), MetricsPhase::Stopped);
    }
}
