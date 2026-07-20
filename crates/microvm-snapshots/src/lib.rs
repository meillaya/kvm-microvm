//! Versioned local snapshot integrity manifest and pre-restore compatibility
//! gate for the kvm-microvm-orchestrator platform.
//!
//! This crate owns the **local snapshot integrity boundary** (plan todo 21).
//! It provides:
//! - [`SnapshotManifest`] — full snapshot metadata with content hashes
//!   (Firecracker binary, kernel/rootfs/block devices, guest memory, VM-state)
//!   and compatibility fields (VM config, CPU/KVM API, cgroup version, owner
//!   tenant, quota, immutable-memory requirement). Serialized form is described
//!   by `schemas/snapshot-manifest.v1.json` ([`SNAPSHOT_SCHEMA_ID`]).
//! - [`CompatibilityGate`] — validates a manifest against the current
//!   host/binary/config and the caller tenant **before** any Firecracker
//!   process is spawned or `/snapshot/load` is issued.
//! - [`SnapshotError`] — typed integrity and compatibility failures, each
//!   mapping to a stable [`ErrorCode`].
//!
//! # Trust model (what this crate deliberately does NOT claim)
//! - The SHA-256 digests are the orchestrator's own content hashes. Firecracker's
//!   internal snapshot CRC is only accidental-corruption detection and is
//!   **never** treated as authentication.
//! - Snapshots are **local, content-addressed, and owner-scoped**. This crate
//!   makes **no cross-host compatibility claim**; cross-host transfer, signing,
//!   or encryption is out of scope. A host-envelope mismatch is a hard
//!   rejection, not a portability negotiation.
//!
//! # Purity
//! This crate performs **no I/O and no host API calls**. The backend supplies
//! actual digests ([`ActualHashes`]) and the host envelope ([`HostEnvironment`])
//! as data; all checks are pure functions. This keeps every test deterministic
//! and runnable without `/dev/kvm`.
//!
//! [`ErrorCode`]: microvm_errors::ErrorCode

#![forbid(unsafe_code)]

pub mod error;
pub mod gate;
pub mod manifest;

pub use error::{SnapshotComponent, SnapshotError};
pub use gate::{CompatibilityGate, HostEnvironment, TenantQuota};
pub use manifest::{
    ActualHashes, ArtifactHashes, BlockDeviceHash, CgroupVersion, CpuCompatibility,
    FirecrackerBinary, HostCompatibility, MemoryRequirements, SnapshotManifest,
    SnapshotManifestBuilder, SnapshotQuota, SnapshotVmConfig, StateHashes,
    SNAPSHOT_MANIFEST_VERSION, SNAPSHOT_SCHEMA_ID,
};
