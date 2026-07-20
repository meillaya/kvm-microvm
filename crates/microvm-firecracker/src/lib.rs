//! Firecracker boot/configure/start/stop adapter for the
//! kvm-microvm-orchestrator platform.
//!
//! This crate implements the transport-neutral
//! [`LifecycleService`](microvm_lifecycle::LifecycleService) trait using
//! Firecracker as the runtime backend. It owns the process-supervision and
//! API-configuration boundary: one Firecracker process per VM, configured over
//! a per-VM Unix-socket API (HTTP/JSON), with guest-readiness gating and
//! fail-closed error mapping into lifecycle states.
//!
//! # Modules
//! - [`config`] — validated [`BootConfig`](config::BootConfig) (digest-bearing,
//!   relative kernel/rootfs paths).
//! - [`phase`] — [`PhaseTimestamps`](phase::PhaseTimestamps) recording
//!   spawn/socket_ready/configured/guest_ready/stopped.
//! - [`api`] — Firecracker UDS API types, the
//!   [`FirecrackerApi`](api::FirecrackerApi) trait, and the real
//!   [`UdsApiClient`](api::UdsApiClient).
//! - [`process`] — [`VmProcess`](process::VmProcess) and the
//!   [`ProcessLauncher`](process::ProcessLauncher) abstraction.
//! - [`readiness`] — guest-readiness probing
//!   ([`GuestReadinessProbe`](readiness::GuestReadinessProbe)).
//! - [`prereq`] — host prerequisite checks that fail before child creation.
//! - [`backend`] — [`FirecrackerBackend`](backend::FirecrackerBackend), the
//!   `LifecycleService` implementation.
//! - [`testing`] — deterministic scripted doubles for tests.
//!
//! # Determinism
//! Boot-config validation, phase-timestamp recording, prerequisite checks, and
//! error mapping are pure and run in the default test lane. The full
//! boot/stop orchestration is exercised against scripted launcher/API/probe
//! doubles. A real Firecracker/jailer run lives behind the `privileged` feature
//! (`cargo test --features privileged --test firecracker_boot`).
//!
//! # Security
//! The Firecracker API socket is unauthenticated and is never exposed to
//! tenants: it lives in a host-only socket root and is absent from every
//! tenant-facing status/metrics response.

pub mod api;
pub mod backend;
pub mod config;
pub mod phase;
pub mod prereq;
pub mod process;
pub mod readiness;
pub mod testing;

pub use api::{
    BootSource, Drive, FaultMessage, FirecrackerApi, InstanceAction, InstanceInfo, MachineConfig,
    NetworkInterface, UdsApiClient, NET_IFACE_ID, ROOT_DRIVE_ID,
};
pub use backend::{
    ApiFactory, BackendBuilder, BackendConfig, FirecrackerBackend, UdsApiFactory, CPU_PERIOD_US,
    DEFAULT_JAILER_GID, DEFAULT_JAILER_UID, DEFAULT_PIDS_MAX, DEFAULT_SOCKET_TIMEOUT,
    SOCKET_POLL_INTERVAL,
};
pub use config::{BootConfig, BootConfigBuilder, NetworkBootConfig, MAX_BOOT_ARGS_LEN};
pub use phase::{Phase, PhaseTimestamps};
pub use prereq::{HostPrerequisiteChecker, HostPrerequisiteCheckerBuilder, PrerequisiteCheck};
pub use process::{LaunchSpec, ProcessLauncher, TokioLauncher, VmProcess};
pub use readiness::{
    GuestReadinessProbe, ReadinessContext, TcpHealthProbe, DEFAULT_POLL_INTERVAL,
    DEFAULT_READINESS_TIMEOUT,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend must be usable across threads (LifecycleService: Send+Sync).
    #[test]
    fn backend_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FirecrackerBackend>();
    }

    /// The scripted doubles must be object-safe and Send+Sync.
    #[test]
    fn trait_objects_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn FirecrackerApi>>();
        assert_send_sync::<Box<dyn ProcessLauncher>>();
        assert_send_sync::<Box<dyn GuestReadinessProbe>>();
        assert_send_sync::<Box<dyn PrerequisiteCheck>>();
        assert_send_sync::<Box<dyn ApiFactory>>();
    }

    /// Re-exports resolve.
    #[test]
    fn reexports_resolve() {
        assert_eq!(ROOT_DRIVE_ID, "rootfs");
        assert_eq!(NET_IFACE_ID, "eth0");
        assert_eq!(MAX_BOOT_ARGS_LEN, 4096);
    }
}
