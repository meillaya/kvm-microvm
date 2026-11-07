//! End-to-end API lifecycle tests for the microvm platform.
//!
//! This is a test-only crate: it ships no production code and exists solely
//! to hold the end-to-end (e2e) integration suite mandated by phase 2 story 2.
//! The real content lives in the integration test targets:
//!
//! - `tests/rest_lifecycle.rs`: the full VM lifecycle driven over the REST
//!   Unix-socket API ([`microvm_rest::RestServer`]): create → start → wait for
//!   guest health → status `Running` → snapshot → restore → stop → status
//!   `Stopped`, followed by resource-cleanup verification (no leftover cgroup,
//!   netns, TAP, or API socket).
//! - `tests/grpc_lifecycle.rs`: the same lifecycle flow driven over the gRPC
//!   Unix-socket API ([`microvm_grpc::GrpcServer`]).
//! - `tests/common/mod.rs`: the shared harness: the composed
//!   [`VmLifecycleService`](microvm_service::VmLifecycleService) backed either
//!   by a fully-scripted inner backend (deterministic, no real Firecracker) or
//!   by the genuine [`FirecrackerBackend`](microvm_firecracker::FirecrackerBackend)
//!   wired with scripted doubles, plus REST/gRPC client drivers over real Unix
//!   sockets.
//!
//! # Lanes
//! - Deterministic (default `cargo test -p microvm-e2e-tests`): no KVM,
//!   root, or real Firecracker binary is required, and no QEMU TCG or mock
//!   stands in for a KVM/Firecracker pass.
//! - Privileged (`cargo test -p microvm-e2e-tests --features privileged`):
//!   boots a real Firecracker/jailer guest through the REST API on a capable
//!   host. On an incapable host it reports a stable `blocked` token and passes
//!   rather than failing or substituting a mock.
#![forbid(unsafe_code)]
