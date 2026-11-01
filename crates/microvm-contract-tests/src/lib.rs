//! Transport contract tests for the kvm-microvm-orchestrator platform.
//!
//! This is a test-only crate: it ships no production code and exists solely
//! to hold the cross-transport contract suite mandated by plan todo 18. The
//! real content lives in the integration test target:
//!
//! - `tests/transport_parity.rs`. REST/gRPC operation + error parity, socket
//!   hardening (mode `0660`, insecure-mode rejection, no-TCP policy), and
//!   request-audit emission checks.
//! - `tests/common/mod.rs`: the shared harness: a deterministic scripted
//!   backend wrapped in the composed
//!   [`VmLifecycleService`](microvm_service::VmLifecycleService), REST/gRPC
//!   client drivers over real Unix sockets, and shared fixtures.
//!
//! Both transports are driven end-to-end over real Unix domain sockets and are
//! backed by the same `VmLifecycleService` instance, so the same request
//! reaches the same service result regardless of transport. Authorization is
//! never duplicated or weakened here: it is delegated entirely to the service
//! and merely asserted by these tests.
//!
//! Run with: `cargo test -p microvm-contract-tests`.
