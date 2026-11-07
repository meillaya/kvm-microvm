//! Adversarial security boundary tests for the microvm platform.
//!
//! This is a test-only crate: it ships no production code and exists solely
//! to hold the adversarial mutation/property suites and privileged isolation
//! probes that cover every known Firecracker/jailer/cgroup/network/snapshot
//! trap. The real content lives in the integration test targets under `tests/`:
//!
//! - `tests/path_security.rs`: symlink escape, `..` traversal, absolute path,
//!   and magic-link rejection through the real descriptor-relative resolver.
//! - `tests/binary_security.rs`: release/static SHA-256 + ELF-form provenance
//!   gate: hash mismatch, dynamic (GNU) binary, debug build, wrong machine,
//!   and version-string rejection.
//! - `tests/cgroup_security.rs`: `--cgroup-version=2` pinning, the cgroup-v2
//!   no-internal-process leaf contract, and controller delegation.
//! - `tests/auth_security.rs`: peer-credential extraction/denial, cross-tenant
//!   and wrong-role denial, and wrong-owner/insecure socket rejection.
//! - `tests/network_security.rs`: inter-VM forward-chain denial and the
//!   no-TCP-binding policy.
//! - `tests/snapshot_security.rs`: content-hash tamper detection and the
//!   pre-restore compatibility/ownership gate.
//! - `tests/scope_fidelity.rs`: structural absence of TCP/rootless/VFIO/
//!   live-migration knobs in the boot and network surface.
//! - `tests/common/mod.rs`: the shared harness: a typed-error probe recorder
//!   that emits a per-domain security evidence artifact, plus synthetic ELF,
//!   binary, and cgroup-hierarchy fixtures.
//!
//! # Methodology (why these are not grep-only checks)
//! Every probe drives the production code path: opening the real resolver,
//! verifying a real (synthetic) binary, building the real jailer argv, running
//! the real compatibility gate, and observes the typed [`microvm_errors::ErrorCode`] the boundary returns.
//! A trap is proven by the structured rejection it produces, never by scanning
//! source text. Source-text scans appear only as a *secondary* scope-fidelity
//! layer in `scope_fidelity.rs`, each paired with a behavioral proof.
//!
//! # Evidence
//! Each domain battery writes a machine-readable artifact under
//! `target/security-evidence/<domain>.json` recording, per probe, the expected
//! and actual error code and pass/fail. The battery writes the artifact
//! before asserting, so a detected bypass still leaves evidence behind.
//!
//! # Determinism / privileged split
//! The default run (`cargo test -p microvm-security-tests`) is fully
//! deterministic: no root, no `/dev/kvm`, no `/dev/net/tun`, no writable
//! `/sys/fs/cgroup`, and no pinned Firecracker/jailer binary is required.
//! Probes that must touch a real kernel boundary live behind the `privileged`
//! feature (`cargo test -p microvm-security-tests --features privileged`).
//!
//! [`microvm_errors::ErrorCode`]: microvm_errors::ErrorCode
#![forbid(unsafe_code)]
