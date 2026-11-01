//! Privileged integration tests for the educational direct-KVM subset.
//!
//! Gated behind BOTH the `direct-kvm` and `privileged` features. These tests
//! require a real `/dev/kvm` on a capable x86_64 host and are never compiled or
//! run in the default workspace build or in CI without host KVM access.
//!
//! Run with:
//!
//! ```text
//! cargo test -p microvm-backend-directkvm --features direct-kvm,privileged
//! ```
//!
//! Contract under test:
//! - On a capable host the marker guest boots on real KVM, writes `0x4B` (`'K'`)
//!   to I/O port `0x3F8`, and stops via `HLT`.
//! - A missing `/dev/kvm` produces a structured `Blocked{kvm_unavailable}`
//!   outcome: never a pass and never a fallback to Firecracker/QEMU/TCG.

#![cfg(all(feature = "direct-kvm", feature = "privileged"))]

use microvm_backend_directkvm::{
    blocked_reason_for_device, open_and_probe, run_subset_boot, run_subset_boot_at, BlockedReason,
    RunOutcome, StopReason, DEFAULT_KVM_DEVICE, GUEST_MARKER_BYTE, KVM_API_VERSION,
};

fn outcome_json(outcome: &RunOutcome) -> String {
    serde_json::to_string(outcome).unwrap_or_else(|_| format!("{outcome:?}"))
}

/// The real boot. On a capable host the marker guest runs and the serial marker
/// is observed before HLT. On a host without KVM the same call must return a
/// structured `Blocked` outcome (not a pass, not a fallback).
#[test]
fn direct_kvm_subset_boot_observes_serial_marker_or_blocks() {
    let outcome = run_subset_boot();
    eprintln!("direct-KVM subset boot outcome: {}", outcome_json(&outcome));

    match &outcome {
        RunOutcome::Completed { serial, stop } => {
            assert_eq!(*stop, StopReason::Hlt, "marker guest must stop via HLT");
            assert!(
                serial.bytes().contains(&GUEST_MARKER_BYTE),
                "serial output must contain the marker byte 0x4B ('K'); got {:?}",
                serial.bytes()
            );
            assert!(serial.contains_marker());
        }
        RunOutcome::Blocked { reason, detail } => {
            // Missing/incompatible /dev/kvm is a structured block, not a pass.
            eprintln!(
                "BLOCKED (not a pass, no fallback): {} ({detail})",
                reason.as_str()
            );
        }
        RunOutcome::Failed {
            reason,
            detail,
            serial,
        } => panic!(
            "subset boot failed on a capable host: {reason:?}: {detail}; serial={:?}",
            serial.bytes()
        ),
    }
}

/// Missing `/dev/kvm` (simulated with a nonexistent path) must produce a
/// structured `Blocked{kvm_unavailable}` outcome; never `Completed`, never
/// `Failed`, never a fallback. Deterministic: independent of host KVM presence.
#[test]
fn missing_device_is_blocked_not_pass_and_has_no_fallback() {
    let bogus = "/dev/definitely-not-kvm-microvm-subset";
    let outcome = run_subset_boot_at(bogus);
    eprintln!("missing-device outcome: {}", outcome_json(&outcome));

    match &outcome {
        RunOutcome::Blocked { reason, detail } => {
            assert_eq!(*reason, BlockedReason::KvmUnavailable);
            assert!(
                detail.contains(bogus) || detail.contains("errno"),
                "detail should identify the device/errno, got: {detail}"
            );
        }
        other => panic!("missing /dev/kvm must be Blocked, got {other:?}"),
    }
    assert!(!outcome.is_completed());
    assert!(!outcome.is_failed());
    assert_eq!(
        blocked_reason_for_device(bogus),
        Some(BlockedReason::KvmUnavailable)
    );
}

/// Probes the real device when present: API version must be exactly 12 and
/// `KVM_CAP_USER_MEMORY` must be available. When the host lacks KVM the probe
/// is blocked with structured evidence (never a fabricated pass).
#[test]
fn probe_real_device_api_version_is_12_or_blocked() {
    match open_and_probe(DEFAULT_KVM_DEVICE) {
        Ok((_kvm, report)) => {
            eprintln!("probe report: {}", serde_json::to_string(&report).unwrap());
            assert_eq!(report.api_version, KVM_API_VERSION);
            assert_eq!(report.api_version, 12);
            assert!(report.user_memory);
            assert_eq!(report.device_path, DEFAULT_KVM_DEVICE);
        }
        Err(e) => {
            eprintln!(
                "host lacks usable KVM; probe blocked: {} ({})",
                e.blocked_reason().as_str(),
                e.detail()
            );
            // A blocked probe is structured evidence, never a pass.
            let outcome = e.into_blocked();
            assert!(outcome.is_blocked());
            assert!(!outcome.is_completed());
        }
    }
}
