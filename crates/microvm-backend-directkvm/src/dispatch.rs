//! Backend-neutral VM-exit dispatcher for the educational direct-KVM subset.
//!
//! The dispatcher is a **pure state machine** over a backend-neutral
//! [`GuestExit`] representation. The privileged runner maps the real
//! `kvm_ioctls::VcpuExit` into [`GuestExit`]; the dispatch logic itself never
//! touches KVM and is fully deterministic, so it is tested in the default
//! (no-feature) lane.
//!
//! Handled exits (exactly the pinned allowed set):
//!
//! | Guest exit            | Action                                   |
//! |-----------------------|------------------------------------------|
//! | `IoOut` (port write)  | record byte if serial; resume            |
//! | `Hlt`                 | stop cleanly (`StopReason::Hlt`)         |
//! | `FailEntry`           | fail (`FailureReason::EntryFailure`)     |
//! | `InternalError`       | fail (`FailureReason::InternalError`)    |
//! | `Unexpected`          | fail (`FailureReason::UnexpectedExit`)   |

use crate::outcome::{FailureReason, StopReason};
use crate::serial::SerialOutput;

/// A backend-neutral representation of one guest VM exit.
///
/// The privileged runner converts `kvm_ioctls::VcpuExit` into this enum; every
/// variant is owned (`Copy`) so it carries no borrow into the KVM run buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestExit {
    /// `KVM_EXIT_IO` (direction OUT): a port write of one byte.
    IoOut {
        /// I/O port targeted by the guest.
        port: u16,
        /// The byte written.
        byte: u8,
    },
    /// `KVM_EXIT_HLT`.
    Hlt,
    /// `KVM_EXIT_FAIL_ENTRY`.
    FailEntry {
        /// `hardware_entry_failure_reason` from KVM.
        hardware_entry_failure_reason: u64,
    },
    /// `KVM_EXIT_INTERNAL_ERROR`.
    InternalError {
        /// `internal_error_suberror` from KVM.
        suberror: u32,
    },
    /// Any exit reason outside the pinned allowed set.
    Unexpected {
        /// The raw KVM exit reason number.
        reason_code: u32,
    },
}

/// What the vCPU loop should do after dispatching one exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchAction {
    /// Resume the vCPU (`KVM_RUN` again).
    Continue,
    /// Stop cleanly; the loop exits with this stop reason.
    Stop(StopReason),
    /// Fail; the loop exits with this failure reason and detail.
    Fail(FailureReason, String),
}

/// Pure exit dispatcher: folds a stream of [`GuestExit`] into serial output and
/// a terminal [`DispatchAction`]. Also carries the host-stop flag checked
/// between `KVM_RUN` iterations.
#[derive(Debug, Default)]
pub struct ExitDispatcher {
    serial: SerialOutput,
    host_stop_requested: bool,
}

impl ExitDispatcher {
    /// Creates a dispatcher with empty serial capture and no stop request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the host-stop flag; honored before resuming after the next exit.
    pub fn request_host_stop(&mut self) {
        self.host_stop_requested = true;
    }

    /// True iff a host stop has been requested.
    #[must_use]
    pub fn host_stop_requested(&self) -> bool {
        self.host_stop_requested
    }

    /// The serial capture so far.
    #[must_use]
    pub fn serial(&self) -> &SerialOutput {
        &self.serial
    }

    /// Consumes the dispatcher and returns the captured serial output.
    #[must_use]
    pub fn into_serial(self) -> SerialOutput {
        self.serial
    }

    /// Dispatches one exit, updating serial capture, and returns the action the
    /// vCPU loop should take.
    pub fn dispatch(&mut self, exit: GuestExit) -> DispatchAction {
        match exit {
            GuestExit::IoOut { port, byte } => {
                // Only the serial data register is emulated; the single-device
                // contract records matching writes and ignores other ports.
                let _ = self.serial.record(port, byte);
                self.resume_or_host_stop()
            }
            GuestExit::Hlt => DispatchAction::Stop(StopReason::Hlt),
            GuestExit::FailEntry {
                hardware_entry_failure_reason,
            } => DispatchAction::Fail(
                FailureReason::EntryFailure,
                format!("hardware_entry_failure_reason={hardware_entry_failure_reason:#x}"),
            ),
            GuestExit::InternalError { suberror } => DispatchAction::Fail(
                FailureReason::InternalError,
                format!("internal_error_suberror={suberror:#x}"),
            ),
            GuestExit::Unexpected { reason_code } => DispatchAction::Fail(
                FailureReason::UnexpectedExit,
                format!("unexpected_exit_reason={reason_code}"),
            ),
        }
    }

    fn resume_or_host_stop(&self) -> DispatchAction {
        if self.host_stop_requested {
            DispatchAction::Stop(StopReason::HostStop)
        } else {
            DispatchAction::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SERIAL_PORT;

    #[test]
    fn serial_write_then_hlt_completes_with_marker() {
        let mut d = ExitDispatcher::new();
        assert_eq!(
            d.dispatch(GuestExit::IoOut {
                port: SERIAL_PORT,
                byte: 0x4B
            }),
            DispatchAction::Continue
        );
        assert_eq!(
            d.dispatch(GuestExit::Hlt),
            DispatchAction::Stop(StopReason::Hlt)
        );
        let serial = d.into_serial();
        assert!(serial.contains_marker());
        assert_eq!(serial.bytes(), &[0x4B]);
    }

    #[test]
    fn fail_entry_is_a_failure_with_reason() {
        let mut d = ExitDispatcher::new();
        let action = d.dispatch(GuestExit::FailEntry {
            hardware_entry_failure_reason: 0x8000_0000,
        });
        match action {
            DispatchAction::Fail(FailureReason::EntryFailure, detail) => {
                assert!(detail.contains("0x80000000"));
            }
            other => panic!("expected EntryFailure, got {other:?}"),
        }
    }

    #[test]
    fn internal_error_is_a_failure_with_suberror() {
        let mut d = ExitDispatcher::new();
        let action = d.dispatch(GuestExit::InternalError { suberror: 0x5 });
        assert!(matches!(
            action,
            DispatchAction::Fail(FailureReason::InternalError, _)
        ));
    }

    #[test]
    fn unexpected_exit_is_a_failure() {
        let mut d = ExitDispatcher::new();
        let action = d.dispatch(GuestExit::Unexpected { reason_code: 99 });
        match action {
            DispatchAction::Fail(FailureReason::UnexpectedExit, detail) => {
                assert!(detail.contains("99"));
            }
            other => panic!("expected UnexpectedExit, got {other:?}"),
        }
    }

    #[test]
    fn host_stop_is_honored_between_iterations() {
        let mut d = ExitDispatcher::new();
        d.request_host_stop();
        // A serial write would normally resume, but the host-stop flag wins.
        let action = d.dispatch(GuestExit::IoOut {
            port: SERIAL_PORT,
            byte: 0x4B,
        });
        assert_eq!(action, DispatchAction::Stop(StopReason::HostStop));
    }

    #[test]
    fn non_serial_port_write_is_ignored_but_resumes() {
        let mut d = ExitDispatcher::new();
        let action = d.dispatch(GuestExit::IoOut {
            port: 0x80,
            byte: 0xAA,
        });
        assert_eq!(action, DispatchAction::Continue);
        assert!(d.serial().is_empty());
    }

    #[test]
    fn dispatcher_accumulates_multiple_serial_bytes() {
        let mut d = ExitDispatcher::new();
        for b in [b'O', b'K'] {
            assert_eq!(
                d.dispatch(GuestExit::IoOut {
                    port: SERIAL_PORT,
                    byte: b
                }),
                DispatchAction::Continue
            );
        }
        assert_eq!(d.serial().as_string(), "OK");
    }
}
