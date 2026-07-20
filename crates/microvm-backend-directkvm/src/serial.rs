//! Serial port output capture for the educational direct-KVM subset.
//!
//! The guest writes to the 16550 UART data register at I/O port `0x3F8`.
//! [`SerialOutput`] records those bytes. This module is pure and deterministic:
//! it requires no host access, no `/dev/kvm`, and no privileged operations, so
//! it is always compiled and tested in the default (no-feature) lane.

use crate::{GUEST_MARKER_BYTE, SERIAL_PORT};
use serde::{Deserialize, Serialize};

/// Captures bytes written by the guest to the 16550 UART data register
/// (I/O port `0x3F8`).
///
/// This is the sole device output surface of the educational subset. It is a
/// pure append-only byte log; no other port is recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialOutput {
    bytes: Vec<u8>,
}

impl SerialOutput {
    /// Creates an empty serial capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one byte iff `port` is the serial data register (`0x3F8`).
    ///
    /// Returns `true` when the byte was captured (the port matched) and `false`
    /// when the write targeted some other port and was ignored.
    pub fn record(&mut self, port: u16, byte: u8) -> bool {
        if port == SERIAL_PORT {
            self.bytes.push(byte);
            true
        } else {
            false
        }
    }

    /// The captured bytes, in guest write order.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of captured bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when no bytes have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Lossy UTF-8 view of the captured bytes.
    #[must_use]
    pub fn as_string(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// True iff the guest marker byte (`0x4B`, `'K'`) was captured.
    #[must_use]
    pub fn contains_marker(&self) -> bool {
        self.bytes.contains(&GUEST_MARKER_BYTE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SERIAL_PORT;

    #[test]
    fn records_only_the_serial_port() {
        let mut serial = SerialOutput::new();
        assert!(serial.record(SERIAL_PORT, 0x4B));
        assert!(!serial.record(0x3F9, 0x99)); // other port ignored
        assert_eq!(serial.bytes(), &[0x4B]);
        assert_eq!(serial.len(), 1);
    }

    #[test]
    fn captures_the_marker_in_order() {
        let mut serial = SerialOutput::new();
        for b in [b'O', b'K', b'!'] {
            serial.record(SERIAL_PORT, b);
        }
        assert_eq!(serial.as_string(), "OK!");
        assert!(serial.contains_marker());
    }

    #[test]
    fn empty_capture_has_no_marker() {
        let serial = SerialOutput::new();
        assert!(serial.is_empty());
        assert!(!serial.contains_marker());
        assert_eq!(serial.as_string(), "");
    }

    #[test]
    fn serial_output_serializes_round_trip() {
        let mut serial = SerialOutput::new();
        serial.record(SERIAL_PORT, 0x4B);
        let json = serde_json::to_string(&serial).unwrap();
        let back: SerialOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(serial, back);
    }
}
