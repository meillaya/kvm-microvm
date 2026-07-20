//! TAP network byte counters and derived RX/TX throughput (plan todo 23).
//!
//! Per-VM network usage is read from the host sysfs statistics of the VM's TAP
//! device: `<sysfs>/class/net/<tap>/statistics/{rx_bytes,tx_bytes}`. These are
//! monotonic byte counters. Throughput (bytes/sec) is derived by the
//! [`MetricsCollector`](crate::MetricsCollector) from the delta between two
//! consecutive samples over their host-monotonic timestamp delta; on the first
//! sample there is no previous counter, so throughput is reported as `None`
//! ([`UnavailableReason::NotYetSampled`]) rather than a fabricated zero.

use crate::availability::UnavailableReason;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// TAP RX/TX byte counters plus derived throughput for one VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Host-monotonic timestamp (ns) when this source was sampled.
    pub sampled_monotonic_ns: u64,
    /// Total bytes received on the TAP (monotonic counter).
    pub rx_bytes: u64,
    /// Total bytes transmitted on the TAP (monotonic counter).
    pub tx_bytes: u64,
    /// Receive throughput in bytes/sec since the previous sample, or `None`
    /// when no previous sample exists yet (never a fabricated zero).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes_per_sec: Option<u64>,
    /// Transmit throughput in bytes/sec since the previous sample, or `None`
    /// when no previous sample exists yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes_per_sec: Option<u64>,
}

/// Parse a single sysfs counter file (e.g. `rx_bytes`).
pub fn parse_counter(content: &str) -> Result<u64, UnavailableReason> {
    content
        .trim()
        .parse::<u64>()
        .map_err(|_| UnavailableReason::ParseError)
}

/// Compute a bytes/sec rate from two monotonic counter samples.
///
/// Returns `None` when the elapsed time is zero (no rate definable) or when
/// the counter went backwards (a reset; a negative rate is meaningless). The
/// multiplication is done in u128 to avoid overflow before the division.
pub fn bytes_per_sec(prev: u64, cur: u64, prev_ns: u64, cur_ns: u64) -> Option<u64> {
    if cur_ns <= prev_ns || cur < prev {
        return None;
    }
    let delta_bytes = (cur - prev) as u128;
    let delta_ns = (cur_ns - prev_ns) as u128;
    let per_sec = delta_bytes.saturating_mul(1_000_000_000) / delta_ns;
    // Saturate rather than truncate if the rate exceeds u64 (pathological
    // byte-delta-over-tiny-interval inputs).
    Some(u64::try_from(per_sec).unwrap_or(u64::MAX))
}

/// Read the raw RX/TX byte counters for a TAP device from sysfs.
///
/// Returns `(rx_bytes, tx_bytes)`. A missing statistics file maps to
/// [`UnavailableReason::SourceMissing`]; other I/O errors to
/// [`UnavailableReason::ReadError`]; malformed content to
/// [`UnavailableReason::ParseError`].
pub fn read_tap_counters(
    sysfs_root: &Path,
    tap_name: &str,
) -> Result<(u64, u64), UnavailableReason> {
    let stats = sysfs_root
        .join("class/net")
        .join(tap_name)
        .join("statistics");
    let read = |name: &str| -> Result<u64, UnavailableReason> {
        let content = match fs::read_to_string(stats.join(name)) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(UnavailableReason::SourceMissing);
            }
            Err(_) => return Err(UnavailableReason::ReadError),
        };
        parse_counter(&content)
    };
    let rx_bytes = read("rx_bytes")?;
    let tx_bytes = read("tx_bytes")?;
    Ok((rx_bytes, tx_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_counter() {
        assert_eq!(parse_counter("12345\n"), Ok(12345));
        assert_eq!(parse_counter("x"), Err(UnavailableReason::ParseError));
    }

    #[test]
    fn rate_is_bytes_per_second() {
        // 1000 bytes over 500ms => 2000 bytes/sec.
        assert_eq!(bytes_per_sec(0, 1000, 0, 500_000_000), Some(2000));
    }

    #[test]
    fn rate_is_none_for_zero_elapsed_or_backwards_counter() {
        assert_eq!(bytes_per_sec(0, 1000, 100, 100), None);
        assert_eq!(bytes_per_sec(1000, 500, 0, 1_000_000_000), None);
    }

    #[test]
    fn rate_does_not_overflow() {
        // Huge byte delta over 1ns would overflow u64 bytes/sec; saturates.
        let r = bytes_per_sec(0, u64::MAX, 0, 1).unwrap();
        assert_eq!(r, u64::MAX);
    }
}
