//! Host cgroup-v2 metrics: CPU usage/throttling, memory current/events, IO,
//! and pids (plan todo 23).
//!
//! # Determinism
//! The parsers ([`parse_cpu_stat`], [`parse_memory_events`], [`parse_io_stat`],
//! [`parse_single_u64`]) are pure functions of file contents: no
//! filesystem access, so they are fully reproducible in tests. The
//! filesystem-facing [`read_cgroup_metrics`] takes a configurable cgroup leaf
//! directory and maps every failure to a bounded [`UnavailableReason`] (never
//! a panic, never a zero-fill); the [`MetricsCollector`](crate::MetricsCollector)
//! records that reason in the slot's availability flag and a bounded error
//! counter.
//!
//! Reference: <https://docs.kernel.org/admin-guide/cgroup-v2.html>.

use crate::availability::UnavailableReason;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// CPU accounting from `cpu.stat`.
///
/// `usage_usec` is the total CPU time consumed; `nr_throttled`/`throttled_usec`
/// expose throttling under the `cpu.max` limit. Counters are monotonic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuStat {
    /// Total CPU time consumed across all CPUs, in microseconds.
    pub usage_usec: u64,
    /// Number of scheduling periods elapsed.
    pub nr_periods: u64,
    /// Number of periods in which the cgroup was throttled.
    pub nr_throttled: u64,
    /// Total time the cgroup was throttled, in microseconds.
    pub throttled_usec: u64,
}

/// Memory pressure/OOM event counters from `memory.events`.
///
/// All fields are monotonic event counts. A present-but-empty file yields all
/// zeros (no events), which is a legitimate measured value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEvents {
    /// Times the cgroup's memory usage was reclaimed due to `memory.low`.
    pub low: u64,
    /// Times usage exceeded `memory.high` and was throttled.
    pub high: u64,
    /// Times usage hit the `memory.max` limit.
    pub max: u64,
    /// Times the cgroup was OOM-killed (memory cgroup OOM).
    pub oom: u64,
    /// Times a task in the cgroup was killed by the kernel OOM killer.
    pub oom_kill: u64,
}

/// Block I/O accounting aggregated across all devices from `io.stat`.
///
/// `io.stat` reports one `MAJ:MIN key=value ...` line per device; we sum the
/// byte and operation counters across devices because the per-VM schema exposes
/// a single aggregate (per-device labels would be high-cardinality and are
/// intentionally dropped).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoMetrics {
    /// Total bytes read across all devices.
    pub read_bytes: u64,
    /// Total bytes written across all devices.
    pub write_bytes: u64,
    /// Total read I/O operations across all devices.
    pub read_ios: u64,
    /// Total write I/O operations across all devices.
    pub write_ios: u64,
}

/// A complete host cgroup-v2 metrics sample for one VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupMetrics {
    /// Host-monotonic timestamp (ns) when this source was sampled.
    pub sampled_monotonic_ns: u64,
    /// CPU usage and throttling counters.
    pub cpu: CpuStat,
    /// Current memory usage in bytes (`memory.current`).
    pub memory_current_bytes: u64,
    /// Memory pressure/OOM event counters (`memory.events`).
    pub memory_events: MemoryEvents,
    /// Aggregate block I/O counters (`io.stat`).
    pub io: IoMetrics,
    /// Current number of processes in the cgroup (`pids.current`).
    pub pids_current: u64,
}

/// Parse a `key value` line, returning the value as `u64`.
fn parse_kv_u64(line: &str) -> Option<(&str, u64)> {
    let mut parts = line.split_whitespace();
    let key = parts.next()?;
    let value = parts.next()?.parse::<u64>().ok()?;
    Some((key, value))
}

/// Parse the contents of a cgroup-v2 `cpu.stat` file.
///
/// Recognized keys: `usage_usec`, `nr_periods`, `nr_throttled`,
/// `throttled_usec`. `usage_usec` is required (it is always present on a
/// real cgroup-v2 `cpu.stat`); the throttling counters default to `0` if a
/// kernel omits them. Returns [`UnavailableReason::ParseError`] if `usage_usec`
/// is missing or any present value is not a valid `u64`.
pub fn parse_cpu_stat(content: &str) -> Result<CpuStat, UnavailableReason> {
    let mut stat = CpuStat::default();
    let mut saw_usage = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = parse_kv_u64(line).ok_or(UnavailableReason::ParseError)?;
        match key {
            "usage_usec" => {
                stat.usage_usec = value;
                saw_usage = true;
            }
            "nr_periods" => stat.nr_periods = value,
            "nr_throttled" => stat.nr_throttled = value,
            "throttled_usec" => stat.throttled_usec = value,
            // Other cpu.stat keys (nr_bursts, burst_usec, ...) are ignored.
            _ => {}
        }
    }
    if saw_usage {
        Ok(stat)
    } else {
        Err(UnavailableReason::ParseError)
    }
}

/// Parse the contents of a cgroup-v2 `memory.events` file.
///
/// Recognized keys: `low`, `high`, `max`, `oom`, `oom_kill`. Missing keys
/// default to `0` (no such events). Malformed lines yield
/// [`UnavailableReason::ParseError`].
pub fn parse_memory_events(content: &str) -> Result<MemoryEvents, UnavailableReason> {
    let mut events = MemoryEvents::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = parse_kv_u64(line).ok_or(UnavailableReason::ParseError)?;
        match key {
            "low" => events.low = value,
            "high" => events.high = value,
            "max" => events.max = value,
            "oom" => events.oom = value,
            "oom_kill" => events.oom_kill = value,
            _ => {}
        }
    }
    Ok(events)
}

/// Parse the contents of a cgroup-v2 `io.stat` file, aggregating across
/// devices.
///
/// Each non-empty line is `MAJ:MIN k=v k=v ...`; we sum `rbytes`, `wbytes`,
/// `rios`, and `wios`. An empty file (no I/O yet) yields all zeros, which is a
/// legitimate measured value. Malformed numeric tokens yield
/// [`UnavailableReason::ParseError`].
pub fn parse_io_stat(content: &str) -> Result<IoMetrics, UnavailableReason> {
    let mut io = IoMetrics::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // First token is the MAJ:MIN device id; skip it.
        let mut tokens = line.split_whitespace();
        let _dev = tokens.next().ok_or(UnavailableReason::ParseError)?;
        for token in tokens {
            let (key, value) = token.split_once('=').ok_or(UnavailableReason::ParseError)?;
            let value = value
                .parse::<u64>()
                .map_err(|_| UnavailableReason::ParseError)?;
            match key {
                "rbytes" => io.read_bytes = io.read_bytes.saturating_add(value),
                "wbytes" => io.write_bytes = io.write_bytes.saturating_add(value),
                "rios" => io.read_ios = io.read_ios.saturating_add(value),
                "wios" => io.write_ios = io.write_ios.saturating_add(value),
                // dbytes/dios and other keys are ignored.
                _ => {}
            }
        }
    }
    Ok(io)
}

/// Parse a single-value cgroup file (e.g. `memory.current`, `pids.current`).
///
/// Trims surrounding whitespace and parses one `u64`. Returns
/// [`UnavailableReason::ParseError`] on any malformed content.
pub fn parse_single_u64(content: &str) -> Result<u64, UnavailableReason> {
    content
        .trim()
        .parse::<u64>()
        .map_err(|_| UnavailableReason::ParseError)
}

/// Read a file's contents, mapping I/O errors to a bounded reason.
///
/// A missing file maps to [`UnavailableReason::SourceMissing`]; any other I/O
/// error maps to [`UnavailableReason::ReadError`].
fn read_to_string(path: &Path) -> Result<String, UnavailableReason> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(UnavailableReason::SourceMissing),
        Err(_) => Err(UnavailableReason::ReadError),
    }
}

/// Read a full [`CgroupMetrics`] sample from a cgroup-v2 leaf directory.
///
/// `monotonic_ns` is the host-monotonic timestamp recorded by the caller for
/// this sample. Required files: `cpu.stat`, `memory.current`, `pids.current`.
/// `memory.events` and `io.stat` are optional (absent => zeroed events/IO,
/// which is a legitimate "nothing happened yet" reading). Any missing required
/// file, I/O failure, or parse failure maps to a bounded [`UnavailableReason`]
///: this function never panics and never fabricates a zero for a source it
/// could not read.
pub fn read_cgroup_metrics(
    cgroup_dir: &Path,
    monotonic_ns: u64,
) -> Result<CgroupMetrics, UnavailableReason> {
    let cpu = parse_cpu_stat(&read_to_string(&cgroup_dir.join("cpu.stat"))?)?;
    let memory_current_bytes =
        parse_single_u64(&read_to_string(&cgroup_dir.join("memory.current"))?)?;
    let pids_current = parse_single_u64(&read_to_string(&cgroup_dir.join("pids.current"))?)?;

    // Optional files: absent => legitimate zero reading.
    let memory_events = match read_to_string(&cgroup_dir.join("memory.events")) {
        Ok(content) => parse_memory_events(&content)?,
        Err(UnavailableReason::SourceMissing) => MemoryEvents::default(),
        Err(reason) => return Err(reason),
    };
    let io = match read_to_string(&cgroup_dir.join("io.stat")) {
        Ok(content) => parse_io_stat(&content)?,
        Err(UnavailableReason::SourceMissing) => IoMetrics::default(),
        Err(reason) => return Err(reason),
    };

    Ok(CgroupMetrics {
        sampled_monotonic_ns: monotonic_ns,
        cpu,
        memory_current_bytes,
        memory_events,
        io,
        pids_current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_stat() {
        let content = "usage_usec 123456\nnr_periods 1000\nnr_throttled 5\nthrottled_usec 789\n";
        let stat = parse_cpu_stat(content).unwrap();
        assert_eq!(
            stat,
            CpuStat {
                usage_usec: 123456,
                nr_periods: 1000,
                nr_throttled: 5,
                throttled_usec: 789,
            }
        );
    }

    #[test]
    fn cpu_stat_ignores_unknown_keys_and_defaults_throttling() {
        let content = "usage_usec 42\nnr_bursts 3\nburst_usec 9\n";
        let stat = parse_cpu_stat(content).unwrap();
        assert_eq!(stat.usage_usec, 42);
        assert_eq!(stat.nr_throttled, 0);
        assert_eq!(stat.throttled_usec, 0);
    }

    #[test]
    fn cpu_stat_missing_usage_is_parse_error() {
        assert_eq!(
            parse_cpu_stat("nr_periods 10\n"),
            Err(UnavailableReason::ParseError)
        );
        assert_eq!(parse_cpu_stat(""), Err(UnavailableReason::ParseError));
    }

    #[test]
    fn cpu_stat_malformed_value_is_parse_error() {
        assert_eq!(
            parse_cpu_stat("usage_usec notanumber\n"),
            Err(UnavailableReason::ParseError)
        );
    }

    #[test]
    fn parses_memory_events() {
        let content = "low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\n";
        let events = parse_memory_events(content).unwrap();
        assert_eq!(
            events,
            MemoryEvents {
                low: 1,
                high: 2,
                max: 3,
                oom: 4,
                oom_kill: 5,
            }
        );
    }

    #[test]
    fn memory_events_defaults_missing_keys_to_zero() {
        let events = parse_memory_events("high 9\n").unwrap();
        assert_eq!(events.high, 9);
        assert_eq!(events.oom_kill, 0);
    }

    #[test]
    fn parses_io_stat_aggregating_devices() {
        let content = "8:0 rbytes=100 wbytes=200 rios=1 wios=2 dbytes=999 dios=9\n\
                       8:16 rbytes=10 wbytes=20 rios=3 wios=4\n";
        let io = parse_io_stat(content).unwrap();
        assert_eq!(io.read_bytes, 110);
        assert_eq!(io.write_bytes, 220);
        assert_eq!(io.read_ios, 4);
        assert_eq!(io.write_ios, 6);
    }

    #[test]
    fn empty_io_stat_is_zero_not_error() {
        assert_eq!(parse_io_stat(""), Ok(IoMetrics::default()));
    }

    #[test]
    fn parses_single_u64_with_whitespace() {
        assert_eq!(parse_single_u64("  4096\n"), Ok(4096));
        assert_eq!(parse_single_u64("max"), Err(UnavailableReason::ParseError));
    }
}
