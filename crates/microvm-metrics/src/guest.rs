//! Optional guest-agent metrics: CPU steal, load, and RSS.
//!
//! Guest-side metrics are only obtainable when a guest agent is reachable over
//! the VM's vsock channel. They are strictly optional: when no agent is
//! configured or the agent is unreachable, the whole [`GuestMetrics`] slot is
//! marked [`Unavailable`](crate::Availability::Unavailable): it is never
//! zero-filled, because a measured `0%` steal and an absent agent are very
//! different facts.
//!
//! The [`GuestAgentReader`] trait abstracts the vsock transport so the
//! collector stays deterministic: tests inject a fixed reader, and the default
//! [`NoGuestAgent`] reader always reports the agent as unreachable.

use crate::availability::UnavailableReason;
use microvm_types::VmId;
use serde::{Deserialize, Serialize};

/// A raw guest-agent sample (without the host-monotonic sample timestamp,
/// which the collector attaches).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct GuestAgentSample {
    /// Guest CPU steal time as a percentage of total CPU time (0.0–100.0).
    pub cpu_steal_pct: f64,
    /// Guest 1-minute load average.
    pub load1: f64,
    /// Guest resident set size in bytes.
    pub rss_bytes: u64,
}

/// Guest-side metrics for one VM, sampled from the guest agent.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct GuestMetrics {
    /// Host-monotonic timestamp (ns) when this source was sampled.
    pub sampled_monotonic_ns: u64,
    /// Guest CPU steal as a percentage (0.0–100.0).
    pub cpu_steal_pct: f64,
    /// Guest 1-minute load average.
    pub load1: f64,
    /// Guest resident set size in bytes.
    pub rss_bytes: u64,
}

impl GuestMetrics {
    /// Attach a host-monotonic sample timestamp to a raw agent sample.
    pub fn from_sample(sample: GuestAgentSample, sampled_monotonic_ns: u64) -> Self {
        Self {
            sampled_monotonic_ns,
            cpu_steal_pct: sample.cpu_steal_pct,
            load1: sample.load1,
            rss_bytes: sample.rss_bytes,
        }
    }
}

/// Abstraction over the guest-agent transport (vsock in production).
///
/// Implementations return a [`GuestAgentSample`] or a bounded
/// [`UnavailableReason`]. They must never panic on an unreachable agent.
pub trait GuestAgentReader: Send + Sync {
    /// Read a fresh sample for `vm_id`.
    fn read(&self, vm_id: &VmId) -> Result<GuestAgentSample, UnavailableReason>;
}

/// The default reader: no guest agent is configured, so guest metrics are
/// always unavailable. This keeps the host-only path honest (guest slot is
/// `Unavailable(NoBackend)`, never zero).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoGuestAgent;

impl GuestAgentReader for NoGuestAgent {
    fn read(&self, _vm_id: &VmId) -> Result<GuestAgentSample, UnavailableReason> {
        Err(UnavailableReason::NoBackend)
    }
}

/// A deterministic reader that returns a fixed result for every VM. Used by
/// tests to simulate a present agent, or an agent that disappears mid-run.
#[derive(Clone, Debug)]
pub struct StaticGuestAgent {
    result: Result<GuestAgentSample, UnavailableReason>,
}

impl StaticGuestAgent {
    /// A reader that always returns `sample`.
    pub fn returning(sample: GuestAgentSample) -> Self {
        Self { result: Ok(sample) }
    }

    /// A reader that always fails with `reason` (e.g. an agent that is gone).
    pub fn failing(reason: UnavailableReason) -> Self {
        Self {
            result: Err(reason),
        }
    }
}

impl GuestAgentReader for StaticGuestAgent {
    fn read(&self, _vm_id: &VmId) -> Result<GuestAgentSample, UnavailableReason> {
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm() -> VmId {
        VmId::new("vm-guest").unwrap()
    }

    #[test]
    fn no_guest_agent_is_unavailable_not_zero() {
        let reader = NoGuestAgent;
        assert_eq!(reader.read(&vm()), Err(UnavailableReason::NoBackend));
    }

    #[test]
    fn static_agent_returns_sample() {
        let sample = GuestAgentSample {
            cpu_steal_pct: 12.5,
            load1: 0.75,
            rss_bytes: 1 << 20,
        };
        let reader = StaticGuestAgent::returning(sample);
        assert_eq!(reader.read(&vm()), Ok(sample));
    }

    #[test]
    fn from_sample_attaches_timestamp() {
        let sample = GuestAgentSample {
            cpu_steal_pct: 1.0,
            load1: 2.0,
            rss_bytes: 4096,
        };
        let m = GuestMetrics::from_sample(sample, 999);
        assert_eq!(m.sampled_monotonic_ns, 999);
        assert_eq!(m.cpu_steal_pct, 1.0);
        assert_eq!(m.rss_bytes, 4096);
    }
}
