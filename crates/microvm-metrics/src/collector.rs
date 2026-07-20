//! The [`MetricsCollector`]: reads cgroup/TAP/guest sources for registered VMs
//! and produces [`VmMetricsRecord`]s (plan todo 23).
//!
//! # Lifecycle
//! A VM is added with [`MetricsCollector::register_vm`] and removed with
//! [`MetricsCollector::stop_sampling`]. **Sampling stops after VM cleanup**:
//! once a VM is removed, [`MetricsCollector::sample`] returns
//! [`ErrorCode::ArtifactNotFound`] and performs no filesystem or agent reads.
//!
//! # Determinism
//! All time comes from an injectable [`Clock`] and all sources are read from
//! configurable roots (cgroup leaf dir, sysfs root) plus an injectable
//! [`GuestAgentReader`]. Tests drive the collector against a `tempfile`
//! directory and a fixed clock, so results are fully reproducible and require
//! no privileged host capabilities.
//!
//! # Failure handling
//! A missing/unreadable/unparseable source never panics and never zero-fills:
//! the corresponding slot is marked [`Availability::Unavailable`] with a
//! bounded reason and a bounded [`MetricErrorKind`] counter is incremented.

use crate::availability::{Availability, UnavailableReason};
use crate::cgroup::read_cgroup_metrics;
use crate::guest::{GuestAgentReader, GuestMetrics, NoGuestAgent};
use crate::network::{bytes_per_sec, read_tap_counters, NetworkMetrics};
use crate::record::{MetricErrorKind, MetricsPhase, PhaseMarkers, VmMetricsRecord, SCHEMA_VERSION};
use chrono::{DateTime, Utc};
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::VmId;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// A source of wall-clock and host-monotonic timestamps.
///
/// Injected so tests are deterministic. The production implementation is
/// [`SystemClock`].
pub trait Clock: Send + Sync {
    /// Current wall-clock time (UTC).
    fn now_wall(&self) -> DateTime<Utc>;
    /// Current host-monotonic time in nanoseconds.
    fn now_monotonic_ns(&self) -> u64;
}

/// Production clock: `SystemTime` for wall clock, `Instant` for monotonic.
#[derive(Debug)]
pub struct SystemClock {
    epoch: Instant,
}

impl SystemClock {
    /// Create a clock whose monotonic epoch is "now".
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_wall(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn now_monotonic_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }
}

/// A deterministic clock with manually advanced wall and monotonic values.
///
/// Uses interior mutability so a single clock can be shared (via [`Arc`])
/// between the collector and a test that advances time.
#[derive(Debug)]
pub struct ManualClock {
    wall: Mutex<DateTime<Utc>>,
    monotonic_ns: AtomicU64,
}

impl ManualClock {
    /// Create a clock starting at the given wall time and monotonic `0`.
    pub fn new(wall: DateTime<Utc>) -> Self {
        Self {
            wall: Mutex::new(wall),
            monotonic_ns: AtomicU64::new(0),
        }
    }

    /// Advance the monotonic clock by `ns` and the wall clock by the same
    /// amount, returning the new monotonic reading.
    pub fn advance(&self, ns: u64) -> u64 {
        let new = self.monotonic_ns.fetch_add(ns, Ordering::SeqCst) + ns;
        *self.wall.lock().unwrap() += chrono::Duration::nanoseconds(ns as i64);
        new
    }

    /// Set the monotonic clock to an absolute value.
    pub fn set_monotonic_ns(&self, ns: u64) {
        self.monotonic_ns.store(ns, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_wall(&self) -> DateTime<Utc> {
        *self.wall.lock().unwrap()
    }

    fn now_monotonic_ns(&self) -> u64 {
        self.monotonic_ns.load(Ordering::SeqCst)
    }
}

impl<T: Clock> Clock for Arc<T> {
    fn now_wall(&self) -> DateTime<Utc> {
        (**self).now_wall()
    }

    fn now_monotonic_ns(&self) -> u64 {
        (**self).now_monotonic_ns()
    }
}

/// Per-VM sampling state tracked by the collector.
#[derive(Debug)]
struct VmTarget {
    phase: MetricsPhase,
    markers: PhaseMarkers,
    /// cgroup leaf directory (absolute). `None` => cgroup `NoBackend`.
    cgroup_dir: Option<PathBuf>,
    /// TAP interface name. `None` => network `NoBackend`.
    tap_name: Option<String>,
    /// Previous network sample `(rx_bytes, tx_bytes, monotonic_ns)` for rates.
    prev_net: Option<(u64, u64, u64)>,
    /// Cumulative bounded error counters.
    errors: BTreeMap<MetricErrorKind, u64>,
}

/// Reads per-VM host and guest metrics on demand.
///
/// Cheap to clone-free: interior state is behind a `Mutex`; sampling is
/// synchronous file I/O and is expected to be brief.
pub struct MetricsCollector {
    cgroup_root: PathBuf,
    sysfs_root: PathBuf,
    guest: Box<dyn GuestAgentReader>,
    clock: Box<dyn Clock>,
    vms: Mutex<HashMap<VmId, VmTarget>>,
}

impl std::fmt::Debug for MetricsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsCollector")
            .field("cgroup_root", &self.cgroup_root)
            .field("sysfs_root", &self.sysfs_root)
            .finish_non_exhaustive()
    }
}

impl MetricsCollector {
    /// Create a collector with explicit roots, guest reader, and clock.
    pub fn new(
        cgroup_root: impl Into<PathBuf>,
        sysfs_root: impl Into<PathBuf>,
        guest: Box<dyn GuestAgentReader>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            sysfs_root: sysfs_root.into(),
            guest,
            clock,
            vms: Mutex::new(HashMap::new()),
        }
    }

    /// Create a host-only collector with no guest agent and the system clock.
    pub fn host_only(cgroup_root: impl Into<PathBuf>, sysfs_root: impl Into<PathBuf>) -> Self {
        Self::new(
            cgroup_root,
            sysfs_root,
            Box::new(NoGuestAgent),
            Box::new(SystemClock::new()),
        )
    }

    /// Begin sampling a VM.
    ///
    /// `cgroup_rel` is the VM's cgroup leaf path relative to the cgroup root
    /// (`None` if the backend exposes no cgroup); `tap_name` is the TAP device
    /// name (`None` if the VM has no network). Re-registering replaces prior
    /// state (including error counters and the previous network sample).
    pub fn register_vm(
        &self,
        vm_id: VmId,
        phase: MetricsPhase,
        cgroup_rel: Option<PathBuf>,
        tap_name: Option<String>,
    ) {
        let cgroup_dir = cgroup_rel.map(|rel| self.cgroup_root.join(rel));
        let mut vms = self.vms.lock().unwrap();
        vms.insert(
            vm_id,
            VmTarget {
                phase,
                markers: PhaseMarkers::default(),
                cgroup_dir,
                tap_name,
                prev_net: None,
                errors: BTreeMap::new(),
            },
        );
    }

    /// Stop sampling a VM and forget its state (called on VM cleanup).
    ///
    /// After this, [`sample`](Self::sample) returns
    /// [`ErrorCode::ArtifactNotFound`] and reads nothing.
    pub fn stop_sampling(&self, vm_id: &VmId) {
        self.vms.lock().unwrap().remove(vm_id);
    }

    /// True iff the VM is currently being sampled.
    pub fn is_sampling(&self, vm_id: &VmId) -> bool {
        self.vms.lock().unwrap().contains_key(vm_id)
    }

    /// Number of VMs currently being sampled.
    pub fn sampling_count(&self) -> usize {
        self.vms.lock().unwrap().len()
    }

    /// Advance a VM's monotonic phase (boot/restore only move forward).
    pub fn set_phase(&self, vm_id: &VmId, phase: MetricsPhase) {
        if let Some(t) = self.vms.lock().unwrap().get_mut(vm_id) {
            t.phase = phase;
        }
    }

    /// Record a monotonic phase marker for a VM (e.g. spawn, service-ready).
    pub fn record_marker(&self, vm_id: &VmId, marker: PhaseMarker, monotonic_ns: u64) {
        if let Some(t) = self.vms.lock().unwrap().get_mut(vm_id) {
            marker.set(&mut t.markers, monotonic_ns);
        }
    }

    /// Collect a fresh [`VmMetricsRecord`] for a VM.
    ///
    /// Returns [`ErrorCode::ArtifactNotFound`] if the VM is not registered
    /// (including after cleanup — sampling has stopped). Source failures are
    /// recorded as availability flags plus bounded error counters, never as
    /// panics or zero-fills.
    pub fn sample(&self, vm_id: &VmId) -> Result<VmMetricsRecord, MicrovmError> {
        let monotonic_ns = self.clock.now_monotonic_ns();
        let collected_at = self.clock.now_wall();

        let mut vms = self.vms.lock().unwrap();
        let target = vms.get_mut(vm_id).ok_or_else(|| {
            MicrovmError::new(
                ErrorCode::ArtifactNotFound,
                "vm is not being sampled (not registered or cleaned up)",
            )
            .with_context("vm_id", vm_id.as_str())
        })?;

        // -- cgroup ---------------------------------------------------------
        let cgroup = match &target.cgroup_dir {
            None => Availability::Unavailable(UnavailableReason::NoBackend),
            Some(dir) => match read_cgroup_metrics(dir, monotonic_ns) {
                Ok(m) => Availability::Available(m),
                Err(reason) => {
                    bump(&mut target.errors, error_kind_for(reason));
                    Availability::Unavailable(reason)
                }
            },
        };

        // -- network --------------------------------------------------------
        let network = match &target.tap_name {
            None => Availability::Unavailable(UnavailableReason::NoBackend),
            Some(tap) => match read_tap_counters(&self.sysfs_root, tap) {
                Ok((rx, tx)) => {
                    let (rx_rate, tx_rate) = match target.prev_net {
                        Some((prx, ptx, pns)) => (
                            bytes_per_sec(prx, rx, pns, monotonic_ns),
                            bytes_per_sec(ptx, tx, pns, monotonic_ns),
                        ),
                        None => (None, None),
                    };
                    target.prev_net = Some((rx, tx, monotonic_ns));
                    Availability::Available(NetworkMetrics {
                        sampled_monotonic_ns: monotonic_ns,
                        rx_bytes: rx,
                        tx_bytes: tx,
                        rx_bytes_per_sec: rx_rate,
                        tx_bytes_per_sec: tx_rate,
                    })
                }
                Err(reason) => {
                    bump(&mut target.errors, error_kind_for(reason));
                    Availability::Unavailable(reason)
                }
            },
        };

        // -- guest ----------------------------------------------------------
        let guest = match self.guest.read(vm_id) {
            Ok(sample) => Availability::Available(GuestMetrics::from_sample(sample, monotonic_ns)),
            Err(reason) => {
                bump(&mut target.errors, error_kind_for(reason));
                Availability::Unavailable(reason)
            }
        };

        let record = VmMetricsRecord {
            vm_id: vm_id.clone(),
            schema_version: SCHEMA_VERSION,
            phase: target.phase,
            collected_at,
            monotonic_ns,
            phases: target.markers,
            cgroup,
            network,
            guest,
            errors: target.errors.clone(),
        };
        Ok(record)
    }
}

/// Increment a bounded error counter.
fn bump(errors: &mut BTreeMap<MetricErrorKind, u64>, kind: MetricErrorKind) {
    *errors.entry(kind).or_insert(0) += 1;
}

/// Map an unavailability reason to the bounded error counter it increments.
fn error_kind_for(reason: UnavailableReason) -> MetricErrorKind {
    match reason {
        UnavailableReason::ParseError => MetricErrorKind::Parse,
        UnavailableReason::AgentUnreachable | UnavailableReason::NoBackend => {
            MetricErrorKind::GuestRead
        }
        _ => MetricErrorKind::CgroupRead,
    }
}

/// A selectable monotonic phase marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseMarker {
    /// VMM process spawned.
    Spawn,
    /// API socket ready.
    SocketReady,
    /// Boot configuration applied.
    Configured,
    /// Guest service-ready (boot complete).
    ServiceReady,
    /// Snapshot load issued (restore start).
    SnapshotLoad,
    /// Restore ready (restore complete).
    RestoreReady,
}

impl PhaseMarker {
    fn set(self, markers: &mut PhaseMarkers, ns: u64) {
        let slot = match self {
            Self::Spawn => &mut markers.spawn_ns,
            Self::SocketReady => &mut markers.socket_ready_ns,
            Self::Configured => &mut markers.configured_ns,
            Self::ServiceReady => &mut markers.service_ready_ns,
            Self::SnapshotLoad => &mut markers.snapshot_load_ns,
            Self::RestoreReady => &mut markers.restore_ready_ns,
        };
        *slot = Some(ns);
    }
}

/// A convenience for tests: write a set of cgroup-v2 files into `dir`.
#[doc(hidden)]
pub fn write_cgroup_fixture(dir: &Path, cpu_stat: &str, memory_current: u64, pids_current: u64) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("cpu.stat"), cpu_stat).unwrap();
    std::fs::write(dir.join("memory.current"), memory_current.to_string()).unwrap();
    std::fs::write(dir.join("pids.current"), pids_current.to_string()).unwrap();
}

/// A convenience for tests: write TAP RX/TX counters into a fake sysfs tree.
#[doc(hidden)]
pub fn write_tap_fixture(sysfs_root: &Path, tap_name: &str, rx_bytes: u64, tx_bytes: u64) {
    let stats = sysfs_root
        .join("class/net")
        .join(tap_name)
        .join("statistics");
    std::fs::create_dir_all(&stats).unwrap();
    std::fs::write(stats.join("rx_bytes"), rx_bytes.to_string()).unwrap();
    std::fs::write(stats.join("tx_bytes"), tx_bytes.to_string()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::GuestAgentSample;
    use crate::guest::StaticGuestAgent;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn clock() -> ManualClock {
        ManualClock::new(Utc.with_ymd_and_hms(2026, 7, 20, 12, 0, 0).unwrap())
    }

    fn vm() -> VmId {
        VmId::new("vm-1").unwrap()
    }

    #[test]
    fn sample_unknown_vm_is_not_found() {
        let tmp = TempDir::new().unwrap();
        let c = MetricsCollector::new(
            tmp.path().join("cgroup"),
            tmp.path().join("sysfs"),
            Box::new(NoGuestAgent),
            Box::new(clock()),
        );
        let err = c.sample(&vm()).unwrap_err();
        assert_eq!(err.code, ErrorCode::ArtifactNotFound);
    }

    #[test]
    fn cleanup_stops_sampling() {
        let tmp = TempDir::new().unwrap();
        let c = MetricsCollector::new(
            tmp.path().to_path_buf(),
            tmp.path().to_path_buf(),
            Box::new(NoGuestAgent),
            Box::new(clock()),
        );
        c.register_vm(vm(), MetricsPhase::Booting, None, None);
        assert!(c.is_sampling(&vm()));
        assert!(c.sample(&vm()).is_ok());

        c.stop_sampling(&vm());
        assert!(!c.is_sampling(&vm()));
        assert_eq!(c.sampling_count(), 0);
        // After cleanup, sampling has stopped: not-found, no reads.
        assert_eq!(
            c.sample(&vm()).unwrap_err().code,
            ErrorCode::ArtifactNotFound
        );
    }

    #[test]
    fn collects_cgroup_network_and_guest() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let sysfs_root = tmp.path().join("sysfs");
        write_cgroup_fixture(
            &cgroup_root.join("microvm/vm-1"),
            "usage_usec 1000\nnr_throttled 2\nthrottled_usec 50\n",
            1 << 20,
            3,
        );
        write_tap_fixture(&sysfs_root, "tap0", 1000, 2000);

        let clk = Arc::new(clock());
        let c = MetricsCollector::new(
            cgroup_root,
            sysfs_root,
            Box::new(StaticGuestAgent::returning(GuestAgentSample {
                cpu_steal_pct: 3.5,
                load1: 0.5,
                rss_bytes: 1 << 19,
            })),
            Box::new(clk.clone()),
        );
        c.register_vm(
            vm(),
            MetricsPhase::Running,
            Some(PathBuf::from("microvm/vm-1")),
            Some("tap0".to_string()),
        );

        let r = c.sample(&vm()).unwrap();
        assert_eq!(r.memory_current_bytes(), Some(1 << 20));
        assert_eq!(r.cpu_usage_usec(), Some(1000));
        assert_eq!(r.cpu_throttled_usec(), Some(50));
        assert_eq!(r.guest_cpu_steal_pct(), Some(3.5));
        // First network sample: counters present, rate not yet derivable.
        let net = r.network.value().unwrap();
        assert_eq!(net.rx_bytes, 1000);
        assert_eq!(net.rx_bytes_per_sec, None);
        assert!(r.errors.is_empty());

        // Advance 1s and bump counters => rate derivable.
        clk.advance(1_000_000_000);
        write_tap_fixture(tmp.path().join("sysfs").as_ref(), "tap0", 3000, 5000);
        let r2 = c.sample(&vm()).unwrap();
        assert_eq!(r2.rx_bytes_per_sec(), Some(2000));
        assert_eq!(r2.tx_bytes_per_sec(), Some(3000));
    }

    #[test]
    fn missing_sources_are_unavailable_with_bounded_errors_not_zero_or_panic() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let sysfs_root = tmp.path().join("sysfs");
        // Register with a cgroup dir and tap that do not exist, and a failing
        // guest agent.
        let c = MetricsCollector::new(
            cgroup_root,
            sysfs_root,
            Box::new(StaticGuestAgent::failing(
                UnavailableReason::AgentUnreachable,
            )),
            Box::new(clock()),
        );
        c.register_vm(
            vm(),
            MetricsPhase::Running,
            Some(PathBuf::from("microvm/gone")),
            Some("tap-gone".to_string()),
        );

        let r = c.sample(&vm()).unwrap();
        assert_eq!(r.cgroup.reason(), Some(UnavailableReason::SourceMissing));
        assert_eq!(r.network.reason(), Some(UnavailableReason::SourceMissing));
        assert_eq!(r.guest.reason(), Some(UnavailableReason::AgentUnreachable));
        // Bounded error counters incremented; no zero-fill.
        assert!(r.error_count(MetricErrorKind::CgroupRead) >= 1);
        assert!(r.error_count(MetricErrorKind::GuestRead) >= 1);
        assert_eq!(r.memory_current_bytes(), None);
        assert_eq!(r.guest_cpu_steal_pct(), None);
    }
}
