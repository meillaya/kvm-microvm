//! Guest-readiness probing.
//!
//! A VM is not `Running` merely because the Firecracker process spawned or its
//! API socket accepts connections: the guest itself must signal readiness.
//! This module defines the [`GuestReadinessProbe`] trait the backend awaits
//! after `InstanceStart`, a [`TcpHealthProbe`] for networked guests, a
//! [`SerialMarkerProbe`] for guests that print a marker on the serial console,
//! and an [`AutoReadinessProbe`] that chooses between them.
//!
//! Deterministic tests substitute a scripted probe (see the `testing` module)
//! so readiness can succeed or fail without a live guest.

use async_trait::async_trait;
use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::VmId;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

/// Default readiness timeout when none is configured.
pub const DEFAULT_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Default interval between readiness polls.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Default serial marker emitted by the guest image init script.
pub const DEFAULT_SERIAL_MARKER: &str = "MICROVM_READY";

/// Context passed to a readiness probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessContext {
    /// The VM being probed.
    pub vm_id: VmId,
    /// The guest IP to probe, if the VM has a network attachment.
    pub guest_ip: Option<Ipv4Addr>,
    /// Path to the VM's serial log, when serial readiness is possible.
    pub serial_log: Option<PathBuf>,
    /// Maximum time to wait before declaring the guest not ready.
    pub timeout: Duration,
}

impl ReadinessContext {
    /// Build a readiness context with no serial log.
    pub fn new(vm_id: VmId, guest_ip: Option<Ipv4Addr>, timeout: Duration) -> Self {
        Self {
            vm_id,
            guest_ip,
            serial_log: None,
            timeout,
        }
    }

    /// Attach the serial log path used by [`SerialMarkerProbe`].
    #[must_use]
    pub fn with_serial_log(mut self, path: impl Into<PathBuf>) -> Self {
        self.serial_log = Some(path.into());
        self
    }
}

/// Waits until a VM's guest signals readiness, or fails.
#[async_trait]
pub trait GuestReadinessProbe: Send + Sync {
    /// Block until the guest is ready or the context timeout elapses.
    ///
    /// # Errors
    /// Returns a typed [`MicrovmError`] (context `phase=guest_ready`) if the
    /// guest does not become ready in time or cannot be probed.
    async fn wait_ready(&self, ctx: &ReadinessContext) -> Result<(), MicrovmError>;
}

/// A readiness probe that polls a TCP endpoint inside the guest.
///
/// The probe repeatedly attempts a TCP connection to `<guest_ip>:<port>` until
/// a connection succeeds (ready) or the context timeout elapses (not ready).
/// A VM with no guest IP cannot be probed this way and fails immediately.
#[derive(Clone, Debug)]
pub struct TcpHealthProbe {
    port: u16,
    poll_interval: Duration,
}

impl TcpHealthProbe {
    /// Create a probe targeting `port` with the default poll interval.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Override the poll interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// The port this probe checks.
    pub fn port(&self) -> u16 {
        self.port
    }
}

#[async_trait]
impl GuestReadinessProbe for TcpHealthProbe {
    async fn wait_ready(&self, ctx: &ReadinessContext) -> Result<(), MicrovmError> {
        let guest_ip = ctx.guest_ip.ok_or_else(|| {
            MicrovmError::new(
                ErrorCode::InternalError,
                "guest readiness probe requires a guest IP",
            )
            .with_context("vm_id", ctx.vm_id.as_str())
            .with_context("phase", "guest_ready")
        })?;

        let deadline = tokio::time::Instant::now() + ctx.timeout;
        let addr = std::net::SocketAddr::from((guest_ip, self.port));
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    "guest did not become ready before timeout",
                )
                .with_context("vm_id", ctx.vm_id.as_str())
                .with_context("phase", "guest_ready")
                .with_context("guest_ip", guest_ip.to_string())
                .with_context("port", self.port.to_string())
                .with_context("timeout_ms", ctx.timeout.as_millis().to_string()));
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

/// A readiness probe that waits for a marker in the guest serial log.
///
/// The guest image init script prints [`DEFAULT_SERIAL_MARKER`] after mounting
/// proc and sysfs. This probe is the no-network path: it needs no guest IP and
/// no TAP device.
#[derive(Clone, Debug)]
pub struct SerialMarkerProbe {
    marker: String,
    poll_interval: Duration,
}

impl SerialMarkerProbe {
    /// Create a probe looking for `marker`.
    pub fn new(marker: impl Into<String>) -> Self {
        Self {
            marker: marker.into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Override the poll interval.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// The marker this probe waits for.
    pub fn marker(&self) -> &str {
        &self.marker
    }
}

#[async_trait]
impl GuestReadinessProbe for SerialMarkerProbe {
    async fn wait_ready(&self, ctx: &ReadinessContext) -> Result<(), MicrovmError> {
        let log_path = ctx.serial_log.as_ref().ok_or_else(|| {
            MicrovmError::new(
                ErrorCode::InternalError,
                "serial readiness probe requires a serial log path",
            )
            .with_context("vm_id", ctx.vm_id.as_str())
            .with_context("phase", "guest_ready")
        })?;

        let deadline = tokio::time::Instant::now() + ctx.timeout;
        loop {
            if let Ok(contents) = std::fs::read_to_string(log_path) {
                if contents.contains(&self.marker) {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(MicrovmError::new(
                    ErrorCode::InternalError,
                    "guest serial marker did not appear before timeout",
                )
                .with_context("vm_id", ctx.vm_id.as_str())
                .with_context("phase", "guest_ready")
                .with_context("marker", self.marker.clone())
                .with_context("serial_log", log_path.display().to_string())
                .with_context("timeout_ms", ctx.timeout.as_millis().to_string()));
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

/// A readiness probe that uses TCP when the VM has a guest IP and the serial
/// marker otherwise.
#[derive(Clone, Debug)]
pub struct AutoReadinessProbe {
    tcp: TcpHealthProbe,
    serial: SerialMarkerProbe,
}

impl AutoReadinessProbe {
    /// Build an automatic probe with `port` for the TCP path.
    pub fn new(port: u16, marker: impl Into<String>) -> Self {
        Self {
            tcp: TcpHealthProbe::new(port),
            serial: SerialMarkerProbe::new(marker),
        }
    }
}

#[async_trait]
impl GuestReadinessProbe for AutoReadinessProbe {
    async fn wait_ready(&self, ctx: &ReadinessContext) -> Result<(), MicrovmError> {
        if ctx.guest_ip.is_some() {
            self.tcp.wait_ready(ctx).await
        } else {
            self.serial.wait_ready(ctx).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_context_construction() {
        let ctx = ReadinessContext::new(
            VmId::new("vm-1").unwrap(),
            Some(Ipv4Addr::new(172, 30, 0, 2)),
            Duration::from_secs(5),
        );
        assert_eq!(ctx.guest_ip, Some(Ipv4Addr::new(172, 30, 0, 2)));
        assert_eq!(ctx.timeout, Duration::from_secs(5));
    }

    #[test]
    fn tcp_probe_accessors() {
        let probe = TcpHealthProbe::new(8080).with_poll_interval(Duration::from_millis(10));
        assert_eq!(probe.port(), 8080);
    }

    #[tokio::test]
    async fn tcp_probe_without_guest_ip_fails() {
        let probe = TcpHealthProbe::new(8080);
        let ctx = ReadinessContext::new(VmId::new("vm-1").unwrap(), None, Duration::from_secs(1));
        let err = probe.wait_ready(&ctx).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("phase").map(String::as_str),
            Some("guest_ready")
        );
    }

    #[tokio::test]
    async fn tcp_probe_succeeds_against_listener() {
        // Bind a local listener and point the probe at it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let probe = TcpHealthProbe::new(port).with_poll_interval(Duration::from_millis(5));
        let ctx = ReadinessContext::new(
            VmId::new("vm-1").unwrap(),
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            Duration::from_secs(5),
        );
        assert!(probe.wait_ready(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn tcp_probe_times_out_when_nothing_listens() {
        // Port 1 on loopback is almost certainly closed.
        let probe = TcpHealthProbe::new(1).with_poll_interval(Duration::from_millis(5));
        let ctx = ReadinessContext::new(
            VmId::new("vm-1").unwrap(),
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            Duration::from_millis(50),
        );
        let err = probe.wait_ready(&ctx).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InternalError);
        assert_eq!(
            err.context.get("phase").map(String::as_str),
            Some("guest_ready")
        );
    }
}
