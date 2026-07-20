//! Cleanup composition for supervisor-death reconciliation.
//!
//! When a VM's supervisor dies unexpectedly, the lifecycle service must release
//! the resources the VM owned (process, sockets, nft table, TAP, netns, cgroup
//! leaf, chroot). This module bridges the service to
//! [`microvm_isolation`]'s idempotent [`CleanupManager`], deriving a
//! [`ResourceRecord`] from the platform's naming conventions and tearing the
//! resources down in reverse-creation order.

use microvm_isolation::{
    CleanupBackend, CleanupManager, CleanupOutcome, ResourceRecord, NETNS_PREFIX, NFT_TABLE_PREFIX,
};
use microvm_types::{TenantId, VmId};
use std::path::PathBuf;
use std::sync::Arc;

/// Relative cgroup leaf path for a VM (`microvm/<vm-id>`).
fn cgroup_leaf_path(vm_id: &VmId) -> String {
    format!("microvm/{}", vm_id.as_str())
}

/// Network namespace name for a VM (`microvm-<vm-id>`).
fn netns_name(vm_id: &VmId) -> String {
    format!("{}{}", NETNS_PREFIX, vm_id.as_str())
}

/// Nftables table name for a VM (`microvm_<vm-id>`).
fn nft_table(vm_id: &VmId) -> String {
    format!("{}{}", NFT_TABLE_PREFIX, vm_id.as_str())
}

/// Releases all resources owned by a VM whose supervisor died.
///
/// Implementations must be idempotent and best-effort: a reconciliation cleanup
/// runs against resources that may already be partially torn down, so repeated
/// invocations and missing resources are normal.
pub trait ReconciliationCleanup: Send + Sync {
    /// Clean up all resources owned by `vm_id`, including killing `pid` if a
    /// supervisor PID is known.
    fn cleanup_vm(&self, vm_id: &VmId, tenant: &TenantId, pid: Option<u32>) -> CleanupOutcome;
}

/// [`ReconciliationCleanup`] backed by [`microvm_isolation::CleanupManager`].
///
/// Derives a [`ResourceRecord`] from the platform's deterministic naming
/// conventions and delegates to a [`CleanupManager`] over a pluggable
/// [`CleanupBackend`]. The socket root is needed to locate the VM's API socket.
pub struct IsolationCleanup {
    manager: CleanupManager,
    backend: Arc<dyn CleanupBackend + Send + Sync>,
    socket_root: PathBuf,
}

impl IsolationCleanup {
    /// Create a cleanup bridge.
    pub fn new(
        manager: CleanupManager,
        backend: Arc<dyn CleanupBackend + Send + Sync>,
        socket_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            manager,
            backend,
            socket_root: socket_root.into(),
        }
    }

    /// Derive the resource record for a VM from naming conventions.
    fn record(&self, vm_id: &VmId, tenant: &TenantId, pid: Option<u32>) -> ResourceRecord {
        let socket = self.socket_root.join(vm_id.as_str()).join("api.sock");
        ResourceRecord::new(
            vm_id.clone(),
            tenant.clone(),
            cgroup_leaf_path(vm_id),
            netns_name(vm_id),
            "tap0",
            nft_table(vm_id),
            vec![socket],
            vm_id.as_str(),
            pid,
        )
    }
}

impl ReconciliationCleanup for IsolationCleanup {
    fn cleanup_vm(&self, vm_id: &VmId, tenant: &TenantId, pid: Option<u32>) -> CleanupOutcome {
        let record = self.record(vm_id, tenant, pid);
        self.manager.cleanup(&record, self.backend.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microvm_isolation::RecordingCleanupBackend;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// `RecordingCleanupBackend` uses a `RefCell` and is not `Sync`; wrap it.
    #[derive(Debug, Default)]
    struct SyncRecording(Mutex<RecordingCleanupBackend>);
    impl CleanupBackend for SyncRecording {
        fn kill_process(&self, pid: u32) -> Result<bool, microvm_errors::MicrovmError> {
            self.0.lock().unwrap().kill_process(pid)
        }
        fn flush_nft_table(&self, table: &str) -> Result<bool, microvm_errors::MicrovmError> {
            self.0.lock().unwrap().flush_nft_table(table)
        }
        fn delete_tap(&self, netns: &str, tap: &str) -> Result<bool, microvm_errors::MicrovmError> {
            self.0.lock().unwrap().delete_tap(netns, tap)
        }
        fn remove_netns(&self, netns: &str) -> Result<bool, microvm_errors::MicrovmError> {
            self.0.lock().unwrap().remove_netns(netns)
        }
    }

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).unwrap()
    }

    #[test]
    fn naming_conventions_match_isolation_defaults() {
        let id = vm("vm-1");
        assert_eq!(cgroup_leaf_path(&id), "microvm/vm-1");
        assert_eq!(netns_name(&id), ResourceRecord::default_netns_name(&id));
        assert_eq!(nft_table(&id), "microvm_vm-1");
    }

    #[test]
    fn cleanup_vm_kills_supervisor_pid_and_is_clean() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let socket_root = tmp.path().join("sockets");
        // Provision the cgroup leaf and socket so cleanup has something to do.
        std::fs::create_dir_all(cgroup_root.join("microvm/vm-1")).unwrap();
        std::fs::create_dir_all(socket_root.join("vm-1")).unwrap();
        std::fs::write(socket_root.join("vm-1/api.sock"), b"").unwrap();

        let recorder = Arc::new(SyncRecording(Mutex::new(RecordingCleanupBackend::new())));
        recorder.0.lock().unwrap().alive_pids.insert(1000);
        let manager = CleanupManager::new(&cgroup_root, tmp.path().join("chroot"), &socket_root);
        let cleanup = IsolationCleanup::new(manager, recorder.clone(), &socket_root);

        let outcome = cleanup.cleanup_vm(&vm("vm-1"), &tenant("t1"), Some(1000));
        assert!(outcome.is_clean(), "leaks: {:?}", outcome.leaks);

        let recorded = recorder.0.lock().unwrap().recorded();
        assert!(
            recorded.iter().any(|(op, _)| op == "kill:1000"),
            "expected a kill:1000 operation, got {recorded:?}"
        );
        // The cgroup leaf is removed by the filesystem cleanup step.
        assert!(!cgroup_root.join("microvm/vm-1").exists());
    }

    #[test]
    fn cleanup_vm_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let socket_root = tmp.path().join("sockets");
        let recorder = Arc::new(SyncRecording(Mutex::new(RecordingCleanupBackend::new())));
        let manager = CleanupManager::new(&cgroup_root, tmp.path().join("chroot"), &socket_root);
        let cleanup = IsolationCleanup::new(manager, recorder.clone(), &socket_root);

        // Nothing provisioned: cleanup is still clean (every step is a no-op).
        let first = cleanup.cleanup_vm(&vm("vm-2"), &tenant("t1"), None);
        assert!(first.is_clean());
        let second = cleanup.cleanup_vm(&vm("vm-2"), &tenant("t1"), None);
        assert!(second.is_clean());
    }
}
