//! The warm pool of pre-restored function instances (plan todo 28).
//!
//! A [`FunctionPool`] holds VMs that have already been restored from the
//! post-readiness snapshot, so serving a request skips the cold boot path. The
//! pool is filled by restoring through the orchestrator ([`VmRestorer`]); restore
//! failures are counted, never hidden, and never produce a pooled VM. There is no
//! autoscaling: the pool is filled to a fixed target size and reused.
//!
//! # Determinism
//! The pool is generic over [`VmRestorer`]; tests drive it with the deterministic
//! [`ScriptedRestorer`](crate::restore::ScriptedRestorer), so fill/acquire/release
//! behaviour is fully reproducible.

use crate::restore::{RestoredVm, SnapshotArtifact, VmRestorer};
use std::collections::VecDeque;

/// A warm pool of pre-restored VMs ready to serve requests.
#[derive(Debug, Default)]
pub struct FunctionPool {
    vms: VecDeque<RestoredVm>,
    warmup_count: usize,
    fill_failures: usize,
}

impl FunctionPool {
    /// An empty pool.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Fill a pool by restoring up to `target` VMs from `snapshot` through
    /// `restorer`.
    ///
    /// Each successful restore is pooled ([`FunctionPool::warmup_count`]); each
    /// failed restore is counted in [`FunctionPool::fill_failures`] and produces
    /// no VM. The pool never exceeds `target` VMs and never autoscales.
    pub async fn fill<R: VmRestorer + ?Sized>(
        restorer: &mut R,
        snapshot: &SnapshotArtifact,
        target: usize,
    ) -> Self {
        let mut pool = Self::empty();
        for _ in 0..target {
            match restorer.restore(snapshot).await {
                Ok(vm) => {
                    pool.warmup_count += 1;
                    pool.vms.push_back(vm);
                }
                Err(_) => pool.fill_failures += 1,
            }
        }
        pool
    }

    /// Take a warm VM from the pool, if one is available.
    pub fn acquire(&mut self) -> Option<RestoredVm> {
        self.vms.pop_front()
    }

    /// Return a warm VM to the pool for reuse.
    pub fn release(&mut self, vm: RestoredVm) {
        self.vms.push_back(vm);
    }

    /// The number of VMs currently in the pool.
    pub fn len(&self) -> usize {
        self.vms.len()
    }

    /// True when the pool holds no VMs.
    pub fn is_empty(&self) -> bool {
        self.vms.is_empty()
    }

    /// The number of VMs successfully pre-restored (warmed) into the pool.
    pub fn warmup_count(&self) -> usize {
        self.warmup_count
    }

    /// The number of restore attempts that failed during [`FunctionPool::fill`].
    pub fn fill_failures(&self) -> usize {
        self.fill_failures
    }

    /// Drain and drop every pooled VM (cleanup), returning how many were
    /// released.
    pub fn drain(&mut self) -> usize {
        self.vms.drain(..).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::{HttpFunction, Rootfs};
    use crate::restore::{ScriptedRestore, ScriptedRestorer};
    use microvm_artifacts::Digest;

    fn function() -> HttpFunction {
        let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
        HttpFunction::new("hello-http", rootfs).unwrap()
    }

    /// Build a restorer that has already cold-started (so it holds the function
    /// and a snapshot) and still has `restores` queued for the warm fill.
    async fn started_restorer(
        restores: Vec<Result<ScriptedRestore, String>>,
    ) -> (ScriptedRestorer, SnapshotArtifact) {
        let mut r = ScriptedRestorer::ok("s", 1.0, 1.0, restores);
        let snap = r.cold_start(&function()).await.unwrap().snapshot;
        (r, snap)
    }

    #[tokio::test]
    async fn fill_pools_successful_restores() {
        let restores = vec![
            Ok(ScriptedRestore::new(1.0, 0.5)),
            Ok(ScriptedRestore::new(1.0, 0.6)),
            Ok(ScriptedRestore::new(1.0, 0.7)),
        ];
        let (mut r, snap) = started_restorer(restores).await;
        let pool = FunctionPool::fill(&mut r, &snap, 3).await;
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.warmup_count(), 3);
        assert_eq!(pool.fill_failures(), 0);
    }

    #[tokio::test]
    async fn fill_counts_failures_without_pooling_them() {
        let restores = vec![
            Ok(ScriptedRestore::new(1.0, 0.5)),
            Err("boom".to_string()),
            Ok(ScriptedRestore::new(1.0, 0.7)),
            Err("boom".to_string()),
        ];
        let (mut r, snap) = started_restorer(restores).await;
        let pool = FunctionPool::fill(&mut r, &snap, 4).await;
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.warmup_count(), 2);
        assert_eq!(pool.fill_failures(), 2);
    }

    #[tokio::test]
    async fn acquire_release_cycles_vms() {
        let restores = vec![
            Ok(ScriptedRestore::new(1.0, 0.5)),
            Ok(ScriptedRestore::new(1.0, 0.6)),
        ];
        let (mut r, snap) = started_restorer(restores).await;
        let mut pool = FunctionPool::fill(&mut r, &snap, 2).await;
        let vm = pool.acquire().unwrap();
        assert_eq!(pool.len(), 1);
        pool.release(vm);
        assert_eq!(pool.len(), 2);
    }

    #[tokio::test]
    async fn acquire_on_empty_pool_is_none() {
        let mut pool = FunctionPool::empty();
        assert!(pool.is_empty());
        assert!(pool.acquire().is_none());
    }

    #[tokio::test]
    async fn drain_releases_every_vm_for_cleanup() {
        let restores = vec![
            Ok(ScriptedRestore::new(1.0, 0.5)),
            Ok(ScriptedRestore::new(1.0, 0.6)),
        ];
        let (mut r, snap) = started_restorer(restores).await;
        let mut pool = FunctionPool::fill(&mut r, &snap, 2).await;
        assert_eq!(pool.drain(), 2);
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn fill_with_zero_target_is_empty() {
        let (mut r, snap) = started_restorer(vec![]).await;
        let pool = FunctionPool::fill(&mut r, &snap, 0).await;
        assert!(pool.is_empty());
        assert_eq!(pool.warmup_count(), 0);
    }
}
