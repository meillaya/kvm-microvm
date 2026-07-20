//! Warm pool-management tests (plan todo 28).
//!
//! The pool is filled to a fixed size by restoring through the orchestrator;
//! there is no autoscaling. Restore failures are counted, never pooled.

use microvm_artifacts::Digest;
use microvm_demo::{
    FunctionPool, HttpFunction, Rootfs, ScriptedRestore, ScriptedRestorer, VmRestorer,
};

fn function() -> HttpFunction {
    let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
    HttpFunction::new("hello-http", rootfs).unwrap()
}

async fn started(
    restores: Vec<Result<ScriptedRestore, String>>,
) -> (ScriptedRestorer, microvm_demo::SnapshotArtifact) {
    let mut r = ScriptedRestorer::ok("s", 1.0, 1.0, restores);
    let snap = r.cold_start(&function()).await.unwrap().snapshot;
    (r, snap)
}

#[tokio::test]
async fn pool_is_filled_to_a_fixed_size_no_autoscaling() {
    let restores: Vec<Result<ScriptedRestore, String>> = (0..5)
        .map(|i| Ok(ScriptedRestore::new(1.0, i as f64 + 1.0)))
        .collect();
    let (mut r, snap) = started(restores).await;
    let pool = FunctionPool::fill(&mut r, &snap, 5).await;
    assert_eq!(pool.len(), 5);
    assert_eq!(pool.warmup_count(), 5);
    assert_eq!(pool.fill_failures(), 0);
}

#[tokio::test]
async fn failed_restores_are_counted_not_pooled() {
    let restores = vec![
        Ok(ScriptedRestore::new(1.0, 1.0)),
        Err("e".to_string()),
        Err("e".to_string()),
        Ok(ScriptedRestore::new(1.0, 2.0)),
    ];
    let (mut r, snap) = started(restores).await;
    let pool = FunctionPool::fill(&mut r, &snap, 4).await;
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.warmup_count(), 2);
    assert_eq!(pool.fill_failures(), 2);
}

#[tokio::test]
async fn acquire_release_reuses_warm_vms() {
    let restores = vec![Ok(ScriptedRestore::new(1.0, 1.0))];
    let (mut r, snap) = started(restores).await;
    let mut pool = FunctionPool::fill(&mut r, &snap, 1).await;
    // Reuse the single warm VM many times (no autoscale on repeated acquire).
    for _ in 0..50 {
        let vm = pool.acquire().unwrap();
        let inv = vm.invoke(&microvm_demo::HttpRequest::invoke());
        assert!(inv.response.is_success());
        pool.release(vm);
    }
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.warmup_count(), 1);
}

#[tokio::test]
async fn drain_cleans_up_every_pooled_vm() {
    let restores: Vec<Result<ScriptedRestore, String>> =
        (0..3).map(|_| Ok(ScriptedRestore::new(1.0, 1.0))).collect();
    let (mut r, snap) = started(restores).await;
    let mut pool = FunctionPool::fill(&mut r, &snap, 3).await;
    assert_eq!(pool.drain(), 3);
    assert!(pool.is_empty());
}
