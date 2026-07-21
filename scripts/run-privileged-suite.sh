#!/usr/bin/env bash
# run-privileged-suite.sh — run all privileged tests for the kvm-microvm-orchestrator.
#
# Usage:
#   devenv shell
#   sudo -E bash scripts/run-privileged-suite.sh
#
# Requires: devenv shell (for firecracker/jailer on PATH), sudo (for cgroup/netns/jailer).
# The direct-KVM test does not need sudo (/dev/kvm is mode 0666).

set -uo pipefail

export PATH="$HOME/.local/bin:$PATH"
PASS=0
FAIL=0
SKIP=0

run() {
  local name="$1"; shift
  echo ""
  echo "================================================================"
  echo "  $name"
  echo "================================================================"
  if "$@"; then
    echo "  ✓ $name PASSED"
    PASS=$((PASS+1))
  else
    local rc=$?
    if [ $rc -eq 77 ]; then
      echo "  ⊘ $name SKIPPED (blocked)"
      SKIP=$((SKIP+1))
    else
      echo "  ✗ $name FAILED (exit $rc)"
      FAIL=$((FAIL+1))
    fi
  fi
}

echo "=== Privileged test suite ==="
echo "firecracker: $(which firecracker 2>/dev/null || echo 'NOT FOUND')"
echo "jailer:      $(which jailer 2>/dev/null || echo 'NOT FOUND')"
echo ""

# --- Cgroup v2 (todo 10) ---
run "cgroup_v2" \
  cargo test -p microvm-isolation --features privileged --test cgroup_v2 -- --nocapture

# --- Jailer + binary provenance (todo 12) ---
run "jailer_invocation" \
  cargo test -p microvm-isolation --features privileged --test jailer_invocation -- --nocapture

# --- Firecracker boot adapter (todo 14) ---
run "firecracker_boot" \
  cargo test -p microvm-firecracker --features privileged --test firecracker_boot -- --nocapture

# --- Snapshot create/load (todo 22) ---
run "snapshot_protocol" \
  cargo test -p microvm-firecracker --features privileged --test snapshot_protocol -- --nocapture

# --- Lifecycle integration (todo 19) ---
run "lifecycle_cleanup" \
  cargo test -p microvm-service --features privileged --test lifecycle_cleanup -- --nocapture

# --- Security adversarial (todo 31) ---
run "security_adversarial" \
  cargo test -p microvm-security-tests --features privileged -- --nocapture

# --- Direct-KVM boot (todo 30) — no sudo needed ---
run "directkvm_boot" \
  cargo test -p microvm-backend-directkvm --features direct-kvm,privileged --test privileged_boot -- --nocapture

echo ""
echo "================================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "================================================================"

# --- Docker comparison (todo 27) — needs Docker daemon ---
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  echo ""
  echo "================================================================"
  echo "  docker_benchmark (Docker daemon detected)"
  echo "================================================================"
  run "docker_benchmark" \
    cargo run -p microvm-bench -- snapshot-restore --samples 100 \
      --out .omo/evidence/kvm-microvm-orchestrator/task-27-benchmark.json
else
  echo ""
  echo "  ⊘ docker_benchmark SKIPPED (Docker daemon not running)"
  SKIP=$((SKIP+1))
fi

# --- Re-aggregate evidence ---
echo ""
echo "================================================================"
echo "  Re-aggregating evidence"
echo "================================================================"
bash scripts/aggregate-evidence.sh --allow-incomplete
echo ""
echo "=== Done: $PASS passed, $FAIL failed, $SKIP skipped ==="
exit $FAIL
