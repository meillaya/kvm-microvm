#!/usr/bin/env bash
# run-privileged-suite.sh: run the surviving privileged tests for the
# kvm-microvm control plane.
#
# Usage (run as the current user; NO sudo required):
#   bash scripts/run-privileged-suite.sh
#
# Tests run:
#   cgroup_v2            real cgroup-v2 cpu/memory/pids limits (microvm-isolation)
#   jailer_invocation    pinned Firecracker/jailer provenance + argv (microvm-isolation)
#   firecracker_boot     real Firecracker boot to guest readiness (microvm-firecracker)
#   snapshot_protocol    snapshot/restore protocol ordering + rebinding
#   lifecycle_cleanup    service lifecycle + full per-resource cleanup
#   security_suite       adversarial security suite (microvm-security-tests)
#
# Tests follow the platform's privileged test model: when the host lacks
# KVM, cgroup delegation, netns access, pinned binaries, or boot artifacts the
# test prints a stable `blocked` token and passes instead of failing. A real
# assertion failure is a FAIL and makes this script exit non-zero.
#
# All host scratch stays under the repository's .work/ directory: the script
# points the tests at .work/bin/{firecracker,jailer} and
# .work/guest/{vmlinux,rootfs.ext4}.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT" || exit 1

# ---------------------------------------------------------------------------
# .work-based environment for the tests (no sudo needed)
# ---------------------------------------------------------------------------
export PATH="$REPO_ROOT/.work/bin:${PATH:-/usr/bin:/bin}"

if [[ -x "$REPO_ROOT/.work/bin/firecracker" ]]; then
  export FC_FIRECRACKER="${FC_FIRECRACKER:-$REPO_ROOT/.work/bin/firecracker}"
elif [[ -x "$REPO_ROOT/.work/firecracker" ]]; then
  export FC_FIRECRACKER="${FC_FIRECRACKER:-$REPO_ROOT/.work/firecracker}"
fi
if [[ -x "$REPO_ROOT/.work/bin/jailer" ]]; then
  export FC_JAILER="${FC_JAILER:-$REPO_ROOT/.work/bin/jailer}"
fi
if [[ -s "$REPO_ROOT/.work/guest/vmlinux" ]]; then
  export FC_KERNEL_PATH="${FC_KERNEL_PATH:-$REPO_ROOT/.work/guest/vmlinux}"
fi
if [[ -s "$REPO_ROOT/.work/guest/rootfs.ext4" ]]; then
  export FC_ROOTFS_PATH="${FC_ROOTFS_PATH:-$REPO_ROOT/.work/guest/rootfs.ext4}"
fi
# The TCP health probe used by the boot/lifecycle tests needs a guest health
# server. Only export the port when the image was built with the real
# microvm-guest-health server; the serial-readiness fallback image has none.
if [[ -f "$REPO_ROOT/.work/guest/health-mode" ]] \
  && grep -qx 'microvm-guest-health' "$REPO_ROOT/.work/guest/health-mode" 2>/dev/null; then
  export FC_GUEST_HEALTH_PORT="${FC_GUEST_HEALTH_PORT:-8080}"
fi

PASS=0
FAIL=0
SKIP=0

run() {
  local name="$1"
  shift
  echo ""
  echo "================================================================"
  echo "  $name"
  echo "================================================================"
  if "$@"; then
    echo "  PASS $name"
    PASS=$((PASS + 1))
  else
    local rc=$?
    if [[ $rc -eq 77 ]]; then
      echo "  SKIP $name (blocked)"
      SKIP=$((SKIP + 1))
    else
      echo "  FAIL $name (exit $rc)"
      FAIL=$((FAIL + 1))
    fi
  fi
}

echo "=== Privileged test suite (current user, no sudo; scratch under .work/) ==="
echo "firecracker: ${FC_FIRECRACKER:-$(command -v firecracker 2>/dev/null || echo 'NOT FOUND')}"
echo "jailer:      ${FC_JAILER:-$(command -v jailer 2>/dev/null || echo 'NOT FOUND')}"
echo "kernel:      ${FC_KERNEL_PATH:-<unset>}"
echo "rootfs:      ${FC_ROOTFS_PATH:-<unset>}"
echo "health port: ${FC_GUEST_HEALTH_PORT:-<unset>}"
echo ""

# --- Cgroup v2 ---
run "cgroup_v2" \
  cargo test -p microvm-isolation --features privileged --test cgroup_v2 -- --nocapture

# --- Jailer + binary provenance ---
run "jailer_invocation" \
  cargo test -p microvm-isolation --features privileged --test jailer_invocation -- --nocapture

# --- Firecracker boot adapter ---
run "firecracker_boot" \
  cargo test -p microvm-firecracker --features privileged --test firecracker_boot -- --nocapture

# --- Snapshot create/load protocol ---
run "snapshot_protocol" \
  cargo test -p microvm-firecracker --features privileged --test snapshot_protocol -- --nocapture

# --- Lifecycle integration + cleanup ---
run "lifecycle_cleanup" \
  cargo test -p microvm-service --features privileged --test lifecycle_cleanup -- --nocapture

# --- Security suite ---
run "security_suite" \
  cargo test -p microvm-security-tests --features privileged -- --nocapture

echo ""
echo "================================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "================================================================"
echo "  Real control-plane e2e gate: bash scripts/e2e-firecracker.sh"
echo "================================================================"
exit "$FAIL"
