#!/usr/bin/env bash
# dev-run.sh: run the `microvmd` daemon against bounded .work scratch, as the
# current user, with no sudo.
#
# Usage:
#   bash scripts/dev-run.sh            # prepare env + config, run microvmd in foreground
#   bash scripts/dev-run.sh --check    # prepare env + config, run microvmd --config ... --check
#
# What it does:
#   1. creates the .work directory tree (config, run, state, artifacts, snapshots,
#      chroot, logs, tmp) and the static busybox/Firecracker cache,
#   2. creates the user-delegated cgroup-v2 wrapper
#        /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/microvm-dev
#      used as [isolation] cgroup_root (CgroupManager creates <wrapper>/microvm),
#   3. writes .work/config/microvmd.toml with every path under .work/,
#   4. runs target/release/microvmd --config .work/config/microvmd.toml.
#
# The EXIT/INT/TERM trap stops the daemon (if still running), removes leftover
# sockets, and removes the cgroup wrapper. Nothing outside the repository is
# written except that delegated wrapper.
#
# Prerequisites:
#   cargo build --release -p microvm-daemon -p microvm-cli
#   bash scripts/build-guest-image.sh
#   (plus /dev/kvm for actually starting VMs and a systemd user session for the
#   cgroup delegation)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK_DIR="$REPO_ROOT/.work"
# shellcheck source=scripts/lib-work.sh
source "$REPO_ROOT/scripts/lib-work.sh"

MICROVMD="$REPO_ROOT/target/release/microvmd"
CONFIG="$WORK_DIR/config/microvmd.toml"
CHECK_MODE=0
DAEMON_PID=""
WRAPPER=""
WRAPPER_CREATED=0
RUN_PREPARED=0

usage() {
  cat <<'EOF'
Usage: bash scripts/dev-run.sh [--check]

  --check   Only validate the generated config: runs
            `microvmd --config .work/config/microvmd.toml --check` and exits.
            Environment setup and cgroup-wrapper cleanup still happen.

Without --check the daemon runs in the foreground; Ctrl-C stops it and cleans up.
EOF
}

while (($#)); do
  case "$1" in
    --check) CHECK_MODE=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    info "stopping microvmd (pid $DAEMON_PID)"
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    local i
    for i in $(seq 1 150); do
      kill -0 "$DAEMON_PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
      warn "microvmd did not exit after SIGTERM; sending SIGKILL"
      kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
  fi
  # Only clean shared host state this run actually created.
  if ((RUN_PREPARED)); then
    clean_run_sockets
  fi
  if ((WRAPPER_CREATED)); then
    remove_cgroup_wrapper
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# --- Preconditions ---------------------------------------------------------
require_exec "$MICROVMD" "microvmd binary (build it with: cargo build --release -p microvm-daemon -p microvm-cli)"
[[ -s "$WORK_DIR/guest/vmlinux" ]] \
  || die "guest kernel missing: $WORK_DIR/guest/vmlinux (run: bash scripts/build-guest-image.sh)"
[[ -s "$WORK_DIR/guest/rootfs.ext4" ]] \
  || die "guest rootfs missing: $WORK_DIR/guest/rootfs.ext4 (run: bash scripts/build-guest-image.sh)"
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  warn "/dev/kvm is not accessible to $(id -un); microvmd will serve the API but VM starts will fail"
fi
# This dev loop owns the .work sockets; refuse to clobber another daemon.
existing_daemon="$(microvmd_pids "$MICROVMD" || true)"
if [[ -n "$existing_daemon" ]]; then
  die "another microvmd appears to be running (pids: $(tr '\n' ' ' <<<"$existing_daemon")); stop it first"
fi

# --- Environment -----------------------------------------------------------
prepare_work_dirs
if ! FC_BIN="$(ensure_firecracker)"; then
  die "Firecracker binary unavailable (set FIRECRACKER_BIN or allow the pinned v1.16.1 download)"
fi
JAILER_BIN="$(jailer_bin_path)"
FC_VERSION_RESOLVED="${FC_VERSION:-$FC_VERSION_DEFAULT}"

info "creating delegated cgroup wrapper: $(cgroup_wrapper_path)"
if ! WRAPPER="$(reset_cgroup_wrapper)"; then
  die "could not create the user cgroup wrapper under $(cgroup_parent_path)"
fi
WRAPPER_CREATED=1

clean_run_sockets
RUN_PREPARED=1
CONFIG_PATH="$(write_microvmd_config "$CONFIG" "$WRAPPER" "$FC_BIN" "$JAILER_BIN" "$FC_VERSION_RESOLVED")"
info "wrote daemon config: $CONFIG_PATH"
info "Firecracker: $FC_BIN"
info "REST socket: $WORK_DIR/run/rest.sock"
info "gRPC socket: $WORK_DIR/run/grpc.sock"
info "logs:        $WORK_DIR/logs"

if [[ "$CHECK_MODE" == 1 ]]; then
  info "validating config: $MICROVMD --config $CONFIG --check"
  if "$MICROVMD" --config "$CONFIG" --check; then
    printf 'PASS: microvmd config validates (--check)\n'
    exit 0
  fi
  fail "microvmd --config $CONFIG --check failed"
  exit 1
fi

info "starting microvmd in the foreground (Ctrl-C stops it and cleans up the cgroup wrapper)"
"$MICROVMD" --config "$CONFIG" &
DAEMON_PID=$!
set +e
wait "$DAEMON_PID"
RC=$?
set -e
DAEMON_PID=""
if ((RC == 0)); then
  info "microvmd exited (status 0)"
else
  fail "microvmd exited with status $RC"
fi
exit "$RC"
