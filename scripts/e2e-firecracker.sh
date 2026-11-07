#!/usr/bin/env bash
# e2e-firecracker.sh: real /dev/kvm end-to-end acceptance gate for the
# microvm Firecracker control plane.
#
# Run from the repository root:
#   bash scripts/e2e-firecracker.sh
#
# Prerequisites (checked up front, each failure is a clear FAIL):
#   - /dev/kvm readable + writable by the current user
#   - target/release/microvmd and target/release/microvm
#     (cargo build --release -p microvm-daemon -p microvm-cli)
#   - .work/guest/vmlinux + .work/guest/rootfs.ext4
#     (bash scripts/build-guest-image.sh)
#   - a Firecracker binary: FIRECRACKER_BIN, .work/bin/firecracker,
#     .work/firecracker, or the pinned v1.16.1 release downloaded on demand
#   - a systemd user cgroup-v2 delegation (normal desktop user session), no sudo
#
# What it does (all scratch under .work/):
#   1. refuses to run if another microvmd is alive; prepares fresh state dirs,
#      config (.work/config/microvmd-e2e.toml) and delegated cgroup wrapper,
#   2. starts microvmd in the background and waits for the REST socket,
#   3. create -> start -> status running -> MICROVM_READY in the serial log ->
#      metrics cgroup.available=true -> snapshot -> stop -> restore ->
#      status running -> list -> stop/delete,
#   4. SIGTERMs the daemon and asserts it exits 0, removed its sockets, left no
#      Firecracker process and no cgroup leaf, then removes the whole wrapper.
#
# Every step prints a PASS line; the first failure prints FAIL plus the relevant
# daemon/serial log tail and exits non-zero. A pass is only printed for checks
# that actually succeeded -- the script never fakes a pass.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK_DIR="$REPO_ROOT/.work"
# shellcheck source=scripts/lib-work.sh
source "$REPO_ROOT/scripts/lib-work.sh"

MICROVMD="$REPO_ROOT/target/release/microvmd"
MICROVM="$REPO_ROOT/target/release/microvm"
CONFIG="$WORK_DIR/config/microvmd-e2e.toml"
REST_SOCK="$WORK_DIR/run/rest.sock"
GRPC_SOCK="$WORK_DIR/run/grpc.sock"
DAEMON_LOG="$WORK_DIR/logs/microvmd-e2e.log"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-30}"
READINESS_TIMEOUT="${READINESS_TIMEOUT:-60}"
SERIAL_TIMEOUT="${SERIAL_TIMEOUT:-30}"
SHUTDOWN_TIMEOUT="${SHUTDOWN_TIMEOUT:-30}"

DAEMON_PID=""
WRAPPER=""
WRAPPER_CREATED=0
DAEMON_STARTED=0
FC_BIN=""
JAILER_BIN=""
VM_ID=""
SNAPSHOT_ID=""
RESTORED_VM_ID=""
CLI_OUT=""
CLI_ERR=""
MATCHED_LINE=""
SERIAL_LOG=""

# ---------------------------------------------------------------------------
# Output / failure helpers
# ---------------------------------------------------------------------------

dump_logs() {
  local f
  if [[ -f "$DAEMON_LOG" ]]; then
    printf '\n--- %s (last 40 lines) ---\n' "$DAEMON_LOG" >&2
    tail -n 40 -- "$DAEMON_LOG" >&2 2>/dev/null || true
  fi
  if [[ -d "$WORK_DIR/logs" ]]; then
    for f in "$WORK_DIR/logs"/*; do
      [[ -f "$f" && "$f" != "$DAEMON_LOG" ]] || continue
      printf '\n--- %s (last 20 lines) ---\n' "$f" >&2
      tail -n 20 -- "$f" >&2 2>/dev/null || true
    done
  fi
}

# fail_now prints a FAIL line, dumps logs, and exits non-zero so the EXIT trap
# performs cleanup. It is the only way this script reports a failed assertion.
fail_now() {
  fail "$*"
  dump_logs
  exit 1
}

# Run one microvm CLI command, capturing stdout in CLI_OUT and stderr in
# CLI_ERR. Returns the CLI exit status.
cli() {
  local name="$1"
  shift
  local errfile="$WORK_DIR/tmp/cli.err"
  mkdir -p "$WORK_DIR/tmp"
  CLI_OUT="$("$MICROVM" --socket "$REST_SOCK" "$@" 2>"$errfile")"
  local rc=$?
  CLI_ERR="$(cat "$errfile" 2>/dev/null || true)"
  if ((rc != 0)); then
    printf 'FAIL: %s: microvm exit %d\n' "$name" "$rc" >&2
    [[ -n "$CLI_OUT" ]] && printf 'stdout: %s\n' "$CLI_OUT" >&2
    [[ -n "$CLI_ERR" ]] && printf 'stderr: %s\n' "$CLI_ERR" >&2
  fi
  return "$rc"
}

# Assert that a CLI command succeeds and its output matches an ERE pattern.
# The first matching stdout line is left in MATCHED_LINE.
expect_line() {
  local name="$1" pattern="$2"
  shift 2
  if ! cli "$name" "$@"; then
    fail_now "$name command failed"
  fi
  MATCHED_LINE="$(grep -E -- "$pattern" <<<"$CLI_OUT" | head -n 1 || true)"
  if [[ -z "$MATCHED_LINE" ]]; then
    printf 'stdout: %s\nstderr: %s\n' "${CLI_OUT:-<empty>}" "${CLI_ERR:-<empty>}" >&2
    fail_now "$name output did not match /$pattern/"
  fi
  pass "$name: $MATCHED_LINE"
}

last_token() {
  awk '{print $NF}' <<<"$1"
}

# ---------------------------------------------------------------------------
# Process / cgroup helpers
# ---------------------------------------------------------------------------

# PIDs belonging to this project: either inside the delegated wrapper cgroup or
# a firecracker process whose command line references this repo's .work dir.
project_firecracker_pids() {
  local pid cmd cg wrapper
  wrapper="$(cgroup_wrapper_path)"
  for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"
    [[ -r "$pid_dir/cmdline" ]] || continue
    # The group redirect suppresses the race where the PID disappears between
    # the readdir snapshot and this read.
    cmd="$({ tr '\0' ' ' <"$pid_dir/cmdline"; } 2>/dev/null || true)"
    if [[ -n "$cmd" && "$cmd" == *firecracker* && "$cmd" == *"$WORK_DIR"* ]]; then
      printf '%s\n' "$pid"
      continue
    fi
    cg="$(cat "$pid_dir/cgroup" 2>/dev/null || true)"
    if [[ -n "$cg" && -n "$wrapper" && "$cg" == *"$wrapper"* ]]; then
      printf '%s\n' "$pid"
    fi
  done
}

# Returns 0 when no Firecracker process from this project remains; prints the
# offending PIDs on stderr and returns 1 otherwise.
assert_no_firecracker_processes() {
  local pids
  pids="$(project_firecracker_pids | sort -u || true)"
  if [[ -n "$pids" ]]; then
    printf 'remaining firecracker/project processes:\n' >&2
    for pid in $pids; do
      printf '  pid %s: %s\n' "$pid" "$({ tr '\0' ' ' <"/proc/$pid/cmdline"; } 2>/dev/null || true)" >&2
    done
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Daemon lifecycle
# ---------------------------------------------------------------------------

stop_daemon() {
  local i rc
  [[ -n "$DAEMON_PID" ]] || return 0
  info "sending SIGTERM to microvmd (pid $DAEMON_PID)"
  kill -TERM "$DAEMON_PID" 2>/dev/null || true
  for i in $(seq 1 $((SHUTDOWN_TIMEOUT * 10))); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      wait "$DAEMON_PID" 2>/dev/null
      rc=$?
      DAEMON_PID=""
      return "$rc"
    fi
    sleep 0.1
  done
  return 1
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    info "stopping microvmd (pid $DAEMON_PID)"
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    local i
    for i in $(seq 1 $((SHUTDOWN_TIMEOUT * 10))); do
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
  # Only touch shared host state this run actually created/started: an early
  # precondition abort must never remove another process's sockets or wrapper.
  if ((DAEMON_STARTED)); then
    local pid
    while IFS= read -r pid; do
      [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done < <(project_firecracker_pids 2>/dev/null || true)
    clean_run_sockets
  fi
  if ((WRAPPER_CREATED)); then
    remove_cgroup_wrapper
  fi
  if ((rc != 0)); then
    printf 'FAIL: e2e-firecracker (aborted; see %s)\n' "$DAEMON_LOG" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Preconditions / setup
# ---------------------------------------------------------------------------

check_preconditions() {
  if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    fail_now "/dev/kvm must be readable and writable by $(id -un); a real KVM host is required"
  fi
  if [[ ! -x "$MICROVMD" ]]; then
    fail_now "missing $MICROVMD (build with: cargo build --release -p microvm-daemon -p microvm-cli)"
  fi
  if [[ ! -x "$MICROVM" ]]; then
    fail_now "missing $MICROVM (build with: cargo build --release -p microvm-daemon -p microvm-cli)"
  fi
  if [[ ! -s "$WORK_DIR/guest/vmlinux" ]]; then
    fail_now "missing $WORK_DIR/guest/vmlinux (run: bash scripts/build-guest-image.sh)"
  fi
  if [[ ! -s "$WORK_DIR/guest/rootfs.ext4" ]]; then
    fail_now "missing $WORK_DIR/guest/rootfs.ext4 (run: bash scripts/build-guest-image.sh)"
  fi
  local running
  running="$(pgrep -x microvmd 2>/dev/null || true)"
  if [[ -n "$running" ]]; then
    fail_now "another microvmd appears to be running (pids: $(tr '\n' ' ' <<<"$running")); stop it first so this gate has exclusive host state"
  fi
  pass "/dev/kvm available, release binaries and guest image present"
}

prepare_run_state() {
  info "preparing fresh .work state (state, artifacts, snapshots, chroot, logs, config)"
  prepare_work_dirs
  rm -rf -- "$WORK_DIR/state" "$WORK_DIR/artifacts" "$WORK_DIR/snapshots" "$WORK_DIR/chroot" "$WORK_DIR/logs"
  mkdir -p \
    "$WORK_DIR/state" \
    "$WORK_DIR/artifacts" \
    "$WORK_DIR/snapshots" \
    "$WORK_DIR/chroot" \
    "$WORK_DIR/logs"
  rm -f -- "$CONFIG"
  clean_run_sockets
}

wait_for_rest_socket() {
  local deadline
  deadline=$((SECONDS + SOCKET_TIMEOUT))
  while ((SECONDS < deadline)); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      fail_now "microvmd exited before the REST socket appeared"
    fi
    if [[ -S "$REST_SOCK" ]]; then
      return 0
    fi
    sleep 0.1
  done
  fail_now "REST socket $REST_SOCK did not appear within ${SOCKET_TIMEOUT}s"
}

wait_for_cli() {
  local deadline
  deadline=$((SECONDS + SOCKET_TIMEOUT))
  while ((SECONDS < deadline)); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      fail_now "microvmd exited while waiting for the CLI to reach it"
    fi
    if "$MICROVM" --socket "$REST_SOCK" list >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  fail_now "REST socket exists but the microvm CLI could not reach microvmd within ${SOCKET_TIMEOUT}s"
}

start_daemon() {
  : >"$DAEMON_LOG"
  info "starting microvmd: $MICROVMD --config $CONFIG"
  "$MICROVMD" --config "$CONFIG" >>"$DAEMON_LOG" 2>&1 &
  DAEMON_PID=$!
  DAEMON_STARTED=1
  pass "daemon: started microvmd (pid $DAEMON_PID, log $DAEMON_LOG)"
  wait_for_rest_socket
  pass "daemon: REST socket ready at $REST_SOCK"
  if [[ -S "$GRPC_SOCK" ]]; then
    pass "daemon: gRPC socket ready at $GRPC_SOCK"
  fi
  wait_for_cli
  pass "daemon: microvm CLI can reach microvmd over the REST socket"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# Poll `status --vm-id` until the printed key=value state equals <want>.
wait_for_state() {
  local vm_id="$1" want="$2" timeout="$3" deadline out rc state
  deadline=$((SECONDS + timeout))
  out=""
  while ((SECONDS < deadline)); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      fail_now "microvmd exited while waiting for vm $vm_id to reach state '$want'"
    fi
    if out="$("$MICROVM" --socket "$REST_SOCK" status --vm-id "$vm_id" 2>/dev/null)"; then
      # The status command prints key=value fields (state=running ...).
      state="$(grep -Eo 'state[[:space:]]*=[[:space:]]*[^[:space:]]+' <<<"$out" | head -n 1 \
        | sed -E 's/^state[[:space:]]*=[[:space:]]*//' | tr -d '",' || true)"
      if [[ -z "$state" ]]; then
        # Tolerate JSON-ish renderings as a fallback.
        state="$(grep -Eo '"state"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$out" | head -n 1 \
          | sed -E 's/^"state"[[:space:]]*:[[:space:]]*"//; s/"$//' || true)"
      fi
      if [[ "$state" == "$want" ]]; then
        return 0
      fi
    fi
    sleep 0.25
  done
  printf 'last status output for vm %s: %s\n' "$vm_id" "${out:-<none>}" >&2
  return 1
}

# Serial log must contain the guest readiness marker. The daemon's own log may
# mention the configured marker string when dumping the config, so that file is
# not accepted as serial evidence.
wait_for_serial_marker() {
  local deadline file
  deadline=$((SECONDS + SERIAL_TIMEOUT))
  while ((SECONDS < deadline)); do
    file="$(grep -R -I -l -m1 -- 'MICROVM_READY' "$WORK_DIR/logs" "$WORK_DIR/run" 2>/dev/null \
      | grep -v -x -F -- "$DAEMON_LOG" \
      | head -n 1 || true)"
    if [[ -n "$file" ]]; then
      SERIAL_LOG="$file"
      return 0
    fi
    sleep 0.25
  done
  SERIAL_LOG=""
  return 1
}

check_metrics_cgroup_available() {
  local vm_id="$1" json
  if ! cli "metrics" --json metrics --vm-id "$vm_id"; then
    fail_now "metrics command failed for running vm $vm_id"
  fi
  json="$CLI_OUT"
  if [[ -z "$json" ]]; then
    fail_now "metrics returned empty output for running vm $vm_id"
  fi
  if command -v jq >/dev/null 2>&1; then
    if ! jq -e '.. | objects | select((.cgroup? | objects | .available?) == true)' <<<"$json" >/dev/null 2>&1; then
      printf 'metrics JSON: %s\n' "$json" >&2
      fail_now "metrics JSON has no cgroup.available=true for running vm $vm_id"
    fi
  else
    if ! grep -q '"cgroup"' <<<"$json" \
      || ! grep -Eq '"available"[[:space:]]*:[[:space:]]*true' <<<"$json"; then
      printf 'metrics JSON: %s\n' "$json" >&2
      fail_now "metrics JSON has no cgroup available=true for running vm $vm_id"
    fi
  fi
  pass "metrics: cgroup.available=true for running vm $vm_id"
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

main() {
  printf '=== microvm Firecracker e2e gate (real /dev/kvm) ===\n'

  check_preconditions
  prepare_run_state

  if ! FC_BIN="$(ensure_firecracker)"; then
    fail_now "Firecracker binary unavailable (set FIRECRACKER_BIN or allow the pinned v1.16.1 download)"
  fi
  JAILER_BIN="$(jailer_bin_path)"
  pass "environment: Firecracker $("$FC_BIN" --version 2>/dev/null | head -n 1)"

  info "creating delegated cgroup wrapper: $(cgroup_wrapper_path)"
  if ! WRAPPER="$(reset_cgroup_wrapper)"; then
    fail_now "could not create the user cgroup wrapper under $(cgroup_parent_path)"
  fi
  WRAPPER_CREATED=1
  pass "cgroup: delegated wrapper ready at $WRAPPER"

  CONFIG_PATH="$(write_microvmd_config "$CONFIG" "$WRAPPER" "$FC_BIN" "$JAILER_BIN" "${FC_VERSION:-$FC_VERSION_DEFAULT}")"
  pass "config: wrote $CONFIG_PATH (cgroup_root=$WRAPPER)"

  start_daemon

  # 1. create
  expect_line "create" '^created vm ' \
    create --vcpu 1 --memory-mib 128 --disk-mib 64 --network-policy none
  VM_ID="$(last_token "$MATCHED_LINE")"
  [[ -n "$VM_ID" ]] || fail_now "could not parse the created VM id"

  # 2. start
  expect_line "start" '^started vm ' start --vm-id "$VM_ID"
  [[ "$(last_token "$MATCHED_LINE")" == "$VM_ID" ]] \
    || fail_now "start output id does not match created vm id $VM_ID"

  # 3. status running
  if ! wait_for_state "$VM_ID" running "$READINESS_TIMEOUT"; then
    fail_now "vm $VM_ID did not reach state 'running' within ${READINESS_TIMEOUT}s"
  fi
  pass "status: vm $VM_ID is running"
  if ! cgroup_subtree_has_procs "$WRAPPER"; then
    fail_now "no Firecracker process is running inside the delegated cgroup wrapper $WRAPPER"
  fi
  pass "cgroup: a Firecracker process is running inside the delegated wrapper"

  # 4. serial readiness marker
  if ! wait_for_serial_marker; then
    fail_now "no serial log under .work/logs or .work/run contains MICROVM_READY within ${SERIAL_TIMEOUT}s"
  fi
  pass "serial: MICROVM_READY observed in $SERIAL_LOG"

  # 5. metrics
  check_metrics_cgroup_available "$VM_ID"

  # 6. snapshot
  expect_line "snapshot" '^created snapshot ' snapshot --vm-id "$VM_ID"
  SNAPSHOT_ID="$(last_token "$MATCHED_LINE")"
  [[ -n "$SNAPSHOT_ID" ]] || fail_now "could not parse the snapshot id"

  # 7. stop the source VM
  expect_line "stop" '^stopped vm ' stop --vm-id "$VM_ID"
  [[ "$(last_token "$MATCHED_LINE")" == "$VM_ID" ]] \
    || fail_now "stop output id does not match vm id $VM_ID"

  # 8. restore the snapshot
  expect_line "restore" '^restored vm ' restore --snapshot-id "$SNAPSHOT_ID"
  RESTORED_VM_ID="$(last_token "$MATCHED_LINE")"
  [[ -n "$RESTORED_VM_ID" ]] || fail_now "could not parse the restored VM id"

  # 9. restored VM is running
  if ! wait_for_state "$RESTORED_VM_ID" running "$READINESS_TIMEOUT"; then
    fail_now "restored vm $RESTORED_VM_ID did not reach state 'running' within ${READINESS_TIMEOUT}s"
  fi
  pass "status: restored vm $RESTORED_VM_ID is running"

  # 10. list
  if ! cli "list" list; then
    fail_now "list command failed"
  fi
  if [[ -z "$CLI_OUT" ]]; then
    fail_now "list returned no VMs while a restored VM is running"
  fi
  if ! grep -Fq -- "$RESTORED_VM_ID" <<<"$CLI_OUT"; then
    printf 'list stdout: %s\n' "$CLI_OUT" >&2
    fail_now "list output does not include restored vm $RESTORED_VM_ID"
  fi
  pass "list: contains restored vm $RESTORED_VM_ID"

  # 11. stop + delete the restored VM, then delete the stopped source VM
  expect_line "stop restored" '^stopped vm ' stop --vm-id "$RESTORED_VM_ID"
  expect_line "delete restored" '^deleted vm ' delete --vm-id "$RESTORED_VM_ID"
  expect_line "delete source" '^deleted vm ' delete --vm-id "$VM_ID"

  # 12. graceful daemon shutdown: SIGTERM -> exit 0, sockets unlinked, leaves gone
  if ! stop_daemon; then
    fail_now "microvmd did not exit cleanly within ${SHUTDOWN_TIMEOUT}s after SIGTERM"
  fi
  pass "daemon: exited 0 after SIGTERM"

  local sock
  for sock in "$REST_SOCK" "$GRPC_SOCK"; do
    if [[ -e "$sock" ]]; then
      fail_now "microvmd left its socket file behind after shutdown: $sock"
    fi
  done
  pass "daemon: removed REST and gRPC socket files on shutdown"

  # 13. no Firecracker process, no cgroup leaf, no wrapper processes remain
  if ! assert_no_firecracker_processes; then
    fail_now "Firecracker processes remain after the daemon exited"
  fi
  pass "cleanup: no Firecracker process remains"

  if ! assert_no_cgroup_leaves; then
    fail_now "cgroup leaves remain under $(cgroup_wrapper_path)/microvm after cleanup"
  fi
  pass "cleanup: no per-VM cgroup leaf remains under $(cgroup_wrapper_path)/microvm"

  if cgroup_subtree_has_procs "$WRAPPER"; then
    fail_now "processes remain inside the delegated cgroup wrapper $WRAPPER"
  fi
  pass "cleanup: no process remains inside the delegated cgroup wrapper"

  printf '\nPASS: firecracker e2e: create/start/serial-readiness/metrics/snapshot/stop/restore/list/delete/cleanup\n'
  exit 0
}

main "$@"
