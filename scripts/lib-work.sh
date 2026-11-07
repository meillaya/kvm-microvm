#!/usr/bin/env bash
# lib-work.sh: shared helpers for the .work-based host scripts.
#
# This file is SOURCED (never executed) by:
#   - scripts/build-guest-image.sh (only the small helpers it needs)
#   - scripts/dev-run.sh
#   - scripts/e2e-firecracker.sh
#
# The caller must set REPO_ROOT and WORK_DIR before sourcing. All development
# scratch lives under $REPO_ROOT/.work; nothing here writes outside the repo
# except the single user-delegated cgroup wrapper described below.
#
# The only external state created by these helpers is the cgroup-v2 wrapper
#   /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/microvm-dev
# which callers MUST remove in their EXIT trap with remove_cgroup_wrapper()
# after every daemon/Firecracker process is gone. No sudo is used: the wrapper
# lives in the caller's own systemd user-session delegation.

# ---------------------------------------------------------------------------
# Messaging / assertions
# ---------------------------------------------------------------------------

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# info/warn go to stderr so that functions returning data on stdout (cgroup
# wrapper path, Firecracker binary path, config path) can be command-substituted.
info() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; }

require_cmd() {
  local name="$1" hint="${2:-}"
  command -v "$name" >/dev/null 2>&1 || die "required command '$name' not found${hint:+: $hint}"
}

require_exec() {
  local path="$1" what="$2"
  [[ -f "$path" ]] || die "$what does not exist: $path"
  [[ -x "$path" ]] || die "$what is not executable: $path"
}

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------

prepare_work_dirs() {
  mkdir -p \
    "$WORK_DIR/bin" \
    "$WORK_DIR/config" \
    "$WORK_DIR/run" \
    "$WORK_DIR/state" \
    "$WORK_DIR/artifacts" \
    "$WORK_DIR/snapshots" \
    "$WORK_DIR/chroot" \
    "$WORK_DIR/logs" \
    "$WORK_DIR/tmp"
}

# Remove only this project's sockets from the .work run dir (never the whole
# directory: other local tooling may keep unrelated state there).
clean_run_sockets() {
  [[ -d "$WORK_DIR/run" ]] || return 0
  rm -f "$WORK_DIR/run/rest.sock" "$WORK_DIR/run/grpc.sock"
  # Daemon per-VM API sockets live under the configured socket_dir, possibly
  # in per-VM subdirectories; remove anything that is clearly a Unix socket.
  local sock
  while IFS= read -r sock; do
    rm -f "$sock"
  done < <(find "$WORK_DIR/run" -maxdepth 3 -type s -name '*.sock' 2>/dev/null || true)
}

# ---------------------------------------------------------------------------
# cgroup-v2 user delegation wrapper
# ---------------------------------------------------------------------------

cgroup_parent_path() {
  printf '/sys/fs/cgroup/user.slice/user-%s.slice/user@%s.service' "$(id -u)" "$(id -u)"
}

cgroup_wrapper_path() {
  printf '%s/microvm-dev' "$(cgroup_parent_path)"
}

_cgroup_procs_in_tree() {
  local dir="$1" entry
  [[ -d "$dir" ]] || return 0
  [[ -r "$dir/cgroup.procs" ]] && cat "$dir/cgroup.procs" 2>/dev/null || true
  for entry in "$dir"/*/; do
    [[ -d "$entry" ]] || continue
    _cgroup_procs_in_tree "${entry%/}"
  done
}

cgroup_subtree_has_procs() {
  [[ -n "$(_cgroup_procs_in_tree "$1")" ]]
}

# Remove the delegated wrapper and everything below it. Best effort: it is
# only fatal for the caller to check that the wrapper is gone afterwards.
remove_cgroup_wrapper() {
  local wrapper dir i pid
  wrapper="$(cgroup_wrapper_path)"
  [[ -d "$wrapper" ]] || return 0

  # cgroup.kill atomically kills the whole subtree (kernel >= 5.14).
  if [[ -w "$wrapper/cgroup.kill" ]]; then
    printf '1' > "$wrapper/cgroup.kill" 2>/dev/null || true
  fi
  for i in $(seq 1 50); do
    cgroup_subtree_has_procs "$wrapper" || break
    sleep 0.1
  done
  # Last resort for kernels without cgroup.kill: SIGKILL listed PIDs.
  if cgroup_subtree_has_procs "$wrapper"; then
    while IFS= read -r pid; do
      [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done < <(_cgroup_procs_in_tree "$wrapper")
    sleep 0.2
  fi
  # Deepest directories first; leaf rmdir succeeds once no processes are attached.
  while IFS= read -r dir; do
    rmdir "$dir" 2>/dev/null || true
  done < <(find "$wrapper" -depth -type d 2>/dev/null || true)

  if [[ -d "$wrapper" ]]; then
    warn "could not fully remove cgroup wrapper $wrapper (processes: $(_cgroup_procs_in_tree "$wrapper" | tr '\n' ' '))"
  fi
}

# Recreate a fresh delegated wrapper and print its path on stdout.
reset_cgroup_wrapper() {
  local parent wrapper
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] \
    || die "cgroup-v2 unified hierarchy not mounted at /sys/fs/cgroup"
  parent="$(cgroup_parent_path)"
  wrapper="$(cgroup_wrapper_path)"
  [[ -d "$parent" ]] || die "no user cgroup delegation at $parent; start a systemd user session (e.g. loginctl enable-linger $(id -u)) and retry"
  if [[ -e "$wrapper" ]]; then
    warn "removing stale cgroup wrapper $wrapper"
    remove_cgroup_wrapper
    [[ -e "$wrapper" ]] && die "stale cgroup wrapper $wrapper could not be removed"
  fi
  mkdir -p "$wrapper" || die "cannot create cgroup wrapper $wrapper"
  [[ -r "$wrapper/cgroup.controllers" ]] || die "not a cgroup-v2 directory: $wrapper"
  printf '%s\n' "$wrapper"
}

# True when no per-VM leaf remains under <wrapper>/microvm (or the parent itself
# is gone). Prints the offending paths on stderr and returns 1 when a leaf
# remains.
assert_no_cgroup_leaves() {
  local wrapper parent leaves
  wrapper="$(cgroup_wrapper_path)"
  [[ -d "$wrapper" ]] || return 0
  parent="$wrapper/microvm"
  [[ -d "$parent" ]] || return 0
  leaves="$(find "$parent" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort || true)"
  if [[ -n "$leaves" ]]; then
    printf 'remaining cgroup leaves:\n%s\n' "$leaves" >&2
    return 1
  fi
  return 0
}

# PIDs whose program (argv[0]) is the given microvmd binary. Matching argv[0]
# (instead of a substring of the full command line) avoids false positives from
# shells or scripts whose arguments merely mention the path.
microvmd_pids() {
  local bin="$1" base
  base="$(basename -- "$bin")"
  ps -eo pid=,args= 2>/dev/null | awk -v bin="$bin" -v base="$base" '{
    pid = $1;
    $1 = "";
    sub(/^[[:space:]]+/, "");
    n = split($0, field, /[[:space:]]+/);
    if (n >= 1 && (field[1] == bin || field[1] == base)) print pid;
  }'
}

# ---------------------------------------------------------------------------
# Firecracker binary (pinned v1.16.1 static release)
# ---------------------------------------------------------------------------

FC_VERSION_DEFAULT="1.16.1"
# SHA-256 of firecracker-v1.16.1-x86_64.tgz (the same pin as devenv.nix).
FC_TARBALL_SHA256_DEFAULT="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"

verify_firecracker_version() {
  local bin="$1" version="$2" out first
  out="$("$bin" --version 2>/dev/null | head -n 1 || true)"
  first="${out%%$'\n'*}"
  [[ "$first" == *"Firecracker v${version}"* ]] \
    || die "Firecracker binary $bin is not v${version} (got '${first:-no version output}')"
}

_download_firecracker() {
  local version="$1" dir="$2" url tarball expected actual
  require_cmd curl
  require_cmd tar
  mkdir -p "$dir" "$WORK_DIR/tmp"
  url="https://github.com/firecracker-microvm/firecracker/releases/download/v${version}/firecracker-v${version}-x86_64.tgz"
  tarball="$WORK_DIR/tmp/firecracker-v${version}-x86_64.tgz"
  if [[ ! -s "$tarball" ]]; then
    info "downloading Firecracker v${version}: $url"
    curl -fSL --retry 3 --connect-timeout 20 -o "$tarball.part" "$url" \
      || die "failed to download Firecracker v${version} from $url"
    expected="${FC_SHA256:-}"
    if [[ -z "$expected" && "$version" == "$FC_VERSION_DEFAULT" ]]; then
      expected="$FC_TARBALL_SHA256_DEFAULT"
    fi
    actual="$(sha256sum "$tarball.part" | awk '{print $1}')"
    if [[ -n "$expected" && "$actual" != "$expected" ]]; then
      rm -f "$tarball.part"
      die "Firecracker tarball sha256 mismatch (expected $expected, got $actual)"
    fi
    [[ -n "$expected" ]] || warn "no pinned sha256 for Firecracker v${version}; downloaded sha256=$actual"
    mv -f "$tarball.part" "$tarball"
  fi
  tar -xzf "$tarball" -C "$dir" --strip-components=1 \
    --wildcards "*/firecracker-v${version}-x86_64" \
    || die "failed to extract Firecracker v${version} from $tarball"
  mv -f "$dir/firecracker-v${version}-x86_64" "$dir/firecracker"
  # The same tarball ships the jailer; keep it beside Firecracker for the
  # privileged test lane (optional: extraction failure is not fatal).
  if tar -xzf "$tarball" -C "$dir" --strip-components=1 \
      --wildcards "*/jailer-v${version}-x86_64" 2>/dev/null; then
    mv -f "$dir/jailer-v${version}-x86_64" "$dir/jailer" 2>/dev/null || true
  fi
  chmod +x "$dir/firecracker"
  [[ -f "$dir/jailer" ]] && chmod +x "$dir/jailer"
  rm -f "$tarball"
}

# Resolve (or download) the Firecracker binary and print its path on stdout.
# Reuses, in order: FIRECRACKER_BIN, .work/bin/firecracker, .work/firecracker,
# then the pinned release download.
ensure_firecracker() {
  local version bin
  version="${FC_VERSION:-$FC_VERSION_DEFAULT}"
  if [[ -n "${FIRECRACKER_BIN:-}" ]]; then
    bin="$FIRECRACKER_BIN"
    require_exec "$bin" "FIRECRACKER_BIN"
  elif [[ -x "$WORK_DIR/bin/firecracker" ]]; then
    bin="$WORK_DIR/bin/firecracker"
  elif [[ -x "$WORK_DIR/firecracker" ]]; then
    # Older runs cached the binary at .work/firecracker; reuse it in place.
    bin="$WORK_DIR/firecracker"
  else
    _download_firecracker "$version" "$WORK_DIR/bin"
    bin="$WORK_DIR/bin/firecracker"
  fi
  verify_firecracker_version "$bin" "$version"
  printf '%s\n' "$bin"
}

jailer_bin_path() {
  if [[ -x "$WORK_DIR/bin/jailer" ]]; then
    printf '%s\n' "$WORK_DIR/bin/jailer"
  elif command -v jailer >/dev/null 2>&1; then
    command -v jailer
  else
    printf 'jailer\n'
  fi
}

# ---------------------------------------------------------------------------
# Generated daemon configuration
# ---------------------------------------------------------------------------

# write_microvmd_config <config-path> <cgroup-root> <firecracker-bin> \
#                      <jailer-bin-or-name> <firecracker-version>
#
# Every path points under $WORK_DIR (all development scratch is bounded there).
# Returns the config path on stdout.
write_microvmd_config() {
  local path="$1" cgroup_root="$2" firecracker="$3" jailer="$4" version="$5"
  local uid gid
  uid="$(id -u)"
  gid="$(id -g)"
  mkdir -p "$(dirname "$path")"
  cat > "$path" <<EOF
# Generated by scripts/dev-run.sh / scripts/e2e-firecracker.sh -- do not edit.
# All state is bounded under the repository's .work/ directory.
backend = "firecracker"

[server]
rest_socket = "$WORK_DIR/run/rest.sock"
grpc_socket = "$WORK_DIR/run/grpc.sock"
socket_mode = "0600"
socket_uid = $uid
socket_gid = $gid
allowed_uids = [$uid]
tenant = "local"
role = "owner"

[image]
kernel = "$WORK_DIR/guest/vmlinux"
rootfs = "$WORK_DIR/guest/rootfs.ext4"
boot_args = "console=ttyS0 reboot=k panic=1 pci=off init=/init"

[paths]
state_dir = "$WORK_DIR/state"
artifact_dir = "$WORK_DIR/artifacts"
snapshot_dir = "$WORK_DIR/snapshots"
socket_dir = "$WORK_DIR/run"
chroot_dir = "$WORK_DIR/chroot"
log_dir = "$WORK_DIR/logs"

[runtime]
firecracker = "$firecracker"
jailer = "$jailer"
firecracker_version = "$version"
readiness = "serial"
readiness_marker = "MICROVM_READY"
readiness_port = 8080
socket_timeout_ms = 10000
readiness_timeout_ms = 60000
use_jailer = false

[isolation]
cgroup_root = "$cgroup_root"
jailer_uid = $uid
jailer_gid = $gid
pids_max = 128
EOF
  printf '%s\n' "$path"
}

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

# Wait until <path> exists as a Unix socket, or <timeout-seconds> elapses.
wait_for_unix_socket() {
  local path="$1" timeout="$2" deadline
  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    [[ -S "$path" ]] && return 0
    sleep 0.1
  done
  return 1
}

# Wait until <path> is an executable regular file, or <timeout-seconds> elapses.
wait_for_file() {
  local path="$1" timeout="$2" deadline
  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    [[ -f "$path" ]] && return 0
    sleep 0.1
  done
  return 1
}
