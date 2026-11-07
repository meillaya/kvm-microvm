#!/usr/bin/env bash
# build-guest-image.sh: build a Firecracker guest image WITHOUT root privileges.
#
# Outputs (all under the repository's .work/ scratch dir by default):
#   .work/guest/vmlinux         pinned Firecracker CI guest kernel
#   .work/guest/rootfs.ext4     64 MiB ext4 rootfs (static busybox + /init)
#   .work/guest/payload.sha256  sha256 of vmlinux + rootfs.ext4
#   .work/bin/busybox           static busybox cache reused by other scripts
#
# The rootfs is materialized directly from a staging directory with
# `mke2fs -q -F -t ext4 -d <stage> <image> <size>`: no loop mount, no sudo, and
# no writes outside the repository.
#
# Guest /init behavior:
#   1. mounts /proc and /sys,
#   2. prints MICROVM_READY on the serial console (the daemon's serial readiness
#      marker),
#   3. writes /MICROVM_READY,
#   4. execs the static microvm-guest-health server when a static one is
#      available, otherwise a clearly-labelled static busybox sleep loop.
#      The no-network e2e gate only depends on serial readiness.
#
# Inputs (all optional; the environment provides the pinned defaults):
#   KERNEL_URL     guest kernel download URL
#                  (default: pinned Firecracker CI vmlinux 6.18.56)
#   KERNEL_PATH    local kernel file to copy instead of downloading
#   KERNEL_SHA256  expected sha256 of the kernel (verified when set)
#   BUSYBOX_BIN    static busybox binary to stage (must be static)
#   HEALTH_BIN     static microvm-guest-health binary to stage
#   GUEST_DIR, BIN_DIR, ROOTFS_SIZE_MIB, HEALTH_PORT, TARGET, HEALTH_BIN_URL
#                  layout/tooling overrides
#
# Exit status is non-zero with a clear message when a required input or command
# is missing. The script NEVER invokes sudo, loop mounts, or emits a
# dynamically linked guest binary.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK_DIR="$REPO_ROOT/.work"
# shellcheck source=scripts/lib-work.sh
source "$REPO_ROOT/scripts/lib-work.sh"

GUEST_DIR="${GUEST_DIR:-$WORK_DIR/guest}"
BIN_DIR="${BIN_DIR:-$WORK_DIR/bin}"
KERNEL_FILE="$GUEST_DIR/vmlinux"
ROOTFS_FILE="$GUEST_DIR/rootfs.ext4"
CHECKSUM_FILE="$GUEST_DIR/payload.sha256"
HEALTH_MODE_FILE="$GUEST_DIR/health-mode"
STAGE_DIR="$GUEST_DIR/stage"
ROOTFS_SIZE_MIB="${ROOTFS_SIZE_MIB:-64}"
ROOTFS_SIZE="${ROOTFS_SIZE_MIB}M"
HEALTH_PORT="${HEALTH_PORT:-8080}"
KERNEL_URL="${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261105-6ea6634994fa-0/x86_64/vmlinux-6.18.56}"
KERNEL_PATH="${KERNEL_PATH:-}"
KERNEL_SHA256="${KERNEL_SHA256:-}"
BUSYBOX_BIN="${BUSYBOX_BIN:-}"
BUSYBOX_URL="${BUSYBOX_URL:-https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox}"
HEALTH_BIN="${HEALTH_BIN:-}"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
HEALTH_BINARY_NAME="microvm-guest-health"
HEALTH_EXISTING="$REPO_ROOT/target/$TARGET/release/$HEALTH_BINARY_NAME"

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

is_static_elf() {
  local bin="$1"
  [[ -f "$bin" ]] || return 1
  if command -v file >/dev/null 2>&1; then
    file -b "$bin" | grep -Eqi 'statically linked|static-pie linked'
  else
    ldd "$bin" 2>&1 | grep -Eqi 'not a dynamic executable|statically linked'
  fi
}

verify_static() {
  local bin="$1" what="$2"
  require_exec "$bin" "$what"
  if ! is_static_elf "$bin"; then
    die "$what '$bin' is not statically linked; a dynamic guest binary cannot run inside the microVM (set HEALTH_BIN/BUSYBOX_BIN to a static build)"
  fi
}

busybox_has_applet() {
  local bb="$1" applet="$2" list out
  list="$("$bb" --list 2>/dev/null || true)"
  if [[ -n "$list" ]]; then
    grep -qx -- "$applet" <<<"$list"
    return
  fi
  # Minimal busybox builds omit --list; probe the applet's usage output instead.
  out="$("$bb" "$applet" --help 2>&1 || true)"
  ! grep -q 'applet not found' <<<"$out"
}

musl_target_installed() {
  if command -v rustup >/dev/null 2>&1; then
    rustup target list --installed 2>/dev/null | grep -qx -- "$TARGET"
    return
  fi
  local sysroot
  sysroot="$(rustc --print sysroot 2>/dev/null || true)"
  [[ -n "$sysroot" && -d "$sysroot/lib/rustlib/$TARGET" ]]
}

# ---------------------------------------------------------------------------
# Kernel
# ---------------------------------------------------------------------------

resolve_kernel() {
  local src dst actual
  mkdir -p "$GUEST_DIR"
  if [[ -n "$KERNEL_PATH" ]]; then
    [[ -f "$KERNEL_PATH" ]] || die "KERNEL_PATH '$KERNEL_PATH' does not exist"
    [[ -s "$KERNEL_PATH" ]] || die "KERNEL_PATH '$KERNEL_PATH' is empty"
    src="$(realpath -m -- "$KERNEL_PATH")"
    dst="$(realpath -m -- "$KERNEL_FILE")"
    if [[ "$src" != "$dst" ]]; then
      info "copying local kernel $KERNEL_PATH -> $KERNEL_FILE"
      cp -f -- "$KERNEL_PATH" "$KERNEL_FILE"
    else
      info "using local kernel $KERNEL_PATH"
    fi
  elif [[ -s "$KERNEL_FILE" ]]; then
    info "reusing existing kernel $KERNEL_FILE"
  else
    require_cmd curl "needed to download the pinned guest kernel"
    [[ -n "$KERNEL_URL" ]] || die "KERNEL_URL is empty and no kernel exists at $KERNEL_FILE"
    info "downloading pinned guest kernel: $KERNEL_URL"
    if ! curl -fSL --retry 3 --connect-timeout 20 -o "$KERNEL_FILE.part" "$KERNEL_URL"; then
      rm -f -- "$KERNEL_FILE.part"
      die "failed to download the guest kernel from $KERNEL_URL (set KERNEL_PATH or KERNEL_URL)"
    fi
    mv -f -- "$KERNEL_FILE.part" "$KERNEL_FILE"
  fi
  [[ -s "$KERNEL_FILE" ]] || die "guest kernel is missing or empty: $KERNEL_FILE"
  if [[ "$(od -An -tx1 -N4 -- "$KERNEL_FILE" | tr -d ' \n')" != "7f454c46" ]]; then
    die "guest kernel $KERNEL_FILE is not an ELF image"
  fi
  if [[ -n "$KERNEL_SHA256" ]]; then
    actual="$(sha256sum "$KERNEL_FILE" | awk '{print $1}')"
    [[ "$actual" == "$KERNEL_SHA256" ]] \
      || die "kernel sha256 mismatch (expected $KERNEL_SHA256, got $actual)"
  fi
}

# ---------------------------------------------------------------------------
# Guest health server (static microvm-guest-health, else busybox fallback)
# ---------------------------------------------------------------------------

# Prints "<mode>:<path>" where mode is "real" or "busybox" (path empty for the
# fallback because /init then uses busybox sleep).
resolve_health() {
  if [[ -n "$HEALTH_BIN" ]]; then
    verify_static "$HEALTH_BIN" "HEALTH_BIN"
    printf 'real:%s\n' "$HEALTH_BIN"
    return
  fi
  if [[ -x "$HEALTH_EXISTING" ]]; then
    verify_static "$HEALTH_EXISTING" "existing guest-health binary"
    printf 'real:%s\n' "$HEALTH_EXISTING"
    return
  fi
  if command -v cargo >/dev/null 2>&1 && musl_target_installed; then
    info "building $HEALTH_BINARY_NAME for $TARGET"
    if ( cd "$REPO_ROOT" && cargo build --release --target "$TARGET" -p "$HEALTH_BINARY_NAME" ); then
      if [[ -f "$HEALTH_EXISTING" ]] && is_static_elf "$HEALTH_EXISTING"; then
        printf 'real:%s\n' "$HEALTH_EXISTING"
        return
      fi
      warn "cargo build produced no static binary at $HEALTH_EXISTING"
    else
      warn "cargo build for $TARGET failed"
    fi
  else
    warn "no static $TARGET $HEALTH_BINARY_NAME binary and no musl Rust target installed"
  fi
  warn "falling back to a static busybox init that prints MICROVM_READY and sleeps (serial readiness only; no guest health server)"
  printf 'busybox:\n'
}

# ---------------------------------------------------------------------------
# Static busybox
# ---------------------------------------------------------------------------

# Prints the path of the staged static busybox (cached at $BIN_DIR/busybox).
# <need_sleep> is 1 when the busybox sleep applet is required (fallback /init).
select_busybox() {
  local need_sleep="$1" cand chosen=""
  local -a candidates=()

  if [[ -n "$BUSYBOX_BIN" ]]; then
    verify_static "$BUSYBOX_BIN" "BUSYBOX_BIN"
    busybox_has_applet "$BUSYBOX_BIN" sh || die "BUSYBOX_BIN '$BUSYBOX_BIN' lacks the sh applet"
    busybox_has_applet "$BUSYBOX_BIN" mount || die "BUSYBOX_BIN '$BUSYBOX_BIN' lacks the mount applet"
    if [[ "$need_sleep" == 1 ]]; then
      busybox_has_applet "$BUSYBOX_BIN" sleep || die "BUSYBOX_BIN '$BUSYBOX_BIN' lacks the sleep applet needed by the fallback /init"
    fi
    candidates+=("$BUSYBOX_BIN")
  else
    [[ -x "$BIN_DIR/busybox" ]] && candidates+=("$BIN_DIR/busybox")
    if command -v busybox >/dev/null 2>&1; then
      candidates+=("$(command -v busybox)")
    fi
    for cand in /nix/store/*busybox*/bin/busybox; do
      [[ -x "$cand" ]] && candidates+=("$cand")
    done
  fi

  for cand in "${candidates[@]}"; do
    [[ -x "$cand" ]] || continue
    is_static_elf "$cand" || continue
    busybox_has_applet "$cand" sh || continue
    busybox_has_applet "$cand" mount || continue
    if [[ "$need_sleep" == 1 ]]; then
      busybox_has_applet "$cand" sleep || continue
    fi
    chosen="$cand"
    break
  done

  if [[ -z "$chosen" ]]; then
    require_cmd curl "needed to download a static busybox"
    mkdir -p "$BIN_DIR"
    info "no usable static busybox found; downloading $BUSYBOX_URL"
    if ! curl -fSL --retry 3 --connect-timeout 20 -o "$BIN_DIR/busybox.part" "$BUSYBOX_URL"; then
      rm -f -- "$BIN_DIR/busybox.part"
      die "failed to download a static busybox from $BUSYBOX_URL (set BUSYBOX_BIN)"
    fi
    chmod 755 "$BIN_DIR/busybox.part"
    is_static_elf "$BIN_DIR/busybox.part" \
      || die "downloaded busybox from $BUSYBOX_URL is not statically linked"
    busybox_has_applet "$BIN_DIR/busybox.part" sh || die "downloaded busybox lacks the sh applet"
    busybox_has_applet "$BIN_DIR/busybox.part" mount || die "downloaded busybox lacks the mount applet"
    if [[ "$need_sleep" == 1 ]]; then
      busybox_has_applet "$BIN_DIR/busybox.part" sleep || die "downloaded busybox lacks the sleep applet"
    fi
    mv -f -- "$BIN_DIR/busybox.part" "$BIN_DIR/busybox"
    chosen="$BIN_DIR/busybox"
  fi

  # Keep exactly one static busybox cache under .work/bin for downstream scripts.
  mkdir -p "$BIN_DIR"
  if [[ "$chosen" != "$BIN_DIR/busybox" ]]; then
    cp -f -- "$chosen" "$BIN_DIR/busybox"
    chmod 755 "$BIN_DIR/busybox"
    chosen="$BIN_DIR/busybox"
  fi
  printf '%s\n' "$chosen"
}

# ---------------------------------------------------------------------------
# Rootfs
# ---------------------------------------------------------------------------

write_init() {
  local health_mode="$1" health_src="$2"
  if [[ "$health_mode" == "real" ]]; then
    cp -f -- "$health_src" "$STAGE_DIR/usr/bin/$HEALTH_BINARY_NAME"
    chmod 755 "$STAGE_DIR/usr/bin/$HEALTH_BINARY_NAME"
    cat > "$STAGE_DIR/init" <<EOF
#!/bin/sh
# Generated guest init (static microvm-guest-health mode) by scripts/build-guest-image.sh.
mount -t proc none /proc
mount -t sysfs none /sys
echo MICROVM_READY
echo ready > /MICROVM_READY
export PORT=$HEALTH_PORT
exec /usr/bin/$HEALTH_BINARY_NAME
EOF
  else
    cat > "$STAGE_DIR/init" <<'EOF'
#!/bin/sh
# Generated guest init (static busybox fallback) by scripts/build-guest-image.sh.
# Serial readiness only: prints MICROVM_READY, records a marker file, and sleeps
# so Firecracker stays alive for snapshot/restore. This is NOT the guest health
# server; pass HEALTH_BIN or install the x86_64-unknown-linux-musl Rust target to
# stage microvm-guest-health instead.
mount -t proc none /proc
mount -t sysfs none /sys
echo MICROVM_READY
echo ready > /MICROVM_READY
exec /bin/busybox sleep 3600
EOF
  fi
  chmod 755 "$STAGE_DIR/init"
}

stage_rootfs() {
  local busybox="$1" health_mode="$2" health_src="$3" applet
  info "staging rootfs at $STAGE_DIR"
  rm -rf -- "$STAGE_DIR"
  mkdir -p "$STAGE_DIR"/bin "$STAGE_DIR"/dev "$STAGE_DIR"/proc "$STAGE_DIR"/sys "$STAGE_DIR"/tmp "$STAGE_DIR"/usr/bin

  cp -f -- "$busybox" "$STAGE_DIR/bin/busybox"
  chmod 755 "$STAGE_DIR/bin/busybox"

  # Applet symlinks needed by /init and by the microVM shell. Applets missing
  # from a particular busybox build are simply skipped.
  for applet in sh mount umount echo cat ls mkdir rm ln sleep mknod hostname ps kill; do
    if busybox_has_applet "$busybox" "$applet"; then
      ln -sf busybox "$STAGE_DIR/bin/$applet"
    fi
  done

  write_init "$health_mode" "$health_src"
}

build_rootfs() {
  require_cmd mke2fs "install e2fsprogs; mke2fs runs unprivileged for this image layout"
  mkdir -p "$GUEST_DIR"
  rm -f -- "$ROOTFS_FILE"
  info "creating ${ROOTFS_SIZE_MIB}MiB ext4 rootfs with mke2fs -d (no loop mount, no sudo)"
  if ! mke2fs -q -F -t ext4 -d "$STAGE_DIR" "$ROOTFS_FILE" "$ROOTFS_SIZE"; then
    die "mke2fs failed to create $ROOTFS_FILE"
  fi
  [[ -s "$ROOTFS_FILE" ]] || die "rootfs image is missing or empty after mke2fs: $ROOTFS_FILE"
  rm -rf -- "$STAGE_DIR"
}

write_checksums() {
  ( cd "$GUEST_DIR" && sha256sum vmlinux rootfs.ext4 > payload.sha256 )
  [[ -s "$CHECKSUM_FILE" ]] || die "failed to write $CHECKSUM_FILE"
}

print_summary() {
  local health_mode="$1" busybox="$2"
  printf '\n==> Guest image ready:\n'
  ls -lh -- "$KERNEL_FILE" "$ROOTFS_FILE" "$CHECKSUM_FILE" "$HEALTH_MODE_FILE"
  printf '\n==> sha256 payload:\n'
  cat "$CHECKSUM_FILE"
  printf '\n==> static busybox: %s (%s)\n' "$busybox" "$(sha256sum "$busybox" | awk '{print $1}')"
  if [[ "$health_mode" == "real" ]]; then
    printf '==> guest health: static %s server; /init mounts proc/sys, prints MICROVM_READY, execs it on port %s\n' "$HEALTH_BINARY_NAME" "$HEALTH_PORT"
  else
    printf '==> guest health: static busybox fallback (serial readiness only; /init prints MICROVM_READY then sleeps)\n'
  fi
  printf '==> health mode recorded in %s: %s\n' "$HEALTH_MODE_FILE" "$health_mode"
  printf '==> rebuild with: bash scripts/build-guest-image.sh   (set HEALTH_BIN for the real health server)\n'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  [[ "$(uname -m)" == "x86_64" ]] || die "guest image build targets x86_64; host is $(uname -m)"

  case "$GUEST_DIR" in
    "$REPO_ROOT"/*) ;;
    *) die "GUEST_DIR must stay inside the repository ($REPO_ROOT); got $GUEST_DIR" ;;
  esac
  case "$BIN_DIR" in
    "$REPO_ROOT"/*) ;;
    *) die "BIN_DIR must stay inside the repository ($REPO_ROOT); got $BIN_DIR" ;;
  esac

  mkdir -p "$GUEST_DIR" "$BIN_DIR"

  resolve_kernel

  local health health_mode health_src busybox
  health="$(resolve_health)"
  health_mode="${health%%:*}"
  health_src="${health#*:}"
  printf '%s\n' "$health_mode" > "$HEALTH_MODE_FILE"

  if [[ "$health_mode" == "real" ]]; then
    busybox="$(select_busybox 0)"
  else
    busybox="$(select_busybox 1)"
  fi

  stage_rootfs "$busybox" "$health_mode" "$health_src"
  build_rootfs
  write_checksums
  print_summary "$health_mode" "$busybox"
}

main "$@"
