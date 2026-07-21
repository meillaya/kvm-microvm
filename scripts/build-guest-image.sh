#!/usr/bin/env bash
# Build a Firecracker-compatible guest image with the microvm-guest-health server.
#
# Outputs:
#   guest/vmlinux       - Firecracker-compatible guest kernel (latest CI, overridable)
#   guest/rootfs.ext4   - 64MiB ext4 rootfs with busybox + health server
#   guest/payload.sha256 - SHA-256 checksums of the above
#
# Prerequisites:
#   - Rust toolchain with x86_64-unknown-linux-musl target
#   - mkfs.ext4, curl/wget, busybox (static), sha256sum
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUEST_DIR="${REPO_ROOT}/guest"
ROOTFS_SIZE_MIB=64
S3_BUCKET="${S3_BUCKET:-https://s3.amazonaws.com/spec.ccfc.min}"
# Explicit kernel URL override for reproducible pinning. When unset, resolve the
# latest guest kernel from the Firecracker CI bucket. The bucket moved from
# version-tagged (firecracker-ci/v1.16.1/...) to date-tagged prefixes, so a
# hardcoded version path no longer resolves (it was the root cause of the
# benchmark's Firecracker lane blocking on `artifact_missing`).
KERNEL_URL="${KERNEL_URL:-}"
TARGET="x86_64-unknown-linux-musl"

# Resolve the latest guest kernel URL from the Firecracker CI bucket, mirroring
# upstream docs/getting-started.md: pick the newest date-tagged prefix (the
# [0-9]{8} filter skips personal/test branches), then the highest vmlinux under it.
resolve_latest_kernel_url() {
  local arch="$1" prefix key
  prefix=$(curl -fsSL "$S3_BUCKET?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP "(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)" \
    | sort | tail -1)
  [[ -n "$prefix" ]] || return 1
  key=$(curl -fsSL "$S3_BUCKET?list-type=2&prefix=${prefix}${arch}/vmlinux-" \
    | grep -oP "(?<=<Key>)(${prefix}${arch}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" \
    | sort -V | tail -1)
  [[ -n "$key" ]] || return 1
  echo "$S3_BUCKET/$key"
}

echo "==> Building microvm-guest-health for ${TARGET}..."
cargo build --release --target "${TARGET}" -p microvm-guest-health

BINARY="${REPO_ROOT}/target/${TARGET}/release/microvm-guest-health"
if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: binary not found at ${BINARY}" >&2
    exit 1
fi

echo "==> Preparing guest output directory..."
mkdir -p "${GUEST_DIR}"

# --- Kernel ---
if [[ ! -f "${GUEST_DIR}/vmlinux" ]]; then
    if [[ -z "${KERNEL_URL}" ]]; then
        echo "==> Resolving latest Firecracker guest kernel from CI bucket..."
        KERNEL_URL="$(resolve_latest_kernel_url "$(uname -m)")"
    fi
    echo "==> Downloading Firecracker-compatible kernel from ${KERNEL_URL}..."
    curl -fSL --retry 3 -o "${GUEST_DIR}/vmlinux" "${KERNEL_URL}"
else
    echo "==> Kernel already present, skipping download."
fi

# --- Rootfs ---
ROOTFS="${GUEST_DIR}/rootfs.ext4"
ROOTFS_MNT="$(mktemp -d)"
trap 'sudo umount "${ROOTFS_MNT}" 2>/dev/null || true; rmdir "${ROOTFS_MNT}" 2>/dev/null || true' EXIT

echo "==> Creating ${ROOTFS_SIZE_MIB}MiB ext4 rootfs..."
dd if=/dev/zero of="${ROOTFS}" bs=1M count="${ROOTFS_SIZE_MIB}" status=progress
mkfs.ext4 -q -F "${ROOTFS}"

echo "==> Mounting rootfs..."
sudo mount -o loop "${ROOTFS}" "${ROOTFS_MNT}"

echo "==> Installing busybox..."
BUSYBOX_BIN="$(command -v busybox || true)"
if [[ -z "${BUSYBOX_BIN}" ]]; then
    echo "ERROR: busybox not found in PATH" >&2
    exit 1
fi
sudo mkdir -p "${ROOTFS_MNT}/bin"
sudo cp "${BUSYBOX_BIN}" "${ROOTFS_MNT}/bin/busybox"
sudo chmod 755 "${ROOTFS_MNT}/bin/busybox"

# Install busybox applet symlinks needed for init
for applet in sh mount mkdir echo ls cat; do
    sudo ln -sf busybox "${ROOTFS_MNT}/bin/${applet}"
done

echo "==> Installing microvm-guest-health binary..."
sudo mkdir -p "${ROOTFS_MNT}/usr/bin"
sudo cp "${BINARY}" "${ROOTFS_MNT}/usr/bin/microvm-guest-health"
sudo chmod 755 "${ROOTFS_MNT}/usr/bin/microvm-guest-health"

echo "==> Creating init script..."
sudo mkdir -p "${ROOTFS_MNT}/proc" "${ROOTFS_MNT}/sys" "${ROOTFS_MNT}/dev"
sudo tee "${ROOTFS_MNT}/init" > /dev/null << 'INIT'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys

echo "microvm guest starting..."
exec /usr/bin/microvm-guest-health
INIT
sudo chmod 755 "${ROOTFS_MNT}/init"

echo "==> Unmounting rootfs..."
sudo umount "${ROOTFS_MNT}"

# --- Checksums ---
echo "==> Generating payload checksums..."
(cd "${GUEST_DIR}" && sha256sum vmlinux rootfs.ext4 > payload.sha256)

echo "==> Done. Guest artifacts:"
ls -lh "${GUEST_DIR}/vmlinux" "${GUEST_DIR}/rootfs.ext4" "${GUEST_DIR}/payload.sha256"
