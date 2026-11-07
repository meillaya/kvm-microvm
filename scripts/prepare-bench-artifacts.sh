#!/usr/bin/env bash
# prepare-bench-artifacts.sh: build guest artifacts and run the full
# Firecracker-vs-Docker benchmark comparison.
#
# Usage (run as the current user; all scratch under .work/):
#   bash scripts/prepare-bench-artifacts.sh
#
# What it does:
#   1. Builds the Firecracker guest image via scripts/build-guest-image.sh
#      -> .work/guest/vmlinux, .work/guest/rootfs.ext4,
#      .work/guest/payload.sha256
#   2. Extracts the busybox payload from the guest rootfs and computes its
#      SHA-256: the single payload hash both benchmark lanes are pinned to
#   3. Boots a Firecracker VM from that guest image, waits for readiness, and
#      takes a full snapshot (snapshot state file + guest memory file)
#   4. Verifies the snapshot and memfile exist and are non-empty (fails closed
#      so the benchmark lane is never pointed at missing artifacts)
#   5. Builds a Docker image from the same busybox payload bytes
#   6. Runs the benchmark with both lanes, passing the shared --payload-hash plus
#      the prepared snapshot/memfile so the FirecrackerSnapshotLane produces real
#      restore-latency samples and both lanes record the same payload_sha256
#
# Every generated file stays under the repository's .work/ directory
# (override with BENCH_WORKDIR / OUT).
#
# Requirements: a Firecracker binary (FIRECRACKER_BIN, .work/bin/firecracker,
# .work/firecracker, or PATH), a running Docker daemon (Docker lane), KVM, and
# e2fsprogs (mke2fs + debugfs; no sudo and no loop mount are required).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORKDIR="${BENCH_WORKDIR:-$REPO_ROOT/.work/bench}"
SAMPLES="${SAMPLES:-100}"
OUT="${OUT:-$WORKDIR/task-27-benchmark.json}"

# Guest image produced by scripts/build-guest-image.sh.
GUEST_DIR="$REPO_ROOT/.work/guest"
GUEST_KERNEL="$GUEST_DIR/vmlinux"
GUEST_ROOTFS="$GUEST_DIR/rootfs.ext4"

# Extracted busybox payload shared by both lanes.
PAYLOAD_DIR="$WORKDIR/payload"

# Prepared Firecracker snapshot artifacts the benchmark lane restores.
SNAPSHOT="$WORKDIR/snapshot"
MEMFILE="$WORKDIR/memfile"

mkdir -p "$WORKDIR"

# Extract /bin/busybox from the guest rootfs into $1. Uses debugfs from
# e2fsprogs (already required for mkfs) so the payload can be extracted as a
# normal user, with no loop mount and no sudo.
extract_busybox() {
  local out="$1"
  rm -f "$out"
  command -v debugfs >/dev/null 2>&1 \
    || { echo "ERROR: debugfs not found (install e2fsprogs)"; return 1; }
  debugfs -R "dump /bin/busybox $out" "$GUEST_ROOTFS" >/dev/null 2>&1 || true
  if [[ ! -s "$out" ]]; then
    echo "ERROR: failed to extract busybox payload from $GUEST_ROOTFS" >&2
    return 1
  fi
}

# Resolve the Firecracker binary from the .work cache, an override, or PATH.
resolve_firecracker() {
  local bin="${FIRECRACKER_BIN:-}"
  if [[ -z "$bin" ]]; then
    if [[ -x "$REPO_ROOT/.work/bin/firecracker" ]]; then
      bin="$REPO_ROOT/.work/bin/firecracker"
    elif [[ -x "$REPO_ROOT/.work/firecracker" ]]; then
      bin="$REPO_ROOT/.work/firecracker"
    else
      bin="$(command -v firecracker 2>/dev/null || true)"
    fi
  fi
  if [[ -z "$bin" ]]; then
    echo "ERROR: Firecracker binary not found (set FIRECRACKER_BIN or run scripts/e2e-firecracker.sh to cache the pinned release)" >&2
    return 1
  fi
  printf '%s\n' "$bin"
}

echo "=== Step 1: Guest image (scripts/build-guest-image.sh) ==="
if [[ ! -f "$GUEST_KERNEL" || ! -f "$GUEST_ROOTFS" ]]; then
  echo "Guest image missing under $GUEST_DIR; building it..."
  bash "$REPO_ROOT/scripts/build-guest-image.sh"
fi
if [[ ! -f "$GUEST_KERNEL" || ! -f "$GUEST_ROOTFS" ]]; then
  echo "ERROR: guest image missing after build (expected $GUEST_KERNEL and $GUEST_ROOTFS)" >&2
  exit 1
fi
echo "kernel: $(file "$GUEST_KERNEL" | head -1)"
echo "rootfs: $(file "$GUEST_ROOTFS" | head -1)"

echo ""
echo "=== Step 2: Extract identical payload (busybox) from guest rootfs ==="
mkdir -p "$PAYLOAD_DIR"
extract_busybox "$PAYLOAD_DIR/busybox"
chmod +x "$PAYLOAD_DIR/busybox"
# The payload SHA-256 is the hash of the busybox binary that BOTH lanes execute:
# the VM rootfs ships it at /bin/busybox and the Docker image is built from these
# exact bytes. Passing this one hash as --payload-hash pins the Firecracker and
# Docker lanes to identical content (Workload.payload_sha256) instead of the
# harness's placeholder default, satisfying the identical-payload requirement.
PAYLOAD_SHA=$(sha256sum "$PAYLOAD_DIR/busybox" | cut -d' ' -f1)
echo "payload (busybox) sha256: $PAYLOAD_SHA"

echo ""
echo "=== Step 3: Firecracker snapshot ==="
SOCK="$WORKDIR/fc-api.sock"
FC_BIN="$(resolve_firecracker)"

# Clean up any previous run.
rm -f "$SOCK" "$SNAPSHOT" "$MEMFILE"

echo "Booting Firecracker VM from guest image..."
"$FC_BIN" --api-sock "$SOCK" &
FC_PID=$!
sleep 1

# Configure the VM from the guest image.
curl -s --unix-socket "$SOCK" -X PUT http://localhost/machine-config \
  -H 'Content-Type: application/json' \
  -d '{"vcpu_count": 1, "mem_size_mib": 128}'

curl -s --unix-socket "$SOCK" -X PUT http://localhost/boot-source \
  -H 'Content-Type: application/json' \
  -d "{\"kernel_image_path\": \"$GUEST_KERNEL\", \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off init=/init\"}"

curl -s --unix-socket "$SOCK" -X PUT http://localhost/drives/rootfs \
  -H 'Content-Type: application/json' \
  -d "{\"drive_id\": \"rootfs\", \"path_on_host\": \"$GUEST_ROOTFS\", \"is_root_device\": true, \"is_read_only\": false}"

# Start the VM. The guest /init prints MICROVM_READY and keeps the VM alive for
# snapshotting (microvm-guest-health or the static busybox sleep fallback).
curl -s --unix-socket "$SOCK" -X PUT http://localhost/actions \
  -H 'Content-Type: application/json' \
  -d '{"action_type": "InstanceStart"}'

echo "Waiting for guest readiness..."
sleep 3

if ! kill -0 "$FC_PID" 2>/dev/null; then
  echo "ERROR: Firecracker process exited before snapshot; guest failed to boot" >&2
  exit 1
fi

# Pause and snapshot.
echo "Pausing VM..."
curl -s --unix-socket "$SOCK" -X PATCH http://localhost/vm \
  -H 'Content-Type: application/json' \
  -d '{"state": "Paused"}'

echo "Taking snapshot..."
curl -s --unix-socket "$SOCK" -X PUT http://localhost/snapshot/create \
  -H 'Content-Type: application/json' \
  -d "{\"snapshot_type\": \"Full\", \"snapshot_path\": \"$SNAPSHOT\", \"mem_file_path\": \"$MEMFILE\"}"

# Stop the VM.
curl -s --unix-socket "$SOCK" -X PUT http://localhost/actions \
  -H 'Content-Type: application/json' \
  -d '{"action_type": "SendCtrlAltDel"}'
sleep 1
kill "$FC_PID" 2>/dev/null || true
wait "$FC_PID" 2>/dev/null || true

# Verify the prepared artifacts exist and are non-empty. The benchmark lane
# probes for these files and blocks with `artifact_missing` when absent, so we
# fail closed here instead of producing a silently-blocked benchmark lane.
if [[ ! -s "$SNAPSHOT" || ! -s "$MEMFILE" ]]; then
  echo "ERROR: Firecracker snapshot creation failed; expected non-empty $SNAPSHOT and $MEMFILE" >&2
  exit 1
fi
echo "Snapshot created:"
ls -lh "$SNAPSHOT" "$MEMFILE"

echo ""
echo "=== Step 4: Docker image from same payload ==="
DOCKER_IMAGE="microvm-bench/payload:latest"
DOCKER_BUILD="$WORKDIR/docker-build"
mkdir -p "$DOCKER_BUILD"

# Build from the exact busybox bytes extracted from the guest rootfs so the
# Docker lane runs the same payload content as the VM lane.
cp "$PAYLOAD_DIR/busybox" "$DOCKER_BUILD/busybox"
chmod +x "$DOCKER_BUILD/busybox"

# The guest busybox is a minimal static build: it provides `sh` plus a few
# applets, with `echo` as a shell builtin. The image therefore invokes busybox
# directly and runs the payload to completion without applet symlinks, so
# `docker run --rm` measures cold-start of the exact payload bytes the VM rootfs
# ships at /bin/busybox.
cat > "$DOCKER_BUILD/Dockerfile" << 'DOCKERFILE'
FROM scratch
COPY busybox /bin/busybox
ENTRYPOINT ["/bin/busybox", "sh", "-c", "echo MICROVM_BENCH_READY"]
DOCKERFILE

# Rebuild only when the payload content changed. A stale image built from
# different bytes would make the two lanes compare different content, defeating
# the identical-payload guarantee; the marker records the payload hash the image
# was built from so a matching image is reused.
BUILT_MARKER="$DOCKER_BUILD/.payload-sha"
if [[ "$(cat "$BUILT_MARKER" 2>/dev/null || true)" != "$PAYLOAD_SHA" ]]; then
  echo "Building Docker image from busybox payload ($PAYLOAD_SHA)..."
  docker build -t "$DOCKER_IMAGE" "$DOCKER_BUILD"
  echo "$PAYLOAD_SHA" > "$BUILT_MARKER"
  echo "Docker image built: $DOCKER_IMAGE"
else
  echo "Docker image already matches payload ($PAYLOAD_SHA): $DOCKER_IMAGE"
fi

# Pin the Docker-side OCI image digest so the workload records both the shared
# payload hash and the concrete image id derived from that same content.
IMAGE_SHA=$(docker image inspect --format '{{.Id}}' "$DOCKER_IMAGE" | sed 's/^sha256://')
echo "docker image sha256: $IMAGE_SHA"

echo ""
echo "=== Step 5: Run benchmark ==="
cd "$REPO_ROOT"
KERNEL_SHA=$(sha256sum "$GUEST_KERNEL" | cut -d' ' -f1)
ROOTFS_SHA=$(sha256sum "$GUEST_ROOTFS" | cut -d' ' -f1)

cargo run -p microvm-bench -- snapshot-restore \
  --samples "$SAMPLES" \
  --payload-hash "$PAYLOAD_SHA" \
  --kernel "$KERNEL_SHA" \
  --rootfs "$ROOTFS_SHA" \
  --image "$IMAGE_SHA" \
  --snapshot "$SNAPSHOT" \
  --memfile "$MEMFILE" \
  --socket-dir "$WORKDIR" \
  --docker-image "$DOCKER_IMAGE" \
  --out "$OUT"

echo ""
echo "=== Done ==="
echo "Benchmark written to: $OUT"
echo "Artifacts in: $WORKDIR"
