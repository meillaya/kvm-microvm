#!/usr/bin/env bash
# prepare-bench-artifacts.sh — build guest artifacts and run the full
# Firecracker-vs-Docker benchmark comparison.
#
# Usage (from inside devenv shell, with sudo):
#   devenv shell
#   sudo env "PATH=$PATH" bash scripts/prepare-bench-artifacts.sh
#
# What it does:
#   1. Builds the Firecracker guest image from phase 2 story 1
#      (scripts/build-guest-image.sh) -> guest/vmlinux, guest/rootfs.ext4,
#      guest/payload.sha256
#   2. Boots a Firecracker VM from that guest image, waits for readiness, and
#      takes a full snapshot (snapshot state file + guest memory file)
#   3. Verifies the snapshot and memfile exist and are non-empty (fails closed
#      so the benchmark lane is never pointed at missing artifacts)
#   4. Builds a Docker image from the same busybox rootfs
#   5. Runs the benchmark with both lanes, passing the prepared snapshot/memfile
#      so the FirecrackerSnapshotLane produces real restore-latency samples
#
# Requirements: firecracker, jailer, docker (daemon running), KVM, mkfs.ext4

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${BENCH_WORKDIR:-/tmp/microvm-bench}"
SAMPLES="${SAMPLES:-100}"
OUT="${OUT:-.omo/evidence/kvm-microvm-orchestrator/task-27-benchmark.json}"

# Guest image produced by phase 2 story 1 (scripts/build-guest-image.sh).
GUEST_DIR="$REPO_ROOT/guest"
GUEST_KERNEL="$GUEST_DIR/vmlinux"
GUEST_ROOTFS="$GUEST_DIR/rootfs.ext4"

# Prepared Firecracker snapshot artifacts the benchmark lane restores.
SNAPSHOT="$WORKDIR/snapshot"
MEMFILE="$WORKDIR/memfile"

mkdir -p "$WORKDIR"

# build-guest-image.sh requires a static busybox on PATH; the devenv shell does
# not ship one, so provision a static musl busybox when none is present.
ensure_busybox() {
  if command -v busybox &>/dev/null; then
    echo "busybox: $(command -v busybox)"
    return
  fi
  local bbdir="$WORKDIR/bin"
  mkdir -p "$bbdir"
  if [[ ! -x "$bbdir/busybox" ]]; then
    echo "busybox not on PATH; fetching static musl busybox..."
    curl -fsSL --retry 3 \
      "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" \
      -o "$bbdir/busybox"
    chmod +x "$bbdir/busybox"
  fi
  export PATH="$bbdir:$PATH"
  echo "busybox: $(command -v busybox)"
}

echo "=== Step 1: Guest image (phase 2 story 1) ==="
ensure_busybox
if [[ ! -f "$GUEST_KERNEL" || ! -f "$GUEST_ROOTFS" ]]; then
  echo "Building guest image via scripts/build-guest-image.sh..."
  bash "$REPO_ROOT/scripts/build-guest-image.sh"
fi
if [[ ! -f "$GUEST_KERNEL" || ! -f "$GUEST_ROOTFS" ]]; then
  echo "ERROR: guest image missing after build (expected $GUEST_KERNEL and $GUEST_ROOTFS)" >&2
  exit 1
fi
echo "kernel: $(file "$GUEST_KERNEL" | head -1)"
echo "rootfs: $(file "$GUEST_ROOTFS" | head -1)"

echo ""
echo "=== Step 2: Firecracker snapshot ==="
SOCK="$WORKDIR/fc-api.sock"
FC_BIN="$(which firecracker)"

# Clean up any previous run.
rm -f "$SOCK" "$SNAPSHOT" "$MEMFILE"

echo "Booting Firecracker VM from guest image..."
"$FC_BIN" --api-sock "$SOCK" &
FC_PID=$!
sleep 1

# Configure the VM from the story-1 guest image.
curl -s --unix-socket "$SOCK" -X PUT http://localhost/machine-config \
  -H 'Content-Type: application/json' \
  -d '{"vcpu_count": 1, "mem_size_mib": 128}'

curl -s --unix-socket "$SOCK" -X PUT http://localhost/boot-source \
  -H 'Content-Type: application/json' \
  -d "{\"kernel_image_path\": \"$GUEST_KERNEL\", \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off init=/init\"}"

curl -s --unix-socket "$SOCK" -X PUT http://localhost/drives/rootfs \
  -H 'Content-Type: application/json' \
  -d "{\"drive_id\": \"rootfs\", \"path_on_host\": \"$GUEST_ROOTFS\", \"is_root_device\": true, \"is_read_only\": false}"

# Start the VM. The guest init runs the microvm-guest-health server, which
# listens forever and keeps the VM alive for snapshotting.
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
echo "=== Step 3: Docker image from same rootfs ==="
DOCKER_IMAGE="microvm-bench/payload:latest"
if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
  echo "Building Docker image from busybox rootfs..."
  DOCKER_BUILD="$WORKDIR/docker-build"
  mkdir -p "$DOCKER_BUILD"

  # Extract busybox from the guest rootfs so the Docker image runs the same
  # payload content as the VM lane.
  MNT="$WORKDIR/mnt-docker"
  mkdir -p "$MNT"
  mount -o loop,ro "$GUEST_ROOTFS" "$MNT"
  cp "$MNT/bin/busybox" "$DOCKER_BUILD/busybox"
  umount "$MNT"
  rmdir "$MNT"

  cat > "$DOCKER_BUILD/Dockerfile" << 'DOCKERFILE'
FROM scratch
COPY busybox /bin/busybox
RUN ["/bin/busybox", "sh", "-c", "for a in sh ls cat echo mkdir sleep; do /bin/busybox ln -sf busybox /bin/$a; done"]
ENTRYPOINT ["/bin/busybox", "sh", "-c", "echo MICROVM_BENCH_READY && sleep 1"]
DOCKERFILE

  docker build -t "$DOCKER_IMAGE" "$DOCKER_BUILD"
  echo "Docker image built: $DOCKER_IMAGE"
else
  echo "Docker image already exists: $DOCKER_IMAGE"
fi

echo ""
echo "=== Step 4: Run benchmark ==="
cd "$REPO_ROOT"
KERNEL_SHA=$(sha256sum "$GUEST_KERNEL" | cut -d' ' -f1)
ROOTFS_SHA=$(sha256sum "$GUEST_ROOTFS" | cut -d' ' -f1)

cargo run -p microvm-bench -- snapshot-restore \
  --samples "$SAMPLES" \
  --kernel "$KERNEL_SHA" \
  --rootfs "$ROOTFS_SHA" \
  --snapshot "$SNAPSHOT" \
  --memfile "$MEMFILE" \
  --socket-dir "$WORKDIR" \
  --docker-image "$DOCKER_IMAGE" \
  --out "$OUT"

echo ""
echo "=== Done ==="
echo "Benchmark written to: $OUT"
echo "Artifacts in: $WORKDIR"
