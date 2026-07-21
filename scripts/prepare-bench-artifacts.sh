#!/usr/bin/env bash
# prepare-bench-artifacts.sh — build guest artifacts and run the full
# Firecracker-vs-Docker benchmark comparison.
#
# Usage (from inside devenv shell, with sudo):
#   devenv shell
#   sudo env "PATH=$PATH" bash scripts/prepare-bench-artifacts.sh
#
# What it does:
#   1. Downloads a Firecracker-compatible guest kernel (vmlinux)
#   2. Creates a minimal busybox-based ext4 rootfs
#   3. Boots a Firecracker VM, waits for readiness, takes a snapshot
#   4. Builds a Docker image from the same busybox rootfs
#   5. Runs the benchmark with both lanes
#
# Requirements: firecracker, jailer, docker (daemon running), KVM, mkfs.ext4

set -euo pipefail

WORKDIR="${BENCH_WORKDIR:-/tmp/microvm-bench}"
KERNEL_URL="${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.16.1/x86_64/vmlinux-6.1.102}"
ROOTFS_SIZE_MIB="${ROOTFS_SIZE_MIB:-64}"
SAMPLES="${SAMPLES:-100}"
OUT="${OUT:-.omo/evidence/kvm-microvm-orchestrator/task-27-benchmark.json}"

mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "=== Step 1: Guest kernel ==="
if [ ! -f vmlinux ]; then
  echo "Downloading Firecracker-compatible kernel..."
  curl -sL "$KERNEL_URL" -o vmlinux
  chmod +x vmlinux
fi
echo "kernel: $(file vmlinux | head -1)"

echo ""
echo "=== Step 2: Minimal busybox rootfs ==="
if [ ! -f rootfs.ext4 ]; then
  echo "Creating ${ROOTFS_SIZE_MIB}MiB ext4 rootfs with busybox..."
  dd if=/dev/zero of=rootfs.ext4 bs=1M count="$ROOTFS_SIZE_MIB" status=progress
  mkfs.ext4 -q rootfs.ext4

  MNT="$WORKDIR/mnt"
  mkdir -p "$MNT"
  mount -o loop rootfs.ext4 "$MNT"

  # Install busybox (static) as init
  mkdir -p "$MNT/bin" "$MNT/proc" "$MNT/sys" "$MNT/dev" "$MNT/tmp"
  if command -v busybox &>/dev/null; then
    cp "$(which busybox)" "$MNT/bin/busybox"
  else
    # Download static busybox
    curl -sL "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" \
      -o "$MNT/bin/busybox"
  fi
  chmod +x "$MNT/bin/busybox"

  # Install busybox applets
  for applet in sh ls cat echo mount mkdir sleep wget; do
    ln -sf busybox "$MNT/bin/$applet"
  done

  # Init script: print marker, then sleep (keeps VM alive for snapshot)
  cat > "$MNT/init" << 'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
echo "MICROVM_BENCH_READY"
sleep 3600
INIT
  chmod +x "$MNT/init"

  umount "$MNT"
  rmdir "$MNT"
fi
echo "rootfs: $(file rootfs.ext4 | head -1)"

echo ""
echo "=== Step 3: Firecracker snapshot ==="
SOCK="$WORKDIR/fc-api.sock"
FC_BIN="$(which firecracker)"
JAILER_BIN="$(which jailer)"

# Clean up any previous run
rm -f "$SOCK" "$WORKDIR/snapshot" "$WORKDIR/memfile"

echo "Booting Firecracker VM..."
"$FC_BIN" --api-sock "$SOCK" &
FC_PID=$!
sleep 1

# Configure the VM
curl -s --unix-socket "$SOCK" -X PUT http://localhost/machine-config \
  -H 'Content-Type: application/json' \
  -d '{"vcpu_count": 1, "mem_size_mib": 128}'

curl -s --unix-socket "$SOCK" -X PUT http://localhost/boot-source \
  -H 'Content-Type: application/json' \
  -d "{\"kernel_image_path\": \"$WORKDIR/vmlinux\", \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off init=/init\"}"

curl -s --unix-socket "$SOCK" -X PUT http://localhost/drives/rootfs \
  -H 'Content-Type: application/json' \
  -d "{\"drive_id\": \"rootfs\", \"path_on_host\": \"$WORKDIR/rootfs.ext4\", \"is_root_device\": true, \"is_read_only\": false}"

# Start the VM
curl -s --unix-socket "$SOCK" -X PUT http://localhost/actions \
  -H 'Content-Type: application/json' \
  -d '{"action_type": "InstanceStart"}'

echo "Waiting for guest readiness..."
sleep 3

# Pause and snapshot
echo "Pausing VM..."
curl -s --unix-socket "$SOCK" -X PATCH http://localhost/vm \
  -H 'Content-Type: application/json' \
  -d '{"state": "Paused"}'

echo "Taking snapshot..."
curl -s --unix-socket "$SOCK" -X PUT http://localhost/snapshot/create \
  -H 'Content-Type: application/json' \
  -d "{\"snapshot_type\": \"Full\", \"snapshot_path\": \"$WORKDIR/snapshot\", \"mem_file_path\": \"$WORKDIR/memfile\"}"

# Stop the VM
curl -s --unix-socket "$SOCK" -X PUT http://localhost/actions \
  -H 'Content-Type: application/json' \
  -d '{"action_type": "SendCtrlAltDel"}'
sleep 1
kill $FC_PID 2>/dev/null || true
wait $FC_PID 2>/dev/null || true

if [ -f "$WORKDIR/snapshot" ] && [ -f "$WORKDIR/memfile" ]; then
  echo "Snapshot created: $(ls -lh "$WORKDIR/snapshot" "$WORKDIR/memfile" | awk '{print $NF, $5}')"
else
  echo "WARNING: Snapshot creation failed; Firecracker lane will be blocked"
fi

echo ""
echo "=== Step 4: Docker image from same rootfs ==="
DOCKER_IMAGE="microvm-bench/payload:latest"
if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
  echo "Building Docker image from busybox rootfs..."
  DOCKER_BUILD="$WORKDIR/docker-build"
  mkdir -p "$DOCKER_BUILD"

  # Extract busybox from the rootfs for the Docker image
  MNT="$WORKDIR/mnt-docker"
  mkdir -p "$MNT"
  mount -o loop,ro rootfs.ext4 "$MNT"
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
echo "=== Step 5: Run benchmark ==="
cd -  # back to repo root
KERNEL_SHA=$(sha256sum "$WORKDIR/vmlinux" | cut -d' ' -f1)
ROOTFS_SHA=$(sha256sum "$WORKDIR/rootfs.ext4" | cut -d' ' -f1)

cargo run -p microvm-bench -- snapshot-restore \
  --samples "$SAMPLES" \
  --kernel "$KERNEL_SHA" \
  --rootfs "$ROOTFS_SHA" \
  --snapshot "$WORKDIR/snapshot" \
  --memfile "$WORKDIR/memfile" \
  --docker-image "$DOCKER_IMAGE" \
  --out "$OUT"

echo ""
echo "=== Done ==="
echo "Benchmark written to: $OUT"
echo "Artifacts in: $WORKDIR"
