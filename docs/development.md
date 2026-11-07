# Development

The workspace builds `microvmd` (daemon) and `microvm` (CLI) plus the crates
they use. Every development artifact belongs under `.work/`, and the development
path needs no sudo.

## Workspace

| Group | Crates | Role |
| --- | --- | --- |
| Daemon and transport | `microvm-daemon`, `microvm-service`, `microvm-rest`, `microvm-grpc`, `microvm-transport-contract` | Serves REST/JSON and gRPC over Unix sockets and routes both to one lifecycle service. |
| Lifecycle and types | `microvm-lifecycle`, `microvm-types`, `microvm-errors` | VM state machine, ids, specs, and typed errors. |
| Runtime and isolation | `microvm-firecracker`, `microvm-isolation`, `microvm-snapshots`, `microvm-artifacts`, `microvm-metrics` | Firecracker supervision, cgroup v2, snapshots, local artifacts, and metrics records. |
| Simulation | `microvm-sim` | In-memory backend for deterministic tests and CLI exploration. |
| Client and guest | `microvm-cli`, `microvm-guest-health` | REST client and the guest readiness helper. |
| Verification | `microvm-e2e-tests`, `microvm-contract-tests`, `microvm-security-tests` | End-to-end lifecycle, transport parity, and boundary tests. |

## Build and test

```bash
cargo build --release
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The workspace test run is deterministic and includes a daemon end-to-end test
against the simulation backend. It touches no KVM device, TUN device, or
cgroupfs. Host-dependent checks live in the scripts, not in `cargo test`.

## Guest image

`scripts/build-guest-image.sh` builds a bootable guest under `.work/guest/`:

```bash
bash scripts/build-guest-image.sh
```

It writes `.work/guest/vmlinux`, `.work/guest/rootfs.ext4`, and
`.work/guest/payload.sha256`. The rootfs is created from a staging directory with
`mke2fs -d`, so the script uses no loop mount and no sudo. It reuses a pinned
Firecracker CI kernel and a cached static busybox. When no static
`microvm-guest-health` binary exists for the target, the fallback `/init` prints
`MICROVM_READY` and sleeps; serial readiness still works.

Overrides: `KERNEL_URL`, `KERNEL_PATH`, `KERNEL_SHA256`, `BUSYBOX_BIN`,
`HEALTH_BIN`, `GUEST_DIR`, `ROOTFS_SIZE_MIB`, and `HEALTH_PORT`.

## Run the daemon locally

```bash
bash scripts/dev-run.sh
bash scripts/dev-run.sh --check
```

The first form creates a delegated cgroup wrapper under your user session,
writes `.work/config/microvmd.toml`, prints the REST and gRPC socket paths
(`.work/run/rest.sock` and `.work/run/grpc.sock`), and serves in the foreground.
Ctrl-C stops the daemon and removes the sockets and the wrapper. The `--check`
form validates the generated config and exits. All scratch, including state,
snapshots, guest files, and logs, stays under `.work/`.

The daemon config names the image, socket, path, runtime, and isolation settings.
The README lists the keys. For local work, set `backend = "sim"` when you only
need the API, and keep `backend = "firecracker"` when you test the real path.

## Real KVM acceptance

```bash
bash scripts/e2e-firecracker.sh
```

The script starts its own daemon and refuses to run while another `microvmd` is
serving. It drives create, start, serial readiness, metrics, snapshot, stop,
restore, list, and delete, then stops the daemon and asserts that no Firecracker
process or cgroup leaf remains. It builds nothing: run `cargo build --release`
and `bash scripts/build-guest-image.sh` first. It needs `/dev/kvm` and uses
Firecracker 1.16.1.

## Figures

The documentation figures come from one generator:

```bash
python3 -B docs/figures/generate.py
bash scripts/render-figures.sh
```

Review the PNG at the width it appears in the document before you commit a scene
change. Keep the `.excalidraw` scene and the `.png` together.

## Rules for changes

- Keep every development artifact under `.work/`.
- Keep the development path free of sudo. The only write outside the repository is the delegated cgroup wrapper, and the script removes it on exit.
- Keep the control plane on Unix sockets and local images.
- Keep one guest image per daemon and one configured principal.
- Keep snapshots limited to `network-policy none` while the networked path stays
  experimental.
- Report test results you ran. Do not copy counts from an older tree.
