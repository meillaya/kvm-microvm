# Operations

This page covers running the daemon, checking a VM and its metrics, taking a
snapshot, and cleaning up a host. Run the commands from the repository root and
use the config that matches the host.

## Host prerequisites

- x86_64 Linux with `/dev/kvm` readable and writable by the daemon user.
- cgroup v2 mounted at `/sys/fs/cgroup`, with the `cpu`, `memory`, and `pids`
  controllers available.
- Firecracker 1.16.1 and jailer at the paths in the config.
- For the no-sudo development path, a systemd user session that delegates a
  cgroup subtree to your user.

## Configure and validate

The daemon takes the config path as a flag value:

```bash
target/release/microvmd --config /etc/microvmd.toml --check
```

`--check` parses the TOML, resolves every path, and validates the image, socket,
and backend settings. It exits 0, serves nothing, and touches no VM. Fix each
reported error before you start the daemon.

The README lists every configuration key. The development script writes
`.work/config/microvmd.toml` with `readiness = "serial"`, `use_jailer = false`,
and all paths under `.work/`. Validate the generated file with:

```bash
bash scripts/dev-run.sh --check
```

## Start and stop the daemon

Development setup, foreground:

```bash
bash scripts/dev-run.sh
```

The script creates the delegated cgroup wrapper, writes the config, prints the
REST and gRPC socket paths, and serves in the foreground. Ctrl-C stops the
daemon and removes the sockets and the wrapper.

Host install:

```bash
target/release/microvmd --config /etc/microvmd.toml
```

Run the daemon as a dedicated user. The socket mode and owner come from
`server.socket_mode`, `server.socket_uid`, and `server.socket_gid`. Logs go to
`paths.log_dir`.

## Check a VM

```bash
MV="target/release/microvm --socket /run/microvm/rest.sock"
$MV status --vm-id "$VM_ID"
$MV metrics --vm-id "$VM_ID"
$MV list
```

Status prints `key=value` fields, including the state. Metrics report cgroup v2
readings for CPU, memory, pids, and block I/O. A reading the cgroup cannot
provide is marked unavailable; the record is never padded with zeros. Failed
reads and daemon errors land in the log file under `paths.log_dir`.

## Snapshot and restore

```bash
SNAP_ID=$($MV snapshot --vm-id "$VM_ID" | awk '{print $3}')
$MV restore --snapshot-id "$SNAP_ID"
```

Snapshot create writes a memory file, a state file, and a manifest under
`paths.snapshot_dir`. Restore validates the manifest and starts a fresh VM. The
source VM record remains; stop and delete it when you no longer need it.

Both commands accept no-network VMs only. The daemon rejects a snapshot of a VM
created with `--network-policy nat-only` or `--network-policy egress-allowed`.
Snapshots stay on the local host. There is no transfer, signing, or encryption.

## Clean up

Stop and delete each VM, then stop the daemon:

```bash
$MV stop --vm-id "$VM_ID"
$MV delete --vm-id "$VM_ID"
$MV list
```

`list` should print no VM lines. After the daemon exits, check for leftovers:

```bash
pgrep -a firecracker
find .work -type s -name '*.sock'
```

The development script removes the delegated cgroup wrapper on Ctrl-C. If a crash
leaves the wrapper behind, remove
`/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/microvm-dev`
after every process in it has gone. `scripts/e2e-firecracker.sh` runs the whole
sequence and asserts that no Firecracker process or cgroup leaf remains, so run it
after a change to the lifecycle or isolation code.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `microvm` cannot connect | The daemon is running, `--socket` matches `server.rest_socket`, and the socket mode lets your UID connect. |
| The VM stays in `configured` | The serial log. The guest must print `MICROVM_READY`; a missing marker ends in a readiness timeout. |
| Start fails with a cgroup error | `isolation.cgroup_root` exists and the daemon user can write the delegated subtree. |
| A restore is rejected | The manifest host envelope matches this host and Firecracker version, and the source VM used `--network-policy none`. |
| A TCP probe fails | The daemon has no TCP listener. Use the REST or gRPC Unix socket. |
