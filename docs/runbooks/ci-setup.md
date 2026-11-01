# Runbook: CI setup

Goal: stand up the two GitHub Actions lanes, the deterministic lane on
GitHub-hosted runners and the privileged lane on a self-hosted KVM runner, and
keep the self-hosted runner registered and capable.

The two lanes mirror the verification lanes in [setup.md](../setup.md):

| Lane | Workflow | Runner | Gate |
| --- | --- | --- | --- |
| deterministic | [`.github/workflows/deterministic.yml`](../../.github/workflows/deterministic.yml) | `ubuntu-latest` (GitHub-hosted) | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` |
| privileged | [`.github/workflows/privileged.yml`](../../.github/workflows/privileged.yml) | `[self-hosted, linux, x86_64, kvm]` | `scripts/run-privileged-suite.sh`, gated by preflight |

## 1. Deterministic lane

The deterministic workflow runs on every push to `main` and on every pull
request that targets `main`. It installs Nix and devenv on an `ubuntu-latest`
runner, then runs the pinned toolchain:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

No runner registration or host setup is needed. A check that only passes on a
privileged host belongs in the privileged lane.

## 2. Privileged lane

The privileged workflow runs the privileged suite on a self-hosted runner with
real KVM, the pinned Firecracker and jailer, and a Docker daemon. The suite is
[`scripts/run-privileged-suite.sh`](../../scripts/run-privileged-suite.sh). It
runs the preflight-gated tests and the Firecracker-vs-Docker benchmark, then
re-aggregates evidence under `.omo/evidence/kvm-microvm-orchestrator/`.
Benchmark artifacts are uploaded on every run, including failures.

### 2.1 Required packages on the runner host

| Requirement | Why | Install (Debian or Ubuntu example) |
| --- | --- | --- |
| KVM (`/dev/kvm`, API 12 or later) | Firecracker and direct-KVM boot | `apt-get install qemu-kvm`, then `modprobe kvm_intel` or `kvm_amd`, and make `/dev/kvm` accessible to the runner user |
| `/dev/net/tun` | Per-VM TAP networking | `modprobe tun` |
| cgroup v2 unified hierarchy (`cpu`, `memory`, `pids`) | Resource-limit enforcement | A kernel with `systemd.unified_cgroup_hierarchy=1` |
| Firecracker and jailer (pinned, static/musl) | Runtime adapter and binary provenance gate | Provided by `devenv shell`, pinned at v1.16.1 |
| Docker with a running daemon | Firecracker-vs-Docker benchmark lane | `apt-get install docker.io`, then `systemctl enable --now docker`, and add the runner user to the `docker` group |
| Nix | devenv and the toolchain | `cachix/install-nix-action` installs it per job, or install Nix on the host |
| e2fsprogs (`mkfs.ext4`, `debugfs`) | Guest rootfs build and payload extraction | `apt-get install e2fsprogs` |

`devenv shell` supplies the pinned Rust toolchain, Firecracker, jailer, and the
Linux VM tools. The host supplies the kernel substrate (KVM, tun, cgroup v2)
and the Docker daemon.

### 2.2 Register the self-hosted runner

1. In the GitHub repository, open Settings, then Actions, then Runners, then
   New self-hosted runner, and select Linux and x64.
2. On the runner host, download and configure the runner with the token from
   that page:

   ```bash
   mkdir -p ~/actions-runner && cd ~/actions-runner
   curl -o actions-runner-linux-x64.tar.gz -L \
     https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz
   tar xzf ./actions-runner-linux-x64.tar.gz
   ./config.sh --url https://github.com/<OWNER>/<REPO> \
     --token <TOKEN> \
     --labels self-hosted,linux,x86_64,kvm \
     --replace
   ```

   The `--labels` line is the contract. The privileged workflow selects
   `[self-hosted, linux, x86_64, kvm]`, so all four labels must be present.

3. Install and start the runner service so it survives a reboot:

   ```bash
   sudo ./svc.sh install
   sudo ./svc.sh start
   sudo ./svc.sh status
   ```

4. Confirm the runner is idle in Settings, Actions, Runners before you trigger
   a build.

The self-hosted runner executes privileged code with `sudo`. Use an ephemeral or
dedicated host, never a machine that holds secrets unrelated to this repository.
See [security.md](../security.md).

### 2.3 Runner labels and workflow triggers

| Workflow | Trigger | Runner selector | Gating |
| --- | --- | --- | --- |
| `deterministic.yml` | `push` to `main`, `pull_request` to `main` | `ubuntu-latest` | None |
| `privileged.yml` | `workflow_dispatch`, `pull_request` (`opened`, `synchronize`, `reopened`, `labeled`) | `[self-hosted, linux, x86_64, kvm]` | A PR run needs the `privileged` label. Manual dispatch always runs. |

To run the privileged lane on a pull request, add the `privileged` label. Remove
and re-add the label, or push a new commit, to trigger another run.

## 3. Verify the setup

```bash
# Deterministic lane: open a pull request to main and watch the
# "deterministic lane (ubuntu-latest)" job.

# Privileged lane: run the "privileged" workflow from the Actions tab, or label
# a pull request 'privileged'. Confirm that:
#   1. the self-hosted KVM runner picks up the job,
#   2. run-privileged-suite.sh prints its pass, fail, and skip summary,
#   3. the "privileged-benchmark-artifacts" artifact contains summary.json and
#      task-27-benchmark.json.
```

A blocked host (no KVM, no Docker, or cgroup v1) makes the privileged suite emit
`blocked` evidence instead of a mocked pass. Fix the host substrate before you
rerun.
