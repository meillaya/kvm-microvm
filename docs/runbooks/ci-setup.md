# Runbook: CI Setup

Goal: stand up the two GitHub Actions lanes for the kvm-microvm-orchestrator —
the **deterministic** lane on GitHub-hosted runners and the **privileged** lane
on a self-hosted KVM runner — and keep the self-hosted runner registered and
capable.

The two lanes mirror the verification lanes in [../setup.md](../setup.md):

| Lane | Workflow | Runner | Gate |
| --- | --- | --- | --- |
| deterministic | [`.github/workflows/deterministic.yml`](../../.github/workflows/deterministic.yml) | `ubuntu-latest` (GitHub-hosted) | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` |
| privileged | [`.github/workflows/privileged.yml`](../../.github/workflows/privileged.yml) | `[self-hosted, linux, x86_64, kvm]` | `scripts/run-privileged-suite.sh` (preflight-gated) |

---

## 1. Deterministic lane (no host capabilities required)

Runs on every push to `main` and every pull request targeting `main`, on a
GitHub-hosted `ubuntu-latest` runner. It installs Nix + devenv, then runs the
pinned-toolchain checks:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

No registration or host setup is needed for this lane. It must stay green on
any host; if a check only passes on a privileged host, it belongs in the
privileged lane instead.

---

## 2. Privileged lane (self-hosted KVM runner)

Runs the privileged suite on a self-hosted runner that has real KVM, the pinned
Firecracker + jailer, and a Docker daemon. The suite is
[`scripts/run-privileged-suite.sh`](../../scripts/run-privileged-suite.sh),
which runs preflight-gated privileged tests and the Firecracker-vs-Docker
benchmark, then re-aggregates evidence under
`.omo/evidence/kvm-microvm-orchestrator/`. Benchmark artifacts are uploaded as
workflow artifacts on every run (including failures, for debugging).

### 2.1 Required packages on the runner host

The runner host must provide the privileged-lane substrate from
[../setup.md](../setup.md):

| Requirement | Why | Install (Debian/Ubuntu example) |
| --- | --- | --- |
| KVM (`/dev/kvm`, API ≥ 12) | Firecracker + direct-KVM boot | `apt-get install qemu-kvm` + `modprobe kvm_intel`/`kvm_amd`; ensure `/dev/kvm` is accessible to the runner user |
| `/dev/net/tun` | Per-VM TAP networking | `modprobe tun` |
| cgroup v2 unified hierarchy (`cpu`,`memory`,`pids`) | Resource-limit enforcement | kernel ≥ 5.x with `systemd.unified_cgroup_hierarchy=1` |
| Firecracker + jailer (pinned, static/musl) | Runtime adapter, binary provenance gate | provided by `devenv shell` (pinned v1.16.1 release) |
| Docker (daemon running) | Firecracker-vs-Docker benchmark lane | `apt-get install docker.io`; `systemctl enable --now docker`; runner user in `docker` group |
| Nix | devenv + toolchain | `cachix/install-nix-action` installs it per job, or install Nix on the host |
| e2fsprogs (`mkfs.ext4`, `debugfs`) | guest rootfs build / payload extraction | `apt-get install e2fsprogs` |

`devenv shell` supplies the pinned Rust toolchain, Firecracker/jailer, and the
Linux VM tooling; the host must supply the kernel-level substrate (KVM, tun,
cgroup v2) and a running Docker daemon that devenv cannot provide.

### 2.2 Register the self-hosted runner

1. In the GitHub repo, open **Settings → Actions → Runners → New self-hosted
   runner** and select **Linux / x64**.
2. On the runner host, download and configure the runner actions package using
   the token from that page:

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

   The `--labels` line is the contract: the privileged workflow selects
   `[self-hosted, linux, x86_64, kvm]`, so all four labels must be present.

3. Install and start the runner as a service so it survives reboots:

   ```bash
   sudo ./svc.sh install
   sudo ./svc.sh start
   sudo ./svc.sh status
   ```

4. Confirm the runner is idle in **Settings → Actions → Runners** before
   triggering a build.

> **Security note.** Self-hosted runners execute privileged code with `sudo`.
> Only run them on ephemeral or dedicated hosts, never on a machine that holds
> secrets or credentials unrelated to this repo. See
> [../security.md](../security.md).

### 2.3 Runner labels and workflow triggers

| Workflow | Trigger | Runner selector | Gating |
| --- | --- | --- | --- |
| `deterministic.yml` | `push` to `main`, `pull_request` to `main` | `ubuntu-latest` | none |
| `privileged.yml` | `workflow_dispatch`, `pull_request` (`opened`/`synchronize`/`reopened`/`labeled`) | `[self-hosted, linux, x86_64, kvm]` | PR runs only when the `privileged` label is present; manual dispatch always runs |

To run the privileged lane on a PR, add the `privileged` label. Remove and
re-add the label (or push a new commit) to re-trigger.

---

## 3. Verify the setup

```bash
# Deterministic lane is GitHub-hosted — open any PR to main and watch the
# "deterministic lane (ubuntu-latest)" job.

# Privileged lane — from the repo Actions tab, run the "privileged" workflow
# manually (workflow_dispatch), or label a PR 'privileged'. Confirm:
#   1. the job is picked up by the self-hosted kvm runner,
#   2. run-privileged-suite.sh reports its PASS/FAIL/SKIP summary,
#   3. the "privileged-benchmark-artifacts" workflow artifact is downloadable
#      and contains summary.json + task-27-benchmark.json.
```

A blocked host (no KVM, no Docker, cgroup v1) makes the privileged suite emit
`blocked` evidence rather than a mocked pass; fix the host substrate above
before re-running.
