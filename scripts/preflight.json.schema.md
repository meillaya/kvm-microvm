# Preflight JSON shape

`scripts/preflight.sh` is a read-only host capability probe. Every
invocation that reaches `main()` emits a single JSON object whose shape
matches the JSON Schema at
[`schemas/evidence-host-preflight.v1.json`](../schemas/evidence-host-preflight.v1.json)
(see `schemas/README.md`).

The script:

- Never mutates sysctls, namespaces, or kernel module state.
- Never opens `/dev/kvm` with write-only intent.
- Always writes the JSON to `--json <path>` atomically (temp + `mv`) when
  the flag is supplied, and additionally to `${PWD}/.preflight/host.json`
  (gitignored) for downstream lane consumers.

## CLI

| Flag             | Behaviour                                                        |
|------------------|------------------------------------------------------------------|
| `--json <path>`  | Emit JSON to `<path>` (atomic temp + `mv`). Required for CI use. |
| `--strict`       | Treat warnings (exit-2 conditions) as blockers (exit 77).        |
| `--help`         | Print usage and exit 0.                                          |

## Exit codes

| Code | Meaning                                                                     |
|------|-----------------------------------------------------------------------------|
| `0`  | Fully capable: no blockers, no degraded warnings.                           |
| `2`  | Degraded: warnings present, no blockers. Lane may proceed with a caveat.    |
| `77` | Blocked: one or more blockers. Privileged lane must not run.                |

## JSON shape

```jsonc
{
  "class": "host_preflight",           // discriminator (constant)
  "host": {
    "os":     "string",                // /etc/os-release PRETTY_NAME (parsed, never sourced)
    "arch":   "string",                // uname -m
    "kernel": "string",                // uname -r
    "nix":    "string"                 // `nix --version`, or "unavailable"
  },
  "cpu": {
    "vendor": "string",                // /proc/cpuinfo vendor_id
    "virt":   true,                    // VMX (Intel) or SVM (AMD) flag present
    "nested": true                     // /sys/module/kvm_{intel,amd}/parameters/nested
  },
  "kvm": {
    "device":      "/dev/kvm",
    "mode":        "0660",             // octal string from stat -c '0%Lp'
    "uid":         0,                  // stat.st_uid
    "gid":         992,                // stat.st_gid
    "accessible":  true,               // open succeeded (see toolchain note)
    "api_version": -1                  // -1 when not probed; see toolchain note
  },
  "tap": {
    "device":     "/dev/net/tun",
    "mode":       "0660",              // octal string from stat
    "accessible": true                 // open succeeded (see toolchain note)
  },
  "cgroup_v2": {
    "unified":     true,               // /sys/fs/cgroup/cgroup.controllers exists
    "controllers": ["cpu","memory","pids","io","cpuset","freezer"]
  },
  "tools": {
    "firecracker": {
      "version":    "Firecracker v1.16.1", // output of `firecracker --version`
      "path":       "/usr/bin/firecracker",
      "sha256":     "<lowercase hex>",
      "accessible": true
    },
    "jailer":      { ... }              // same shape
  },
  "mitigations": {
    "spectre_v2":      "mitigated",
    "meltdown":        "mitigated",
    "mds":             "mitigated",
    "tsx_async_abort": "not affected",
    "itlb_multihit":   "not affected"
    // … any key the kernel exposes under
    // /sys/devices/system/cpu/vulnerabilities/*. The schema accepts
    // arbitrary additional mitigation keys (additionalProperties: { type: string }).
  },
  "blockers":       ["kvm_unavailable", "firecracker_binary_missing", ...],
  "warnings":       ["nested_unavailable", "kvm_api_version_unprobed_in_bash", ...],
  "blocked_reason": "Host /dev/kvm is not accessible to this process."   // string | null
}
```

## Toolchain limitation

Pure Bash cannot issue `ioctl(2)`. The preflight script therefore cannot
actually run `KVM_GET_API_VERSION` (or `TUNGETFEATURES`) from inside Bash.
When the device is openable via `exec 3< /dev/kvm` (O_RDONLY), the script
records `kvm.accessible = true` and `kvm.api_version = -1` and emits the
warning token `kvm_api_version_unprobed_in_bash` so a reviewer can see the
gap. A future privileged-host runner should ship a small companion
`kvm-probe` binary (one-line C program calling `open(O_RDONLY|O_CLOEXEC)`
then `ioctl(fd, KVM_GET_API_VERSION, 0)`) to refine `api_version` and
re-classify `accessible` against the schema's strict O_RDWR+ioctl
semantics. This is a documented gap; the script
continues to emit a complete, schema-valid JSON object on every invocation
so downstream tooling can always parse the file.

## Example payload

The full positive reference fixture lives at
[`schemas/examples/host-preflight-ok.json`](../schemas/examples/host-preflight-ok.json).
A truncated example:

```json
{
  "class": "host_preflight",
  "host": {
    "os": "CachyOS",
    "arch": "x86_64",
    "kernel": "7.1.3-2-cachyos",
    "nix": "nix (Determinate Nix 3.21.7) 2.34.8"
  },
  "cpu": { "vendor": "AuthenticAMD", "virt": true, "nested": false },
  "kvm": { "device": "/dev/kvm", "mode": "0666", "uid": 0, "gid": 990,
           "accessible": true, "api_version": -1 },
  "tap": { "device": "/dev/net/tun", "mode": "0666", "accessible": true },
  "cgroup_v2": {
    "unified": true,
    "controllers": ["cpuset","cpu","memory","io","pids","rdma","misc"]
  },
  "tools": {
    "firecracker": {
      "version": "unavailable", "path": "", "sha256": "unavailable",
      "accessible": false
    },
    "jailer": {
      "version": "unavailable", "path": "", "sha256": "unavailable",
      "accessible": false
    }
  },
  "mitigations": {
    "spectre_v2": "mitigated", "meltdown": "mitigated",
    "mds": "mitigated", "tsx_async_abort": "not affected"
  },
  "blockers": [
    "firecracker_binary_missing", "jailer_binary_missing",
    "kvm_api_version_unprobed_in_bash"
  ],
  "warnings": ["nested_unavailable"],
  "blocked_reason": "Firecracker binary not found at /usr/bin/firecracker, /usr/local/bin/firecracker, or on PATH."
}
```

## Validation

If `python3` and `jsonschema` are available, the emitted JSON can be
validated against the committed schema:

```bash
bash scripts/preflight.sh --json /tmp/preflight.json
python3 -m jsonschema \
    --schema schemas/evidence-host-preflight.v1.json \
    --instance /tmp/preflight.json
```

If `jsonschema` is not installed (for example on a lean container image),
the script still emits a schema-shaped JSON object; validation is deferred
to the CI lane (`devenv shell -- bash scripts/preflight.sh --strict && devenv shell -- bash scripts/run-privileged-suite.sh`) where the toolchain
is fully provisioned.

## Stable token vocabulary

The `blockers` and `warnings` arrays use stable machine-readable tokens so
the privileged lane can branch without parsing `blocked_reason`:

| Token                                 | Kind    | Meaning                                                                  |
| ------------------------------------- | ------- | ------------------------------------------------------------------------ |
| `cpu_virt_unavailable`                | blocker | `/proc/cpuinfo` flags do not include VMX or SVM.                         |
| `kvm_unavailable`                     | blocker | `/dev/kvm` is missing or unreadable by this process.                     |
| `kvm_api_version_unprobed_in_bash`    | warning | KVM open succeeded; `KVM_GET_API_VERSION` not issued (pure-Bash gap).    |
| `tun_unavailable`                     | blocker | `/dev/net/tun` is missing or unreadable by this process.                 |
| `cgroup_v2_missing`                   | blocker | `/sys/fs/cgroup/cgroup.controllers` is not present.                      |
| `cgroup_v2_controller_missing:<name>` | blocker | A required controller (`cpu`, `memory`, `pids`) is not exposed.          |
| `firecracker_binary_missing`          | blocker | Firecracker binary not found at standard paths or on `PATH`.             |
| `jailer_binary_missing`               | blocker | Jailer binary not found at standard paths or on `PATH`.                  |
| `nested_unavailable`                  | warning | Nested virtualization not advertised by `/sys/module/kvm_*/parameters/`. |
| `nft_cli_unavailable`                 | warning | `nft` not found on `PATH`.                                               |
| `jq_missing`                          | blocker | `jq` is required and not installed.                                      |
