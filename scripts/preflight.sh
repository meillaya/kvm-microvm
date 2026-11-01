#!/usr/bin/env bash
# scripts/preflight.sh: read-only host capability probe.
#
# Detects host OS / arch / kernel / Nix version; CPU vendor + VMX/SVM + nested;
# /dev/kvm device mode/uid/gid + open + (best-effort) KVM_GET_API_VERSION probe;
# /dev/net/tun device mode + open + (best-effort) TUNGETFEATURES probe;
# cgroup-v2 unified mount + controller list; Firecracker and jailer binary
# presence / version / sha256; CPU mitigation status from
# /sys/devices/system/cpu/vulnerabilities/*; nft CLI availability.
#
# Exit codes:
#   0   host is fully capable (no blockers, no degraded warnings).
#   2   host is degraded (warnings present; lane may proceed with caveat).
#   77  host is blocked (one or more blockers).
#
# Flags:
#   --json <path>   Always emit JSON to <path> (atomic temp + mv).
#   --strict        Treat warnings (exit-2 conditions) as blockers (exit 77).
#   --help          Print usage and exit 0.
#
# Toolchain policy:
#   This script sources NOTHING from outside the repo (no `. /etc/...` or
#   `source /path/to/external-script`). /etc/os-release is parsed with grep
#   and sed, never sourced. The script requires only standard POSIX utilities
#   plus `jq`, `ip`, `nft`, and `sha256sum`. It never mutates sysctls, never
#   creates namespaces, never loads kernel modules, and never opens /dev/kvm
#   with write-only intent.
#
# Toolchain limitation (documented):
#   Pure Bash cannot issue ioctl(2). The script therefore cannot run
#   KVM_GET_API_VERSION or TUNGETFEATURES from inside Bash. The KVM probe
#   reports the device as openable when `exec 3< /dev/kvm` succeeds, and
#   always sets `kvm.api_version = -1`. The TUN probe reports
#   `tap.accessible` based on whether the device is openable. The warning
#   token `kvm_api_version_unprobed_in_bash` is emitted whenever /dev/kvm
#   is openable, recording the gap. A future privileged-host runner should
#   ship a small `kvm-probe` companion binary to refine `api_version` and
#   the `accessible` flag to the schema's strict O_RDWR+ioctl semantics.

set -u
LC_ALL=C
export LC_ALL

PROG="${0##*/}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-5}"  # seconds; per external command

JSON_PATH=""
STRICT=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: preflight.sh [--json <path>] [--strict] [--help]

Read-only host capability probe for kvm-microvm-orchestrator.

  --json <path>   Emit JSON to <path> atomically (temp + mv). Required for CI.
  --strict        Treat warnings as blockers (exit 77 instead of 2).
  --help          Print this message and exit 0.

Exit codes:
  0   fully capable (no blockers, no degraded warnings)
  2   degraded (warnings present; blocked under --strict)
  77  blocked (one or more blockers)
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)
            [[ $# -ge 2 ]] || { echo "$PROG: --json requires a path" >&2; exit 2; }
            JSON_PATH="$2"
            shift 2
            ;;
        --strict)
            STRICT=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "$PROG: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Toolchain gate
# ---------------------------------------------------------------------------
require_tool() {
    local t="$1"
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "$PROG: required tool missing: $t" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Helper: parse /etc/os-release without sourcing it.
# ---------------------------------------------------------------------------
parse_os_release() {
    local f="${1:-/etc/os-release}"
    [[ -r "$f" ]] || { uname -s 2>/dev/null || echo "Linux"; return; }
    local name
    name=$(grep -E '^PRETTY_NAME=' "$f" 2>/dev/null | head -n1 \
        | sed -e 's/^PRETTY_NAME=//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
    if [[ -z "$name" ]]; then
        name=$(grep -E '^NAME=' "$f" 2>/dev/null | head -n1 \
            | sed -e 's/^NAME=//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
    fi
    [[ -z "$name" ]] && name=$(uname -s 2>/dev/null || echo "Linux")
    printf '%s' "$name"
}

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------
probe_arch() {
    uname -m 2>/dev/null || echo "unknown"
}

probe_kernel() {
    uname -r 2>/dev/null || echo "unknown"
}

probe_os() {
    parse_os_release /etc/os-release
}

probe_nix() {
    if command -v nix >/dev/null 2>&1; then
        timeout "$PROBE_TIMEOUT" nix --version 2>/dev/null | head -n1 \
            | tr -d '\n' || echo "unavailable"
    else
        echo "unavailable"
    fi
}

probe_cpu() {
    local vendor="unknown" virt="false" flags=""
    if [[ -r /proc/cpuinfo ]]; then
        vendor=$(awk -F': ' '/^vendor_id[ \t]*:/ {gsub(/[ \t]+$/,"",$2); print $2; exit}' \
            /proc/cpuinfo 2>/dev/null)
        flags=$(awk -F': ' '/^flags[ \t]*:/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)
    fi
    case "$flags" in
        *\ vmx\ *|*\ svm\ *|*\ vmx|*\ svm) virt="true" ;;
        *) virt="false" ;;
    esac
    [[ -z "$vendor" ]] && vendor="unknown"
    jq -n --arg v "$vendor" --argjson virt "$virt" \
        '{vendor: $v, virt: $virt, nested: false}'
}

probe_nested() {
    if [[ -r /sys/module/kvm_intel/parameters/nested ]]; then
        local v
        v=$(awk '{print toupper($1)}' /sys/module/kvm_intel/parameters/nested 2>/dev/null \
            | head -n1)
        case "$v" in
            1|Y|TRUE|YES|ON) echo "true"; return ;;
            *) echo "false"; return ;;
        esac
    fi
    if [[ -r /sys/module/kvm_amd/parameters/nested ]]; then
        local v
        v=$(awk '{print toupper($1)}' /sys/module/kvm_amd/parameters/nested 2>/dev/null \
            | head -n1)
        case "$v" in
            1|Y|TRUE|YES|ON) echo "true"; return ;;
            *) echo "false"; return ;;
        esac
    fi
    echo "false"
}

# Best-effort KVM probe. Pure Bash cannot issue KVM_GET_API_VERSION, so
# api_version is always -1 from this script. accessible is set to true when
# the device exists AND `exec 3< /dev/kvm` (O_RDONLY) succeeds, i.e. when the
# process can read the device. The schema's strict definition requires O_RDWR
# + successful ioctl; we honor that intent by also emitting the
# kvm_api_version_unprobed_in_bash warning whenever accessible=true, so a
# reviewer sees the gap.
probe_kvm() {
    local device="/dev/kvm" mode="0000" uid=0 gid=0 accessible="false" api_version="-1"
    if [[ -e "$device" ]]; then
        local stat_out
        stat_out=$(stat -c '0%a %u %g' -- "$device" 2>/dev/null || true)
        if [[ -n "$stat_out" ]]; then
            # shellcheck disable=SC2086
            set -- $stat_out
            mode="$1"; uid="$2"; gid="$3"
        fi
        if timeout "$PROBE_TIMEOUT" bash -c "exec 3< '$device'" 2>/dev/null; then
            accessible="true"
            exec 3<&- 2>/dev/null || true
        fi
    fi
    jq -n --arg d "$device" --arg m "$mode" --argjson u "$uid" --argjson g "$gid" \
        --argjson a "$accessible" --argjson v "$api_version" \
        '{device: $d, mode: $m, uid: $u, gid: $g, accessible: $a, api_version: $v}'
}

# Best-effort TUN probe. Same constraint: TUNGETFEATURES is an ioctl that
# pure Bash cannot issue. accessible reflects whether the process can open
# the device O_RDONLY.
probe_tap() {
    local device="/dev/net/tun" mode="0000" accessible="false"
    if [[ -e "$device" ]]; then
        local stat_out
        stat_out=$(stat -c '0%a' -- "$device" 2>/dev/null || true)
        [[ -n "$stat_out" ]] && mode="$stat_out"
        if timeout "$PROBE_TIMEOUT" bash -c "exec 3< '$device'" 2>/dev/null; then
            accessible="true"
            exec 3<&- 2>/dev/null || true
        fi
    fi
    jq -n --arg d "$device" --arg m "$mode" --argjson a "$accessible" \
        '{device: $d, mode: $m, accessible: $a}'
}

probe_cgroup_v2() {
    local unified="false" controllers="[]"
    if [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
        unified="true"
        controllers=$(jq -R 'split(" ") | map(select(length > 0))' \
            < /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo "[]")
    fi
    jq -n --argjson u "$unified" --argjson c "$controllers" \
        '{unified: $u, controllers: $c}'
}

# Generic tool probe: search candidate paths in order, then `which`. Capture
# version from `--version`. Compute sha256 when readable.
probe_tool() {
    local label="$1"; shift
    local version="unavailable" path="" sha256="unavailable" accessible="false"
    local candidate
    for candidate in "$@"; do
        if [[ -x "$candidate" ]]; then
            path="$candidate"
            accessible="true"
            break
        fi
    done
    if [[ "$accessible" != "true" ]]; then
        local w
        w=$(command -v "$label" 2>/dev/null || true)
        if [[ -n "$w" && -x "$w" ]]; then
            path="$w"
            accessible="true"
        fi
    fi
    if [[ "$accessible" == "true" ]]; then
        local v
        v=$(timeout "$PROBE_TIMEOUT" "$path" --version 2>&1 | head -n1 | tr -d '\n' || true)
        if [[ -n "$v" ]]; then
            version="$v"
        else
            version="unavailable"
        fi
        if [[ -r "$path" ]] && command -v sha256sum >/dev/null 2>&1; then
            local h
            h=$(timeout "$PROBE_TIMEOUT" sha256sum -- "$path" 2>/dev/null \
                | awk '{print $1}' | head -n1 || true)
            if [[ -n "$h" ]]; then
                sha256="$h"
            fi
        fi
    fi
    jq -n --arg v "$version" --arg p "$path" --arg s "$sha256" --argjson a "$accessible" \
        '{version: $v, path: $p, sha256: $s, accessible: $a}'
}

probe_firecracker() {
    probe_tool firecracker /usr/bin/firecracker /usr/local/bin/firecracker
}

probe_jailer() {
    probe_tool jailer /usr/bin/jailer /usr/local/bin/jailer
}

probe_mitigations() {
    local dir="/sys/devices/system/cpu/vulnerabilities"
    local out='{}'
    if [[ -d "$dir" ]]; then
        local f key val
        for f in "$dir"/*; do
            [[ -f "$f" ]] || continue
            key=$(basename -- "$f")
            val=$(awk 'NR==1 {print $2; exit}' "$f" 2>/dev/null || true)
            [[ -z "$val" ]] && continue
            out=$(jq --arg k "$key" --arg v "$val" '. + {($k): $v}' <<<"$out" 2>/dev/null \
                || echo "$out")
        done
    fi
    # Always include spectre_v2 and meltdown; if missing, mark unavailable.
    if [[ "$(jq -r 'has("spectre_v2")' <<<"$out" 2>/dev/null || echo false)" != "true" ]]; then
        out=$(jq --arg v "unavailable" '. + {spectre_v2: $v}' <<<"$out" 2>/dev/null \
            || echo "$out")
    fi
    if [[ "$(jq -r 'has("meltdown")' <<<"$out" 2>/dev/null || echo false)" != "true" ]]; then
        out=$(jq --arg v "unavailable" '. + {meltdown: $v}' <<<"$out" 2>/dev/null \
            || echo "$out")
    fi
    jq . <<<"$out" 2>/dev/null || echo '{"spectre_v2":"unavailable","meltdown":"unavailable"}'
}

probe_nft_available() {
    if command -v nft >/dev/null 2>&1; then
        echo "true"
    else
        echo "false"
    fi
}

# ---------------------------------------------------------------------------
# Blockers / warnings
# ---------------------------------------------------------------------------
derive_blockers_warnings() {
    local cpu="$1" kvm="$2" tap="$3" cgroup="$4" tools="$5" nested="$6" nft_ok="$7"
    local blockers=()
    local warnings=()
    local reason=""

    # CPU virtualization
    local virt
    virt=$(jq -r '.virt' <<<"$cpu" 2>/dev/null || echo "false")
    if [[ "$virt" != "true" ]]; then
        blockers+=("cpu_virt_unavailable")
        reason="CPU virtualization extensions (VMX/SVM) are not advertised by the kernel."
    fi

    # KVM
    local kvm_accessible kvm_api
    kvm_accessible=$(jq -r '.accessible' <<<"$kvm" 2>/dev/null || echo "false")
    kvm_api=$(jq -r '.api_version' <<<"$kvm" 2>/dev/null || echo "-1")
    if [[ "$kvm_accessible" != "true" ]]; then
        blockers+=("kvm_unavailable")
        reason="Host /dev/kvm is not accessible to this process (device missing or unreadable)."
    else
        # Open succeeded; flag the api-version probe gap as a warning so
        # reviewers see the toolchain limitation.
        warnings+=("kvm_api_version_unprobed_in_bash")
    fi

    # TUN
    local tap_accessible
    tap_accessible=$(jq -r '.accessible' <<<"$tap" 2>/dev/null || echo "false")
    if [[ "$tap_accessible" != "true" ]]; then
        blockers+=("tun_unavailable")
        if [[ -z "$reason" ]]; then
            reason="Host /dev/net/tun is not accessible to this process."
        fi
    fi

    # cgroup v2
    local cgroup_unified
    cgroup_unified=$(jq -r '.unified' <<<"$cgroup" 2>/dev/null || echo "false")
    if [[ "$cgroup_unified" != "true" ]]; then
        blockers+=("cgroup_v2_missing")
        if [[ -z "$reason" ]]; then
            reason="Cgroup v2 unified hierarchy is not mounted at /sys/fs/cgroup."
        fi
    else
        local ctrl
        for ctrl in cpu memory pids; do
            if ! jq -e --arg c "$ctrl" '.controllers | index($c) != null' \
                    <<<"$cgroup" >/dev/null 2>&1; then
                blockers+=("cgroup_v2_controller_missing:$ctrl")
                if [[ -z "$reason" ]]; then
                    reason="Cgroup v2 controller '$ctrl' is not exposed by the parent cgroup."
                fi
            fi
        done
    fi

    # Tools
    local fc_acc
    fc_acc=$(jq -r '.firecracker.accessible' <<<"$tools" 2>/dev/null || echo "false")
    if [[ "$fc_acc" != "true" ]]; then
        blockers+=("firecracker_binary_missing")
        if [[ -z "$reason" ]]; then
            reason="Firecracker binary not found at /usr/bin/firecracker, /usr/local/bin/firecracker, or on PATH."
        fi
    fi
    local jailer_acc
    jailer_acc=$(jq -r '.jailer.accessible' <<<"$tools" 2>/dev/null || echo "false")
    if [[ "$jailer_acc" != "true" ]]; then
        blockers+=("jailer_binary_missing")
        if [[ -z "$reason" ]]; then
            reason="Jailer binary not found at /usr/bin/jailer, /usr/local/bin/jailer, or on PATH."
        fi
    fi

    # Warnings
    if [[ "$nested" != "true" ]]; then
        warnings+=("nested_unavailable")
    fi
    if [[ "$nft_ok" != "true" ]]; then
        warnings+=("nft_cli_unavailable")
    fi

    # Serialize arrays
    local blockers_json warnings_json
    if [[ ${#blockers[@]} -gt 0 ]]; then
        blockers_json=$(printf '%s\n' "${blockers[@]}" | jq -R 'select(length>0)' | jq -s 'map(.)')
    else
        blockers_json="[]"
    fi
    if [[ ${#warnings[@]} -gt 0 ]]; then
        warnings_json=$(printf '%s\n' "${warnings[@]}" | jq -R 'select(length>0)' | jq -s 'map(.)')
    else
        warnings_json="[]"
    fi

    jq -n --argjson b "$blockers_json" --argjson w "$warnings_json" \
        --arg r "${reason:-}" \
        '{
            blockers: $b,
            warnings: $w,
            blocked_reason: (if ($r | length) > 0 then $r else null end)
        }'
}

# ---------------------------------------------------------------------------
# JSON emission
# ---------------------------------------------------------------------------
emit_json() {
    local json="$1"

    # 1) Print to stdout always (so users can pipe).
    printf '%s\n' "$json"

    # 2) Atomic write to --json path if requested.
    if [[ -n "$JSON_PATH" ]]; then
        local dir
        dir=$(dirname -- "$JSON_PATH")
        if [[ -n "$dir" && "$dir" != "." ]]; then
            mkdir -p "$dir" 2>/dev/null || true
        fi
        local tmp="${JSON_PATH}.tmp.$$"
        if printf '%s\n' "$json" > "$tmp" 2>/dev/null; then
            mv -f "$tmp" "$JSON_PATH" 2>/dev/null \
                || printf '%s\n' "$json" > "$JSON_PATH" 2>/dev/null || true
            rm -f "$tmp" 2>/dev/null || true
        else
            # Last resort: write in-place.
            printf '%s\n' "$json" > "$JSON_PATH" 2>/dev/null || true
        fi
    fi

    # 3) Convenience write to gitignored ${PWD}/.preflight/host.json.
    #    This is the only path the script writes to outside --json.
    if [[ -n "${PWD:-}" ]] && [[ -w "${PWD:-}" || -w "${PWD:-}/.preflight" || ! -e "${PWD:-}/.preflight" ]]; then
        mkdir -p .preflight 2>/dev/null || true
        if [[ -d .preflight ]]; then
            printf '%s\n' "$json" > .preflight/host.json 2>/dev/null || true
        fi
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # Hard requirement: jq (without jq we cannot construct JSON).
    if ! require_tool jq; then
        echo '{"class":"host_preflight","error":"jq_missing","blockers":["jq_missing"],"warnings":[],"blocked_reason":"jq is required to construct preflight JSON."}' >&2
        exit 77
    fi

    local os arch kernel nix
    os=$(probe_os)
    arch=$(probe_arch)
    kernel=$(probe_kernel)
    nix=$(probe_nix)

    local host_json cpu_json kvm_json tap_json cgroup_json tools_json mit_json
    local nested_bool nft_ok

    host_json=$(jq -n --arg os "$os" --arg arch "$arch" --arg kernel "$kernel" --arg nix "$nix" \
        '{os: $os, arch: $arch, kernel: $kernel, nix: $nix}')

    cpu_json=$(probe_cpu)
    nested_bool=$(probe_nested)
    cpu_json=$(jq --argjson n "$nested_bool" '. + {nested: $n}' <<<"$cpu_json")

    kvm_json=$(probe_kvm)
    tap_json=$(probe_tap)
    cgroup_json=$(probe_cgroup_v2)

    local fc jailer
    fc=$(probe_firecracker)
    jailer=$(probe_jailer)
    tools_json=$(jq -n --argjson f "$fc" --argjson j "$jailer" \
        '{firecracker: $f, jailer: $j}')

    mit_json=$(probe_mitigations)
    nft_ok=$(probe_nft_available)

    local bw
    bw=$(derive_blockers_warnings "$cpu_json" "$kvm_json" "$tap_json" \
        "$cgroup_json" "$tools_json" "$nested_bool" "$nft_ok")

    local payload
    payload=$(jq -n \
        --arg class "host_preflight" \
        --argjson host "$host_json" \
        --argjson cpu "$cpu_json" \
        --argjson kvm "$kvm_json" \
        --argjson tap "$tap_json" \
        --argjson cg "$cgroup_json" \
        --argjson tools "$tools_json" \
        --argjson mit "$mit_json" \
        --argjson bw "$bw" \
        '{
            class: $class,
            host: $host,
            cpu: $cpu,
            kvm: $kvm,
            tap: $tap,
            cgroup_v2: $cg,
            tools: $tools,
            mitigations: $mit,
            blockers: $bw.blockers,
            warnings: $bw.warnings,
            blocked_reason: $bw.blocked_reason
        }')

    emit_json "$payload"

    local nblockers nwarnings
    nblockers=$(jq -r '.blockers | length' <<<"$payload" 2>/dev/null || echo 0)
    nwarnings=$(jq -r '.warnings | length' <<<"$payload" 2>/dev/null || echo 0)

    if [[ "$nblockers" -gt 0 ]]; then
        exit 77
    fi
    if [[ "$STRICT" -eq 1 && "$nwarnings" -gt 0 ]]; then
        exit 77
    fi
    if [[ "$nwarnings" -gt 0 ]]; then
        exit 2
    fi
    exit 0
}

main "$@"
