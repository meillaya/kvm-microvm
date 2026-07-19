#!/usr/bin/env bash
# scripts/run-privileged-tests.sh — privileged-lane placeholder.
#
# Runs the privileged test gate when a privileged host runner is available.
# For now this only re-runs the strict preflight (scripts/preflight.sh --strict)
# and exits 0 on success / 77 on failure. Real privileged tests will be added
# by later waves.

set -u
LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "$PROG: running privileged-lane preflight (--strict)..."

if ! bash "$SCRIPT_DIR/preflight.sh" --strict; then
    rc=$?
    case "$rc" in
        77)
            echo "$PROG: preflight blocked (exit 77); refusing to run privileged tests." >&2
            ;;
        2)
            echo "$PROG: preflight degraded (exit 2); refusing to run privileged tests under --strict." >&2
            ;;
        *)
            echo "$PROG: preflight failed unexpectedly (exit $rc)." >&2
            ;;
    esac
    exit 77
fi

echo "$PROG: preflight passed; no real privileged tests yet (placeholder)."
echo "$PROG: future waves will add: jailer e2e, snapshot/restore, cgroup-v2 migration, networking."
exit 0
