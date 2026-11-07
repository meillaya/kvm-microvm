#!/usr/bin/env bash
# scripts/run-privileged-tests.sh: strict preflight gate for the privileged lane.
#
# This script decides whether the host may run the privileged suite. It runs
# scripts/preflight.sh --strict and exits 0 on success or 77 when the host is
# blocked or degraded. The tests themselves live in run-privileged-suite.sh.

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

echo "$PROG: preflight passed; run the privileged suite with:"
echo "  bash ${SCRIPT_DIR}/run-privileged-suite.sh   # current user, no sudo; scratch under .work/"
exit 0
