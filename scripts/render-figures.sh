#!/usr/bin/env bash
# render-figures.sh: render the architecture Excalidraw scenes to PNG.
#
# Renders, with the installed Excalidraw CLI at scale 2 and max-width 3200:
#   docs/figures/architecture.excalidraw     -> docs/figures/architecture.png
#   docs/figures/lifecycle.excalidraw        -> docs/figures/lifecycle.png
#   docs/figures/snapshot-restore.excalidraw -> docs/figures/snapshot-restore.png
#
# Usage:
#   bash scripts/render-figures.sh                 # render all three scenes
#   bash scripts/render-figures.sh <scene> [...]    # render specific scenes (no .excalidraw suffix)
#
# Environment overrides:
#   FIGURES_DIR   directory holding the .excalidraw scenes (default: docs/figures)
#   OUT_DIR       directory for the rendered PNGs (default: FIGURES_DIR)
#   SCALE         render scale (default: 2)
#   MAX_WIDTH     maximum PNG width in pixels (default: 3200)
#
# The script is render-only: it does not edit the scenes or docs, and it fails
# with a clear message when the Excalidraw CLI or a scene file is missing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FIGURES_DIR="${FIGURES_DIR:-$REPO_ROOT/docs/figures}"
OUT_DIR="${OUT_DIR:-$FIGURES_DIR}"
SCALE="${SCALE:-2}"
MAX_WIDTH="${MAX_WIDTH:-3200}"

if (($# > 0)); then
  SCENES=("$@")
else
  SCENES=(architecture lifecycle snapshot-restore)
fi

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

command -v excalidraw >/dev/null 2>&1 \
  || die "the Excalidraw CLI is not installed (expected 'excalidraw' on PATH)"

[[ -d "$FIGURES_DIR" ]] || die "figures directory not found: $FIGURES_DIR"
mkdir -p "$OUT_DIR"

# Validate every requested scene up front so a typo fails before rendering.
missing=0
for scene in "${SCENES[@]}"; do
  if [[ ! -f "$FIGURES_DIR/$scene.excalidraw" ]]; then
    printf 'ERROR: missing Excalidraw scene: %s\n' "$FIGURES_DIR/$scene.excalidraw" >&2
    missing=1
  fi
done
((missing == 0)) || exit 1

pngs=()
for scene in "${SCENES[@]}"; do
  src="$FIGURES_DIR/$scene.excalidraw"
  out="$OUT_DIR/$scene.png"
  printf '==> rendering %s -> %s (scale %s, max-width %s)\n' "$src" "$out" "$SCALE" "$MAX_WIDTH"
  excalidraw render "$src" --out "$out" --scale "$SCALE" --max-width "$MAX_WIDTH"
  [[ -s "$out" ]] || die "render did not produce a non-empty PNG: $out"
  pngs+=("$out")
done

printf '\n==> rendered figures:\n'
ls -lh -- "${pngs[@]}"
