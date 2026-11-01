# Architecture figures

The architecture page uses four Excalidraw scenes. Each scene and its rendered
PNG live in this directory, and `generate.py` writes the scenes from one source.

| Scene | Figure |
| --- | --- |
| `component-topology.excalidraw` | Five components and their evidence boundaries. |
| `transport-path.excalidraw` | REST and gRPC adapters over one service contract. |
| `isolation-boundaries.excalidraw` | Jailer, cgroup, network namespace, and nftables boundaries. |
| `snapshot-gate.excalidraw` | The pre-restore compatibility gate. |

## Regenerate

Edit `generate.py`, then write the scenes and render every PNG:

```bash
python3 -B docs/figures/generate.py

export EXCALIDRAW_BROWSER_PATH="/path/to/chrome-or-chromium"
for scene in component-topology transport-path isolation-boundaries snapshot-gate; do
  excalidraw render "docs/figures/$scene.excalidraw" \
    --out "docs/figures/$scene.png" \
    --scale 2 --max-width 3200
done
```

The Excalidraw CLI drives Chrome, Chromium, Edge, or Firefox. On Linux, the
packaged `excalidraw` wrapper already points at Chrome. On macOS, set
`EXCALIDRAW_BROWSER_PATH` to a Chromium-based browser binary.

## Check before committing

- The scene and the PNG are both present and current.
- Every box label fits inside its box.
- Every arrow has a label near the arrow, and no arrow crosses text.
- The smallest text is readable when the PNG is 700 px wide.
- Colors match the role palette in the house drawing rules.

The scenes use the palette and defaults from `agents/excalidraw.nix` in the
nixos repository: roughness 2, hachure fills, 2-unit strokes, Virgil text, and a
white background.
