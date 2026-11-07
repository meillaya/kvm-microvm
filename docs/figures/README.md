# Figures

The documentation uses three hand-drawn Excalidraw scenes. Each scene file and
its rendered PNG live in this directory. `generate.py` writes the scenes from one
source, so the geometry stays reproducible.

| Scene | Claim |
| --- | --- |
| `architecture.excalidraw` | One daemon owns every VM from a local Unix socket. |
| `lifecycle.excalidraw` | Every VM moves through one checked lifecycle. |
| `snapshot-restore.excalidraw` | Restore checks the manifest before it loads state. |

## Regenerate

Edit `generate.py`, then write the scenes and render every PNG:

```bash
python3 -B docs/figures/generate.py
bash scripts/render-figures.sh
```

The render script covers the three scenes. To run one render by hand:

```bash
excalidraw render docs/figures/architecture.excalidraw \
  --out docs/figures/architecture.png --scale 2 --max-width 3200
```

The Excalidraw CLI drives Chrome, Chromium, Edge, or Firefox. The packaged wrapper
on this host points at Chrome, and a render takes a few seconds.
Set `EXCALIDRAW_BROWSER_PATH` when the browser is not on `PATH`.

## Inspect before you commit

- Open the PNG at the width it appears in the document.
- Check that every text label stays inside its box.
- Check that every arrow has a label near the arrow.
- Check that no arrow crosses text.
- Check that the scene and the PNG are both present and current.

The scenes follow the house drawing rules: 1520 units wide, white background,
roughness 2, hachure fills, 2-unit strokes, Virgil text, and the role palette.
