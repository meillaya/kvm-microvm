#!/usr/bin/env python3
"""Generate the Excalidraw scenes for the microvm documentation.

Run from the repository root:

    python3 -B docs/figures/generate.py

The script writes three .excalidraw files next to this file. Render each scene
with the packaged Excalidraw CLI after changing it:

    excalidraw render docs/figures/architecture.excalidraw \
      --out docs/figures/architecture.png --scale 2 --max-width 3200

The palette, font sizes, canvas width, and composition rules follow
agents/excalidraw.nix in the nixos repository. Keep the scene and the PNG
together, and inspect the PNG before calling a figure done.
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCENE_WIDTH = 1520
MARGIN = 40
BACKGROUND = "#ffffff"
INK = "#1e1e1e"
MUTED = "#5c5f66"

# Role palette from agents/excalidraw.nix. Strokes carry the meaning and fills
# stay pale.
PALETTE = {
    "input": {"stroke": "#1971c2", "fill": "#d0ebff"},
    "cuda": {"stroke": "#e8590c", "fill": "#ffe8cc"},
    "hip": {"stroke": "#2f9e44", "fill": "#d3f9d8"},
    "runtime": {"stroke": "#9c36b5", "fill": "#f3d9fa"},
    "analysis": {"stroke": "#f08c00", "fill": "#fff3bf"},
    "risk": {"stroke": "#e03131", "fill": "#ffe3e3"},
    "model": {"stroke": "#0c8599", "fill": "#c5f6fa"},
    "neutral": {"stroke": "#495057", "fill": "#f1f3f5"},
}

FONT = 1
TITLE_SIZE = 32
BODY_SIZE = 22
NOTE_SIZE = 18


def element(eid, etype, x, y, width, height, **overrides):
    """Build one element with the full field set Excalidraw expects."""
    value = {
        "id": eid,
        "type": etype,
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "angle": 0,
        "strokeColor": INK,
        "backgroundColor": "transparent",
        "fillStyle": "hachure",
        "strokeWidth": 2,
        "strokeStyle": "solid",
        "roughness": 2,
        "opacity": 100,
        "groupIds": [],
        "frameId": None,
        "roundness": {"type": 3},
        "seed": 1000 + len(eid) * 37,
        "version": 1,
        "versionNonce": 1,
        "isDeleted": False,
        "boundElements": [],
        "updated": 1,
        "link": None,
        "locked": False,
    }
    value.update(overrides)
    return value


def text_size(content, size):
    """Estimate the box a text element needs."""
    lines = content.split("\n")
    width = max(len(line) for line in lines) * size * 0.55 + 8
    height = len(lines) * size * 1.25
    return width, height


def text(eid, x, y, content, size=BODY_SIZE, color=INK):
    """Build a standalone text element."""
    width, height = text_size(content, size)
    return element(
        eid,
        "text",
        x,
        y,
        width,
        height,
        strokeColor=color,
        backgroundColor="transparent",
        fillStyle="hachure",
        roundness=None,
        text=content,
        fontSize=size,
        fontFamily=FONT,
        textAlign="left",
        verticalAlign="top",
        containerId=None,
        originalText=content,
        lineHeight=1.25,
        autoResize=True,
    )


def box(eid, x, y, width, height, label, role, size=BODY_SIZE):
    """Build a rounded rectangle with a centered, bound label."""
    colors = PALETTE[role]
    shape = element(
        eid,
        "rectangle",
        x,
        y,
        width,
        height,
        strokeColor=colors["stroke"],
        backgroundColor=colors["fill"],
        roundness={"type": 3},
    )

    label_width, label_height = text_size(label, size)
    label_width = min(label_width, width - 20)
    label_height = min(label_height, height - 12)
    label_element = element(
        f"{eid}-label",
        "text",
        x + (width - label_width) / 2,
        y + (height - label_height) / 2,
        label_width,
        label_height,
        strokeColor=INK,
        backgroundColor="transparent",
        fillStyle="hachure",
        roundness=None,
        text=label,
        fontSize=size,
        fontFamily=FONT,
        textAlign="center",
        verticalAlign="middle",
        containerId=eid,
        originalText=label,
        lineHeight=1.25,
        autoResize=True,
    )
    shape["boundElements"] = [{"type": "text", "id": label_element["id"]}]
    return [shape, label_element]


def arrow(eid, start, end, label, color="neutral", label_offset=(0, -30)):
    """Build a straight labeled arrow from start to end."""
    x1, y1 = start
    x2, y2 = end
    dx = x2 - x1
    dy = y2 - y1
    label_width, _ = text_size(label, NOTE_SIZE)
    mid_x = x1 + dx / 2
    mid_y = y1 + dy / 2
    arrow_element = element(
        eid,
        "arrow",
        x1,
        y1,
        abs(dx),
        abs(dy),
        strokeColor=PALETTE[color]["stroke"],
        backgroundColor="transparent",
        fillStyle="hachure",
        roundness={"type": 2},
        points=[[0, 0], [dx, dy]],
        startArrowhead=None,
        endArrowhead="arrow",
        startBinding=None,
        endBinding=None,
        lastCommittedPoint=None,
    )
    label_element = text(
        f"{eid}-label",
        mid_x + label_offset[0] - label_width / 2,
        mid_y + label_offset[1],
        label,
        size=NOTE_SIZE,
    )
    return [arrow_element, label_element]


def scene(title, claim, elements, height):
    """Assemble one scene with a title, a one-line claim, and body elements."""
    title_width, _ = text_size(title, TITLE_SIZE)
    elements.insert(0, text("subtitle", 0, 86, claim, size=NOTE_SIZE, color=MUTED))
    elements.insert(0, text("title", (SCENE_WIDTH - title_width) / 2, 40, title, size=TITLE_SIZE))
    # Center the subtitle and the claim once their width is known.
    for item in elements[:2]:
        item["x"] = (SCENE_WIDTH - item["width"]) / 2
    return {
        "type": "excalidraw",
        "version": 2,
        "source": "https://excalidraw.com",
        "elements": elements,
        "appState": {
            "gridSize": None,
            "viewBackgroundColor": BACKGROUND,
            "exportBackground": True,
        },
        "files": {},
    }


def architecture():
    """One claim: one local daemon owns every VM and its host resources."""
    elements = []

    # Column 1: local clients.
    elements += box("cli", 60, 170, 300, 90, "microvm CLI", "input")
    elements += box("grpc-client", 60, 310, 300, 90, "local gRPC client", "input")

    # Column 2: socket, daemon, service.
    elements += box("sockets", 580, 170, 360, 90, "Unix sockets\nREST and gRPC", "neutral")
    elements += box(
        "daemon",
        580,
        310,
        360,
        150,
        "microvmd daemon\nREST + gRPC",
        "runtime",
    )
    elements += box(
        "service",
        580,
        520,
        360,
        110,
        "lifecycle service\nvalidates each transition",
        "runtime",
    )

    # Column 3: host isolation and the guest.
    elements += box("cgroup", 1120, 170, 340, 90, "cgroup v2\ncpu, memory, pids", "analysis")
    elements += box("firecracker", 1120, 310, 340, 110, "Firecracker process", "model")
    elements += box("guest", 1120, 470, 340, 110, "guest kernel and rootfs", "neutral")

    # Bottom row: daemon-owned paths and records.
    elements += box("artifacts", 60, 700, 340, 110, "artifacts\nimage content", "analysis")
    elements += box("snapshots", 580, 700, 340, 110, "snapshots\nstate and memory files", "analysis")
    elements += box("logs", 1120, 700, 340, 110, "logs\nreadiness and errors", "neutral")

    elements += arrow("cli-sockets", (360, 215), (580, 215), "REST/JSON", label_offset=(0, -32))
    elements += arrow("grpc-client-sockets", (360, 355), (580, 250), "gRPC", label_offset=(0, -30))
    elements += arrow("sockets-daemon", (760, 260), (760, 310), "peer check", label_offset=(120, 0))
    elements += arrow("daemon-service", (760, 460), (760, 520), "typed request", label_offset=(122, 0))
    elements += arrow(
        "service-firecracker",
        (940, 575),
        (1120, 365),
        "spawns and controls",
        label_offset=(-20, -46),
    )
    elements += arrow("firecracker-guest", (1290, 420), (1290, 470), "boots image", label_offset=(122, -12))
    elements += arrow("firecracker-cgroup", (1290, 310), (1290, 260), "runs inside", label_offset=(120, -10))
    elements += arrow("daemon-artifacts", (580, 420), (400, 700), "image hashes", label_offset=(-18, -34))
    elements += arrow("service-snapshots", (760, 630), (750, 700), "writes manifest", label_offset=(-120, 0))
    elements += arrow("service-logs", (930, 630), (1180, 700), "logs each call", label_offset=(0, -38))

    return scene(
        "One daemon owns every VM",
        "A local client enters over a Unix socket and the daemon drives Firecracker.",
        elements,
        880,
    )


def lifecycle():
    """One claim: a VM moves through one checked state machine."""
    elements = []

    # Column 1: creation and a failed start.
    elements += box("created", 60, 170, 300, 100, "created", "input")
    elements += box("configured", 60, 410, 300, 100, "configured", "neutral")
    elements += box("failed", 60, 650, 300, 100, "failed\nterminal state", "risk")

    # Column 2: the running machine and its stop path.
    elements += box("running", 560, 170, 300, 100, "running", "model")
    elements += box("paused", 560, 410, 300, 100, "paused", "model")
    elements += box("stopped", 560, 650, 300, 100, "stopped", "neutral")

    # Column 3: the snapshot path back to running.
    elements += box("snapshotting", 1060, 170, 300, 100, "snapshotting", "analysis")
    elements += box(
        "snapshot-files",
        1060,
        410,
        300,
        100,
        "snapshot files\nmemory and state",
        "analysis",
    )
    elements.append(
        text(
            "snapshot-resume-note",
            1060,
            555,
            "A running VM resumes\nafter the snapshot is written.",
            size=NOTE_SIZE,
            color=MUTED,
        )
    )
    elements.append(
        text(
            "restore-note",
            1060,
            660,
            "Restore starts a fresh\nFirecracker process.",
            size=NOTE_SIZE,
            color=MUTED,
        )
    )

    elements += arrow("created-configured", (210, 270), (210, 410), "create", label_offset=(100, 0))
    elements += arrow("configured-running", (360, 410), (560, 270), "start", label_offset=(0, -30))
    elements += arrow("running-paused", (790, 270), (790, 410), "pause", label_offset=(92, 0))
    elements += arrow("paused-running", (630, 410), (630, 270), "resume", label_offset=(-92, 0))
    elements += arrow("running-snapshotting", (860, 220), (1060, 220), "snapshot", label_offset=(0, -32))
    elements += arrow(
        "snapshotting-files",
        (1210, 270),
        (1210, 410),
        "state and memory",
        label_offset=(116, 0),
    )
    elements += arrow(
        "files-running",
        (1060, 410),
        (860, 270),
        "restore",
        label_offset=(34, -49),
    )
    elements += arrow("configured-failed", (210, 510), (210, 650), "start fails", label_offset=(112, 0))
    elements += arrow("paused-stopped", (610, 510), (610, 650), "stop", label_offset=(-80, 0))

    return scene(
        "Every VM follows one checked lifecycle",
        "Illegal transitions return an error instead of changing state.",
        elements,
        840,
    )


def snapshot_restore():
    """One claim: restore validates a local manifest before it loads state."""
    elements = []

    # Row 1: snapshot creation.
    elements += box("paused-vm", 60, 170, 300, 100, "paused VM", "model")
    elements += box("snapshot-files", 560, 170, 300, 100, "snapshot files\nmemory and state", "analysis")
    elements += box("manifest", 1060, 170, 300, 100, "manifest\ncontent hashes", "analysis")

    # Row 2: restore request, gate, fresh process.
    elements += box("restore-request", 60, 390, 300, 100, "restore request", "input")
    elements += box(
        "gate",
        560,
        390,
        300,
        100,
        "compatibility gate\nhost, binary, tenant",
        "risk",
    )
    elements += box("fresh-process", 1060, 390, 300, 100, "fresh Firecracker process", "neutral")

    # Row 3: rejection and the loaded guest.
    elements += box("rejected", 60, 620, 300, 100, "restore rejected", "risk")
    elements += box("load", 560, 620, 300, 100, "load memory and state", "runtime")
    elements += box("running-vm", 1060, 620, 300, 100, "running VM", "model")

    elements += arrow("paused-files", (360, 220), (560, 220), "pause and write", label_offset=(0, -32))
    elements += arrow("files-manifest", (860, 220), (1060, 220), "record hashes", label_offset=(0, -32))
    elements += arrow(
        "manifest-gate",
        (1210, 270),
        (860, 390),
        "verify before load",
        label_offset=(-24, -26),
    )
    elements += arrow("request-gate", (360, 440), (560, 440), "restore call", label_offset=(0, -30))
    elements += arrow("gate-process", (860, 440), (1060, 440), "gate passes", label_offset=(0, -30))
    elements += arrow("gate-rejected", (740, 490), (360, 620), "mismatch", label_offset=(0, -26))
    elements += arrow(
        "process-load",
        (1160, 490),
        (860, 620),
        "load snapshot",
        label_offset=(0, -26),
    )
    elements += arrow("load-running", (860, 670), (1060, 670), "resume guest", label_offset=(0, -30))

    return scene(
        "Restore checks the manifest before load",
        "Snapshot files stay local and a fresh process loads them after the gate passes.",
        elements,
        800,
    )


FIGURES = {
    "architecture": architecture,
    "lifecycle": lifecycle,
    "snapshot-restore": snapshot_restore,
}


def main():
    for name, build in FIGURES.items():
        content = build()
        path = HERE / f"{name}.excalidraw"
        path.write_text(json.dumps(content, indent=2) + "\n")
        print(f"wrote {path.relative_to(HERE.parent.parent)}")


if __name__ == "__main__":
    main()
