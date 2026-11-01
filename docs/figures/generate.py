#!/usr/bin/env python3
"""Generate the Excalidraw scenes for the architecture page.

Run from the repository root:

    python3 -B docs/figures/generate.py

The script writes one .excalidraw file per figure next to this file. Render each
scene with the packaged Excalidraw CLI after changing it:

    excalidraw render docs/figures/component-topology.excalidraw \
      --out docs/figures/component-topology.png \
      --scale 2 --max-width 3200

The palette, font sizes, and canvas width follow agents/excalidraw.nix in the
nixos repository. Keep the scene and the PNG together.
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCENE_WIDTH = 1520
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


def text(eid, x, y, content, size=BODY_SIZE, color=INK, width=None, align="left"):
    """Build a standalone text element."""
    estimated_width, height = text_size(content, size)
    return element(
        eid,
        "text",
        x,
        y,
        width if width is not None else estimated_width,
        height,
        strokeColor=color,
        backgroundColor="transparent",
        fillStyle="solid",
        roundness=None,
        text=content,
        fontSize=size,
        fontFamily=FONT,
        textAlign=align,
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
        fillStyle="solid",
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


def arrow(eid, start, end, label, color="neutral", label_offset=(0, -30), size=NOTE_SIZE):
    """Build a straight arrow with a separate label near its midpoint."""
    x1, y1 = start
    x2, y2 = end
    dx = x2 - x1
    dy = y2 - y1
    label_width, _ = text_size(label, size)
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
        fillStyle="solid",
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
        size=size,
        color=INK,
    )
    return [arrow_element, label_element]


def scene(title, subtitle, elements, height):
    """Assemble one scene with a title and a one-line claim."""
    title_width, _ = text_size(title, TITLE_SIZE)
    title_element = text(
        "title",
        (SCENE_WIDTH - title_width) / 2,
        36,
        title,
        size=TITLE_SIZE,
        color=INK,
    )
    subtitle_width, _ = text_size(subtitle, NOTE_SIZE)
    subtitle_element = text(
        "subtitle",
        (SCENE_WIDTH - subtitle_width) / 2,
        86,
        subtitle,
        size=NOTE_SIZE,
        color=MUTED,
    )
    return {
        "type": "excalidraw",
        "version": 2,
        "source": "https://excalidraw.com",
        "elements": [title_element, subtitle_element] + elements,
        "appState": {
            "gridSize": None,
            "viewBackgroundColor": BACKGROUND,
            "exportBackground": True,
        },
        "files": {},
    }, height


def component_topology():
    """One claim: five components, each with its own evidence boundary."""
    elements = []
    elements += box(
        "environment",
        360,
        150,
        800,
        110,
        "Environment\nNix toolchain and host preflight",
        "neutral",
    )
    elements += box(
        "lifecycle",
        60,
        350,
        380,
        180,
        "Lifecycle\nTyped state machine\nREST, gRPC",
        "runtime",
    )
    elements += box(
        "isolation",
        580,
        350,
        380,
        180,
        "Isolation\nJailer, cgroup v2, TAP",
        "model",
    )
    elements += box(
        "state",
        1100,
        350,
        380,
        180,
        "State and observability\nSnapshots, metrics, scheduler",
        "analysis",
    )
    elements += box(
        "interfaces",
        300,
        740,
        900,
        110,
        "Interfaces\nOCI, demo, Docker, direct-KVM",
        "input",
    )

    elements += arrow("env-lifecycle", (560, 260), (250, 350), "toolchain and preflight", label_offset=(-90, -18))
    elements += arrow("env-isolation", (760, 260), (770, 350), "host capability gates", label_offset=(0, -22))
    elements += arrow("env-state", (960, 260), (1290, 350), "evidence paths", label_offset=(90, -18))
    elements += arrow("lifecycle-isolation", (440, 440), (580, 440), "typed calls", label_offset=(0, -38))
    elements += arrow("isolation-state", (960, 440), (1100, 440), "runtime data", label_offset=(0, -38))
    elements += arrow("lifecycle-interfaces", (250, 530), (520, 740), "control operations", label_offset=(-40, -10))
    elements += arrow("state-interfaces", (1290, 530), (1000, 740), "evidence records", label_offset=(40, -10))

    return scene(
        "Five components, one toolchain",
        "Each component can fail alone and produces its own evidence.",
        elements,
        900,
    )


def transport_path():
    """One claim: two transports enter one lifecycle contract."""
    elements = []
    elements += box(
        "rest-client",
        40,
        240,
        340,
        120,
        "microvm CLI\nREST client",
        "input",
    )
    elements += box("grpc-client", 40, 480, 340, 100, "gRPC client", "input")
    elements += box("rest", 560, 240, 340, 130, "microvm-rest\nREST/JSON adapter", "input")
    elements += box("grpc", 560, 460, 340, 130, "microvm-grpc\ngRPC adapter", "input")
    elements += box(
        "service",
        1080,
        220,
        360,
        150,
        "Transport-neutral service\nmicrovm-service",
        "runtime",
    )
    elements += box(
        "fsm",
        1080,
        470,
        360,
        130,
        "Lifecycle state machine\nmicrovm-lifecycle",
        "runtime",
    )

    elements += arrow("client-rest", (380, 300), (560, 305), "REST/JSON over UDS", label_offset=(0, -40), size=16)
    elements += arrow("client-grpc", (380, 530), (560, 525), "gRPC over UDS", label_offset=(0, -40))
    elements += arrow("rest-service", (900, 305), (1080, 300), "typed requests", label_offset=(0, -40))
    elements += arrow("grpc-service", (900, 525), (1080, 370), "typed requests", label_offset=(160, -27))
    elements += arrow("service-fsm", (1260, 370), (1260, 470), "validates transitions", label_offset=(110, -10))

    return scene(
        "Two transports, one contract",
        "REST and gRPC are adapters over the same typed service.",
        elements,
        660,
    )


def isolation_boundaries():
    """One claim: four host boundaries wrap the untrusted guest."""
    elements = []
    elements += box("host", 60, 240, 300, 120, "Host\nKVM and cgroup v2", "neutral", size=20)
    elements += box("jailer", 560, 240, 300, 120, "Jailer\nvalidated argv", "runtime")
    elements += box(
        "firecracker",
        560,
        500,
        300,
        180,
        "Firecracker microVM\nuntrusted guest",
        "model",
    )
    elements += box(
        "artifacts",
        60,
        560,
        300,
        110,
        "Verified artifacts\nSHA-256 and ELF",
        "analysis",
    )
    elements += box(
        "cgroup",
        1200,
        140,
        260,
        110,
        "cgroup v2 leaf\ncpu, memory, pids",
        "analysis",
        size=20,
    )
    elements += box(
        "netns",
        1200,
        330,
        260,
        110,
        "TAP in netns\nno host network",
        "model",
        size=20,
    )
    elements += box(
        "nft",
        1200,
        520,
        260,
        110,
        "nftables NAT\npolicy-scoped egress",
        "input",
        size=20,
    )

    elements += arrow("host-jailer", (360, 300), (560, 300), "spawns jailer", label_offset=(0, -38))
    elements += arrow("artifacts-jailer", (360, 560), (560, 360), "verified binary", label_offset=(150, -40))
    elements += arrow("jailer-vm", (710, 360), (710, 500), "starts", label_offset=(40, -10))
    elements += arrow("vm-cgroup", (860, 520), (1200, 230), "cgroup limits", label_offset=(-80, -30))
    elements += arrow("vm-netns", (860, 560), (1200, 385), "TAP attach", label_offset=(0, 68))
    elements += arrow("netns-nft", (1330, 440), (1330, 520), "filters egress", label_offset=(0, -18))

    elements.append(
        text(
            "fail-closed",
            560,
            740,
            "Missing prerequisite stops the spawn.",
            size=NOTE_SIZE,
            color=PALETTE["risk"]["stroke"],
        )
    )

    return scene(
        "Four boundaries wrap every guest",
        "A missing capability is a hard error before the process starts.",
        elements,
        820,
    )


def snapshot_gate():
    """One claim: the compatibility gate rejects before Firecracker load."""
    elements = []
    elements += box(
        "manifest",
        60,
        300,
        340,
        150,
        "Snapshot manifest\nSHA-256 and host envelope",
        "analysis",
        size=20,
    )
    elements += box(
        "gate",
        560,
        280,
        340,
        190,
        "Compatibility gate\nhost, binary, tenant",
        "risk",
    )
    elements += box(
        "load",
        1080,
        300,
        320,
        150,
        "Firecracker load\n/snapshot/load",
        "model",
        size=20,
    )
    elements += box(
        "inputs",
        560,
        580,
        340,
        120,
        "Current host and caller\nCPU, binary, owner",
        "neutral",
        size=20,
    )
    elements += box(
        "reject",
        1080,
        580,
        320,
        120,
        "Reject before spawn",
        "risk",
    )

    elements += arrow("manifest-gate", (400, 375), (560, 375), "manifest hashes", label_offset=(0, -40))
    elements += arrow("inputs-gate", (730, 580), (730, 470), "current host and caller", label_offset=(160, -10))
    elements += arrow("gate-load", (900, 375), (1080, 375), "compatible", label_offset=(0, -40))
    elements += arrow("gate-reject", (900, 440), (1240, 580), "mismatch", label_offset=(80, -28), color="risk")

    return scene(
        "No load without a matching host",
        "The gate checks the manifest, the host envelope, and the caller.",
        elements,
        780,
    )


FIGURES = {
    "component-topology": component_topology,
    "transport-path": transport_path,
    "isolation-boundaries": isolation_boundaries,
    "snapshot-gate": snapshot_gate,
}


def main():
    for name, build in FIGURES.items():
        content, _ = build()
        path = HERE / f"{name}.excalidraw"
        path.write_text(json.dumps(content, indent=2) + "\n")
        print(f"wrote {path.relative_to(HERE.parent.parent)}")


if __name__ == "__main__":
    main()
