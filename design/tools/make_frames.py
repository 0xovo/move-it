#!/usr/bin/env python3
"""Move It loader frames, style C (big head, eyes, ringed tail).

Each pose becomes a matched pair drawn from ONE shape:
  <name>.outline.svg  white stroke on the edge, no fill
  <name>.mask.svg     the same shape, solid white (the fill is clipped to it)
and frames/manifest.js lists them. The loader reads only manifest.js.

Run: tools/.venv/bin/python tools/make_frames.py
"""
import json
import math
from pathlib import Path

from icon_concepts import CONCEPTS, CHIBI, figure, path_d, svg, W, H, STROKE

STYLE = CONCEPTS["c"][0]
OUT = Path(__file__).resolve().parent.parent / "loader" / "frames"


def pose(**kw):
    p = dict(CHIBI)
    p.update(kw)
    return p


POSES = {
    # head thrown to one side, arm up high
    "dance-01": pose(head=(114, 122), tilt=16, chest=(116, 182), belly=(120, 224), look=(0.02, 0.1),
                     rarm=[(134, 178), (160, 150), (178, 116)], larm=[(104, 182), (80, 204), (62, 194)],
                     lleg=[(110, 244), (96, 262), (94, 282), (78, 286)], rleg=[(130, 244), (146, 262), (150, 282), (166, 286)],
                     tail=[(112, 240), (64, 256), (28, 206), (46, 156)]),
    # arms wide, ta-da (screenshot 2); also the finale
    "dance-02": pose(),
    # hip sway, arm raised to the side, other hand on hip (screenshot 3)
    "dance-03": pose(head=(114, 124), tilt=10, chest=(118, 182), belly=(126, 224), look=(0.08, 0.02),
                     rarm=[(132, 178), (170, 166), (186, 128)], larm=[(106, 182), (84, 204), (104, 220)],
                     lleg=[(116, 246), (110, 264), (108, 283), (92, 286)], rleg=[(136, 246), (156, 260), (146, 281), (164, 286)],
                     tail=[(114, 240), (70, 240), (40, 190), (52, 140)]),
    # jump, knees tucked, arms up and out (screenshot 4)
    "dance-04": pose(head=(120, 114), chest=(120, 172), belly=(120, 214), look=(0, 0.1),
                     larm=[(106, 170), (78, 168), (50, 154)], rarm=[(134, 170), (162, 168), (190, 154)],
                     lleg=[(110, 234), (96, 254), (106, 272), (90, 278)], rleg=[(130, 234), (144, 254), (134, 272), (150, 278)],
                     tail=[(112, 230), (60, 262), (24, 270), (16, 232)]),
    # disco point
    "dance-05": pose(head=(126, 124), tilt=-8, chest=(122, 182), belly=(118, 224), look=(0.1, 0.06),
                     rarm=[(136, 178), (162, 156), (190, 132)], larm=[(106, 182), (82, 204), (102, 222)],
                     lleg=[(110, 244), (96, 262), (90, 283), (72, 286)], rleg=[(130, 244), (138, 264), (140, 283), (158, 286)],
                     tail=[(112, 240), (58, 256), (26, 210), (42, 164)]),
    # hands up, shaking
    "dance-06": pose(head=(120, 122), tilt=-5, look=(-0.08, 0.04),
                     larm=[(106, 180), (78, 196), (64, 164)], rarm=[(134, 180), (162, 196), (176, 164)],
                     lleg=[(110, 244), (104, 264), (100, 283), (84, 286)], rleg=[(130, 244), (140, 264), (144, 283), (160, 286)],
                     tail=[(112, 240), (62, 250), (36, 200), (58, 152)]),
    # waiting: hands on hips, foot tapping, glancing to the side
    "wait-01": pose(tilt=-6, look=(0.1, 0.0),
                    larm=[(106, 182), (76, 200), (102, 222)], rarm=[(134, 182), (164, 200), (138, 222)],
                    lleg=[(110, 244), (104, 264), (102, 283), (86, 286)], rleg=[(130, 244), (138, 264), (142, 280), (158, 274)],
                    tail=[(112, 240), (62, 254), (34, 206), (50, 158)]),
    "wait-02": pose(tilt=-3, look=(0.1, 0.0),
                    larm=[(106, 182), (76, 200), (102, 222)], rarm=[(134, 182), (164, 200), (138, 222)],
                    lleg=[(110, 244), (104, 264), (102, 283), (86, 286)], rleg=[(130, 244), (138, 264), (142, 283), (160, 286)],
                    tail=[(112, 240), (64, 258), (30, 212), (40, 162)]),
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    frames, tops = {}, []
    for name, p in POSES.items():
        g = figure(STYLE, p)
        d = path_d(g)
        (OUT / f"{name}.mask.svg").write_text(svg(f'<path fill="#fff" fill-rule="evenodd" d="{d}"/>'))
        (OUT / f"{name}.outline.svg").write_text(svg(
            f'<path fill="none" stroke="#fff" stroke-width="{STROKE}" stroke-linejoin="round" d="{d}"/>'))
        frames[name] = {"outline": f"{name}.outline.svg", "mask": f"{name}.mask.svg"}
        b = g.bounds
        assert b[0] > 2 and b[1] > 2 and b[2] < W - 2 and b[3] < H - 2, (name, b)
        if name.startswith("dance"):
            tops.append(b[1])
        print(name, [round(v) for v in b])
    manifest = {
        "version": 1,
        "style": "C: big head, eyes, ringed tail. Swap these pairs for the real frames.",
        "canvas": {"width": W, "height": H},
        "fill": {"bottom": 286 + STROKE / 2, "top": math.floor(min(tops) - STROKE / 2)},
        "beatMs": 488,
        "dance": [n for n in POSES if n.startswith("dance")],
        "wait": [n for n in POSES if n.startswith("wait")],
        "finale": "dance-02",
        "frames": frames,
    }
    (OUT / "manifest.js").write_text(
        "// Move It loader frames. The loader reads only this file.\n"
        "// Swap art: put outline + mask pairs in this folder and list them below.\n"
        "window.MOVEIT_FRAMES = " + json.dumps(manifest, indent=2) + ";\n")
    print("fill", manifest["fill"])


if __name__ == "__main__":
    main()
