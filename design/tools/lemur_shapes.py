#!/usr/bin/env python3
"""Lemur figure shapes used by make_frames.py. Three styles. Writes loader/concepts/<id>.outline.svg + .mask.svg.

Run: tools/.venv/bin/python tools/lemur_shapes.py
"""
import math
from pathlib import Path

from shapely import affinity
from shapely.geometry import Point, Polygon, MultiPolygon, LineString
from shapely.ops import unary_union

W, H = 240, 300
STROKE = 3.4
OUT = Path(__file__).resolve().parent.parent / "loader" / "concepts"


def vec(a, l=1.0):
    r = math.radians(a)
    return (math.cos(r) * l, -math.sin(r) * l)


def add(p, v, k=1.0):
    return (p[0] + v[0] * k, p[1] + v[1] * k)


def circ(p, r):
    return Point(p).buffer(r, quad_segs=32)


def ellipse(p, rx, ry, rot=0):
    e = affinity.scale(circ((0, 0), 1), rx, ry)
    e = affinity.rotate(e, rot)
    return affinity.translate(e, *p)


def capsule(a, b, ra, rb):
    return circ(a, ra).union(circ(b, rb)).convex_hull


def chain(pts, radii):
    return unary_union([capsule(pts[i], pts[i + 1], radii[i], radii[i + 1]) for i in range(len(pts) - 1)])


def bezier(p0, p1, p2, p3, n=60):
    out = []
    for i in range(n + 1):
        t = i / n; u = 1 - t
        out.append((u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0],
                    u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1]))
    return out


def ang(a, b):
    return math.degrees(math.atan2(-(b[1] - a[1]), b[0] - a[0]))


def leaf(base, a, length, width):
    mid = add(base, vec(a, length * 0.55))
    tip = add(base, vec(a, length))
    return capsule(base, mid, width * 0.4, width).union(capsule(mid, tip, width, width * 0.12))


def hand(elbow, wrist, s):
    d = ang(elbow, wrist)
    parts = [circ(wrist, 5.6 * s)]
    for off in (-34, -11, 12, 35):
        b = add(wrist, vec(d + off, 3 * s))
        parts.append(capsule(b, add(b, vec(d + off, 12 * s)), 2.1 * s, 1.5 * s))
    return unary_union(parts)


def head(c, hr, tilt, eyes, look=None):
    """Front view head. Returns (solid, eye_holes, pupils), all already tilted."""
    up = 90 + tilt
    solid = [ellipse(c, hr * 1.1, hr * 0.92)]
    solid.append(ellipse(add(c, vec(up - 180, hr * 0.70)), hr * 0.28, hr * 0.24, -tilt))  # muzzle
    for k in (-1, 1):  # big ears up and out at the top corners, rounded tips
        d = up + k * 50
        solid.append(capsule(add(c, vec(d, hr * 0.5)), add(c, vec(d, hr * 1.44)), hr * 0.44, hr * 0.11))
    for k in (-1, 1):  # round furry jowls make the face wide at the bottom
        d = up - 180 + k * 58
        solid.append(ellipse(add(c, vec(d, hr * 0.58)), hr * 0.52, hr * 0.40, -tilt))
    band_c = add(c, vec(up, hr * 0.92))
    band = affinity.rotate(Polygon([(-hr * .28, hr * .10), (hr * .28, hr * .10), (hr * .36, -hr * .18), (-hr * .36, -hr * .18)]), -tilt, origin=(0, 0))
    solid.append(affinity.translate(band, *band_c))
    top = add(band_c, vec(up, hr * 0.16))
    for off, ln in [(0, 0.82), (-30, 0.74), (30, 0.74), (-62, 0.56), (62, 0.56)]:
        solid.append(leaf(top, up + off, hr * ln, hr * 0.15))
    solid = unary_union(solid)
    holes, pupils = [], []
    if eyes:
        side = (math.cos(math.radians(tilt)), -math.sin(math.radians(tilt)))
        for k in (-1, 1):
            ec = add(add(c, side, k * hr * 0.40), vec(up, hr * 0.02))
            holes.append(circ(ec, hr * 0.31))
            lx, ly = look if look else (-k * 0.06, 0.04)
            pupils.append(circ(add(add(ec, side, lx * hr), vec(up, ly * hr)), hr * 0.12))
    return solid, holes, pupils


def figure(st, pose):
    s = st["limb"]
    parts = []
    chest, belly = pose["chest"], pose["belly"]
    parts.append(capsule(chest, belly, st["chest_r"], st["belly_r"]))
    hsolid, holes, pupils = head(pose["head"], st["hr"], pose.get("tilt", 0), st["eyes"], pose.get("look"))
    parts.append(capsule(chest, pose["head"], 9 * s, 9 * s))
    for side in ("l", "r"):
        sh, el, wr = pose[side + "arm"]
        parts.append(chain([sh, el, wr], [6.4 * s, 4.8 * s, 4 * s]))
        parts.append(hand(el, wr, s))
        hp, kn, an, toe = pose[side + "leg"]
        parts.append(chain([hp, kn, an], [12 * s, 7.4 * s, 5 * s]))
        parts.append(capsule(an, toe, 5.4 * s, 3.8 * s))
    # bushy tail
    pts = bezier(*pose["tail"])
    n = len(pts) - 1
    tr = st["tail_r"]
    radii = [tr * (0.78 + 0.32 * math.sin(math.pi * min(1, i / n * 1.25))) for i in range(n + 1)]
    tail = chain(pts, radii)
    body = unary_union(parts + [hsolid, tail])
    body = body.buffer(2.4, join_style="round").buffer(-2.4, join_style="round")
    if st["rings"]:  # stripes stay dark even when the figure is full
        line = LineString(pts)
        inner = tail.buffer(-2.2)
        bands = []
        for f in [0.27 + i * 0.15 for i in range(5)]:
            p = line.interpolate(f, normalized=True)
            q = line.interpolate(min(1, f + 0.01), normalized=True)
            a = ang((p.x, p.y), (q.x, q.y))
            hw = 0.036 * line.length  # stripe width scales with tail length
            bar = affinity.rotate(Polygon([(-hw, -30), (hw, -30), (hw, 30), (-hw, 30)]), -a, origin=(0, 0))
            bands.append(affinity.translate(bar, p.x, p.y).intersection(inner))
        body = body.difference(unary_union(bands).buffer(1.2).buffer(-1.2))
    if holes:
        body = body.difference(unary_union(holes)).union(unary_union(pupils))
    return body.simplify(0.1, preserve_topology=True)


ARMS_WIDE = dict(
    chest=(120, 170), belly=(120, 216), head=(120, 114),
    larm=[(106, 162), (80, 184), (52, 186)], rarm=[(134, 162), (160, 184), (188, 186)],
    lleg=[(108, 238), (96, 260), (102, 282), (86, 286)], rleg=[(132, 238), (144, 260), (138, 282), (154, 286)],
    tail=[(110, 232), (54, 252), (26, 188), (58, 132)],
)
CHIBI = dict(ARMS_WIDE, head=(120, 124), chest=(120, 182), belly=(120, 224),
             larm=[(106, 180), (82, 198), (56, 196)], rarm=[(134, 180), (158, 198), (184, 196)],
             lleg=[(110, 244), (100, 264), (104, 282), (88, 286)], rleg=[(130, 244), (140, 264), (136, 282), (152, 286)],
             tail=[(112, 240), (60, 258), (30, 200), (56, 150)])

CONCEPTS = {
    "a": (dict(hr=38, chest_r=15, belly_r=29, limb=1.0, tail_r=10, eyes=True, rings=True), ARMS_WIDE),
    "b": (dict(hr=38, chest_r=15, belly_r=29, limb=1.0, tail_r=10, eyes=False, rings=False), ARMS_WIDE),
    "c": (dict(hr=50, chest_r=16, belly_r=26, limb=0.9, tail_r=10, eyes=True, rings=True), CHIBI),
}


def path_d(g):
    polys = g.geoms if isinstance(g, MultiPolygon) else [g]
    out = []
    for poly in polys:
        for ring in [poly.exterior, *poly.interiors]:
            out.append("M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in list(ring.coords)[:-1]) + "Z")
    return " ".join(out)


def svg(body):
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">{body}</svg>\n'


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for cid, (st, pose) in CONCEPTS.items():
        g = figure(st, pose)
        d = path_d(g)
        (OUT / f"{cid}.mask.svg").write_text(svg(f'<path fill="#fff" fill-rule="evenodd" d="{d}"/>'))
        (OUT / f"{cid}.outline.svg").write_text(svg(
            f'<path fill="none" stroke="#fff" stroke-width="{STROKE}" stroke-linejoin="round" d="{d}"/>'))
        print(cid, "bounds", [round(v) for v in g.bounds])
