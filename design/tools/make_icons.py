#!/usr/bin/env python3
"""Move It's own icon set.

One drawing rule for every glyph: 48 x 48 grid, 3.6 stroke, round caps and joins,
the same weight as the lemur's outline. Writes:
  design/style/icons/<name>.svg      glyph in currentColor (the app packs these via build_icons.py)
  docs/img/icons/<name>.svg          README tile: white glyph on the ink stage colour
Run: design/tools/.venv/bin/python design/tools/make_icons.py
"""
import re
from pathlib import Path

from shapely.geometry import Point, MultiPolygon, box
from shapely.ops import unary_union

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "design" / "style" / "icons"
TILE = ROOT / "docs" / "img" / "icons"
SW = 3.6


def c(x, y, r):
    return Point(x, y).buffer(r, quad_segs=24)


def outline(geom):
    polys = geom.geoms if isinstance(geom, MultiPolygon) else [geom]
    d = []
    for p in polys:
        for ring in [p.exterior, *p.interiors]:
            d.append("M" + " L".join(f"{x:.2f} {y:.2f}" for x, y in list(ring.coords)[:-1]) + "Z")
    return f'<path d="{" ".join(d)}"/>'


def dot(x, y, r=2.1):
    return f'<circle cx="{x}" cy="{y}" r="{r}" fill="currentColor" stroke="none"/>'


ICONS = {
    # what moves
    "cookie": outline(c(24, 25, 16.5).difference(c(39, 10, 8))) + dot(18, 21) + dot(28, 30) + dot(17.5, 31.5) + dot(29, 19.5, 1.8),
    "puzzle": outline(unary_union([box(9, 15, 33, 39), c(21, 10.5, 5.5), c(37.5, 27, 5.5)]).difference(c(9, 27, 5)).buffer(1.6).buffer(-1.6))
              + '<path d="M17.85 15A5.5 5.5 0 1 1 24.15 15"/>',
    "bookmark": '<path d="M16 7H32Q35 7 35 10V41L24 32.5L13 41V10Q13 7 16 7Z"/>' + dot(24, 17, 3.2),
    "history": '<path d="M9.5 20.5A15.5 15.5 0 1 1 11 32"/><path d="M8.5 12V21H17.5"/><path d="M25 16V25L31 29"/>',
    "password": '<rect x="5" y="15" width="38" height="18" rx="5"/>' + dot(14, 24, 2.4) + dot(21, 24, 2.4) + dot(28, 24, 2.4) + '<path d="M35 19V29"/>',
    # how it works
    "pair": '<rect x="5" y="10" width="15" height="28" rx="4"/><rect x="28" y="10" width="15" height="28" rx="4"/>'
            '<path d="M20 20H28M20 28H28"/>',
    "sealed": '<rect x="7" y="9" width="34" height="9" rx="3"/><path d="M10 18V36Q10 39 13 39H35Q38 39 38 36V18"/>'
              + '<circle cx="24" cy="28.5" r="5" fill="currentColor" stroke="none"/>',
    "move": '<path d="M5 17H12M3 24H8M5 31H12"/><path d="M16 24H40"/><path d="M31 15L40 24L31 33"/>',
    "sync": '<path d="M10.5 21A14 14 0 0 1 36 15.5"/><path d="M37 7V16H28"/><path d="M37.5 27A14 14 0 0 1 12 32.5"/><path d="M11 41V32H20"/>',
    "swap": '<path d="M9 17H38"/><path d="M31 10L38 17L31 24"/><path d="M39 31H10"/><path d="M17 24L10 31L17 38"/>',
    "undo": '<path d="M15 11L8 18L15 25"/><path d="M8 18H29A10 10 0 0 1 29 38H18"/>',
    "check": '<circle cx="24" cy="24" r="17"/><path d="M16.5 24.5L21.5 29.5L31.5 19"/>',
    # places and devices
    "cloud": outline(unary_union([c(17, 28, 8.5), c(27, 21, 10.5), c(35.5, 28.5, 7.5), box(11, 28, 38, 36.5)]).buffer(1.2).buffer(-1.2)) + dot(26, 29, 3.6),
    "folder": '<path d="M7 14Q7 10.5 10.5 10.5H19L23 15H37.5Q41 15 41 18.5V34.5Q41 38 37.5 38H10.5Q7 38 7 34.5Z"/>' + dot(24, 27, 3.6),
    "git": '<circle cx="15" cy="11" r="4.5"/><circle cx="15" cy="37" r="4.5"/><circle cx="33" cy="17" r="4.5"/>'
           '<path d="M15 15.5V32.5"/><path d="M33 21.5C33 30 15 25 15 32.5"/>',
    "browser": '<rect x="5" y="9" width="38" height="30" rx="5"/><path d="M5 17H43"/>' + dot(11, 13, 1.6) + dot(16, 13, 1.6) + dot(21, 13, 1.6),
    "laptop": '<rect x="9" y="10" width="30" height="21" rx="3"/><path d="M5 37H43"/>',
    "desktop": '<rect x="6" y="8" width="36" height="24" rx="3"/><path d="M24 32V39M16 40H32"/>',
    "devices": '<rect x="4" y="11" width="26" height="18" rx="3"/><path d="M2 34H31"/><rect x="34" y="15" width="11" height="22" rx="3"/>',
    # support: a coffee cup with yellow steam, and the X mark drawn in our stroke
    "coffee": '<path d="M9 19H32V30Q32 40 22.5 40H18.5Q9 40 9 30Z"/><path d="M32 22H35Q40 22 40 27Q40 32 35 32H32"/>'
              '<path d="M16 14C14 11.5 18 9.5 16 7M24 14C22 11.5 26 9.5 24 7"/>',
    "x": '<path d="M8 8.5H17L40 39.5H31Z"/><path d="M39 8.5L28.6 19.6M19.4 28.4L9 39.5"/>',
}


# The signature: every icon has one spot in the lemur's eye yellow.
# "dots" = the filled circles; a list = element positions (0-based) in the icon body.
SPOT = {
    "cookie": "dots", "puzzle": [1], "bookmark": "dots", "history": [2], "password": "dots",
    "pair": [2], "sealed": "dots", "move": [0], "sync": [1, 3], "swap": [1, 3], "undo": [0], "check": [1],
    "cloud": "dots", "folder": "dots", "git": [2], "browser": "dots",
    "laptop": [1], "desktop": [1], "devices": [2],
    "coffee": [2], "x": [1],
}
SPOT_APP, SPOT_TILE = "#d9981c", "#f5c542"


def apply_spot(name, body):
    rule = SPOT.get(name)
    parts = re.findall(r"<(?:path|circle|rect)\b[^>]*/>", body)
    out = []
    for i, el in enumerate(parts):
        hit = (rule == "dots" and 'fill="currentColor"' in el) or (isinstance(rule, list) and i in rule)
        if hit:
            el = el.replace('fill="currentColor"', 'class="f"') if 'fill="currentColor"' in el else el.replace("<path", '<path class="a"', 1).replace("<circle", '<circle class="a"', 1).replace("<rect", '<rect class="a"', 1)
        out.append(el)
    return "".join(out)


def glyph_svg(body):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" fill="none" stroke="currentColor" '
            f'stroke-width="{SW}" stroke-linecap="round" stroke-linejoin="round">'
            f'<style>.a{{stroke:var(--spot,{SPOT_APP})}}.f{{fill:var(--spot,{SPOT_APP})}}</style>{body}</svg>\n')


def tile_svg(body):
    inner = (body.replace('class="a"', f'stroke="{SPOT_TILE}"').replace('class="f"', f'fill="{SPOT_TILE}"')
             .replace('fill="currentColor"', 'fill="#fff"'))
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
            '<rect x="0.5" y="0.5" width="63" height="63" rx="17" fill="#1f1d1a" stroke="#3b3732"/>'
            f'<g transform="translate(14 14) scale(0.75)" fill="none" stroke="#fff" stroke-width="{SW}" '
            f'stroke-linecap="round" stroke-linejoin="round">{inner}</g></svg>\n')


if __name__ == "__main__":
    APP.mkdir(parents=True, exist_ok=True)
    TILE.mkdir(parents=True, exist_ok=True)
    for name, body in ICONS.items():
        body = apply_spot(name, body)
        (APP / f"{name}.svg").write_text(glyph_svg(body))
        (TILE / f"{name}.svg").write_text(tile_svg(body))
    print(len(ICONS), "icons")
