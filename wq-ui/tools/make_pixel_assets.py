#!/usr/bin/env python3
"""Draw the pixel-art frames for the built-in "Pixel" theme into ../theme_assets/.

    python3 tools/make_pixel_assets.py [--preview]

Each frame is a 7x7 "art pixel" nine-slice with stepped (notched) corners, drawn 2x so the pixels
are chunky but still sharp on a normal screen. The QSS uses them as
`border-image: url(@assets/pixel_button.png) 6 6 6 6 stretch stretch; border-width: 6px;`
(3 art pixels = 6 px per corner). Colours are the Pixel theme's own palette, so changing a colour
here and in wq_themes.py and re-running is all it takes to re-skin it. Needs Pillow.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

OUT = Path(__file__).resolve().parent.parent / "theme_assets"
S = 2                                    # screen pixels per art pixel
N = 7                                    # art pixels per side

INK = "#0e0a18"                          # darkest outline
PAL = {
    "fill_hi": "#342c55", "fill": "#251f3d", "well": "#120d20",
    "edge": "#5b5486", "edge_lit": "#8f86c9", "bevel_lo": "#1f1936",
    "amber": "#ffb02e", "amber_lt": "#ffd38a", "amber_dk": "#c47d0a", "amber_hot": "#ffc65a",
    "dim_fill": "#201a35", "dim_edge": "#3a3358",
}


def rgba(h: str):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 255


def frame(name: str, fill: str, border: str, hi: str | None = None, lo: str | None = None) -> Image.Image:
    grid = [[None] * N for _ in range(N)]
    for y in range(N):
        for x in range(N):
            edge_x, edge_y = x in (0, N - 1), y in (0, N - 1)
            corner = edge_x and edge_y
            step = (x in (1, N - 2)) and (y in (1, N - 2))
            if corner:
                continue                                     # notch: stays transparent
            if edge_x or edge_y or step:
                grid[y][x] = border
            else:
                grid[y][x] = fill
    # bevel: one art pixel just inside the edge, between the stepped corners
    for i in range(2, N - 2):
        if hi:
            grid[1][i] = hi
            grid[i][1] = hi
        if lo:
            grid[N - 2][i] = lo
            grid[i][N - 2] = lo
    img = Image.new("RGBA", (N * S, N * S), (0, 0, 0, 0))
    px = img.load()
    for y in range(N):
        for x in range(N):
            if grid[y][x]:
                c = rgba(grid[y][x])
                for dy in range(S):
                    for dx in range(S):
                        px[x * S + dx, y * S + dy] = c
    img.save(OUT / f"{name}.png")
    return img


def tile() -> Image.Image:
    """4x4 art-pixel dither tile for the window background (very low contrast)."""
    a, b = rgba("#1a1428"), rgba("#1e1830")
    img = Image.new("RGBA", (4 * S, 4 * S))
    px = img.load()
    for y in range(4):
        for x in range(4):
            c = b if (x + y) % 2 == 0 and (x % 2 == 0) else a
            for dy in range(S):
                for dx in range(S):
                    px[x * S + dx, y * S + dy] = c
    img.save(OUT / "pixel_bg.png")
    return img


def main() -> int:
    OUT.mkdir(exist_ok=True)
    P = PAL
    made = {
        "pixel_button":          frame("pixel_button", P["fill_hi"], P["edge"], P["edge_lit"], INK),
        "pixel_button_hover":    frame("pixel_button_hover", P["fill_hi"], P["amber"], P["edge_lit"], INK),
        "pixel_button_pressed":  frame("pixel_button_pressed", P["fill"], P["amber"], INK, P["edge"]),
        "pixel_button_disabled": frame("pixel_button_disabled", P["dim_fill"], P["dim_edge"]),
        "pixel_accent":          frame("pixel_accent", P["amber"], INK, P["amber_lt"], P["amber_dk"]),
        "pixel_accent_hover":    frame("pixel_accent_hover", P["amber_hot"], "#ffffff", P["amber_lt"], P["amber_dk"]),
        "pixel_accent_pressed":  frame("pixel_accent_pressed", P["amber_dk"], INK, P["amber_dk"], P["amber_lt"]),
        "pixel_panel":           frame("pixel_panel", P["fill"], P["edge"], None, P["bevel_lo"]),
        "pixel_field":           frame("pixel_field", P["well"], P["edge"], INK, None),
        "pixel_field_focus":     frame("pixel_field_focus", P["well"], P["amber"], INK, None),
    }
    made["pixel_bg"] = tile()
    if "--preview" in sys.argv:
        sheet = Image.new("RGBA", (len(made) * 70, 90), (26, 20, 40, 255))
        for i, (k, im) in enumerate(made.items()):
            sheet.paste(im.resize((im.width * 4, im.height * 4), Image.NEAREST) if im.width < 20 else im,
                        (i * 70 + 4, 4), im.resize((im.width * 4, im.height * 4), Image.NEAREST) if im.width < 20 else im)
        sheet.save("/tmp/pixel_preview.png")
    print("wrote", len(made), "images to", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
