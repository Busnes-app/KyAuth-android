#!/usr/bin/env python3
"""Builds the 512x512 Play Store icon from the Busnes.app-site KyAuth master.

Play wants a full-bleed opaque square and applies its own 30% corner mask, so the master's rounded
charcoal tile is cropped and its ivory corners filled with the tile colour.
Usage: tools/play_icon.py [master] [out]
"""
import sys

from PIL import Image, ImageDraw

MASTER = sys.argv[1] if len(sys.argv) > 1 else "../Busnes.app-site/kyauth-icon.png"
OUT = sys.argv[2] if len(sys.argv) > 2 else "fastlane/metadata/android/en-US/images/icon.png"
CHARCOAL = (24, 36, 40)  # #182428, the launcher's adaptive background
SIZE, MASK_RADIUS, MARGIN = 512, 0.30 * 512, 16
INSET = 6  # master pixels: drops the tile's anti-aliased straight edges


def tile(master):
    gray = master.convert("L")
    box = gray.point(lambda v: 255 if v < 70 else 0).getbbox()  # the charcoal tile
    side = min(box[2] - box[0], box[3] - box[1]) - 2 * INSET
    cx, cy = (box[0] + box[2]) // 2, (box[1] + box[3]) // 2
    return master.crop((cx - side // 2, cy - side // 2, cx + side // 2, cy + side // 2))


def inside_mask(x, y):
    # Play's rounded-square mask: only the corner quadrants are curved.
    r = MASK_RADIUS - MARGIN
    nx, ny = min(max(x, MASK_RADIUS), SIZE - MASK_RADIUS), min(max(y, MASK_RADIUS), SIZE - MASK_RADIUS)
    return (x - nx) ** 2 + (y - ny) ** 2 <= r ** 2


def main():
    square = tile(Image.open(MASTER).convert("RGB"))
    side = square.size[0]
    # The tile's rounded corner reaches charcoal this far along the top edge; paint each corner box.
    row = square.convert("L").load()
    curve = next(x for x in range(side) if row[x, 0] < 70) + 4
    draw = ImageDraw.Draw(square)
    for x, y in ((0, 0), (side - curve, 0), (0, side - curve), (side - curve, side - curve)):
        draw.rectangle((x, y, x + curve - 1, y + curve - 1), fill=CHARCOAL)
    icon = square.resize((SIZE, SIZE), Image.LANCZOS)

    px = icon.load()
    art = [(x, y) for y in range(SIZE) for x in range(SIZE) if sum(abs(a - b) for a, b in zip(px[x, y], CHARCOAL)) > 60]
    assert art, "no artwork found"
    outside = [p for p in art if not inside_mask(*p)]
    assert not outside, f"{len(outside)} artwork pixels fall in Play's corner mask, e.g. {outside[:3]}"
    for corner in ((0, 0), (SIZE - 1, 0), (0, SIZE - 1), (SIZE - 1, SIZE - 1)):
        assert sum(abs(a - b) for a, b in zip(px[corner], CHARCOAL)) <= 12, (corner, px[corner])

    icon.convert("RGBA").save(OUT)  # 32-bit, fully opaque
    print(OUT, icon.size, "artwork bbox", min(x for x, _ in art), min(y for _, y in art), max(x for x, _ in art), max(y for _, y in art))


if __name__ == "__main__":
    main()
