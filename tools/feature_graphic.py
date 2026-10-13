#!/usr/bin/env python3
"""Builds the 1024x500 Play feature graphic from the 01-codes screenshot.

Usage: tools/feature_graphic.py [screenshot] [out]
"""
import sys

from PIL import Image, ImageDraw, ImageFilter, ImageFont

SHOT = sys.argv[1] if len(sys.argv) > 1 else "fastlane/metadata/android/en-US/images/phoneScreenshots/01-codes.png"
OUT = sys.argv[2] if len(sys.argv) > 2 else "fastlane/metadata/android/en-US/images/featureGraphic.png"
FONT = "/usr/share/fonts/noto/NotoSans-{}.ttf"

W, H = 1024, 500
ACCENT, DEEP, CREAM = (191, 63, 24), (122, 36, 12), (248, 246, 240)


def background():
    # Diagonal brand-orange gradient: vibrant, never white, black or grey against Play's own UI.
    down = Image.linear_gradient("L").resize((W, H))
    across = Image.linear_gradient("L").rotate(90).resize((W, H))
    ramp = Image.blend(across, down, 0.35)
    return Image.composite(Image.new("RGB", (W, H), DEEP), Image.new("RGB", (W, H), ACCENT), ramp)


def ui_panel(height):
    # Both code cards with the app's own background around them; no device frame.
    shot = Image.open(SHOT).convert("RGB")
    crop = shot.crop((24, 478, 1056, 1442))
    panel = crop.resize((round(crop.width * height / crop.height), height), Image.LANCZOS)
    mask = Image.new("L", panel.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, *panel.size), radius=22, fill=255)
    return panel, mask


def main():
    image = background()
    panel, mask = ui_panel(368)
    x, y = W - 96 - panel.width, (H - panel.height) // 2

    shadow = Image.new("L", (W, H), 0)
    ImageDraw.Draw(shadow).rounded_rectangle((x, y + 10, x + panel.width, y + 10 + panel.height), radius=22, fill=110)
    image.paste((60, 16, 4), mask=shadow.filter(ImageFilter.GaussianBlur(18)))
    image.paste(panel, (x, y), mask)

    draw = ImageDraw.Draw(image)
    title = ImageFont.truetype(FONT.format("Bold"), 76)
    body = ImageFont.truetype(FONT.format("Medium"), 28)
    left = 96
    draw.text((left, 150), "KyAuth", font=title, fill=CREAM)
    slogan = "Codes and sign-in approvals,\nsecured on your phone."
    draw.multiline_text((left, 262), slogan, font=body, fill=(251, 232, 224), spacing=12)
    assert x - draw.multiline_textbbox((left, 262), slogan, font=body, spacing=12)[2] >= 40, "text crowds the panel"

    assert image.size == (W, H) and image.mode == "RGB"
    image.save(OUT)
    print(OUT, image.size, image.mode)


if __name__ == "__main__":
    main()
