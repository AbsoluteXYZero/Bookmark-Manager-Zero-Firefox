#!/usr/bin/env python3
"""Generate extension icons from the shield design"""

from PIL import Image, ImageDraw
import math

def draw_shield_icon(size):
    """Draw the shield icon with bookmark at specified size"""
    # Create image with dark background
    img = Image.new('RGBA', (size, size), (26, 26, 26, 255))
    draw = ImageDraw.Draw(img)

    scale = size / 48
    cx = size / 2

    # Draw shield shape
    shield_points = [
        (cx, 4 * scale),
        (8 * scale, 10 * scale),
        (8 * scale, 20 * scale),
        (12 * scale, 30 * scale),
        (cx, 44 * scale),
        (size - 12 * scale, 30 * scale),
        (size - 8 * scale, 20 * scale),
        (size - 8 * scale, 10 * scale),
    ]

    # Fill shield
    draw.polygon(shield_points, fill=(45, 45, 45, 255), outline=(34, 197, 94, 255), width=max(1, int(2 * scale)))

    # Inner shield accent
    inner_shield = [
        (cx, 8 * scale),
        (12 * scale, 12.5 * scale),
        (12 * scale, 21 * scale),
        (cx, 38.5 * scale),
        (size - 12 * scale, 21 * scale),
        (size - 12 * scale, 12.5 * scale),
    ]
    draw.polygon(inner_shield, fill=(45, 45, 45, 200))

    # Draw bookmark
    bx = cx - 8 * scale
    by = 16 * scale
    bw = 16 * scale
    bh = 16 * scale

    bookmark_points = [
        (bx, by),
        (bx + bw, by),
        (bx + bw, by + bh),
        (cx, by + bh - 3 * scale),
        (bx, by + bh),
    ]

    draw.polygon(bookmark_points, fill=(74, 222, 128, 255), outline=(34, 197, 94, 255), width=max(1, int(1.5 * scale)))

    return img

# Generate both icon sizes
sizes = [16, 32, 48, 96]

for size in sizes:
    img = draw_shield_icon(size)
    filename = f'bookmark-{size}.png'
    img.save(filename)
    print(f'Generated {filename}')

print('\nAll icons generated successfully!')
print('Icons created: bookmark-16.png, bookmark-32.png, bookmark-48.png, bookmark-96.png')
