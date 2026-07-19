#!/usr/bin/env python3
"""Generate Nightjar's PWA / notification icons with no third-party deps.

    python tools/mk-icons.py

Writes into public/:
  icon-192.png, icon-512.png   app icons (opaque square, so they double as
                               'maskable' and the OS rounds the corners)
  apple-touch-icon.png (180)   iOS Home Screen (iOS rounds it; required for iOS
                               web push, DESIGN 7.4)
  badge-96.png                 the small status-bar badge. Android builds it from
                               the ALPHA CHANNEL ALONE, so it is a white crescent
                               on transparency (colour is discarded); a coloured
                               app icon here would mask to a solid white blob.

The mark is a crescent moon (nightjar = a nocturnal bird) in the app accent on
the app background, matching src/styles.css. Placeholder-grade but on-theme and
crisp (4x supersampled); swap for real art any time. Pure stdlib: zlib + struct.
"""

import struct
import zlib

# Palette from src/styles.css.
BG = (0x0B, 0x0E, 0x14)      # --bg
ACCENT = (0x7A, 0xA2, 0xF7)  # --accent
SS = 4                       # supersampling factor per axis


def _disc(px, py, cx, cy, r):
    dx, dy = px - cx, py - cy
    return dx * dx + dy * dy <= r * r


def _crescent_cov(px, py, n):
    """Coverage in [0,1] of the crescent at a supersampled point (px,py)."""
    outer = (0.50 * n, 0.50 * n, 0.34 * n)
    inner = (0.64 * n, 0.38 * n, 0.30 * n)  # subtracted disc -> crescent
    inside = _disc(px, py, *outer) and not _disc(px, py, *inner)
    return 1.0 if inside else 0.0


def _rrect(px, py, n, radius):
    """True if (px,py) is inside a rounded rectangle covering the whole canvas."""
    x = min(px, n - px)
    y = min(py, n - py)
    if x >= radius or y >= radius:
        return True
    dx, dy = radius - x, radius - y
    return dx * dx + dy * dy <= radius * radius


def _sample(fn, x, y):
    """Average fn over an SSxSS grid inside pixel (x,y)."""
    acc = 0.0
    for sy in range(SS):
        for sx in range(SS):
            px = x + (sx + 0.5) / SS
            py = y + (sy + 0.5) / SS
            acc += fn(px, py)
    return acc / (SS * SS)


def app_icon(n, radius_frac=0.0):
    """Opaque square (or rounded) icon: bg fill + accent crescent."""
    radius = radius_frac * n
    out = bytearray()
    for y in range(n):
        out.append(0)  # PNG filter type 0 for this scanline
        for x in range(n):
            bg_a = 1.0 if radius <= 0 else _sample(lambda px, py: 1.0 if _rrect(px, py, n, radius) else 0.0, x, y)
            moon = _sample(lambda px, py: _crescent_cov(px, py, n), x, y)
            # Composite crescent over background; background over transparency.
            r = ACCENT[0] * moon + BG[0] * (1 - moon)
            g = ACCENT[1] * moon + BG[1] * (1 - moon)
            b = ACCENT[2] * moon + BG[2] * (1 - moon)
            a = 255 * bg_a
            out += bytes((int(r + 0.5), int(g + 0.5), int(b + 0.5), int(a + 0.5)))
    return bytes(out)


def badge_icon(n):
    """Transparent canvas, white crescent (alpha = coverage). Alpha is all Android keeps."""
    out = bytearray()
    for y in range(n):
        out.append(0)
        for x in range(n):
            a = _sample(lambda px, py: _crescent_cov(px, py, n), x, y)
            out += bytes((255, 255, 255, int(255 * a + 0.5)))
    return bytes(out)


def write_png(path, n, raw_rgba):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)  # 8-bit RGBA
    idat = zlib.compress(raw_rgba, 9)
    with open(path, "wb") as f:
        f.write(sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b""))
    print(f"wrote {path} ({n}x{n})")


if __name__ == "__main__":
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    pub = os.path.join(here, "..", "public")
    write_png(os.path.join(pub, "icon-192.png"), 192, app_icon(192))
    write_png(os.path.join(pub, "icon-512.png"), 512, app_icon(512))
    write_png(os.path.join(pub, "apple-touch-icon.png"), 180, app_icon(180))
    write_png(os.path.join(pub, "badge-96.png"), 96, badge_icon(96))
