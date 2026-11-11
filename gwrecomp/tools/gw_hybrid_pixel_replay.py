#!/usr/bin/env python3
"""Replay authentic GeneWars indexed-pixel writes into a host BMP.

This is a diagnostic backend, not a widened world renderer. It consumes the
write-address/value stream captured from one original recompiled draw call.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def write_bmp(path: Path, width: int, height: int, pixels: bytes,
              palette_rgb6: list[int]) -> None:
    row_bytes = (width * 3 + 3) & ~3
    image_bytes = row_bytes * height
    file_bytes = 54 + image_bytes
    header = bytearray(54)
    header[:2] = b"BM"
    struct.pack_into("<I", header, 2, file_bytes)
    struct.pack_into("<I", header, 10, 54)
    struct.pack_into("<I", header, 14, 40)
    struct.pack_into("<ii", header, 18, width, height)
    struct.pack_into("<HH", header, 26, 1, 24)
    struct.pack_into("<I", header, 34, image_bytes)
    with path.open("wb") as f:
        f.write(header)
        row = bytearray(row_bytes)
        for y in range(height - 1, -1, -1):
            row[:] = b"\0" * row_bytes
            for x in range(width):
                index = pixels[y * width + x]
                r, g, b = palette_rgb6[index * 3:index * 3 + 3]
                row[x * 3:x * 3 + 3] = bytes((b * 255 // 63,
                                             g * 255 // 63,
                                             r * 255 // 63))
            f.write(row)


def read_bmp24(path: Path) -> tuple[int, int, bytes]:
    raw = path.read_bytes()
    if raw[:2] != b"BM" or struct.unpack_from("<H", raw, 28)[0] != 24:
        raise ValueError(f"not a 24-bit BMP: {path}")
    width, signed_height = struct.unpack_from("<ii", raw, 18)
    height = abs(signed_height)
    offset = struct.unpack_from("<I", raw, 10)[0]
    stride = (width * 3 + 3) & ~3
    rows = [raw[offset + y * stride:offset + y * stride + width * 3]
            for y in range(height)]
    if signed_height > 0:
        rows.reverse()
    return width, height, b"".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--reference", type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--require-terrain", action="store_true",
                    help="fail unless the capture has world-region writes and triangle primitives")
    args = ap.parse_args()
    source = json.loads(args.capture.read_text(encoding="utf-8"))
    width, height = int(source["width"]), int(source["height"])
    if width != 640 or height != 480:
        raise SystemExit("this first parity backend accepts only the original 640x480 surface")
    palette = source["dac_rgb6"]
    if len(palette) != 768 or any(not 0 <= x <= 63 for x in palette):
        raise SystemExit("capture has no valid authentic 6-bit DAC palette")
    pixels = bytearray(width * height)
    seen = bytearray(width * height)
    for x, y, value in source["commands"]:
        if not (0 <= x < width and 0 <= y < height and 0 <= value <= 255):
            raise SystemExit(f"out-of-bounds pixel command: {(x, y, value)}")
        at = y * width + x
        pixels[at] = value
        seen[at] = 1
    unique = sum(seen)
    if unique == 0:
        raise SystemExit("capture contains no effective framebuffer writes")
    world_writes = sum(1 for x, _y, _value in source["commands"] if x >= 128)
    primitive_path = args.capture.with_name("hybrid_terrain_primitives_turn435.json")
    primitive_records = 0
    if primitive_path.exists():
        primitive_records = len(json.loads(primitive_path.read_text(encoding="utf-8")).get("records", []))
    write_bmp(args.output, width, height, pixels, palette)
    parity = None
    if args.reference:
        rw, rh, ref = read_bmp24(args.reference)
        own_w, own_h, own = read_bmp24(args.output)
        if (rw, rh) != (width, height) or (own_w, own_h) != (width, height):
            raise SystemExit("reference/output dimensions do not match the captured 640x480 draw")
        parity = sum(a == b for a, b in zip(own, ref)) / len(ref)
    report = {
        "schema": "gwrecomp.hybrid-pixel-replay/v1",
        "source_capture": str(args.capture),
        "output_bmp": str(args.output),
        "dimensions": [width, height],
        "unique_written_pixels": unique,
        "pixel_write_coverage": unique / (width * height),
        "writes_in_world_region_x_ge_128": world_writes,
        "captured_original_triangle_primitives": primitive_records,
        "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "reference_bmp": str(args.reference) if args.reference else None,
        "rgb_byte_parity": parity,
        "claim": "host replay of captured authentic original pixel writes only; terrain is unverified unless world-region writes and original primitives are present",
        "terrain_capture_qualified": world_writes > 0 and primitive_records > 0,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if args.require_terrain and not report["terrain_capture_qualified"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
