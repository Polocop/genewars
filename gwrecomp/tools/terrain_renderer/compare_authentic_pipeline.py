#!/usr/bin/env python3
"""Compare the helper renderer with captured terrain and compose HUD crop.

Uses only the Python standard library so it remains runnable in the project
venv without image packages. The source HUD mask is palette index 0 from the
captured indexed WScreen; nonzero indices in the 176px HUD strip are scaled
nearest-neighbour over the 2K terrain image.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path


def read_bmp(path):
    b = Path(path).read_bytes()
    if b[:2] != b"BM":
        raise ValueError(f"not BMP: {path}")
    off = struct.unpack_from("<I", b, 10)[0]
    dib = struct.unpack_from("<I", b, 14)[0]
    w, hs = struct.unpack_from("<ii", b, 18)
    planes, bpp = struct.unpack_from("<HH", b, 26)
    comp = struct.unpack_from("<I", b, 30)[0]
    if planes != 1 or comp != 0 or bpp not in (8, 24, 32):
        raise ValueError(f"unsupported BMP {path}: bpp={bpp}, compression={comp}")
    h = abs(hs)
    stride = ((w * bpp + 31) // 32) * 4
    palette = []
    if bpp == 8:
        n = struct.unpack_from("<I", b, 46)[0] or 256
        for i in range(n):
            blue, green, red, _ = struct.unpack_from("<BBBB", b, 14 + dib + 4 * i)
            palette.append((red, green, blue))
    rows = []
    for y in range(h):
        file_y = y if hs < 0 else h - 1 - y
        base = off + file_y * stride
        row = []
        for x in range(w):
            p = base + x * (bpp // 8)
            if bpp == 8:
                row.append(palette[b[p]])
            else:
                blue, green, red = b[p:p+3]
                row.append((red, green, blue))
        rows.append(row)
    return w, h, rows, hashlib.sha256(b).hexdigest(), bpp


def write_bmp24(path, w, h, rows):
    stride = (w * 3 + 3) & ~3
    image_size = stride * h
    header = bytearray(54)
    header[:2] = b"BM"
    struct.pack_into("<I", header, 2, 54 + image_size)
    struct.pack_into("<I", header, 10, 54)
    struct.pack_into("<IiiHHIIiiII", header, 14, 40, w, h, 1, 24, 0,
                     image_size, 2835, 2835, 0, 0)
    with open(path, "wb") as f:
        f.write(header)
        pad = b"\0" * (stride - w * 3)
        for y in range(h - 1, -1, -1):
            for r, g, b in rows[y]:
                f.write(bytes((b, g, r)))
            f.write(pad)


def main():
    root = Path(__file__).resolve().parents[2]
    out640 = root / "evidence/modern_renderer_integrated_640x480.bmp"
    ref = root / "evidence/e19c0_surface_021d9cac_640x480.bmp"
    original = root / "evidence/terrain_geometry_projection_resolution/original_MapDisplay_turn435_640x480.bmp"
    coverage640 = root / "evidence/modern_renderer_integrated_640x480.coverage.raw"
    coverage2k = root / "evidence/authentic_terrain_pipeline_integrated_2560x1440.coverage.raw"
    raw = root / "evidence/authentic_65f20_capture_435_585_final_wscreen.raw"
    pal = root / "evidence/authentic_65f20_capture_435_585_final_palette6.raw"
    out2k = root / "evidence/authentic_terrain_pipeline_integrated_2560x1440.bmp"
    w0, h0, a, ha, bpp_a = read_bmp(out640)
    wr, hr, b, hb, bpp_b = read_bmp(ref)
    wo, ho, o, ho_sha, bpp_o = read_bmp(original)
    if (w0, h0) != (wr, hr) or (w0, h0) != (wo, ho):
        raise ValueError("640 comparison dimensions differ")
    def compare_region(lhs, rhs, x0, x1):
        count = (x1 - x0) * h0
        exact_count = sum(lhs[y][x] == rhs[y][x] for y in range(h0) for x in range(x0, x1))
        error = sum(abs(lhs[y][x][k] - rhs[y][x][k])
                    for y in range(h0) for x in range(x0, x1) for k in range(3))
        return {"exact_rgb_pixels": exact_count, "total_pixels": count,
                "exact_rgb_percent": 100.0 * exact_count / count,
                "mean_abs_rgb_error_per_channel": error / (count * 3)}
    all_candidate = compare_region(a, b, 0, w0)
    world_candidate = compare_region(a, b, 128, 640)
    world_original = compare_region(a, o, 128, 640)
    cov640 = coverage640.read_bytes()
    cov2k = coverage2k.read_bytes()
    if len(cov640) != 640*480 or len(cov2k) != 2560*1440:
        raise ValueError("coverage output dimensions mismatch")
    gaps640 = sum(v == 0 for v in cov640)
    gaps2k = sum(v == 0 for v in cov2k)
    source, palette = raw.read_bytes(), pal.read_bytes()
    w2, h2, pano, hpano, bpp2 = read_bmp(out2k)
    if len(source) != 640 * 480 or len(palette) != 768 or (w2, h2) != (2560, 1440):
        raise ValueError("input buffer/palette/panorama dimensions mismatch")
    # Keep the 176px HUD strip at native logical layout, scaled 3x. Index 0
    # remains transparent so the expanded terrain shows through the curved edge.
    copied = 0
    for y in range(480):
        for x in range(176):
            idx = source[y * 640 + x]
            if idx == 0:
                continue
            p = idx * 3
            rgb = tuple((palette[p + c] * 255) // 63 for c in range(3))
            for sy in range(y * 3, (y + 1) * 3):
                row = pano[sy]
                for sx in range(x * 3, (x + 1) * 3):
                    row[sx] = rgb
            copied += 1
    write_bmp24(out2k, w2, h2, pano)
    # RGB exact comparison for the generated 640 image against the candidate
    # guest-range BMP. It does not attest that the guest range is a pure surface.
    obj = {
        "schema": "gwrecomp.authentic-terrain-render-compare/v1",
        "640x480": {
            "output": str(out640), "output_sha256": ha, "output_bpp": bpp_a,
            "candidate_reference": str(ref), "candidate_sha256": hb, "candidate_bpp": bpp_b,
            "candidate_whole_frame": all_candidate,
            "candidate_world_x128_639": world_candidate,
            "original_MapDisplay_reference": str(original), "original_sha256": ho_sha,
            "original_bpp": bpp_o, "original_world_x128_639": world_original,
            "coverage": {"bytes": len(cov640), "uncovered_pixels": gaps640,
                         "coverage_gaps": int(json.loads((root / "evidence/modern_renderer_integrated_640x480.mesh.json").read_text())["coverage_gaps"])},
            "reference_qualification": "candidate BMP from guest range 0x021D9CAC; allocation ownership/pitch not established in prior evidence"
        },
        "coverage_2560x1440": {"bytes": len(cov2k), "uncovered_pixels": gaps2k,
            "coverage_gaps": int(json.loads((root / "evidence/authentic_terrain_pipeline_integrated_2560x1440.mesh.json").read_text())["coverage_gaps"])},
        "2560x1440": {
            "output": str(out2k), "sha256_after_hud_composition": hashlib.sha256(out2k.read_bytes()).hexdigest(),
            "dimensions": [w2, h2], "source_terrain_sha256_before_composition": hpano,
            "hud_source": str(raw), "hud_palette": str(pal), "hud_logical_rect": [0,0,176,480],
            "hud_scale": 3, "transparent_palette_index": 0, "nontransparent_source_pixels": copied,
            "composition": "nearest-neighbour 3x HUD strip; index 0 left transparent"
        }
    }
    print(json.dumps(obj, indent=2))


if __name__ == "__main__":
    main()
