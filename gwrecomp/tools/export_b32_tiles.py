#!/usr/bin/env python3
"""Export the Gene Wars terrain tile banks (DATA/B32A..B32D.DAT) of YOUR OWN installation to PNG, for local
HD remastering of the 3D terrain (gwrecomp.ini: terrain_3d_hd_tiles = 1).

Nothing of the game is stored in this repository: the script reads the installed files, decodes them (RNC method 1,
the game's own compression) and writes, for each bank, into <out>/<BANK>/ (for example hd_textures/B32A/):

    tile_000.png .. tile_NNN.png   one 32 x 32 RGB tile each, in bank order (8 tiles per bank row)
    atlas.png                      the whole bank as one image (256 px wide = 8 tiles, 32 px per tile row)
    manifest.json                  bank, palette, tile size, columns/rows and, per tile, its atlas cell and the
                                   byte offset of its top-left texel inside the decoded bank

Upscale the PNGs with your own tools (keep the file names; every tile the same square size, up to 256 x 256, or an
atlas exactly 8 x N tiles of that size) and copy the folder next to gwrecomp.exe:

    <gwrecomp folder>\\hd_textures\\B32A\\atlas.png        (or tile_000.png ...)

GWRecomp loads atlas.png when present, otherwise the tile_*.png files (a missing tile keeps the original texels).
Only the albedo is replaced: the game logic (water, GOOP, heights) keeps reading the original tile indices.

Banks per mission: each campaign level file LEVELS/CONQnnn.DAT holds its bank at offset 0x1C5B (0 = B32A ... 3 =
B32D; the game loads the file at 0x2F1A28 and formats "data\b32%c.dat" from that byte); the script reads them and
lists, per bank, the missions that use it (also in manifest.json).

Palette: missions draw the terrain with DATA/MAIN.PAL (the palette the game keeps loaded in play, checked byte for
byte against a live mission); --palette picks any other 768-byte VGA (0..63) palette, compressed (RNC) or not.

    python tools/export_b32_tiles.py                     # all banks, install dir from gwrecomp.local.json
    python tools/export_b32_tiles.py --bank A --out C:\\Users\\me\\Desktop\\GWRecomp-v1.0\\hd_textures
    python tools/export_b32_tiles.py --install "D:\\Games\\GENEWARS" --no-tiles
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import zlib
from pathlib import Path

TILE = 32
BANK_W = 256                  # bytes per bank row = 8 tiles


# ---- RNC ProPack method 1 ------------------------------------------------------------------------------------------
class _Bits:
    """The RNC1 bit stream: 16-bit little-endian words; literal bytes are interleaved after the current word."""

    def __init__(self, data: bytes, pos: int) -> None:
        self.d = data
        self.p = pos
        self.buf = self._w(pos)
        self.cnt = 16

    def _w(self, p: int) -> int:
        d = self.d
        return (d[p] if p < len(d) else 0) | ((d[p + 1] if p + 1 < len(d) else 0) << 8)

    def peek(self, mask: int) -> int:
        return self.buf & mask

    def advance(self, n: int) -> None:
        self.buf >>= n
        self.cnt -= n
        if self.cnt < 16:
            self.p += 2
            self.buf |= self._w(self.p) << self.cnt
            self.cnt += 16

    def read(self, mask: int, n: int) -> int:
        v = self.peek(mask)
        self.advance(n)
        return v

    def fix(self) -> None:
        """After literal bytes were taken at self.p: drop the top word and load the word now at self.p."""
        self.cnt -= 16
        self.buf &= (1 << self.cnt) - 1
        self.buf |= self._w(self.p) << self.cnt
        self.cnt += 16


def _mirror(x: int, n: int) -> int:
    r = 0
    for _ in range(n):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def _huftable(bs: _Bits) -> list[tuple[int, int, int]]:
    num = bs.read(0x1F, 5)
    if not num:
        return []
    lens = [bs.read(0x0F, 4) for _ in range(num)]
    table, code = [], 0
    for ln in range(1, max(lens + [1]) + 1):
        for value, l2 in enumerate(lens):
            if l2 == ln:
                table.append((_mirror(code, ln), ln, value))
                code += 1
        code <<= 1
    return table


def _hufread(table: list[tuple[int, int, int]], bs: _Bits) -> int:
    for code, ln, value in table:
        if bs.peek((1 << ln) - 1) == code:
            bs.advance(ln)
            if value >= 2:
                base = 1 << (value - 1)
                return base | bs.read(base - 1, value - 1)
            return value
    raise ValueError("RNC: bad Huffman code")


def _crc16(data: bytes) -> int:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
        table.append(c)
    crc = 0
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def rnc_unpack(data: bytes) -> bytes:
    """Decodes an RNC method-1 file; returns the data unchanged when it is not RNC-packed."""
    if data[:3] != b"RNC":
        return data
    if data[3] != 1:
        raise ValueError(f"RNC method {data[3]} not supported")
    size, packed = struct.unpack(">II", data[4:12])
    crc_unpacked = struct.unpack(">H", data[12:14])[0]
    out = bytearray()
    bs = _Bits(data, 18)
    bs.advance(2)                                   # lock and key flags
    while len(out) < size:
        raw, dist, length = _huftable(bs), _huftable(bs), _huftable(bs)
        chunks = bs.read(0xFFFF, 16)
        while True:
            n = _hufread(raw, bs)
            if n:
                out += bs.d[bs.p:bs.p + n]
                bs.p += n
                bs.fix()
            chunks -= 1
            if chunks <= 0:
                break
            back = _hufread(dist, bs) + 1
            n = _hufread(length, bs) + 2
            for _ in range(n):
                out.append(out[-back])
    out = bytes(out[:size])
    if _crc16(out) != crc_unpacked:
        raise ValueError("RNC: CRC mismatch (damaged file?)")
    return out


# ---- PNG writer (stdlib only) --------------------------------------------------------------------------------------
def write_png(path: Path, w: int, h: int, rgb: bytes) -> None:
    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)
    rows = b"".join(b"\0" + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")
    path.write_bytes(png)


# ---- export --------------------------------------------------------------------------------------------------------
def load_palette(path: Path) -> list[tuple[int, int, int]]:
    pal = rnc_unpack(path.read_bytes())
    if len(pal) < 768:
        raise ValueError(f"{path}: palette has {len(pal)} bytes, 768 expected")
    six = max(pal[:768]) <= 63
    return [tuple((c * 255 // 63) if six else c for c in pal[i * 3:i * 3 + 3]) for i in range(256)]


def export_bank(install: Path, letter: str, out_root: Path, palette: Path | None, tiles: bool, atlas: bool,
                missions: list[int] | None = None) -> dict:
    bank_file = install / "DATA" / f"B32{letter}.DAT"
    bank = rnc_unpack(bank_file.read_bytes())
    if len(bank) % (BANK_W * TILE):
        raise ValueError(f"{bank_file}: decoded size {len(bank)} is not a whole number of 256 x 32 tile rows")
    pal_file = palette or install / "DATA" / "MAIN.PAL"
    pal = load_palette(pal_file)
    rows = len(bank) // (BANK_W * TILE)
    out = out_root / f"B32{letter}"
    out.mkdir(parents=True, exist_ok=True)
    rgb = bytes(c for i in bank for c in pal[i])
    if atlas:
        write_png(out / "atlas.png", BANK_W, rows * TILE, rgb)
    manifest = {"bank": f"B32{letter}", "source": f"DATA/B32{letter}.DAT", "palette": pal_file.name,
                "tile_size": TILE, "columns": BANK_W // TILE, "rows": rows, "bank_bytes": len(bank),
                "atlas": "atlas.png" if atlas else None, "missions": missions or [], "tiles": []}
    for t in range(rows * (BANK_W // TILE)):
        cx, cy = t % (BANK_W // TILE), t // (BANK_W // TILE)
        name = f"tile_{t:03d}.png"
        if tiles:
            px = bytearray()
            for y in range(TILE):
                o = (cy * TILE + y) * BANK_W + cx * TILE
                px += rgb[o * 3:(o + TILE) * 3]
            write_png(out / name, TILE, TILE, bytes(px))
        manifest["tiles"].append({"index": t, "file": name if tiles else None, "atlas_cell": [cx, cy],
                                  "bank_offset": (cy * TILE) * BANK_W + cx * TILE})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def missions_by_bank(install: Path) -> dict[str, list[int]]:
    """Campaign missions (LEVELS/CONQ001..024.DAT) per bank letter, from the level header byte at 0x1C5B."""
    out: dict[str, list[int]] = {}
    for n in range(1, 25):
        f = install / "LEVELS" / f"CONQ{n:03d}.DAT"
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if len(data) > 0x1C5B and data[0x1C5B] < 26:
            out.setdefault(chr(ord("A") + data[0x1C5B]), []).append(n)
    return out


def default_install() -> Path | None:
    cfg = Path(__file__).resolve().parent.parent / "gwrecomp.local.json"
    try:
        return Path(json.loads(cfg.read_text(encoding="utf-8-sig"))["GENEWARS_INSTALL_DIR"])
    except (OSError, KeyError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--install", type=Path, default=default_install(), help="Gene Wars folder (the one with DATA/)")
    ap.add_argument("--out", type=Path, default=Path("hd_textures"), help="output root (default: ./hd_textures)")
    ap.add_argument("--bank", default="ABCD", help="bank letters to export (default ABCD)")
    ap.add_argument("--palette", type=Path, help="palette file instead of DATA/MAIN.PAL")
    ap.add_argument("--no-tiles", action="store_true", help="write only atlas.png and manifest.json")
    ap.add_argument("--no-atlas", action="store_true", help="write only the tile_*.png files and manifest.json")
    a = ap.parse_args(argv)
    if not a.install or not (a.install / "DATA").is_dir():
        ap.error("Gene Wars install folder not found: pass --install <folder containing DATA>")
    by_bank = missions_by_bank(a.install)
    for letter in a.bank.upper():
        if letter not in "ABCD":
            ap.error(f"unknown bank {letter}")
        if not (a.install / "DATA" / f"B32{letter}.DAT").is_file():
            print(f"B32{letter}: not in this installation, skipped")
            continue
        m = export_bank(a.install, letter, a.out, a.palette, not a.no_tiles, not a.no_atlas, by_bank.get(letter))
        print(f"B32{letter}: {len(m['tiles'])} tiles ({m['columns']}x{m['rows']}), palette {m['palette']}, "
              f"missions {','.join(map(str, m['missions'])) or '-'} -> {a.out / m['bank']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
