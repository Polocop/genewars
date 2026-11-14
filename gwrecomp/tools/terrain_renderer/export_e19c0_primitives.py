#!/usr/bin/env python3
"""Pack captured E19C0 vertex records for the standalone C++ primitive test."""
import json
import pathlib
import struct
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: export_e19c0_primitives.py capture.json output.bin")
capture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
records = capture["records"]
out = bytearray(b"GWPRIM1\0")
out += struct.pack("<I", len(records))
for row in records:
    out += struct.pack("<II", int(row["ordinal"]), int(row["callsite"], 16))
    for vertex in row["vertices"]:
        raw = bytes.fromhex(vertex["bytes_hex"])
        if len(raw) != 20:
            raise SystemExit("captured vertex is not 20 bytes")
        out += raw
pathlib.Path(sys.argv[2]).write_bytes(out)
print(f"packed {len(records)} triangles ({len(out)} bytes)")
