"""Inventory the 90F90 modes in a live trace and hash remaps in GWSNAP2 fixtures."""

import argparse
import csv
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

GUEST_SIZE = 0x03002000
PALETTE_OFFSET_WIN32 = 28264


def snapshot(path):
    raw = path.read_bytes()
    if len(raw) < GUEST_SIZE + PALETTE_OFFSET_WIN32 + 768 or raw[:8] != b"GWSNAP2\0":
        raise ValueError(f"Invalid snapshot header in {path}")
    version, size, turn = struct.unpack_from("<III", raw, 8)
    memory = raw[-GUEST_SIZE:]
    if (version, size, turn) != (2, GUEST_SIZE, struct.unpack_from("<I", memory, 0x002F1472)[0]):
        raise ValueError(f"Unsupported snapshot ABI in {path}")
    dac = raw[PALETTE_OFFSET_WIN32:PALETTE_OFFSET_WIN32 + 768]
    if not any(dac) or max(dac) > 63:
        raise ValueError(f"Unexpected DAC data in {path}")
    fnv = 2166136261
    for byte in dac:
        fnv = ((fnv ^ byte) * 16777619) & 0xffffffff
    return turn, fnv, memory, hashlib.sha256(raw).hexdigest()


def mode(flags):
    if flags & ~15:
        return "unknown"
    return "destination_dependent" if flags & 12 else "opaque_source_remap"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("load_turn", type=int)
    parser.add_argument("snapshots", type=Path, nargs="+")
    args = parser.parse_args()
    with args.trace.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    fixtures = [snapshot(path) for path in args.snapshots]
    calls = Counter(
        ("pre_load" if int(row["turn"]) < args.load_turn else "post_load",
         int(row["extra_arg"], 16), int(row["flags"], 16),
         int(row["selector"], 16), int(row["palette_fnv32"], 16))
        for row in rows if int(row["blit"], 16) == 0x90f90
    )
    groups = []
    for (segment, table, flags, selector, dac), count in sorted(calls.items()):
        if table <= 0 or table > GUEST_SIZE - 256:
            raise ValueError(f"Invalid table address {table:#x}")
        matched = [mem[table:table + 256] for _, fnv, mem, _ in fixtures if fnv == dac]
        hashes = sorted({hashlib.sha256(item).hexdigest() for item in matched})
        groups.append({"segment": segment, "table": hex(table), "flags": hex(flags),
                       "selector": hex(selector), "dac_fnv32": f"{dac:08x}", "calls": count,
                       "mode": mode(flags), "matching_dac_snapshots": len(matched),
                       "snapshot_table_sha256": hashes})
    print(json.dumps({
        "trace_sha256": hashlib.sha256(args.trace.read_bytes()).hexdigest(),
        "snapshot_sha256": {str(turn): digest for turn, _, _, digest in fixtures},
        "calls_per_segment": {
            segment: sum(count for key, count in calls.items() if key[0] == segment)
            for segment in ("pre_load", "post_load")
        },
        "groups": groups,
    }, indent=2))


if __name__ == "__main__":
    main()
