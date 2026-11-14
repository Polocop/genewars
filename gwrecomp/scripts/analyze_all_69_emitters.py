#!/usr/bin/env python3
"""Canonical-LE census of the 69 packet-Action anchors already recorded by REA.

This intentionally labels function boundaries and caller ancestry as unresolved
where the compact MAP has no function symbol. It is a reproducible evidence
extractor, not a claim that linear decoding can recover the full CFG.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence" / "genewars-1_1.exe"
MAP = ROOT / "evidence" / "genewars-1_1.map"
SOURCE = ROOT / "evidence" / "sighting_block3_full_35packets_census_and_6th.json"
OUT = ROOT / "evidence" / "overnight_phase2_packet_emitter_matrix.json"
EXPECTED = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def main() -> None:
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "third_party" / "pcrecomp")]
    from le_loader import load_le
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32

    digest = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if digest != EXPECTED:
        raise SystemExit(f"canonical LE hash mismatch: {digest}")
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    if source.get("target", {}).get("sha256") != EXPECTED:
        raise SystemExit("emitter census is not tied to canonical GeneWars 1.1")
    rows = source.get("action_emitter_census", {}).get("writers", [])
    if len(rows) != 69:
        raise SystemExit(f"expected 69 REA anchors, found {len(rows)}")

    image = load_le(TARGET, object_rebases={1: 0x1EB000, 3: 0x1DA000})
    code_obj = image.objects[0]
    code = bytes(image.object_data(1))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    symbols: list[tuple[int, str]] = []
    for line in MAP.read_text(encoding="latin-1", errors="replace").splitlines():
        match = re.match(r"\s*[0-9A-Fa-f]{4}:([0-9A-Fa-f]{8})\s+(.+?)\s*$", line)
        if match:
            symbols.append((int(match.group(1), 16), match.group(2).strip()))
    symbols.sort()

    def symbol_at(address: int) -> dict[str, str] | None:
        candidates = [s for s in symbols if s[0] <= address]
        if not candidates:
            return None
        va, name = candidates[-1]
        return {"link": f"0x{va:08X}", "name": name,
                "offset_from_symbol": f"0x{address - va:X}"}

    result_rows = []
    for row in rows:
        anchor_text = row.get("store_link") or row.get("rea_xref_or_search_anchor")
        anchor = int(anchor_text, 16)
        store_text = row.get("store_link")
        store = int(store_text, 16) if store_text else None
        # Decode forward from a recorded instruction boundary; preceding bytes
        # are preserved raw because the anchor census does not carry function
        # entry/boundary metadata.
        offset = anchor - code_obj.base
        decoded = list(md.disasm(code[offset:offset + 0x30], anchor))
        surrounding = [{"link": f"0x{x.address:08X}", "bytes": bytes(x.bytes).hex(),
                        "mnemonic": x.mnemonic, "operands": x.op_str}
                       for x in decoded[:12]]
        result_rows.append({
            "anchor_link": f"0x{anchor:08X}",
            "store_link": f"0x{store:08X}" if store is not None else None,
            "action_value": row.get("action_value"),
            "classification": row.get("classification"),
            "nearest_map_symbol": symbol_at(anchor),
            "forward_instructions_from_recorded_boundary": surrounding,
            "instruction_window_note": "canonical LE bytes, disassembled forward from the recorded xref/store boundary; not a full containing-function disassembly",
            "caller_ancestry": "unresolved here: compact MAP has no verified function boundary/callgraph for this anchor",
        })

    # Verify the complete LE-backed dispatcher independently and list its
    # action aliases without equating static emitters with runtime execution.
    dispatch_fixups = []
    by_slot = {f.source_link: f for f in image.fixups
               if f.source_link >= 0x92F7C and f.source_link < 0x92F7C + 35 * 4}
    for index in range(35):
        slot = 0x92F7C + index * 4
        fix = by_slot.get(slot)
        if fix is None or fix.source_type != 0x07 or fix.target_object != 1:
            raise SystemExit(f"dispatcher slot lacks verified LE code fixup: {slot:#x}")
        dispatch_fixups.append({"action": index, "slot_link": f"0x{slot:08X}",
                                "handler_link": f"0x{code_obj.base + fix.target_offset:08X}",
                                "target_object": fix.target_object,
                                "fixup_verified": True})
    live_codes = sorted(int(k, 16) for k in source.get("previously_live_packet_codes", {}))
    report = {
        "schema": "gw-overnight-phase2-packet-emitter-matrix/v1",
        "target_sha256": digest,
        "authority": "canonical LE bytes/fixups; REA reference-anchor list retained from the hash-bound 69-emitter census",
        "source_evidence": str(SOURCE.relative_to(ROOT)),
        "anchor_count": len(result_rows),
        "anchors": result_rows,
        "dispatch_table": {"table_link": "0x00092F7C", "entries": dispatch_fixups,
                            "all_35_fixups_verified": len(dispatch_fixups) == 35},
        "already_live_packet_codes": [f"0x{x:02X}" for x in live_codes],
        "new_distinct_live_packets_proven_by_this_analysis": [],
        "limitations": [
            "This static matrix does not reconstruct complete function bodies or caller trees for every anchor; no function start was inferred from a nearby symbol.",
            "Static Action stores do not prove that a guard is reachable in the current single-player state or that process_packets dispatched the code.",
            "No packet code is added to the live set without a same-run emission and dispatch trace."
        ],
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PASS canonical emitter matrix: {len(result_rows)} anchors, 35 fixups; saved {OUT}")


if __name__ == "__main__":
    main()
