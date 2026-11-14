from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.w3_279_play_smk_step import MAX_BYTES, MAX_ROWS

EVENT_LINKS = {
    "w3_281_second_gate_entry": 0xAE2E3,
    "w3_281_second_gate_test": 0xAE2E6,
    "w3_281_media_callsite": 0xAE2EB,
}
DESTINATIONS = {0xAE2E8, 0xAE2F2}


def parse(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_BYTES:
        raise ValueError("byte cap exceeded")
    lines = raw.splitlines()
    if len(lines) > MAX_ROWS:
        raise ValueError("row cap exceeded")
    rows = [json.loads(line) for line in lines]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("non-object JSON")
    return rows


def analyze(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mappings = [row for row in rows if row.get("event") == "main_mapping"]
    if len(mappings) != 1 or mappings[0].get("mapping_matches") is not True:
        raise ValueError("fresh MAIN mapping missing/duplicate")
    base = int(mappings[0]["code_rebase"])
    selected: dict[str, dict[str, Any]] = {}
    destination = None
    for row in rows:
        event = row.get("event")
        link = int(row.get("link_va", -1))
        if event in EVENT_LINKS:
            if link != EVENT_LINKS[event]:
                raise ValueError(f"unexpected link VA for {event}")
            selected[event] = row
        elif event == "w3_281_second_gate_target" and link in DESTINATIONS:
            if destination is not None:
                raise ValueError("duplicate second-gate destination")
            destination = row
        else:
            continue
        if int(row["code_rebase"]) != base or int(row["runtime_linear"]) - base != link:
            raise ValueError("runtime mapping mismatch")
    entry = selected.get("w3_281_second_gate_entry")
    test = selected.get("w3_281_second_gate_test")
    callsite = selected.get("w3_281_media_callsite")
    ordered = bool(entry and test and destination and
                   int(entry["sequence"]) < int(test["sequence"]) <
                   int(destination["sequence"]) and
                   (not callsite or int(destination["sequence"]) < int(callsite["sequence"])))
    dest_link = int(destination["link_va"]) if destination else None
    bl = int(entry["ebx"]) & 0xff if entry else None
    return {
        "code_rebase": f"0x{base:08X}",
        "second_gate_entry_seen": entry is not None,
        "bl_at_test_entry": f"0x{bl:02X}" if bl is not None else None,
        "test_eflags": f"0x{int(test['eflags']):08X}" if test else None,
        "branch_destination": f"0x{dest_link:08X}" if dest_link is not None else None,
        "conditional_je_taken": dest_link == 0xAE2F2 if dest_link is not None else None,
        "media_callsite_seen": callsite is not None,
        "ordered": ordered,
        "complete": ordered,
        "missing": [name for name, present in (
            ("second_gate_entry", entry), ("test_flags", test),
            ("branch_destination", destination),
        ) if present is None],
        "selected_sequences": {
            name: int(row["sequence"]) for name, row in selected.items()
        } | ({"branch_destination": int(destination["sequence"])} if destination else {}),
    }


def verify_window_integration(source: str) -> bool:
    fallback_start = source.find("if (w3_143_postopen_probe_window || w3_146_transfer_probe_window")
    fallback_end = source.find("sync_dh_fpu_and_run_normal_core()", fallback_start)
    if fallback_start < 0 or fallback_end < 0:
        return False
    fallback = source[fallback_start:fallback_end]
    required = (
        'GWRECOMP_W3_281_BRANCH_STEP', 'w3_280_first_fallthrough_seen',
        'w3_281_window_done', 'w3_281_step_instruction_count < 16',
        'candidate_link_va >= 0x000ae2e3 && candidate_link_va <= 0x000ae2eb',
        'w3_281_second_gate_probe_window', 'CPU_Cycles = 1',
    )
    return 'w3_281_second_gate_probe_window' in fallback and all(token in source for token in required)


def verify_source_file(path: Path) -> bool:
    return verify_window_integration(path.read_text(encoding="utf-8"))
