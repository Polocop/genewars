from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.w3_278_play_smk_branch import MAX_BYTES, MAX_ROWS

EVENT_LINKS = {
    "w3_278_later_play_smk_entry": 0xAE2D0,
    "w3_278_global_load": 0xAE2DF,
    "w3_278_branch_test": 0xAE2E1,
}
DESTINATIONS = {0xAE2E3, 0xAE2E8}


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
    code_rebase = int(mappings[0]["code_rebase"])
    selected: dict[str, dict[str, Any]] = {}
    destination = None
    for row in rows:
        event = row.get("event")
        link = int(row.get("link_va", -1))
        if event in EVENT_LINKS:
            if link != EVENT_LINKS[event]:
                raise ValueError(f"unexpected link VA for {event}")
            selected[event] = row
        elif event == "w3_278_branch_target" and link in DESTINATIONS:
            if destination is not None:
                raise ValueError("duplicate branch destination")
            destination = row
        else:
            continue
        runtime = int(row["runtime_linear"])
        rebase = int(row["code_rebase"])
        if rebase != code_rebase or runtime - rebase != link:
            raise ValueError("runtime mapping mismatch")
    entry = selected.get("w3_278_later_play_smk_entry")
    loaded = selected.get("w3_278_global_load")
    test = selected.get("w3_278_branch_test")
    ordered = bool(entry and loaded and test and destination and
                   int(entry["sequence"]) < int(loaded["sequence"]) <
                   int(test["sequence"]) < int(destination["sequence"]))
    dest_link = int(destination["link_va"]) if destination else None
    return {
        "code_rebase": f"0x{code_rebase:08X}",
        "later_entry_seen": entry is not None,
        "loaded_ecx": f"0x{int(loaded['ecx']):08X}" if loaded else None,
        "test_eflags": f"0x{int(test['eflags']):08X}" if test else None,
        "branch_destination": f"0x{dest_link:08X}" if dest_link is not None else None,
        "branch_taken": dest_link == 0xAE2E8 if dest_link is not None else None,
        "ordered": ordered,
        "complete": ordered,
        "missing": [name for name, present in (
            ("later_entry", entry), ("loaded_ecx", loaded),
            ("test_flags", test), ("branch_destination", destination),
        ) if present is None],
        "selected_sequences": {
            name: int(row["sequence"]) for name, row in selected.items()
        } | ({"branch_destination": int(destination["sequence"])} if destination else {}),
    }


def verify_step_window(source: str) -> bool:
    required = (
        'GWRECOMP_W3_279_BRANCH_STEP',
        'w3_278_later_play_smk_entry_seen',
        'w3_278_branch_target_seen',
        'w3_279_step_instruction_count < 16',
        'candidate_link_va >= 0x000ae2d0 && candidate_link_va <= 0x000ae2e8',
        'w3_279_branch_probe_window',
    )
    return all(token in source for token in required)


def verify_source_file(path: Path) -> bool:
    return verify_step_window(path.read_text(encoding="utf-8"))
