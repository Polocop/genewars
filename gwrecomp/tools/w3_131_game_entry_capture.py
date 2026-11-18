"""Bounded parser for the W3-131 original startup-to-game boundary."""
from __future__ import annotations

import json
from typing import Any

CAP_BYTES = 1_048_576
CAP_EVENTS = 12
TARGETS = {0x92AE2, 0x92B6B, 0x92B71, 0x929C8, 0x94347, 0x92710}


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > CAP_BYTES:
        raise ValueError("trace byte cap exceeded")
    rows = []
    for line in raw.splitlines():
        if line.strip():
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
    return rows


def relevant(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    for row in rows:
        if row.get("event") != "target_runtime_checkpoint":
            continue
        link = row.get("link_va")
        marked = any(row.get(key) is True for key in (
            "w3_109_targeted_playintro_return",
            "w3_117_play_smacker_call_boundary",
            "w3_121_reset_inputs_boundary",
            "w3_124_post_join_continuation",
            "w3_106_targeted_game_page",
        ))
        if link in TARGETS and marked:
            selected.append(row)
        if len(selected) >= CAP_EVENTS:
            break
    return selected


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    events = relevant(rows)
    links = [row["link_va"] for row in events]
    rebases = sorted({row["eip"] - row["link_va"] for row in events
                      if isinstance(row.get("eip"), int) and isinstance(row.get("link_va"), int)})
    return {
        "classification": ("GAME_ENTRY_OBSERVED" if 0x92710 in links else
                           "MAIN_GAME_CALLSITE_OBSERVED" if 0x94347 in links else
                           "PLAYINTRO_RETURN_OBSERVED" if 0x929C8 in links else
                           "POST_SMACKER_CONTINUATION_ONLY" if 0x92AE2 in links else
                           "NO_W3_131_FRONTIER"),
        "event_count": len(events),
        "events": events,
        "link_vas": [f"0x{link:08X}" for link in links],
        "runtime_rebases": [f"0x{base:08X}" for base in rebases],
        "mapping_consistent": len(rebases) <= 1,
        "main_game_callsite_seen": 0x94347 in links,
        "game_entry_seen": 0x92710 in links,
        "last_checkpoint": events[-1].get("checkpoint") if events else None,
    }


def source_coverage(source: str) -> dict[str, bool]:
    return {
        "post_smacker_return": "case 0x00092ae2" in source,
        "post_join_branch": "case 0x00092b6b" in source and "case 0x00092b71" in source,
        "playintro_return": "case 0x000929c8" in source,
        "main_game_callsite": "case 0x00094347" in source,
        "game_entry": "case 0x00092710" in source,
        "bounded_playintro_filter": "w3_109_checkpoint_count < 12" in source,
        "bounded_game_filter": "w3_106_checkpoint_count < 12" in source,
    }
