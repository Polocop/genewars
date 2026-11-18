"""Bounded host-only parsing and source checks for W3-115."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CAP = 5
TARGETS = (0x929D0, 0x929FA, 0x92A00, 0x92A4F, 0x92A11)
BRANCH_FALLTHROUGH = 0x92A00
BRANCH_TAKEN = 0x92A4F
ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


def parse_jsonl(raw: bytes, max_bytes: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > max_bytes:
        raise ValueError("trace exceeds configured size cap")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def parse_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("w3_115_play_smacker_branch") is True][:CAP]


def mapping(events: list[dict[str, Any]]) -> dict[str, Any]:
    bases = set()
    for event in events:
        link, eip = event.get("link_va"), event.get("eip")
        if not isinstance(link, int) or not isinstance(eip, int) or eip < link:
            raise ValueError("event requires valid link VA and runtime EIP")
        bases.add(eip - link)
    return {"rebases": [f"0x{x:08X}" for x in sorted(bases)], "consistent": len(bases) <= 1}


def branch_outcome(events: list[dict[str, Any]]) -> str:
    links = {event.get("link_va") for event in events}
    if BRANCH_TAKEN in links:
        return "JE_TAKEN_TO_92A4F"
    if BRANCH_FALLTHROUGH in links:
        return "JE_NOT_TAKEN_TO_92A00"
    return "BRANCH_DESTINATION_NOT_OBSERVED"


def state_updates_are_siblings(source: str) -> bool:
    update_start = source.index("if (w3_107_target_checkpoint) {\n\t\t\t\t\t++w3_107_checkpoint_count;")
    w109_start = source.index("if (w3_109_target_checkpoint) {\n\t\t\t\t\t++w3_109_checkpoint_count;", update_start)
    w115_start = source.index("if (w3_115_target_checkpoint) {\n\t\t\t\t\t++w3_115_checkpoint_count;", w109_start)
    w103_start = source.index("if (w3_103_page_mode_trigger)", w115_start)
    return all(
        source[left:right].count("{") == source[left:right].count("}")
        for left, right in ((update_start, w109_start), (w109_start, w115_start), (w115_start, w103_start))
    )


def source_coverage(source: str) -> dict[str, bool]:
    selected_start = source.index("const bool selected_capture_site")
    selected_end = source.index("// Before MAIN's runtime mapping is known", selected_start)
    selected_block = source[selected_start:selected_end]
    selected = {int(x, 16) for x in re.findall(r"candidate_link_va\s*==\s*(0x[0-9a-fA-F]+)", selected_block)}
    return {
        "all_targets_selected": all(target in selected for target in TARGETS),
        "compare_checkpoint_named": '"W3_115_PLAYSMACKER_COMPARE"' in source,
        "both_branch_destinations_named": (
            '"W3_115_PLAYSMACKER_BRANCH_TAKEN"' in source and
            '"W3_115_PLAYSMACKER_BRANCH_FALLTHROUGH"' in source
        ),
        "saved_dl_sample_serialized": "w3_115_saved_dl" in source,
        "ser_start_sample_serialized": "w3_115_ser_start_u8" in source,
        "state_updates_are_siblings": state_updates_are_siblings(source),
    }


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "event_count": len(events),
        "link_vas": [f"0x{event['link_va']:08X}" for event in events],
        "mapping": mapping(events),
        "branch_outcome": branch_outcome(events),
    }
