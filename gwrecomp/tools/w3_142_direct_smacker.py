"""Bounded parser for the first natural direct-Smacker display route."""
from __future__ import annotations

import json
from typing import Any

MAX_TRACE_BYTES = 1_048_576
TARGETS = {
    "W3_142_SMACKTOBUFFER_ENTRY": 0xC5140,
    "W3_142_SMACKDOFRAME_ENTRY": 0xC5BD0,
    "W3_142_LBSCREENSWAP_CALLSITE": 0xAE47F,
    "W3_142_LBSCREENSWAP_ENTRY": 0x9FFE0,
}


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB cap")
    rows = []
    for index, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"non-object JSONL event at line {index}")
        rows.append(row)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    direct = next((row for row in rows if row.get("checkpoint") == "W3_133_PLAY_SMK_DIRECT_ENTRY"
                   and row.get("link_va") == 0xAE308), None)
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        name = row.get("checkpoint")
        if row.get("event") != "target_runtime_checkpoint" or name not in TARGETS:
            continue
        if row.get("link_va") != TARGETS[name] or name in seen:
            continue
        seen.add(name)
        selected.append(row)
        if len(selected) == len(TARGETS):
            break
    rebase_values = {row["eip"] - row["link_va"] for row in selected
                     if isinstance(row.get("eip"), int) and isinstance(row.get("link_va"), int)}
    ordered = all(selected[i]["sequence"] < selected[i + 1]["sequence"]
                  for i in range(len(selected) - 1))
    same_process = bool(selected) and all(
        row.get("process_psp") == selected[0].get("process_psp") and
        row.get("cs") == selected[0].get("cs") for row in selected)
    route_proven = bool(direct and direct.get("link_va") == 0xAE308)
    return {
        "classification": ("DIRECT_ROUTE_CHECKPOINTS_CAPTURED" if selected else
                          "DIRECT_ENTRY_CAPTURED_TRANSFER_NOT_OBSERVED" if direct else
                          "DIRECT_ROUTE_NOT_REACHED_OR_NOT_CAPTURED"),
        "direct_route_entry": direct,
        "events": selected,
        "target_event_count": len(selected),
        "all_same_runtime_rebase": len(rebase_values) <= 1 and bool(rebase_values),
        "runtime_rebases": [f"0x{value:08X}" for value in sorted(rebase_values)],
        "strictly_ordered": ordered,
        "same_process_context": same_process,
        "direct_entry_observed": route_proven,
        "draw_or_framebuffer_proven": False,
    }
