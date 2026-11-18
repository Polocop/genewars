"""Bounded parser for the first original post-SMACKOPEN branch result."""
from __future__ import annotations

import json
from typing import Any

MAX_TRACE_BYTES = 1_048_576
TARGETS = {
    "W3_143_SMACKOPEN_SUCCESS_FLAG_ZERO": 0xAE39A,
    "W3_143_SMACKOPEN_SUCCESS_FLAG_ONE": 0xAE3C9,
    "W3_143_SMACKOPEN_FAILURE": 0xAE4CE,
    "W3_142_SMACKTOBUFFER_ENTRY": 0xC5140,
}


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB cap")
    rows = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"non-object JSONL event at line {number}")
        rows.append(row)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    direct = next((r for r in rows if r.get("event") == "target_runtime_checkpoint" and
                   r.get("checkpoint") == "W3_133_PLAY_SMK_DIRECT_ENTRY" and
                   r.get("link_va") == 0xAE308), None)
    selected = []
    seen = set()
    for row in rows:
        name = row.get("checkpoint")
        if row.get("event") != "target_runtime_checkpoint" or name not in TARGETS:
            continue
        if row.get("link_va") != TARGETS[name] or name in seen:
            continue
        seen.add(name)
        selected.append(row)
    success_names = ("W3_143_SMACKOPEN_SUCCESS_FLAG_ZERO", "W3_143_SMACKOPEN_SUCCESS_FLAG_ONE")
    result = next((r for r in selected if r["checkpoint"] in
                   (*success_names, "W3_143_SMACKOPEN_FAILURE")), None)
    smto = next((r for r in selected if r["checkpoint"] == "W3_142_SMACKTOBUFFER_ENTRY"), None)
    mappings = {r["eip"] - r["link_va"] for r in [direct, *selected]
                if isinstance(r, dict) and isinstance(r.get("eip"), int)
                and isinstance(r.get("link_va"), int)}
    if not direct:
        classification = "DIRECT_ROUTE_NOT_REACHED"
    elif not result:
        classification = "DIRECT_ROUTE_REACHED_POSTOPEN_BRANCH_NOT_CAPTURED"
    elif result["checkpoint"] in success_names:
        classification = "SMACKOPEN_SUCCESS_BRANCH_OBSERVED"
    else:
        classification = "SMACKOPEN_FAILURE_BRANCH_OBSERVED"
    return {
        "classification": classification,
        "direct_route_entry": direct,
        "postopen_branch": result,
        "smack_to_buffer_entry": smto,
        "same_runtime_rebase": len(mappings) == 1,
        "runtime_rebases": [f"0x{x:08X}" for x in sorted(mappings)],
        "branch_return_eax": result.get("eax") if result else None,
        "branch_eflags": result.get("eflags") if result else None,
        "transfer_followed": bool(result and result["checkpoint"] in success_names and smto),
        "framebuffer_proven": False,
    }
