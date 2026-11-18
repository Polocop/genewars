"""Bounded validation of the target restart-PC diagnostic."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
CAP = 16
ANCHOR_RANGE = (0x92B71, 0x92B82)
CALLEE = 0x91E00


def parse_jsonl(raw: bytes, max_bytes: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > max_bytes:
        raise ValueError("trace byte cap exceeded")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def restart_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events, seen_consecutive = [], None
    for row in rows:
        if row.get("event") != "w3_127_target_instruction_restart":
            continue
        link = row.get("link_va")
        if not (ANCHOR_RANGE[0] <= link <= ANCHOR_RANGE[1] or link == CALLEE):
            continue
        if link == seen_consecutive:
            continue
        events.append(row)
        seen_consecutive = link
        if len(events) >= CAP:
            break
    return events


def source_coverage(source: str) -> dict[str, bool]:
    return {
        "narrow_code_range": "candidate_link_va >= 0x00092b71 && candidate_link_va <= 0x00092b82" in source,
        "callee_entry_included": "candidate_link_va == 0x00091e00" in source,
        "event_cap_sixteen": "w3_127_restart_event_count < 16" in source,
        "duplicate_suppressed": "candidate_link_va != w3_127_last_restart_link_va" in source,
        "json_event_named": "w3_127_target_instruction_restart" in source,
    }


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    links = [event.get("link_va") for event in events]
    anchor_idx = next((index for index, link in enumerate(links) if link == 0x92B71), None)
    return_idx = next((index for index, link in enumerate(links)
                       if anchor_idx is not None and index > anchor_idx and link == 0x92B82), None)
    post_anchor = links[anchor_idx:return_idx + 1] if anchor_idx is not None and return_idx is not None else (
        links[anchor_idx:] if anchor_idx is not None else [])
    return {"link_vas": [f"0x{link:08X}" for link in links],
            "count": len(events), "bounded": len(events) <= CAP,
            "post_anchor_link_vas": [f"0x{link:08X}" for link in post_anchor],
            "callsite_restart_observed": 0x92B7D in post_anchor,
            "callee_restart_observed": CALLEE in post_anchor,
            "caller_return_restart_observed": 0x92B82 in post_anchor,
            "callee_then_return_observed": CALLEE in post_anchor and 0x92B82 in post_anchor and
                post_anchor.index(CALLEE) < post_anchor.index(0x92B82)}


def contract_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize(events)
    links = [event.get("link_va") for event in events]
    anchor_idx = next((index for index, link in enumerate(links) if link == 0x92B71), None)
    return_idx = next((index for index, link in enumerate(links)
                       if anchor_idx is not None and index > anchor_idx and link == 0x92B82), None)
    path = events[anchor_idx:return_idx + 1] if anchor_idx is not None and return_idx is not None else []
    callee = next((event for event in path if event.get("link_va") == CALLEE), None)
    caller = next((event for event in path if event.get("link_va") == 0x92B82), None)
    rebases = {int(event["eip"]) - int(event["link_va"]) for event in path}
    selectors = {event.get("cs") for event in path}
    return {**summary,
            "same_run_mapping_delta": next(iter(rebases)) if len(rebases) == 1 else None,
            "same_run_cs": next(iter(selectors)) if len(selectors) == 1 else None,
            "callee_entry_registers": callee,
            "caller_return_registers": caller,
            "entry_to_return_esp_delta": (int(caller["esp"]) - int(callee["esp"]))
                if callee and caller else None}
