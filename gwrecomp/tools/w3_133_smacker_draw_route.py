"""Bounded evidence parser for W3-133 Smacker route and first draw capture."""
from __future__ import annotations

import json
from typing import Any

CAP_BYTES = 1_048_576
CAP_EVENTS = 12


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > CAP_BYTES:
        raise ValueError("trace byte cap exceeded")
    rows = []
    for line in raw.splitlines():
        if line.strip():
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
    return rows


def target_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("event") == "target_runtime_checkpoint" and
            row.get("w3_133_target_checkpoint") is True][:CAP_EVENTS]


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    events = target_events(rows)
    links = [row.get("link_va") for row in events if isinstance(row.get("link_va"), int)]
    rebases = sorted({row["eip"] - row["link_va"] for row in events
                      if isinstance(row.get("eip"), int) and isinstance(row.get("link_va"), int)})
    entry = next((row for row in events if row.get("checkpoint") == "W3_133_PLAY_SMK_ENTRY"), None)
    route = ("direct" if any(row.get("link_va") == 0xAE308 for row in events) else
             "via_buffer" if any(row.get("link_va") == 0xAE4D8 for row in events) else None)
    callback_value = entry.get("w3_133_draw_callback_value") if entry else None
    callback_valid = bool(entry and entry.get("w3_133_draw_callback_valid"))
    ebx = entry.get("ebx") if entry else None
    route_inference = None
    if callback_valid and isinstance(ebx, int):
        route_inference = {
            "path": "via_buffer" if callback_value or (ebx & 0x84) else "direct",
            "basis": "measured callback global and BL flags evaluated by exact-target play_smk_ control flow",
            "callback_global_nonzero": bool(callback_value),
            "bl_mask_0x84": ebx & 0x84,
            "dynamic_selected_function_entry_observed": route is not None,
        }
    alloc = next((row for row in events if row.get("checkpoint") == "W3_133_LBMEMORYALLOC_4AC_ENTRY"), None)
    rebase = entry.get("eip", 0) - entry.get("link_va", 0) if entry else None
    smack_malloc_value = entry.get("w3_133_smack_malloc_value") if entry else None
    return {
        "classification": ("COPY_TO_SCREEN_OBSERVED" if 0xAE668 in links else
                           "DRAW_CALLBACK_TARGET_OBSERVED" if any(row.get("checkpoint") == "W3_133_DRAW_CALLBACK_TARGET" for row in events) else
                           "SMACKER_ROUTE_SELECTED" if route else
                           "DIRECT_ROUTE_INFERRED_FROM_ENTRY_STATE" if route_inference and route_inference["path"] == "direct" else
                           "BUFFER_ROUTE_INFERRED_FROM_ENTRY_STATE" if route_inference else
                           "PLAY_SMK_ENTRY_ONLY" if entry else "NO_W3_133_TARGET"),
        "event_count": len(events),
        "events": events,
        "link_vas": [f"0x{link:08X}" for link in links],
        "runtime_rebases": [f"0x{base:08X}" for base in rebases],
        "mapping_consistent": len(rebases) <= 1,
        "selected_playback_route": route,
        "draw_callback_sample_valid": callback_valid if entry else None,
        "draw_callback_value": callback_value,
        "playback_route_inference": route_inference,
        "smack_malloc_sample_valid": entry.get("w3_133_smack_malloc_valid") if entry else None,
        "smack_malloc_value": smack_malloc_value,
        "smack_malloc_matches_lbmemoryalloc_runtime": bool(
            isinstance(smack_malloc_value, int) and isinstance(rebase, int) and
            smack_malloc_value == rebase + 0x91E00),
        "allocation_request_eax": f"0x{alloc['eax']:08X}" if alloc else None,
        "allocation_return_address": f"0x{alloc['return_address']:08X}" if alloc and alloc.get("return_address") else None,
        "allocator_return_observed": any(row.get("checkpoint") == "W3_133_LBMEMORYALLOC_RETURN" for row in events),
        "copy_to_screen_observed": 0xAE668 in links,
        "callback_target_observed": any(row.get("checkpoint") == "W3_133_DRAW_CALLBACK_TARGET" for row in events),
        "last_checkpoint": events[-1].get("checkpoint") if events else None,
    }


def source_coverage(source: str) -> dict[str, bool]:
    return {
        "w3_133_state": "w3_133_checkpoint_count" in source and "w3_133_capture_armed" in source,
        "play_smk_entry": "0x000ae2d0" in source,
        "direct_route": "0x000ae308" in source,
        "buffer_route": "0x000ae4d8" in source,
        "smackopen_and_radm_malloc": "0x000c62f0" in source and "0x000ae63c" in source,
        "filtered_allocator_request": "reg_eax == 0x000004ac" in source,
        "bounded_global_reads": "target_data_rebase + 0x0010b4dc" in source and
                                "target_data_rebase + 0x001a029c" in source,
        "draw_transfer": "0x000ae668" in source,
        "event_cap": "w3_133_checkpoint_count < 12" in source,
    }
