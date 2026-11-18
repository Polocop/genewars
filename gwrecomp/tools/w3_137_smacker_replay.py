"""Bounded parser for the single W3-137 original Smacker replay."""
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


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    events = []
    seen = set()
    for row in rows:
        if row.get("event") != "target_runtime_checkpoint" or row.get("w3_133_target_checkpoint") is not True:
            continue
        identity = (row.get("checkpoint"), row.get("link_va"))
        if identity in seen:
            continue
        seen.add(identity)
        events.append(row)
        if len(events) >= CAP_EVENTS:
            break
    links = [row.get("link_va") for row in events if isinstance(row.get("link_va"), int)]
    rebases = sorted({row["eip"] - row["link_va"] for row in events
                      if isinstance(row.get("eip"), int) and isinstance(row.get("link_va"), int)})
    entry = next((row for row in events if row.get("checkpoint") == "W3_133_PLAY_SMK_ENTRY"), None)
    direct = next((row for row in events if row.get("link_va") == 0xAE308), None)
    via_buffer = next((row for row in events if row.get("link_va") == 0xAE4D8), None)
    smackopen = next((row for row in events if row.get("link_va") == 0xC62F0), None)
    radmalloc = next((row for row in events if row.get("link_va") == 0xAE63C), None)
    alloc = next((row for row in events if row.get("link_va") == 0x91E00 and row.get("eax") == 0x4AC), None)
    alloc_return = next((row for row in events if row.get("checkpoint") ==
                         "W3_133_LBMEMORYALLOC_RETURN"), None)
    copy = next((row for row in events if row.get("link_va") == 0xAE668), None)
    callback = next((row for row in events if row.get("checkpoint") ==
                     "W3_133_DRAW_CALLBACK_TARGET"), None)
    callback_value = entry.get("w3_133_draw_callback_value") if entry else None
    callback_valid = bool(entry and entry.get("w3_133_draw_callback_valid"))
    ebx = entry.get("ebx") if entry else None
    route_inference = None
    if callback_valid and isinstance(ebx, int):
        route_inference = {
            "route": "via_buffer" if callback_value or (ebx & 0x84) else "direct",
            "basis": "same-run callback global and BL mask; inference from exact-target wrapper control flow",
            "dynamic_selected_entry_observed": bool(direct or via_buffer),
        }
    caller_stack = alloc.get("stack_words_u32") if alloc else None
    alloc_return_addr = caller_stack[0] if isinstance(caller_stack, list) and caller_stack else None
    return {
        "classification": ("COPY_TO_SCREEN_TARGET_OBSERVED" if copy else
                           "DRAW_CALLBACK_TARGET_OBSERVED" if callback else
                           "DIRECT_PLAYBACK_ENTRY_OBSERVED" if direct else
                           "BUFFER_PLAYBACK_ENTRY_OBSERVED" if via_buffer else
                           "PLAY_SMK_ONLY" if entry else "NO_W3_133_TARGET"),
        "event_count": len(events),
        "events": events,
        "link_vas": [f"0x{x:08X}" for x in links],
        "runtime_rebases": [f"0x{x:08X}" for x in rebases],
        "mapping_consistent": len(rebases) <= 1,
        "play_smk_entry": entry,
        "draw_callback_sample_valid": callback_valid if entry else None,
        "draw_callback_value": callback_value,
        "route_entry_observed": "direct" if direct else "via_buffer" if via_buffer else None,
        "route_inference": route_inference,
        "smackopen_entry": smackopen,
        "radmalloc_entry": radmalloc,
        "allocator_entry_4ac": alloc,
        "allocator_stack_return_runtime": (f"0x{alloc_return_addr:08X}"
                                            if isinstance(alloc_return_addr, int) else None),
        "allocator_return_checkpoint": alloc_return,
        "copy_to_screen_target_observed": bool(copy),
        "callback_target_observed": bool(callback),
        "framebuffer_write_observed": False,
        "visible_frame_observed": False,
        "menu_observed": False,
        "last_target_checkpoint": events[-1].get("checkpoint") if events else None,
    }
