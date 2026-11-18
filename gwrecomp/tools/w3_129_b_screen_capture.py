"""Bounded parsing and source checks for the W3-129 b_screen capture."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
CAP_BYTES = 1_048_576


def parse_jsonl(raw: bytes, max_bytes: int = CAP_BYTES) -> list[dict[str, Any]]:
    if len(raw) > max_bytes:
        raise ValueError("trace byte cap exceeded")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def source_coverage(source: str) -> dict[str, bool]:
    return {
        "post_store_checkpoint": "link_va == 0x00092b87" in source,
        "bounded_free_entry": "link_va == 0x00092030" in source,
        "data_mapping_sample": "target_data_rebase + 0x00114ca0" in source,
        "descriptor_checked": "checkpoint_ds_valid" in source and "checkpoint_ds_descriptor.GetLimit()" in source,
        "same_pointer_free_filter": "reg_eax == w3_129_b_screen_value" in source,
        "bounded_event_cap": "w3_129_b_screen_capture_count < 8" in source,
    }


def relevant_checkpoints(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        if row.get("event") != "target_runtime_checkpoint" or not row.get("w3_129_target_checkpoint"):
            continue
        if row.get("checkpoint") not in ("W3_129_B_SCREEN_POST_STORE", "W3_129_MEMORY_FREE_ENTRY"):
            continue
        out.append(row)
    return out


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    checkpoints = relevant_checkpoints(rows)
    stores = [row for row in checkpoints if row.get("checkpoint") == "W3_129_B_SCREEN_POST_STORE"]
    frees = [row for row in checkpoints if row.get("checkpoint") == "W3_129_MEMORY_FREE_ENTRY"]
    store = stores[0] if stores else None
    free = frees[0] if frees else None
    data_anchor = next((row for row in rows if row.get("event") == "target_code_anchor"
                        and row.get("anchor") == "CRT_ARGV_LOAD"), None)
    main_anchor = next((row for row in rows if row.get("event") == "target_code_anchor"
                        and row.get("anchor") == "MAIN_ENTRY"), None)
    restarts = [row for row in rows if row.get("event") == "w3_127_target_instruction_restart"]
    anchor_index = next((i for i, row in enumerate(restarts) if row.get("link_va") == 0x92B71), None)
    allocator_entry = allocator_return = None
    if anchor_index is not None:
        allocator_entry = next((row for row in restarts[anchor_index + 1:]
                                if row.get("link_va") == 0x91E00), None)
        if allocator_entry:
            allocator_return = next((row for row in restarts[restarts.index(allocator_entry) + 1:]
                                     if row.get("link_va") == 0x92B82), None)
    mapping = store.get("data_rebase") if store else None
    code_rebase = main_anchor.get("candidate_rebase") if main_anchor else None
    free_return_link = (free.get("return_address") - code_rebase
                        if free and code_rebase is not None else None)
    return {
        "checkpoint_count": len(checkpoints),
        "data_anchor_seen": data_anchor is not None,
        "data_anchor_rebase": data_anchor.get("data_rebase") if data_anchor else None,
        "main_code_rebase": code_rebase,
        "allocator_entry_seen": allocator_entry is not None,
        "allocator_entry_sequence": allocator_entry.get("sequence") if allocator_entry else None,
        "allocator_request_eax": f"0x{allocator_entry['eax']:08X}" if allocator_entry else None,
        "allocator_return_continuation_seen": allocator_return is not None,
        "allocator_return_sequence": allocator_return.get("sequence") if allocator_return else None,
        "allocator_return_eax": f"0x{allocator_return['eax']:08X}" if allocator_return else None,
        "allocator_and_store_same_pointer": bool(store and allocator_return and
                                                  allocator_return.get("eax") == store.get("eax")),
        "store_seen": store is not None,
        "store_sample_valid": bool(store and store.get("w3_129_b_screen_sample_valid")),
        "store_link_va": f"0x{store['link_va']:08X}" if store else None,
        "store_eax": f"0x{store['eax']:08X}" if store else None,
        "b_screen_link_offset": "0x00114CA0",
        "store_data_rebase": mapping,
        "store_runtime_offset": store.get("w3_129_b_screen_offset") if store else None,
        "b_screen_value": f"0x{store['w3_129_b_screen_value']:08X}"
        if store and store.get("w3_129_b_screen_sample_valid") else None,
        "ds_descriptor_valid": store.get("ds_descriptor_valid") if store else None,
        "ds_base": store.get("ds_base") if store else None,
        "ds_limit": store.get("ds_limit") if store else None,
        "matching_free_seen": free is not None,
        "free_eax": f"0x{free['eax']:08X}" if free else None,
        "free_return_address": f"0x{free['return_address']:08X}" if free else None,
        "free_return_link_va": f"0x{free_return_link:08X}" if free_return_link is not None else None,
        "free_checkpoint_ordinal": free.get("checkpoint_ordinal") if free else None,
        "first_later_free_linked": bool(store and free and free.get("eax") == store.get("w3_129_b_screen_value")),
        "first_later_free_after_store": bool(store and free and
                                               free.get("sequence", 0) > store.get("sequence", 0)),
        "raw_checkpoint_order": [row.get("checkpoint") for row in checkpoints],
    }
