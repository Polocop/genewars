"""Bounded event filtering and evidence checks for W3-263."""
from __future__ import annotations

import json
from typing import Any

MAX_TRACE_BYTES = 1_048_576
MAX_EVENTS = 128
MAX_COPY_BYTES = 65_536
MAX_FRAME_HASH_BYTES = 1_048_576
TARGET_LINKS = {"copy_pre": 0xA0013, "copy_post": 0xA0015}


def parse_trace(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB cap")
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSONL line {line_no}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"JSONL line {line_no} is not an object")
        rows.append(row)
        if len(rows) > MAX_EVENTS:
            raise ValueError("trace exceeds 128 event cap")
    return rows


def select_target_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    for row in rows:
        event = row.get("event")
        if event in {"main_mapping", "backend_present_return"}:
            selected.append(row)
        elif event in TARGET_LINKS and row.get("link_va") == TARGET_LINKS[event]:
            selected.append(row)
    return selected


def analyze_trace(rows: list[dict[str, Any]], guard: dict[str, Any] | None = None) -> dict[str, Any]:
    original_count = len(rows)
    rows = select_target_events(rows)
    names = [row.get("event") for row in rows]
    ordinals = [(row.get("event"), row.get("invocation_ordinal", 1)) for row in rows]
    if len(ordinals) != len(set(ordinals)):
        raise ValueError("duplicate event for an invocation ordinal")
    by_event = {row.get("event"): row for row in rows}
    mapping = by_event.get("main_mapping")
    pre = by_event.get("copy_pre")
    post = by_event.get("copy_post")
    present = by_event.get("backend_present_return")
    mapping_valid = bool(
        mapping and mapping.get("mapping_matches") is True and
        mapping.get("link_va") == 0xAF96C and
        mapping.get("runtime_linear", 0) - mapping.get("link_va", 0) == mapping.get("code_rebase") and
        mapping.get("instruction_bytes", "").startswith("eb765741")
    )
    copy_mapping_valid = bool(
        mapping_valid and pre and post and pre.get("mapping_matches") is True and
        post.get("mapping_matches") is True and
        pre.get("code_rebase") == mapping.get("code_rebase") == post.get("code_rebase") and
        pre.get("runtime_linear", 0) - pre.get("link_va", 0) == pre.get("code_rebase") and
        post.get("runtime_linear", 0) - post.get("link_va", 0) == post.get("code_rebase")
    )
    copy_bytes = pre.get("copy_bytes", 0) if pre else 0
    copy_valid = bool(
        copy_mapping_valid and pre and post and pre.get("copy_range_bounded") is True and
        post.get("full_copy_valid") is True and 0 < copy_bytes <= MAX_COPY_BYTES and
        copy_bytes == post.get("copy_bytes") and
        pre.get("source_hash_fnv1a64") == post.get("source_hash_fnv1a64") ==
        post.get("destination_hash_fnv1a64")
    )
    frame_hash_bytes = present.get("frame_hash_covered_bytes", 0) if present else 0
    frame_valid = bool(
        present and present.get("surface_valid") is True and
        present.get("sdl_render_present_returned") is True and
        0 < present.get("render_width_px", 0) and 0 < present.get("render_height_px", 0) and
        0 < frame_hash_bytes <= MAX_FRAME_HASH_BYTES and
        present.get("sampled_pixels", 0) > 0 and present.get("nonzero_pixels", 0) > 0 and
        present.get("frame_hash") is not None
    )
    timeout = bool(guard and (guard.get("cause") == "TIMEOUT" or
                              guard.get("exit_reason") == "TIMEOUT"))
    if frame_valid:
        classification = "RENDERER_BUFFER_PRESENTED"
    elif copy_valid:
        classification = "A0000_COPY_AND_VGA_STATE_OBSERVED"
    elif pre:
        classification = "COPY_PRE_ONLY_OR_INVALID"
    elif mapping_valid:
        classification = "MAIN_MAPPING_ONLY"
    else:
        classification = "MAIN_MAPPING_NOT_OBSERVED"
    if timeout:
        classification += "_GUARD_TIMEOUT"
    return {
        "classification": classification,
        "event_order": names,
        "input_event_count": original_count,
        "selected_event_count": len(rows),
        "main_mapping": mapping,
        "copy_pre": pre,
        "copy_post": post,
        "backend_present_return": present,
        "main_mapping_valid": mapping_valid,
        "copy_mapping_valid": copy_mapping_valid,
        "copy_hash_match": copy_valid,
        "renderer_buffer_presented": frame_valid,
        "visible_screenshot_proven": False,
        "guard_timeout": timeout,
    }
