"""Parser and evidence checks for the bounded W3-262 custom trace."""
from __future__ import annotations

import json
from typing import Any

MAX_TRACE_BYTES = 1_048_576
MAX_EVENTS = 128
MAX_COPY_BYTES = 65_536
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
        if event == "backend_present_return":
            selected.append(row)
        elif event in TARGET_LINKS and row.get("link_va") == TARGET_LINKS[event]:
            selected.append(row)
    return selected


def analyze_trace(rows: list[dict[str, Any]], guard: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = select_target_events(rows)
    names = [row.get("event") for row in rows]
    if len(names) != len(set((name, row.get("invocation_ordinal", 1))
                             for name, row in zip(names, rows))):
        raise ValueError("duplicate event for an invocation ordinal")
    by_event = {row.get("event"): row for row in rows}
    pre = by_event.get("copy_pre")
    post = by_event.get("copy_post")
    present = by_event.get("backend_present_return")
    mapping_valid = bool(
        pre and post and pre.get("mapping_matches") is True and
        post.get("mapping_matches") is True and
        pre.get("code_rebase") == post.get("code_rebase") and
        pre.get("runtime_linear", 0) - pre.get("link_va", 0) == pre.get("code_rebase") and
        post.get("runtime_linear", 0) - post.get("link_va", 0) == post.get("code_rebase")
    )
    copy_valid = bool(
        mapping_valid and pre and post and
        pre.get("copy_range_bounded") is True and post.get("full_copy_valid") is True and
        pre.get("copy_bytes", 0) == post.get("copy_bytes", -1) and
        0 < pre.get("copy_bytes", 0) <= MAX_COPY_BYTES and
        pre.get("source_hash_fnv1a64") == post.get("source_hash_fnv1a64") and
        pre.get("source_hash_fnv1a64") == post.get("destination_hash_fnv1a64")
    )
    framebuffer_pixels_proven = bool(
        present and present.get("frame_hash") and
        present.get("nonzero_pixels", 0) > 0 and
        present.get("render_width_px", 0) > 0 and
        present.get("render_height_px", 0) > 0
    )
    timeout = bool(guard and (guard.get("cause") == "TIMEOUT" or
                              guard.get("exit_reason") == "TIMEOUT"))
    if copy_valid:
        classification = "COPY_AND_VGA_STATE_OBSERVED"
    elif pre:
        classification = "COPY_PRE_ONLY_OR_INVALID"
    else:
        classification = "TARGET_COPY_NOT_REACHED"
    if timeout:
        classification += "_GUARD_TIMEOUT"
    return {
        "classification": classification,
        "event_order": names,
        "copy_pre": pre,
        "copy_post": post,
        "backend_present_return": present,
        "main_mapping_valid": mapping_valid,
        "copy_hash_match": copy_valid,
        "backend_present_observed": bool(present),
        "framebuffer_pixels_proven": framebuffer_pixels_proven,
        "framebuffer_limit": ("present method returned, but host frame pixels/hash were not captured"
                              if present and not framebuffer_pixels_proven else None),
        "guard_timeout": timeout,
        "event_count": len(rows),
    }
