#!/usr/bin/env python3
"""Bounded W3-300 MAIN activation and dispatch-site trace analysis."""
from __future__ import annotations

import json

MAX_TRACE_BYTES = 1024 * 1024
MAX_SELECTED_EVENTS = 48
SELECTED_PREFIXES = ("W3_298_", "W3_300_")


def parse_trace(raw: bytes) -> list[dict]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB")
    rows = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL row {number}: {exc}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"JSONL row {number} is not an object")
        rows.append(item)
    selected = [r for r in rows if str(r.get("event", "")).startswith(SELECTED_PREFIXES)]
    if len(selected) > MAX_SELECTED_EVENTS:
        raise ValueError("selected event count exceeds 48")
    return rows


def analyze(rows: list[dict]) -> dict:
    selected = [r for r in rows if str(r.get("event", "")).startswith(SELECTED_PREFIXES)]
    main_markers = [r for r in selected if r.get("event") == "W3_300_MAIN_HOOK_ARMED"]
    site_markers = [r for r in selected if r.get("event") == "W3_300_SITE_DISPATCH"]
    sound_rows = [r for r in selected if str(r.get("event", "")).startswith("W3_298_")]
    cps = [r for r in rows if r.get("event") == "target_runtime_checkpoint"]
    apis = [r for r in rows if r.get("event") == "setup_dos_api"]
    last_cp = cps[-1] if cps else None
    last_api = apis[-1] if apis else None
    unique_site_links = sorted({int(r.get("link_va", -1)) for r in site_markers})
    if not main_markers:
        classification = "MAIN_ACTIVATION_MARKER_ABSENT"
    elif not site_markers:
        classification = "MAIN_ACTIVE_SOUND_SITES_NOT_DISPATCHED_IN_CAPTURE"
    elif not sound_rows:
        classification = "DISPATCH_SEEN_W3_298_RECORDER_GAP"
    else:
        classification = "PAIRED_ORIGINAL_SOUND_CAPTURE"
    return {
        "classification": classification,
        "main_activation_marker_count": len(main_markers),
        "main_activation_marker": main_markers[0] if main_markers else None,
        "dispatch_site_count": len(site_markers),
        "dispatch_site_links": [hex(x) for x in unique_site_links],
        "w3_298_sound_event_count": len(sound_rows),
        "w3_298_events": sound_rows,
        "selected_event_count": len(selected),
        "generic_checkpoint_count": len(cps),
        "checkpoint_names_in_order": [r.get("checkpoint") for r in cps],
        "game_main_entry_reached": any(int(r.get("link_va", -1)) == 0x00093f30
                                        for r in cps),
        "video_setup_reached": any(int(r.get("link_va", -1)) in
                                    (0x0009fd40, 0x0009fdef, 0x0009fdf9) for r in cps),
        "last_generic_checkpoint": ({"sequence": last_cp.get("sequence"),
            "checkpoint": last_cp.get("checkpoint"),
            "link_va": hex(int(last_cp.get("link_va", 0))),
            "runtime_eip": hex(int(last_cp.get("eip", 0))),
            "data_rebase": hex(int(last_cp.get("data_rebase", 0)))} if last_cp else None),
        "last_dos_api": ({"sequence": last_api.get("sequence"),
            "ordinal": last_api.get("ordinal"), "operation": last_api.get("operation"),
            "path": last_api.get("requested_path"), "cwd": last_api.get("cwd"),
            "cf": last_api.get("cf"), "result": last_api.get("result")}
            if last_api else None),
    }


def validate_first_hit(rows: list[dict]) -> None:
    selected = [r for r in rows if str(r.get("event", "")).startswith(SELECTED_PREFIXES)]
    if len(selected) > MAX_SELECTED_EVENTS:
        raise ValueError("selected event count exceeds 48")
    checkpoints = [r.get("checkpoint") for r in selected
                   if r.get("event") == "W3_298_SOUND_PIT_CHECKPOINT"]
    if len(checkpoints) != len(set(checkpoints)):
        raise ValueError("duplicate W3-298 first-hit checkpoint")
    site_links = [r.get("link_va") for r in selected
                  if r.get("event") == "W3_300_SITE_DISPATCH"]
    if len(site_links) != len(set(site_links)):
        raise ValueError("duplicate W3-300 dispatch-site marker")

