#!/usr/bin/env python3
"""Bounded parser/validator for the W3-298 original sound/PIT capture."""
from __future__ import annotations

import json
from pathlib import Path

MAX_TRACE_BYTES = 1024 * 1024
MAX_SELECTED_EVENTS = 32
SELECTED_EVENTS = {"W3_298_SOUND_PIT_CHECKPOINT", "W3_298_SOUND_GATE_BRANCH",
                   "W3_298_PIT_PORT_IO", "W3_298_PIT_LOOP_BRANCH"}


def parse_trace(raw: bytes) -> list[dict]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError(f"trace exceeds {MAX_TRACE_BYTES} byte cap")
    rows = []
    for line_no, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL row {line_no}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"JSONL row {line_no} is not an object")
        rows.append(row)
    selected = [row for row in rows if row.get("event") in SELECTED_EVENTS]
    if len(selected) > MAX_SELECTED_EVENTS:
        raise ValueError("selected W3-298 event count exceeds 32")
    return rows


def analyze(rows: list[dict]) -> dict:
    selected = [row for row in rows if row.get("event") in SELECTED_EVENTS]
    checkpoints = [row for row in selected
                   if row.get("event") == "W3_298_SOUND_PIT_CHECKPOINT"]
    branches = [row for row in selected
                if row.get("event") == "W3_298_SOUND_GATE_BRANCH"]
    ports = [row for row in selected if row.get("event") in
             {"W3_298_PIT_PORT_IO", "W3_298_PIT_LOOP_BRANCH"}]
    mappings = [row for row in rows if row.get("event") == "target_code_anchor" and
                row.get("anchor") == "MAIN_ENTRY"]
    checkpoints_all = [row for row in rows if row.get("event") == "target_runtime_checkpoint"]
    dos_calls = [row for row in rows if row.get("event") == "setup_dos_api"]
    last_dos_call = dos_calls[-1] if dos_calls else None
    duplicate_sites = sorted({str(row.get("checkpoint")) for row in checkpoints
                              if sum(other.get("checkpoint") == row.get("checkpoint")
                                     for other in checkpoints) > 1})
    names = [row.get("checkpoint") for row in checkpoints]
    return {
        "selected_event_count": len(selected),
        "checkpoint_names_in_order": names,
        "duplicate_checkpoints": duplicate_sites,
        "main_anchor_count": len(mappings),
        "main_mapping": mappings[0] if mappings else None,
        "branches": branches,
        "pit_events": ports,
        "direct_gate_reached": "PLAY_SMK_DIRECT_ENTRY" in names,
        "buffer_gate_reached": "PLAY_SMK_BUFFER_ENTRY" in names,
        "smack_setup_reached": "SMACKSOUNDUSEMSS_ENTRY" in names,
        "callback_indirect_site_reached": "SMACK_CALLBACK_INDIRECT_CALL" in names,
        "pit_callback_reached": "PIT_CALLBACK_ENTRY" in names,
        "pit_io_observed": any(row.get("event") == "W3_298_PIT_PORT_IO"
                                for row in selected),
        "last_original_checkpoint": ({key: checkpoints_all[-1].get(key) for key in
            ("sequence", "checkpoint", "process_psp", "link_va", "eip", "eax", "ebx", "ecx",
             "edx", "esi", "edi", "ebp", "esp", "eflags", "data_rebase")}
            if checkpoints_all else None),
        "last_dos_api": ({key: last_dos_call.get(key) for key in
            ("sequence", "ordinal", "operation", "process_psp", "cs", "eip", "in_ax", "in_bx",
             "out_ax", "out_dx", "cf", "result", "requested_path", "resolved_path",
             "cwd_valid", "cwd", "requested_bytes", "before_position", "dos_error")}
            if last_dos_call else None),
        "conclusion": ("original PIT callback/port evidence observed"
                       if any(row.get("event") == "W3_298_PIT_PORT_IO" for row in selected)
                       else "INCONCLUSIVE: no W3-298 target checkpoint fired; the bounded replay does not distinguish an unreached sound path from a hook-activation gap"),
    }


def validate_first_hit(rows: list[dict]) -> None:
    summary = analyze(rows)
    if summary["duplicate_checkpoints"]:
        raise ValueError("first-hit checkpoint duplicates found")
    if summary["selected_event_count"] > MAX_SELECTED_EVENTS:
        raise ValueError("selected W3-298 event count exceeds cap")
    for row in rows:
        if row.get("event", "").startswith("W3_298_") and "ordinal" in row:
            if not 1 <= int(row["ordinal"]) <= MAX_SELECTED_EVENTS:
                raise ValueError("W3-298 event ordinal is outside the bounded range")


def load_trace(path: Path) -> tuple[bytes, list[dict]]:
    raw = path.read_bytes()
    return raw, parse_trace(raw)
