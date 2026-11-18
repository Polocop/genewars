#!/usr/bin/env python3
"""Parse one bounded W3-291 trace for the silent ECD40 target-hit event."""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_BYTES = 1_048_576
MAX_ROWS = 2048
TARGET_EVENT = "w3_291_ecd40_target_hit"
STEP_EVENT = "W3_198_ECD40_CONTINUATION_STEP"


def parse_trace(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_BYTES:
        raise ValueError("trace byte cap exceeded")
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"trace row {line_no} is not an object")
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise ValueError("trace row cap exceeded")
    return rows


def analyze(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mappings = [r for r in rows if r.get("event") == "main_mapping" and r.get("mapping_matches") is True]
    if len(mappings) != 1:
        raise ValueError("exactly one matching fresh MAIN mapping is required")
    base = int(mappings[0]["code_rebase"])
    steps = [r for r in rows if r.get("event") == STEP_EVENT]
    ordinals = [int(r.get("ordinal", -1)) for r in steps]
    if ordinals and ordinals != list(range(1, len(ordinals) + 1)):
        raise ValueError("W3-198 step prefix is not contiguous")
    if len(steps) > 5:
        raise ValueError("W3-198 continuation exceeded the five-step bound")
    if len(steps) == 5 and int(steps[-1].get("after_runtime", -1)) != base + 0xECD40:
        raise ValueError("complete W3-198 sequence does not reach fresh mapped ECD40")
    target_hits = [r for r in rows if r.get("event") == TARGET_EVENT]
    if len(target_hits) > 1:
        raise ValueError("one-shot ECD40 target-hit event duplicated")
    hit = target_hits[0] if target_hits else None
    if hit:
        if len(steps) != 5:
            raise ValueError("target-hit event lacks the complete five-step context")
        if int(hit.get("code_rebase", -1)) != base:
            raise ValueError("target-hit code rebase differs from fresh MAIN mapping")
        if int(hit.get("runtime_linear", -1)) != base + 0xECD40 or int(hit.get("link_va", -1)) != 0xECD40:
            raise ValueError("target-hit runtime/link mapping mismatch")
        if int(hit.get("continuation_steps", -1)) != 5:
            raise ValueError("target-hit did not follow the captured five-step sequence")
        if int(hit.get("sequence", -1)) <= int(steps[-1].get("sequence", -1)):
            raise ValueError("target-hit event is not ordered after the fifth continuation step")
        if hit.get("trigger") != "W3_198_target_hit_branch_before_disarm":
            raise ValueError("target-hit did not originate at the intended branch")
    last_numbered = [r for r in rows if isinstance(r.get("sequence"), int)]
    last = max(last_numbered, key=lambda r: r["sequence"]) if last_numbered else None
    w3_193 = [r for r in rows if r.get("event") == "W3_193_ECD40_STEP_RESULT"]
    stops = [r for r in rows if r.get("event") == "W3_198_ECD40_CONTINUATION_STOP"]
    if len(w3_193) > 1 or len(stops) > 1:
        raise ValueError("W3-193/W3-198 boundary events duplicated")
    if w3_193 and stops and int(stops[0].get("steps", -1)) != len(steps):
        raise ValueError("W3-198 stop step count differs from the emitted step prefix")
    return {
        "code_rebase": f"0x{base:08X}",
        "step_ordinals": [int(r["ordinal"]) for r in steps],
        "continuation_armed_by_initial_step": bool(w3_193 and int(w3_193[0].get("after_link_va", -1)) == 0xECD31),
        "initial_step_result": ({k: w3_193[0].get(k) for k in ("sequence", "before_link_va", "after_link_va", "target_runtime", "normal_core_return")} if w3_193 else None),
        "continuation_stop": ({k: stops[0].get(k) for k in ("sequence", "reason", "link_va", "runtime_eip", "steps")} if stops else None),
        "last_step": ({k: steps[-1].get(k) for k in ("sequence", "before_link_va", "after_link_va", "before_runtime", "after_runtime")} if steps else None),
        "target_hit_seen": hit is not None,
        "target_hit": ({k: hit.get(k) for k in (
            "sequence", "process_psp", "cs", "ds", "es", "ss", "eip", "runtime_linear", "link_va",
            "code_rebase", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags", "continuation_steps"
        )} if hit else None),
        "last_emitted_event": ({"sequence": last.get("sequence"), "event": last.get("event"), "link_va": last.get("link_va"), "checkpoint": last.get("checkpoint"), "reason": last.get("reason"), "after_link_va": last.get("after_link_va")} if last else None),
        "later_smacker_callee_seen": any(r.get("event") == "w3_289_smacker_callee_entry" for r in rows),
        "framebuffer_pixels_verified": False,
        "conclusion": "ECD40_TARGET_HIT_BRANCH_ORIGINAL_OBSERVED" if hit else "INCONCLUSIVE_ECD40_TARGET_HIT_NOT_OBSERVED",
    }


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
