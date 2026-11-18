#!/usr/bin/env python3
"""Parse and validate one bounded W3-289 later-Smacker original capture."""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_BYTES = 1_048_576
MAX_ROWS = 2048
CALLSITE = "w3_275_second_smacker_callsite"
MEDIA_ENTRY = "w3_275_second_smacker_media_entry"
BRANCH_ENTRY = "w3_278_later_play_smk_entry"
BRANCH_TARGET = "w3_278_branch_target"
CALLEE_EVENT = "w3_289_smacker_callee_entry"
ALLOWED_CALLEES = {0xAE308, 0xAE4D8}


def parse_trace(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_BYTES:
        raise ValueError("trace byte cap exceeded")
    rows = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"non-object JSON row {number}")
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise ValueError("trace row cap exceeded")
    return rows


def analyze(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mappings = [r for r in rows if r.get("event") == "main_mapping" and r.get("mapping_matches") is True]
    if len(mappings) != 1:
        raise ValueError("exactly one matching fresh MAIN mapping is required")
    base = int(mappings[0]["code_rebase"])
    required = [CALLSITE, MEDIA_ENTRY, BRANCH_ENTRY, BRANCH_TARGET]
    found = {name: [r for r in rows if r.get("event") == name] for name in required}
    callee_rows = [r for r in rows if r.get("event") == CALLEE_EVENT]
    if len(callee_rows) > 1:
        raise ValueError("one-shot callee event duplicated")
    callee = callee_rows[0] if callee_rows else None
    ordered = False
    sequences: dict[str, int | None] = {name: (int(found[name][0]["sequence"]) if found[name] else None) for name in required}
    if callee:
        sequences["callee"] = int(callee["sequence"])
        ordered = all(sequences[name] is not None for name in required) and all(
            sequences[required[i]] < sequences[required[i + 1]] for i in range(len(required) - 1)
        ) and sequences[BRANCH_TARGET] < sequences["callee"]
        link = int(callee.get("link_va", -1))
        runtime = int(callee.get("runtime_linear", -1))
        if link not in ALLOWED_CALLEES:
            raise ValueError(f"unexpected callee link VA: 0x{link:x}")
        if int(callee.get("code_rebase", -1)) != base or runtime - base != link:
            raise ValueError("callee runtime/link mapping mismatch")
        if not ordered:
            raise ValueError("callee event is not ordered after the measured later invocation latches")
    result = {
        "code_rebase": f"0x{base:08X}",
        "latch_sequences": sequences,
        "later_caller_latches_complete": all(bool(found[name]) for name in required),
        "callee_entry_seen": callee is not None,
        "callee_entry_ordered": ordered,
        "callee": ({k: callee.get(k) for k in (
            "sequence", "callee", "cs", "ds", "es", "ss", "eip", "runtime_linear", "link_va",
            "code_rebase", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags",
            "stack_linear", "stack_descriptor_valid", "stack_words_u32") if k in callee} if callee else None),
        "observed_branch_destination": (
            f"0x{int(found[BRANCH_TARGET][0]['link_va']):08X}" if found[BRANCH_TARGET] else None
        ),
        "conclusion": "ORIGINAL_OBSERVED_LATER_CALLEE" if callee else "INCONCLUSIVE_NO_LATER_CALLEE_EVENT",
        "menu_verified": False,
        "gameplay_verified": False,
        "framebuffer_pixels_verified": False,
    }
    return result


def source_instrumentation_valid(source: str) -> bool:
    return all(token in source for token in (
        'GWRECOMP_W3_289_CAPTURE',
        'w3_275_second_smacker_callsite_seen',
        'w3_275_second_smacker_media_entry_seen',
        'w3_278_branch_target_seen',
        'candidate_link_va == 0x000ae308 || candidate_link_va == 0x000ae4d8',
        'w3_289_smacker_callee_entry',
    ))


def trace_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
