"""Bounded parsing and validation for the first ResetAllInputs call."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
PRIOR = ROOT / "evidence/w3_118_play_smacker_call_boundary.json"
SUCCESSOR = ROOT / "evidence/w3_120_post_media_successor.json"
MAP = ROOT / "evidence/genewars-1_1.map"
TRACE_PRIOR = ROOT / "build/dosboxx_oracle/C/W3_118_PLAYSMACKER_CALL_20261009_01.jsonl"
CALLSITE, CALLEE, RETURN = 0x92AE2, 0x5B880, 0x92AE7
CALL_BYTES = bytes.fromhex("e8998dfcff")
TARGETS = (CALLSITE, CALLEE, RETURN)
CAP = 3


def relative_call_target(link_va: int, encoded: bytes) -> tuple[int, int]:
    if len(encoded) < 5 or encoded[0] != 0xE8:
        raise ValueError("expected a 32-bit relative CALL")
    displacement = int.from_bytes(encoded[1:5], "little", signed=True)
    return (link_va + 5 + displacement) & 0xFFFFFFFF, (link_va + 5) & 0xFFFFFFFF


def prior_frontier() -> dict[str, Any]:
    result = json.loads(PRIOR.read_text(encoding="utf-8"))
    successor = json.loads(SUCCESSOR.read_text(encoding="utf-8"))
    raw = TRACE_PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest() != result["trace"]["sha256"]:
        raise ValueError("W3-118 raw trace hash mismatch")
    if successor["raw_trace"]["sha256"] != result["trace"]["sha256"]:
        raise ValueError("W3-120 successor plan is not bound to W3-118 trace")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    event = next((r for r in rows if r.get("link_va") == CALLSITE and
                  r.get("checkpoint") == "W3_117_PLAYSMACKER_CALL_RETURN"), None)
    if event is None:
        raise ValueError("W3-118 trace lacks dynamic 0x92AE2 continuation")
    target, fallthrough = relative_call_target(CALLSITE, bytes.fromhex(event["bytes"][:10]))
    if (target, fallthrough) != (CALLEE, RETURN):
        raise ValueError("W3-118 bytes disagree with W3-120 static successor")
    map_line = next((line.strip() for line in MAP.read_text(encoding="utf-8").splitlines()
                     if "0001:0005B880" in line and "ResetAllInputs" in line), None)
    if map_line is None:
        raise ValueError("pinned map lacks ResetAllInputs at 0x5B880")
    return {"target_sha256": result["target_sha256"],
            "trace_sha256": hashlib.sha256(raw).hexdigest(),
            "trace_bytes": len(raw), "instruction_bytes": event["bytes"][:10],
            "map_line": map_line, "callee_link_va": target,
            "return_link_va": fallthrough}


def parse_jsonl(raw: bytes, max_bytes: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > max_bytes:
        raise ValueError("trace exceeds configured size cap")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def capture_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = []
    seen = set()
    names = {"W3_121_POST_MEDIA_CALLSITE", "W3_121_RESET_INPUTS_ENTRY",
             "W3_121_POST_RESET_INPUTS_RETURN"}
    for row in rows:
        if row.get("w3_121_reset_inputs_boundary") is not True and row.get("checkpoint") not in names:
            continue
        link = row.get("link_va")
        if link not in TARGETS or link in seen:
            continue
        events.append(row)
        seen.add(link)
        if len(events) == CAP:
            break
    return events


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    links = [e.get("link_va") for e in events]
    indices = [TARGETS.index(link) if link in TARGETS else -1 for link in links]
    return {"link_vas": [f"0x{x:08X}" for x in links],
            "ordered": all(a < b for a, b in zip(indices, indices[1:])),
            "callsite_observed": CALLSITE in links,
            "callee_entry_observed": CALLEE in links,
            "return_observed": RETURN in links}


def source_coverage(source: str) -> dict[str, bool]:
    start = source.index("const bool selected_capture_site")
    end = source.index("// Before MAIN's runtime mapping is known", start)
    selected = source[start:end]
    return {
        "all_sites_selected_after_mapping": all(x in selected for x in ("0x00092ae2", "0x0005b880", "0x00092ae7")),
        "targets_named": all(x in source for x in ("W3_121_RESET_INPUTS_ENTRY", "W3_121_POST_RESET_INPUTS_RETURN")),
        "target_cap_three": "w3_121_checkpoint_count < 3" in source,
        "arm_after_play_smacker_callsite": "if (link_va == 0x00092add)\n\t\t\t\t\t\tw3_121_capture_armed = true;" in source,
        "state_serialized": "w3_121_reset_inputs_boundary" in source,
    }
