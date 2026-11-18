"""Bounded static and trace validation for the first play_smk_ call."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
PRIOR_TRACE = ROOT / "build/dosboxx_oracle/C/W3_116_PLAYSMACKER_BRANCH_20261009_01.jsonl"
MAP = ROOT / "evidence/genewars-1_1.map"
CALLSITE = 0x92ADD
CALLEE = 0xAE2D0
RETURN = 0x92AE2
CALL_BYTES = bytes.fromhex("e8eeb70100")
TARGETS = (CALLSITE, CALLEE, RETURN)


def relative_call_target(link_va: int, encoded: bytes) -> tuple[int, int]:
    if len(encoded) < 5 or encoded[0] != 0xE8:
        raise ValueError("expected a 32-bit relative CALL instruction")
    displacement = int.from_bytes(encoded[1:5], "little", signed=True)
    return (link_va + 5 + displacement) & 0xFFFFFFFF, (link_va + 5) & 0xFFFFFFFF


def parse_jsonl(raw: bytes, cap: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > cap:
        raise ValueError("trace exceeds configured size cap")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def capture_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checkpoint_names = {
        "W3_117_PLAYSMACKER_CALLSITE",
        "W3_117_PLAYSMACKER_CALLEE_ENTRY",
        "W3_117_PLAYSMACKER_CALL_RETURN",
    }
    events = []
    seen = set()
    for row in rows:
        if row.get("w3_117_play_smacker_call_boundary") is not True and row.get("checkpoint") not in checkpoint_names:
            continue
        link = row.get("link_va")
        if link not in TARGETS or link in seen:
            continue
        events.append(row)
        seen.add(link)
        if len(events) == len(TARGETS):
            break
    if len(events) > len(TARGETS):
        raise ValueError("target capture exceeded three-record bound")
    return events


def target_order(events: list[dict[str, Any]]) -> dict[str, Any]:
    links = [e.get("link_va") for e in events]
    if any(not isinstance(link, int) for link in links):
        raise ValueError("captured events must have integer link VAs")
    ordered = all(a < b for a, b in zip(
        [TARGETS.index(link) if link in TARGETS else -1 for link in links],
        [TARGETS.index(link) if link in TARGETS else -1 for link in links][1:]))
    return {
        "link_vas": [f"0x{x:08X}" for x in links],
        "ordered": ordered,
        "callsite_observed": CALLSITE in links,
        "callee_entry_observed": CALLEE in links,
        "return_observed": RETURN in links,
    }


def source_coverage(source: str) -> dict[str, bool]:
    selected_start = source.index("const bool selected_capture_site")
    selected_end = source.index("// Before MAIN's runtime mapping is known", selected_start)
    selected = source[selected_start:selected_end]
    names = (
        '"W3_117_PLAYSMACKER_CALLSITE"',
        '"W3_117_PLAYSMACKER_CALLEE_ENTRY"',
        '"W3_117_PLAYSMACKER_CALL_RETURN"',
    )
    addresses = ("0x00092add", "0x000ae2d0", "0x00092ae2")
    return {
        "selected_sites": all(address in selected for address in addresses),
        "named_checkpoints": all(name in source for name in names),
        "runtime_mapping_required": "target_main_rebase &&" in selected,
        "bounded_target_counter": "w3_117_checkpoint_count < 3" in source,
        "armed_at_playintro": "if (link_va == 0x00092983)\n\t\t\t\t\t\tw3_117_capture_armed = true;" in source,
        "ordered_state_serialized": "w3_117_play_smacker_call_boundary" in source,
    }


def verify_prior_static_evidence(raw: bytes, map_text: str) -> dict[str, Any]:
    rows = parse_jsonl(raw)
    prior = next((r for r in rows if r.get("event") == "target_runtime_checkpoint" and
                  r.get("link_va") == CALLSITE), None)
    if prior is None or not str(prior.get("bytes", "")).startswith(CALL_BYTES.hex()):
        raise ValueError("W3-116 trace lacks the measured CALL bytes at 0x92ADD")
    if "0001:000AE2D0" not in map_text or "play_smk_" not in map_text:
        raise ValueError("pinned map lacks play_smk_ at the calculated call target")
    target, ret = relative_call_target(CALLSITE, bytes.fromhex(prior["bytes"][:10]))
    if (target, ret) != (CALLEE, RETURN):
        raise ValueError("observed CALL bytes do not resolve to the expected callee/return")
    return {"trace_sha256": hashlib.sha256(raw).hexdigest(),
            "trace_bytes": len(raw), "call_bytes": prior["bytes"][:10],
            "callsite_link_va": CALLSITE, "callee_link_va": target,
            "map_symbol": "play_smk_", "return_link_va": ret}
