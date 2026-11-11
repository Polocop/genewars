"""Bounded analysis helpers for the original branch after 0x92B6B."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
PRIOR = ROOT / "evidence/w3_123_post_join_branch.json"
TRACE_PRIOR = ROOT / "build/dosboxx_oracle/C/W3_123_POST_JOIN_BRANCH_20261009_01.jsonl"
ANCHOR, BRANCH, FALLTHROUGH, TARGET = 0x92B6B, 0x92B6F, 0x92B71, 0x92B87
TARGETS = (ANCHOR, BRANCH, FALLTHROUGH, TARGET)
CAP = 4


def short_jcc(ip: int, encoded: bytes) -> tuple[int, int, bool]:
    if len(encoded) < 2 or encoded[0] not in (0x74, 0x75):
        raise ValueError("expected JE/JNE rel8")
    fallthrough = (ip + 2) & 0xFFFFFFFF
    target = (fallthrough + int.from_bytes(encoded[1:2], "little", signed=True)) & 0xFFFFFFFF
    return fallthrough, target, encoded[0] == 0x75


def prior_anchor() -> dict[str, Any]:
    result = json.loads(PRIOR.read_text(encoding="utf-8"))
    raw = TRACE_PRIOR.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != result["trace"]["sha256"]:
        raise ValueError("W3-123 trace hash mismatch")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    row = next((r for r in rows if r.get("event") == "target_runtime_checkpoint" and
                r.get("link_va") == ANCHOR), None)
    if row is None or not str(row.get("bytes", "")).startswith("807dfc007516"):
        raise ValueError("W3-123 lacks the measured 0x92B6B bytes")
    fall, target, jne = short_jcc(BRANCH, bytes.fromhex(row["bytes"][8:12]))
    if (fall, target, jne) != (FALLTHROUGH, TARGET, True):
        raise ValueError("decoded branch destination mismatch")
    return {"target_sha256": result["target_sha256"], "trace_sha256": digest,
            "anchor_sequence": row["sequence"], "anchor_link_va": row["link_va"],
            "anchor_bytes": row["bytes"][:24], "branch_link_va": BRANCH,
            "branch_opcode": "75 16", "fallthrough_link_va": fall,
            "taken_target_link_va": target, "local_ebp_minus_4": "UNKNOWN"}


def parse_jsonl(raw: bytes, cap_bytes: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > cap_bytes:
        raise ValueError("trace exceeds configured byte cap")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def capture_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {"W3_124_BRANCH_ANCHOR", "W3_124_BRANCH",
             "W3_124_BRANCH_FALLTHROUGH", "W3_124_BRANCH_TAKEN"}
    events, seen = [], set()
    for row in rows:
        if row.get("w3_124_post_join_continuation") is not True and row.get("checkpoint") not in names:
            continue
        link = row.get("link_va")
        if link not in TARGETS or link in seen:
            continue
        events.append(row)
        seen.add(link)
        if len(events) >= CAP:
            break
    return events


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    links = [e.get("link_va") for e in events]
    branch = next((e for e in events if e.get("link_va") == BRANCH), None)
    outcome = None
    if branch:
        fall, target, is_jne = short_jcc(BRANCH, bytes.fromhex(str(branch.get("bytes", ""))[:4]))
        zf = bool(int(branch.get("eflags", 0)) & 0x40)
        taken = not zf if is_jne else zf
        expected = target if taken else fall
        index = links.index(BRANCH)
        next_link = links[index + 1] if index + 1 < len(links) else None
        outcome = {"condition": "JNE", "eflags": branch.get("eflags"), "zf": zf,
                   "taken": taken, "expected_next_link": expected,
                   "next_captured_link": next_link,
                   "captured_path_matches_flags": next_link == expected}
    return {"link_vas": [f"0x{value:08X}" for value in links],
            "ordered": links == [value for value in TARGETS if value in links],
            "branch": outcome,
            "fallthrough_observed_immediately": bool(outcome and outcome["next_captured_link"] == FALLTHROUGH),
            "taken_target_observed_immediately": bool(outcome and outcome["next_captured_link"] == TARGET)}


def source_coverage(source: str) -> dict[str, bool]:
    start = source.index("const bool selected_capture_site")
    end = source.index("// Before MAIN's runtime mapping is known", start)
    selected = source[start:end]
    return {
        "sites_selected_after_mapping": all(f"0x{x:08x}" in selected for x in TARGETS),
        "four_event_cap": "w3_124_checkpoint_count < 4" in source,
        "anchor_arms_capture": "if (link_va == 0x00092b6b)\n\t\t\t\t\t\tw3_124_capture_armed = true;" in source,
        "event_flag_serialized": "w3_124_post_join_continuation" in source,
    }
