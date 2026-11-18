"""Bounded analysis of the conditional after the post-reset join."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
PRIOR = ROOT / "evidence/w3_122_post_reset_branches.json"
TRACE_PRIOR = ROOT / "build/dosboxx_oracle/C/W3_122_POST_RESET_BRANCHES_20261009_01.jsonl"
BRANCH, FALLTHROUGH, TARGET = 0x92B2F, 0x92B31, 0x92B6B
TARGETS = (BRANCH, FALLTHROUGH, TARGET)
CAP = 3


def short_jcc(ip: int, encoded: bytes) -> tuple[int, int, bool | None]:
    if len(encoded) < 2 or encoded[0] not in (0x74, 0x75):
        raise ValueError("expected JE/JNE rel8")
    fallthrough = (ip + 2) & 0xFFFFFFFF
    target = (fallthrough + int.from_bytes(encoded[1:2], "little", signed=True)) & 0xFFFFFFFF
    return fallthrough, target, encoded[0] == 0x75


def prior_callsite() -> dict[str, Any]:
    result = json.loads(PRIOR.read_text(encoding="utf-8"))
    raw = TRACE_PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest() != result["trace"]["sha256"]:
        raise ValueError("W3-122 trace hash mismatch")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    event = next((r for r in rows if r.get("link_va") == 0x92B2B and
                  r.get("event") == "target_runtime_checkpoint"), None)
    if event is None or not str(event.get("bytes", "")).startswith("807dfc00753a"):
        raise ValueError("W3-122 lacks the measured 0x92B2B instruction bytes")
    fall, target, jne = short_jcc(BRANCH, bytes.fromhex(event["bytes"][8:12]))
    if (fall, target, jne) != (FALLTHROUGH, TARGET, True):
        raise ValueError("JNE target/fall-through mismatch")
    return {"target_sha256": result["target_sha256"],
            "trace_sha256": hashlib.sha256(raw).hexdigest(),
            "join_event_sequence": event["sequence"],
            "join_link_va": event["link_va"], "join_bytes": event["bytes"][:24],
            "branch_link_va": BRANCH, "branch_opcode": "75 3A",
            "fallthrough_link_va": fall, "taken_target_link_va": target}


def parse_jsonl(raw: bytes, cap_bytes: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > cap_bytes:
        raise ValueError("trace exceeds configured size cap")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def capture_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {"W3_123_BRANCH", "W3_123_BRANCH_FALLTHROUGH", "W3_123_BRANCH_TAKEN"}
    events, seen = [], set()
    for row in rows:
        if row.get("w3_123_post_join_branch") is not True and row.get("checkpoint") not in names:
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
    branch = next((e for e in events if e.get("link_va") == BRANCH), None)
    outcome = None
    if branch:
        code = bytes.fromhex(str(branch.get("bytes", ""))[:4])
        fall, target, is_jne = short_jcc(BRANCH, code)
        zf = bool(int(branch.get("eflags", 0)) & 0x40)
        taken = not zf if is_jne else zf
        expected = target if taken else fall
        idx = links.index(BRANCH)
        next_link = links[idx + 1] if idx + 1 < len(links) else None
        outcome = {"condition": "JNE", "eflags": branch.get("eflags"), "zf": zf,
                   "taken": taken, "expected_next_link": expected,
                   "next_captured_link": next_link,
                   "captured_path_matches_flags": next_link == expected}
    return {"link_vas": [f"0x{x:08X}" for x in links],
            "ordered": links == [x for x in TARGETS if x in links],
            "branch": outcome,
            "fallthrough_observed": FALLTHROUGH in links,
            "taken_target_observed_immediately": bool(outcome and outcome["next_captured_link"] == TARGET),
            "taken_target_observed_later": TARGET in links and bool(outcome and outcome["next_captured_link"] != TARGET)}


def source_coverage(source: str) -> dict[str, bool]:
    start = source.index("const bool selected_capture_site")
    end = source.index("// Before MAIN's runtime mapping is known", start)
    selected = source[start:end]
    return {
        "sites_selected_after_mapping": all(f"0x{x:08x}" in selected for x in TARGETS),
        "event_cap_three": "w3_123_checkpoint_count < 3" in source,
        "armed_after_join": "if (link_va == 0x00092b2b)\n\t\t\t\t\t\tw3_123_capture_armed = true;" in source,
        "event_flag_serialized": "w3_123_post_join_branch" in source,
    }
