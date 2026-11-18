"""Bounded branch decoding and trace validation after ResetAllInputs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
PRIOR = ROOT / "evidence/w3_121_reset_inputs_boundary.json"
TRACE_PRIOR = ROOT / "build/dosboxx_oracle/C/W3_121_RESET_INPUTS_20261009_01.jsonl"
TARGETS = (0x92AE9, 0x92AEB, 0x92AF2, 0x92AF4, 0x92B2B)
CAP = 5


def short_branch(ip: int, encoded: bytes) -> tuple[int, int]:
    if len(encoded) < 2 or not 0x70 <= encoded[0] <= 0x7F:
        raise ValueError("expected a short conditional branch")
    fallthrough = (ip + 2) & 0xFFFFFFFF
    target = (fallthrough + int.from_bytes(encoded[1:2], "little", signed=True)) & 0xFFFFFFFF
    return fallthrough, target


def prior_return() -> dict[str, Any]:
    result = json.loads(PRIOR.read_text(encoding="utf-8"))
    raw = TRACE_PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest() != result["trace"]["sha256"]:
        raise ValueError("W3-121 trace hash mismatch")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    row = next((r for r in rows if r.get("link_va") == 0x92AE7 and
                r.get("checkpoint") == "W3_121_POST_RESET_INPUTS_RETURN"), None)
    if row is None or not str(row.get("bytes", "")).startswith("84ed7440f60561162f0040"):
        raise ValueError("W3-121 return event lacks expected branch bytes")
    first = short_branch(0x92AE9, bytes.fromhex(row["bytes"][4:8]))
    second = short_branch(0x92AF2, bytes.fromhex(row["bytes"][22:26]))
    if first != (0x92AEB, 0x92B2B) or second != (0x92AF4, 0x92B2B):
        raise ValueError("conditional branch decode disagrees with expected targets")
    return {"target_sha256": result["target_sha256"],
            "trace_sha256": hashlib.sha256(raw).hexdigest(),
            "return_event_link_va": row["link_va"], "return_bytes": row["bytes"][:32],
            "first_branch": {"link_va": 0x92AE9, "fallthrough": first[0], "target": first[1]},
            "second_branch": {"link_va": 0x92AF2, "fallthrough": second[0], "target": second[1]}}


def parse_jsonl(raw: bytes, cap_bytes: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > cap_bytes:
        raise ValueError("trace exceeds configured size cap")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def capture_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {"W3_122_FIRST_BRANCH", "W3_122_FIRST_BRANCH_FALLTHROUGH",
             "W3_122_SECOND_BRANCH", "W3_122_SECOND_BRANCH_FALLTHROUGH",
             "W3_122_COMMON_BRANCH_TARGET"}
    events = []
    seen = set()
    for row in rows:
        if row.get("w3_122_post_reset_branch") is not True and row.get("checkpoint") not in names:
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
    order = [TARGETS.index(link) if link in TARGETS else -1 for link in links]
    def branch(link: int, next_options: tuple[int, int]) -> dict[str, Any] | None:
        event = next((e for e in events if e.get("link_va") == link), None)
        if event is None:
            return None
        code = bytes.fromhex(str(event.get("bytes", ""))[:4])
        fallthrough, target = short_branch(link, code)
        zf = bool(int(event.get("eflags", 0)) & 0x40)
        taken = zf if code[0] == 0x74 else None
        expected = target if taken else fallthrough
        idx = links.index(link)
        next_link = links[idx + 1] if idx + 1 < len(links) else None
        return {"condition": "JE", "eflags": event.get("eflags"), "zf": zf,
                "taken": taken, "fallthrough": fallthrough, "target": target,
                "expected_next_link": expected, "next_captured_link": next_link,
                "captured_path_matches_flags": next_link == expected if next_link in next_options else False}
    return {"link_vas": [f"0x{x:08X}" for x in links],
            "ordered": all(a < b for a, b in zip(order, order[1:])),
            "first_branch_seen": 0x92AE9 in links,
            "first_branch": branch(0x92AE9, (0x92AEB, 0x92B2B)),
            "second_branch_seen": 0x92AF2 in links,
            "second_branch": branch(0x92AF2, (0x92AF4, 0x92B2B)),
            "common_target_observed_later": 0x92B2B in links}


def source_coverage(source: str) -> dict[str, bool]:
    start = source.index("const bool selected_capture_site")
    end = source.index("// Before MAIN's runtime mapping is known", start)
    selected = source[start:end]
    return {
        "all_sites_selected_after_mapping": all(f"0x{x:08x}" in selected for x in TARGETS),
        "target_counter_capped": "w3_122_checkpoint_count < 5" in source,
        "armed_after_reset_return": "if (link_va == 0x00092ae7)\n\t\t\t\t\t\tw3_122_capture_armed = true;" in source,
        "event_flag_serialized": "w3_122_post_reset_branch" in source,
    }
