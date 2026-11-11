#!/usr/bin/env python3
"""One guarded replay of the W3-198 bounded ECD40 continuation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import w3_192_ecd40_progress_runner as shared
from tools.w3_193_arm_ecd40_step import inspect_source as inspect_193
from tools.w3_198_ecd40_bounded_continuation import inspect_source as inspect_198

RUN_ID = "w3-199-ecd40-continuation-20261009-01"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_199_ECD40_CONTINUATION_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_199_ecd40_continuation.json"
DOSBOX_SHA256 = "6ca858b293b106ec8741ac16c0cdfa6538c2b59a4a57941fd2167b2326466550"
OPERATION = "W3-199 one guarded bounded ECD40 continuation replay"
TARGET_LINK = 0x000ECD40
MAX_STEP_EVENTS = 5


def inspect_source(text: str) -> dict:
    first = inspect_193(text)
    second = inspect_198(text)
    return {"all_checks_pass": first["all_checks_pass"] and second["all_checks_pass"],
            "w3_193": first, "w3_198": second}


shared.RUN_ID = RUN_ID
shared.TRACE = TRACE
shared.RESULT = RESULT
shared.DOSBOX_SHA256 = DOSBOX_SHA256
shared.OPERATION = OPERATION
shared.inspect_source = inspect_source


def synthetic_preflight():
    return shared.synthetic_preflight()


def classify_continuation(step_events: list[dict], stop_events: list[dict],
                          progress_seen: bool, target_link: int = TARGET_LINK) -> dict:
    bounded = len(step_events) <= MAX_STEP_EVENTS and len(stop_events) <= 1
    if not bounded:
        return {"classification": "EVENT_BOUND_VIOLATION", "bounded": False,
                "step_count": len(step_events), "stop_count": len(stop_events)}
    if progress_seen:
        return {"classification": "TARGET_CHECKPOINT_CAPTURED", "bounded": True,
                "step_count": len(step_events), "stop_count": len(stop_events)}
    if any(int(row.get("after_link_va", -1)) == target_link for row in step_events):
        return {"classification": "TARGET_REACHED_CHECKPOINT_UNCONFIRMED", "bounded": True,
                "step_count": len(step_events), "stop_count": len(stop_events)}
    reason = stop_events[0].get("reason") if stop_events else "timeout_or_natural_end_before_target"
    return {"classification": "STOPPED_BEFORE_TARGET", "bounded": True,
            "step_count": len(step_events), "stop_count": len(stop_events), "stop_reason": reason}


def run_once():
    identity = synthetic_preflight()
    sidecars = (
        ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json",
        ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt",
    )
    for path in (TRACE, RESULT, *sidecars):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite W3-199 artifact: {path}")
    code = shared.run_once()
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in TRACE.read_text(encoding="utf-8").splitlines() if line.strip()]
    steps = [row for row in rows if row.get("event") == "W3_198_ECD40_CONTINUATION_STEP"]
    stops = [row for row in rows if row.get("event") == "W3_198_ECD40_CONTINUATION_STOP"]
    progress = any(row.get("checkpoint") == "W3_181_SMACKINTERNAL010_PROGRESS" and
                   row.get("link_va") == TARGET_LINK for row in rows)
    classification = classify_continuation(steps, stops, progress)
    rebase = int(result["code_rebase"], 16)
    target_runtime = rebase + TARGET_LINK
    bad_mapping = [row for row in steps if int(row.get("target_runtime", -1)) != target_runtime]
    bad_ordinals = [row for index, row in enumerate(steps, 1)
                    if int(row.get("ordinal", -1)) != index]
    result["schema"] = "w3-199-ecd40-continuation/v1"
    result["task"] = "W3-199"
    result["run_id"] = RUN_ID
    result["preflight_identity"] = identity
    result["continuation"] = {**classification, "step_events": steps, "stop_events": stops,
                              "progress_checkpoint_seen": progress,
                              "target_link_va": TARGET_LINK,
                              "target_runtime_from_this_run": target_runtime,
                              "mapping_valid": not bad_mapping,
                              "ordinals_contiguous": not bad_ordinals,
                              "mapping_errors": bad_mapping,
                              "ordinal_errors": bad_ordinals}
    result.setdefault("guard", {})["operation"] = OPERATION
    result["limitations"] = [
        "Exactly one bounded original replay with at most five continuation-step events.",
        "A guard timeout is not natural process completion.",
        "Static fall-through does not substitute for the dynamic target checkpoint.",
        "No framebuffer pixels, visible frame, menu, or gameplay are claimed.",
    ]
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(run_once())
    except Exception as exc:
        print(f"W3-199 preflight/replay failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
