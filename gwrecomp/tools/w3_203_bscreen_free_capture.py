#!/usr/bin/env python3
"""One guarded original replay for the bounded B_SCREEN pre-free sample."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import w3_192_ecd40_progress_runner as shared
from tools.w3_193_arm_ecd40_step import inspect_source as inspect_193
from tools.w3_198_ecd40_bounded_continuation import inspect_source as inspect_198
from tools.w3_202_bscreen_free_sample import inspect_source as inspect_202

RUN_ID = "w3-203-bscreen-free-20261009-01"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_203_BSCREEN_FREE_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_203_bscreen_free_sample.json"
DOSBOX_SHA256 = "0e84b018b0cfded50345b2f7d4f96ab18f8f73c3de120a1d92446b04754fdd34"
OPERATION = "W3-203 one guarded B_SCREEN pre-free raw sample"


def inspect_source(text: str) -> dict:
    checks = {"w3_193": inspect_193(text), "w3_198": inspect_198(text), "w3_202": inspect_202(text)}
    return {"all_checks_pass": all(item["all_checks_pass"] for item in checks.values()), **checks}


shared.RUN_ID = RUN_ID
shared.TRACE = TRACE
shared.RESULT = RESULT
shared.DOSBOX_SHA256 = DOSBOX_SHA256
shared.OPERATION = OPERATION
shared.inspect_source = inspect_source


def synthetic_preflight():
    return shared.synthetic_preflight()


def classify_sample_rows(rows: list[dict]) -> dict:
    frees = [row for row in rows if row.get("checkpoint") == "W3_129_MEMORY_FREE_ENTRY"]
    if not frees:
        return {"classification": "FREE_NOT_REACHED", "free_count": 0}
    free = frees[0]
    candidates = [row for row in frees if row.get("w3_202_b_screen_free_sample_candidate") is True]
    if len(frees) != 1 or len(candidates) > 1:
        return {"classification": "CHECKPOINT_OR_SAMPLE_DUPLICATED", "free_count": len(frees),
                "candidate_count": len(candidates)}
    if not candidates:
        return {"classification": "FREE_REACHED_WITHOUT_MATCHING_ALLOCATION", "free_count": len(frees),
                "reason": free.get("w3_202_b_screen_sample_reason")}
    if free.get("w3_202_b_screen_sample_bounds_valid") is True and int(free.get("w3_202_b_screen_sample_bytes", 0)) == 64:
        return {"classification": "CAPTURED_RAW_ALLOCATION_BYTES", "free_count": len(frees),
                "candidate_count": 1, "sample_bytes": 64,
                "nonzero_bytes": int(free.get("w3_202_b_screen_sample_nonzero", 0)),
                "reason": free.get("w3_202_b_screen_sample_reason")}
    return {"classification": "ELIGIBLE_BUT_BOUNDS_FAILED", "free_count": len(frees),
            "candidate_count": 1, "sample_bytes": int(free.get("w3_202_b_screen_sample_bytes", 0)),
            "reason": free.get("w3_202_b_screen_sample_reason")}


def run_once():
    identity = synthetic_preflight()
    sidecars = (ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json",
                ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt")
    for path in (TRACE, RESULT, *sidecars):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite W3-203 artifact: {path}")
    code = shared.run_once()
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in TRACE.read_text(encoding="utf-8").splitlines() if line.strip()]
    free_rows = [row for row in rows if row.get("checkpoint") == "W3_129_MEMORY_FREE_ENTRY"]
    allocation_rows = [row for row in rows if row.get("checkpoint") == "W3_188_B_SCREEN_ALLOC_RETURN"]
    store_rows = [row for row in rows if row.get("checkpoint") == "W3_129_B_SCREEN_POST_STORE"]
    classified = classify_sample_rows(rows)
    sample = free_rows[0] if free_rows else None
    if sample and allocation_rows and store_rows:
        pointer = int(allocation_rows[0].get("eax", 0))
        same_run_valid = (pointer != 0 and int(allocation_rows[0].get("w3_188_alloc_size", 0)) == 0x4B000 and
                          int(store_rows[0].get("w3_188_alloc_pointer", 0)) == pointer and
                          int(sample.get("eax", 0)) == pointer and
                          allocation_rows[0].get("process_psp") == store_rows[0].get("process_psp") == sample.get("process_psp") and
                          allocation_rows[0].get("eip", 0) - allocation_rows[0].get("link_va", 0) ==
                          store_rows[0].get("eip", 0) - store_rows[0].get("link_va", 0) ==
                          sample.get("eip", 0) - sample.get("link_va", 0))
        sample = dict(sample)
        sample["same_run_allocation_store_free_identity_valid"] = same_run_valid
        sample["allocation_pointer"] = pointer
    result["schema"] = "w3-203-bscreen-free-sample/v1"
    result["task"] = "W3-203"
    result["run_id"] = RUN_ID
    result["preflight_identity"] = identity
    result["b_screen_free_sample"] = {**classified,
                                      "sample_event": sample,
                                      "free_event_count": len(free_rows),
                                      "allocation_event_count": len(allocation_rows),
                                      "store_event_count": len(store_rows),
                                      "interpretation_limit": "Raw bytes from a measured allocation only; no pixel/display meaning inferred."}
    result.setdefault("guard", {})["operation"] = OPERATION
    result["limitations"] = [
        "Exactly one guarded replay; sample is capped at 64 bytes and only at a matching free entry.",
        "The guard timeout is not natural process completion.",
        "Nonzero bytes do not establish pixel format, visible framebuffer, menu, or gameplay.",
    ]
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(run_once())
    except Exception as exc:
        print(f"W3-203 preflight/replay failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
