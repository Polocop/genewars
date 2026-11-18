#!/usr/bin/env python3
"""One guarded replay for the handler-armed natural ECD40 checkpoint."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import w3_192_ecd40_progress_runner as shared
from tools.w3_193_arm_ecd40_step import inspect_source

RUN_ID = "w3-196-ecd40-armed-20261009-01"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_196_ECD40_ARMED_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_196_ecd40_armed_progress.json"
DOSBOX_SHA256 = "a28e0531c1e38f09ff625e99232457aa3337ad48cdd5a0b9e2f5c80b91443c8a"
OPERATION = "W3-196 single armed first natural _SmackInternal010 checkpoint at 0xECD40"

shared.RUN_ID = RUN_ID
shared.TRACE = TRACE
shared.RESULT = RESULT
shared.DOSBOX_SHA256 = DOSBOX_SHA256
shared.OPERATION = OPERATION
shared.inspect_source = inspect_source


def synthetic_preflight():
    return shared.synthetic_preflight()


def run_once():
    identity = synthetic_preflight()
    sidecars = (
        ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json",
        ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt",
    )
    for path in (TRACE, RESULT, *sidecars):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite W3-196 artifact: {path}")
    code = shared.run_once()
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    result["schema"] = "w3-196-ecd40-armed-progress/v1"
    result["task"] = "W3-196"
    result["run_id"] = RUN_ID
    result["preflight_identity"] = identity
    result.setdefault("guard", {})["operation"] = OPERATION
    result["limitations"] = [
        "Exactly one bounded original replay; no global trace or full-buffer dump.",
        "The ECD40 target is armed only after the selected handler-entry event.",
        "At most one pre/post step-result event is emitted; timeout is not natural completion.",
        "No pixel format, complete frame, visible framebuffer, menu, or gameplay is claimed.",
    ]
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(run_once())
    except Exception as exc:
        print(f"W3-196 preflight/replay failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
