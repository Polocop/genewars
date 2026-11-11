#!/usr/bin/env python3
"""One guarded replay for the first natural 0xECD40 progress checkpoint."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import w3_181_smackinternal010_progress_runner as base
from tools.w3_191_ecd40_cache_probe import inspect_source

RUN_ID = "w3-192-ecd40-progress-20261009-01"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_192_ECD40_PROGRESS_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_192_ecd40_original_progress.json"
DOSBOX_SHA256 = "4641d9a855757946c1d8cdcb409345e451fac4e3cbae6a60dfd5f2e8ae9e2d4f"
OPERATION = "W3-192 first natural _SmackInternal010 progress checkpoint at 0xECD40"


def synthetic_preflight():
    """Read-only local identity check; deliberately does not verify/mount/run DOSBox."""
    probe = inspect_source(base.CORE.read_text(encoding="utf-8", errors="replace"))
    binary_hash = base.sha(base.DOSBOX)
    if binary_hash != DOSBOX_SHA256:
        raise RuntimeError(f"instrumented DOSBox hash mismatch: {binary_hash}")
    if base.sha(base.FIXTURE) != base.GW_SHA256 or base.FIXTURE.stat().st_size != base.GW_SIZE:
        raise RuntimeError("W3-067 authentic fixture identity mismatch")
    if base.sha(base.CONFIG) != base.CONFIG_SHA256 or base.sha(base.CUE) != base.CUE_SHA256:
        raise RuntimeError("functional config or read-only CUE identity mismatch")
    return {"binary_sha256": binary_hash, "probe": probe, "run_id": RUN_ID,
            "trace_path": str(TRACE.relative_to(ROOT)), "result_path": str(RESULT.relative_to(ROOT))}


def run_once():
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    identity = synthetic_preflight()
    for path in (TRACE, RESULT, ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json",
                 ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt"):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite W3-192 artifact: {path}")
    # Reuse W3-181's strict sandbox/fixture/read-only-CUE preflight and result parser,
    # but bind all outputs and the guard operation to this new, separately identified run.
    base.RUN_ID, base.TRACE, base.RESULT = RUN_ID, TRACE, RESULT
    real_run = base.subprocess.run

    def guarded_run(command, *args, **kwargs):
        if isinstance(command, list) and len(command) > 2 and str(command[1]).endswith("oracle_guard.py") and command[2] == "run":
            command = list(command)
            index = command.index("--operation")
            command[index + 1] = OPERATION
        return real_run(command, *args, **kwargs)

    base.subprocess.run = guarded_run
    try:
        result_code = base.main()
    finally:
        base.subprocess.run = real_run
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    result["schema"] = "w3-192-ecd40-original-progress/v1"
    result["task"] = "W3-192"
    result["run_id"] = RUN_ID
    result["guard"]["operation"] = OPERATION
    result["limitations"] = [
        "One bounded original replay only; no global trace and no full-buffer dump.",
        "Progress capture is limited to the first naturally reached 0xECD40 checkpoint after the measured dispatch and handler-entry anchors.",
        "A timeout after evidence capture is not treated as natural process completion.",
        "No pixel format, complete decoded frame, visible framebuffer, menu, or gameplay is claimed."
    ]
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result.get("classification"),
                      "progress": result.get("progress_checkpoint_valid", False),
                      "guard_cause": result.get("guard", {}).get("cause")}, indent=2))
    return result_code


if __name__ == "__main__":
    try:
        raise SystemExit(run_once())
    except Exception as exc:
        print(f"W3-192 preflight/replay failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
