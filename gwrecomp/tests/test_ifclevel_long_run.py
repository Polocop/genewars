"""Run the original native game() loop to Turn 1000 with host-only stopping."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
TURN_LIMIT = int(os.environ.get("GWRECOMP_IFCLEVEL_LONG_RUN_TURN", "1000"))
STEM = os.environ.get("GWRECOMP_IFCLEVEL_REPLAY_STEM") or f"native_ifclevel_long_run_{TURN_LIMIT}"


def main() -> None:
    env = os.environ.copy()
    env.update({
        "GWRECOMP_IFCLEVEL_CONTINUE": "1",
        "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP": "1",
        "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN": str(TURN_LIMIT),
        "GWRECOMP_IFCLEVEL_REPLAY_STEM": STEM,
        "GWRECOMP_IFCLEVEL_SECOND_SPEC_PICK": "0",
        "GWRECOMP_IFCLEVEL_DIRECT_PICK_CLICK": "0",
        "GWRECOMP_IFCLEVEL_HOVER_PICK": "0",
        "GWRECOMP_IFCLEVEL_FULL_GAME_ENTRY": "0",
        "GWRECOMP_IFCLEVEL_FRESH_GAME_ENTRY": "0",
    })
    result = subprocess.run([str(PYTHON), str(ROOT / "tests" / "test_ifctitle_creature_probe.py")],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=1800)
    out = ROOT / "evidence" / f"{STEM}.stdout.log"
    err = ROOT / "evidence" / f"{STEM}.stderr.log"
    # The underlying integration test already writes these files. Preserve a
    # bounded wrapper summary here if the build/replay fails before that point.
    if not out.exists(): out.write_text(result.stdout, encoding="utf-8")
    if not err.exists(): err.write_text(result.stderr, encoding="utf-8")
    evidence_path = ROOT / "evidence" / f"{STEM}.json"
    if result.returncode:
        raise SystemExit(f"native {TURN_LIMIT}-turn test failed exit={result.returncode}; see {err}")
    if not evidence_path.exists():
        raise SystemExit("native 1000-turn evidence JSON was not produced")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    trace = evidence.get("native_trace", "")
    if evidence.get("frontier") is not None or not evidence.get("passed") or f"Turn={TURN_LIMIT}" not in trace:
        raise SystemExit(f"native loop did not reach bounded Turn {TURN_LIMIT} cleanly")
    for turn in ("500", str(TURN_LIMIT)):
        if int(turn) > TURN_LIMIT: continue
        if turn not in evidence.get("snapshots", {}):
            raise SystemExit(f"missing original-code framebuffer snapshot at turn {turn}")
    print(result.stdout, end="")
    print(f"PASS original game() loop reached host-bounded Turn {TURN_LIMIT}; evidence: {evidence_path}")


if __name__ == "__main__":
    main()
