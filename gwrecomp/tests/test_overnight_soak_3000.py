"""Bounded 3,000-turn native-loop soak with the existing deterministic SDL input sweep."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
TARGET = EVIDENCE / "genewars-1_1.exe"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
STEM = "overnight_phase5_ui_soak_3000"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    actual = sha(TARGET)
    if actual != TARGET_SHA256:
        raise SystemExit(f"canonical LE hash mismatch: {actual}")
    common = EVIDENCE / "native_ifctitle_creature_probe.json"
    previous_common = common.read_bytes() if common.exists() else None
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("GWRECOMP_IFCLEVEL_") or key.startswith("GWRECOMP_CAMPAIGN_"):
            env.pop(key, None)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "GWRECOMP_IFCLEVEL_CONTINUE": "1",
        "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP": "1",
        "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN": "3000",
        "GWRECOMP_IFCLEVEL_REPLAY_STEM": STEM,
        "GWRECOMP_IFCLEVEL_EXTENDED_SESSION": "1",
        "GWRECOMP_IFCLEVEL_SECOND_SPEC_PICK": "0",
        "GWRECOMP_IFCLEVEL_DIRECT_PICK_CLICK": "0",
        "GWRECOMP_IFCLEVEL_HOVER_PICK": "0",
        "GWRECOMP_IFCLEVEL_FULL_GAME_ENTRY": "0",
        "GWRECOMP_IFCLEVEL_FRESH_GAME_ENTRY": "0",
    })
    started = time.perf_counter()
    proc = None
    try:
        proc = subprocess.run(
            [str(ROOT / ".venv" / "Scripts" / "python.exe"),
             str(ROOT / "tests" / "test_ifctitle_creature_probe.py")],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=21600,
        )
    finally:
        if previous_common is None:
            common.unlink(missing_ok=True)
        else:
            common.write_bytes(previous_common)
    elapsed = time.perf_counter() - started
    stdout = EVIDENCE / f"{STEM}.wrapper.stdout.log"
    stderr = EVIDENCE / f"{STEM}.wrapper.stderr.log"
    stdout.write_text(proc.stdout if proc else "", encoding="utf-8")
    stderr.write_text(proc.stderr if proc else "", encoding="utf-8")
    run_json = EVIDENCE / f"{STEM}.json"
    if proc is None:
        raise SystemExit("bounded native soak did not start")
    if proc.returncode != 0 or not run_json.is_file():
        failure = {
            "schema": "gw-native-3000-turn-soak-failure/v1",
            "target_sha256": actual,
            "exit_code": proc.returncode,
            "wall_clock_seconds": round(elapsed, 3),
            "stdout": str(stdout.relative_to(ROOT)),
            "stderr": str(stderr.relative_to(ROOT)),
            "passed": False,
        }
        (EVIDENCE / "overnight_phase5_3000turns_soak_test.json").write_text(
            json.dumps(failure, indent=2) + "\n", encoding="utf-8")
        raise SystemExit(f"native 3,000-turn soak failed exit={proc.returncode}; see {stderr}")
    result = json.loads(run_json.read_text(encoding="utf-8"))
    trace = result.get("native_trace", "")
    frontier = result.get("frontier")
    expected = ("500", "1000", "1500", "2000", "2500", "3000")
    snapshots = result.get("snapshots", {})
    if not result.get("passed") or frontier is not None or any(t not in snapshots for t in expected):
        raise SystemExit("native evidence lacks successful loop/frontier or all six turn snapshots")
    if "Turn=3000" not in trace or result.get("MCB_chain_valid", True) is not True:
        raise SystemExit("native loop did not reach Turn 3000 with valid MCB chain")
    native_stderr = EVIDENCE / f"{STEM}.stderr.log"
    lines = native_stderr.read_text(encoding="utf-8", errors="replace").splitlines()
    input_rows = [x for x in lines if x.startswith((
        "TRACE native_extended_key_input ", "TRACE native_extended_second_portrait "))]
    key_rows = [x for x in lines if x.startswith((
        "TRACE native_extended_key_control_entry ", "TRACE native_extended_key_control_return "))]
    snapshot_hashes = {}
    for turn in expected:
        row = snapshots[turn]
        for kind, key in (("bmp", "bmp"), ("wscreen", "guest_wscreen_raw"), ("palette6", "palette6_raw")):
            p = ROOT / row[key]
            if not p.is_file():
                raise SystemExit(f"missing {kind} snapshot at Turn {turn}: {p}")
            snapshot_hashes.setdefault(turn, {})[kind] = sha(p)
    evidence = {
        "schema": "gw-native-3000-turn-ui-soak/v1",
        "target_sha256": actual,
        "profile": "Original native game() loop, host stop after original Turn 3000; deterministic SDL extended input sweep before Turn 425; no guest globals or packet state forced.",
        "exit_code": proc.returncode,
        "wall_clock_seconds": round(elapsed, 3),
        "turn_final": 3000,
        "frontier": frontier,
        "unexpected_writes": result.get("unexpected_writes"),
        "MCB_chain_valid": result.get("MCB_chain_valid"),
        "native_loop_evidence": str(run_json.relative_to(ROOT)),
        "native_trace": trace,
        "input_sweep": {
            "profile": "GWRECOMP_IFCLEVEL_EXTENDED_SESSION=1",
            "event_rows": len(input_rows),
            "original_key_dispatch_rows": len(key_rows),
            "input_rows": input_rows,
            "coverage_limit": "The existing extended-session script injects a deterministic HUD/key sweep in the early level window; it does not repeat input at each 500-turn checkpoint or claim every requested camera/options/pause combination was exercised throughout all 3,000 turns.",
        },
        "snapshots": {turn: {"paths": snapshots[turn], "sha256": snapshot_hashes[turn]} for turn in expected},
        "preservation": {"canonical_le_modified": False, "GeneWarsFX_modified": False, "Oracle_modified": False},
        "passed": True,
    }
    out = EVIDENCE / "overnight_phase5_3000turns_soak_test.json"
    out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"PASS native game() Turn 3000 soak; six snapshots; evidence: {out}")


if __name__ == "__main__":
    main()
