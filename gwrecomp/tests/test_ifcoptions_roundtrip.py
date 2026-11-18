"""Matched A/B test for the original Options escape/resume path.

The baseline and treatment differ only by the SDL Escape/Resume sequence
scheduled by the native harness.  This wrapper preserves each child replay's
evidence before the next run replaces the shared probe result.
"""
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
EXPECTED_HASH = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
CHILD = ROOT / "tests" / "test_ifctitle_creature_probe.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_profile(name: str, causal_mode: str) -> dict:
    stem = f"native_ifcoptions_roundtrip_{name}"
    started = time.perf_counter()
    replay_exit = 0
    reused = os.environ.get("GW_IFCOPTIONS_REUSE_EXISTING") == "1"
    if not reused:
        env = os.environ.copy()
        for key in tuple(env):
            if key.startswith("GWRECOMP_IFCLEVEL_") or key in {
                "GW_FULL_TRACE", "GW_CAMPAIGN_CREATURE_BRANCH_TRACE",
                "GWRECOMP_IFC_TRANSITION_CAUSAL_PROBE",
            }:
                env.pop(key, None)
        env.update({
            "PYTHONDONTWRITEBYTECODE": "1",
            "GWRECOMP_IFCLEVEL_CONTINUE": "1",
            "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP": "1",
            "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN": "500",
            "GWRECOMP_IFCLEVEL_REPLAY_STEM": stem,
            "GWRECOMP_IFC_TRANSITION_CAUSAL_PROBE": causal_mode,
        })
        proc = subprocess.run([str(PYTHON), str(CHILD)], cwd=ROOT, env=env,
                              text=True, capture_output=True, timeout=1800)
        replay_exit = proc.returncode
        (EVIDENCE / f"{stem}.wrapper.stdout.log").write_text(proc.stdout, encoding="utf-8")
        (EVIDENCE / f"{stem}.wrapper.stderr.log").write_text(proc.stderr, encoding="utf-8")
        if replay_exit:
            raise AssertionError(f"{name} native replay exited {replay_exit}")
    child_out = EVIDENCE / f"{stem}.stdout.log"
    child_err = EVIDENCE / f"{stem}.stderr.log"
    trace_path = EVIDENCE / f"{stem}.trace"
    if not all(p.is_file() for p in (child_out, child_err, trace_path)):
        raise AssertionError(f"{name} missing native stdout/stderr/trace evidence")
    trace = trace_path.read_text(encoding="utf-8", errors="replace")
    stderr = child_err.read_text(encoding="utf-8", errors="replace")
    stdout = child_out.read_text(encoding="utf-8", errors="replace")
    native_line = next((line for line in trace.splitlines()
                        if line.startswith("TRACE native_game_loop_result ")), "")
    result_line = next((line for line in trace.splitlines()
                        if line.startswith("result completed_ticks=")), "")
    stores = [line for line in trace.splitlines()
              if line.startswith("TRACE ifc_transition_store ")]
    inputs = [line for line in stderr.splitlines()
              if line.startswith("TRACE ifc_transition_input ")]
    integrity_ok = ("MCB_chain_valid=1" in native_line and
                    "post_loader_frontier=0" in result_line and
                    "continuation_ok=1" in result_line and
                    "PASS native original game() loop turns=" in stdout)
    row = {"profile": name, "causal_mode": causal_mode,
           "exit_code": replay_exit, "wall_clock_seconds": round(time.perf_counter() - started, 3),
           "native_replay_rerun": not reused,
           "unexpected_writes": 0 if integrity_ok else None,
           "frontier": None if integrity_ok else "unverified",
           "mcb_chain_valid": "MCB_chain_valid=1" in native_line,
           "stdout": str(child_out.relative_to(ROOT)),
           "stderr": str(child_err.relative_to(ROOT)),
           "trace": str(trace_path.relative_to(ROOT)),
           "evidence": str((EVIDENCE / f"{stem}.json").relative_to(ROOT)),
           "native_loop_trace": native_line, "result_line": result_line,
           "transition_stores": stores, "input_events": inputs,
           "integrity_ok": integrity_ok}
    if name == "baseline":
        row["profile_ok"] = (integrity_ok and len(stores) == 0 and
                             "draw_gate_current=0035fe9a" in native_line and
                             "currentIFC=0035fe9a pendingIFC=00000000" in result_line)
    else:
        row["profile_ok"] = (integrity_ok and len(stores) == 2 and
                             all("new=00360034" in item for item in stores[:2]) and
                             "phase=options-id4-up" in "\n".join(inputs) and
                             "draw_gate_current=00360034" in native_line and
                             "currentIFC=0035fe9a pendingIFC=00000000" in result_line)
    summary = {k: row[k] for k in ("profile", "causal_mode", "exit_code", "wall_clock_seconds",
                                    "native_replay_rerun", "native_loop_trace", "result_line",
                                    "transition_stores", "input_events", "integrity_ok", "profile_ok")}
    (EVIDENCE / f"{stem}.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return row


def main() -> None:
    actual = sha256(TARGET)
    if actual != EXPECTED_HASH:
        raise SystemExit(f"canonical LE hash mismatch: {actual}")
    started = time.perf_counter()
    runs = [run_profile("baseline", "baseline"),
            run_profile("escape_resume", "roundtrip")]
    passed = len(runs) == 2 and all(r.get("profile_ok") for r in runs)
    report = {
        "schema": "gw-ifcoptions-roundtrip-ab/v1",
        "target_sha256": actual,
        "profiles": runs,
        "comparison": {
            "baseline_stays_on_planetside": bool(runs and runs[0].get("profile_ok")),
            "escape_enters_options_and_resume_returns": bool(len(runs) > 1 and runs[1].get("profile_ok")),
            "guest_memory_seeded_by_harness": False,
        },
        "wall_clock_seconds": round(time.perf_counter() - started, 3),
        "passed": passed,
    }
    out = EVIDENCE / "native_ifcoptions_roundtrip_ab.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{'PASS' if passed else 'FAIL'} IFCOptions A/B regression; evidence: {out}")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
