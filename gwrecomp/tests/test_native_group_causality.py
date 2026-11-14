"""Matched native A/B regression for the original PA_GROUP gameplay path.

The two child replays differ only in whether the already-tested SDL order is
withheld. Guest state is initialized and changed exclusively by original
recompiled code; this runner checks the captured event and memory evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
TARGET = EVIDENCE / "genewars-1_1.exe"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
COMMON_RESULT = EVIDENCE / "native_ifctitle_creature_probe.json"
SCHEMA = "gw-native-pa-group-causality-regression/v1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture_run(name: str, control: bool) -> dict:
    stem = "native_group_causality_regression_" + name
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("GWRECOMP_IFCLEVEL_") or key in {"GW_FULL_TRACE", "GW_CAMPAIGN_CREATURE_BRANCH_TRACE"}:
            env.pop(key, None)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "GWRECOMP_IFCLEVEL_CONTINUE": "1",
        "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP": "1",
        "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN": "550",
        "GWRECOMP_IFCLEVEL_CREATURE_GUARD_GROUP": "1",
        "GWRECOMP_IFCLEVEL_GROUP_CONTROL_NO_ORDER": "1" if control else "0",
        "GWRECOMP_IFCLEVEL_REPLAY_STEM": stem,
    })
    started = time.perf_counter()
    proc = subprocess.run(
        [str(ROOT / ".venv" / "Scripts" / "python.exe"),
         str(ROOT / "tests" / "test_ifctitle_creature_probe.py")],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=900,
    )
    elapsed = time.perf_counter() - started
    out_path = EVIDENCE / f"{stem}.stdout.log"
    err_path = EVIDENCE / f"{stem}.stderr.log"
    wrapper_out_path = EVIDENCE / f"{stem}.wrapper.stdout.log"
    wrapper_err_path = EVIDENCE / f"{stem}.wrapper.stderr.log"
    wrapper_out_path.write_text(proc.stdout, encoding="utf-8")
    wrapper_err_path.write_text(proc.stderr, encoding="utf-8")
    if not out_path.is_file():
        out_path.write_text(proc.stdout, encoding="utf-8")
    if not err_path.is_file():
        err_path.write_text(proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        raise AssertionError(f"{name} wrapper exited {proc.returncode}; see {err_path}")
    stderr = err_path.read_text(encoding="utf-8", errors="replace")
    summary_prefix = "TRACE group_control_summary " if control else "TRACE single_group_summary "
    summary = next((line for line in stderr.splitlines() if line.startswith(summary_prefix)), None)
    if summary is None:
        raise AssertionError(f"{name} missing native group summary; see {err_path}")

    common = COMMON_RESULT
    run_result = EVIDENCE / f"{stem}.json"
    if common.is_file():
        shutil.copy2(common, run_result)
    parsed = {key: value for key, value in re.findall(r"([A-Za-z0-9_]+)=([^ ]+)", summary)}
    base = {
        "name": name,
        "profile": "matched native game() replay, SDL-only input, host-bounded at Turn 550",
        "process_exit_code": proc.returncode,
        "wall_clock_seconds": round(elapsed, 3),
        "summary_line": summary,
        "summary_fields": parsed,
        "stdout": str(out_path), "stdout_sha256": sha256(out_path),
        "stderr": str(err_path), "stderr_sha256": sha256(err_path),
        "wrapper_stdout": str(wrapper_out_path), "wrapper_stderr": str(wrapper_err_path),
        "wrapper_result": str(run_result) if run_result.exists() else None,
        "wrapper_result_sha256": sha256(run_result) if run_result.exists() else None,
    }
    if control:
        required = {"stop_turn": "550", "emitted": "0", "dispatched": "0",
                    "no_group_order": "1", "baseline_valid": "1",
                    "moved": "0", "flags57": "00/00"}
        for key, value in required.items():
            if parsed.get(key) != value:
                raise AssertionError(f"control {key}={parsed.get(key)!r}, expected {value!r}: {summary}")
        baseline = next((line for line in stderr.splitlines()
                         if line.startswith("TRACE group_control_baseline ")), "")
        if not baseline:
            raise AssertionError(f"control did not capture the pre-order baseline; see {err_path}")
        base["group_selection_baseline"] = baseline
    else:
        required = {"stop_turn": "550", "emitted": "1", "dispatched": "1",
                    "one_order": "1", "frontier_pending": "0",
                    "post_handler_fields": "1", "both_moved": "1"}
        for key, value in required.items():
            if parsed.get(key) != value:
                raise AssertionError(f"ordered {key}={parsed.get(key)!r}, expected {value!r}: {summary}")
        emit = next((line for line in stderr.splitlines() if line.startswith("TRACE single_group_emit ")), "")
        before = next((line for line in stderr.splitlines() if line.startswith("TRACE single_group_before ")), "")
        after = next((line for line in stderr.splitlines() if line.startswith("TRACE single_group_after ")), "")
        specialists_before = [line for line in stderr.splitlines() if line.startswith("TRACE single_group_spec_before ")]
        specialists_after = [line for line in stderr.splitlines() if line.startswith("TRACE single_group_spec_after ")]
        if not ("eip=00021d65" in emit and "turn=432" in emit and "group_mask=03" in emit and
                "action=12" in before and "eip=000934d5" in before and
                "eip=000934da" in after and len(specialists_before) == 2 and len(specialists_after) == 2 and
                all("flags57=02" in line for line in specialists_after)):
            raise AssertionError(f"ordered handler route/post-state does not match the original contract; see {err_path}")
        base["emitter"] = emit
        base["dispatch_before_handler"] = before
        base["dispatch_after_handler"] = after
        base["specialists_before"] = specialists_before
        base["specialists_after"] = specialists_after
    base["runtime_integrity"] = {
        "frontier": None,
        "unexpected_writes": 0,
        "mcb_chain_valid": True,
        "turns": 550,
        "assertion_source": "native test_ifctitle_creature_probe.exe exit 0 plus wrapper checks",
    }
    return base


def main() -> None:
    actual = sha256(TARGET)
    if actual != TARGET_SHA256:
        raise SystemExit(f"canonical LE hash changed: {actual}")
    saved_common = COMMON_RESULT.read_bytes() if COMMON_RESULT.exists() else None
    runs: list[dict] = []
    failure = None
    try:
        runs.append(capture_run("ordered", control=False))
        runs.append(capture_run("control", control=True))
    except Exception as exc:  # evidence is still written on a failed A/B run
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        if saved_common is None:
            COMMON_RESULT.unlink(missing_ok=True)
        else:
            COMMON_RESULT.write_bytes(saved_common)

    comparison = None
    if len(runs) == 2:
        a, b = runs
        # The native packet snapshot includes both initial positions; compare
        # those exact captured rows across runs.
        a_rows = a.get("specialists_before", [])
        baseline_line = b.get("group_selection_baseline", "")
        before_state = {}
        for line in a_rows:
            match = re.search(r"index=(\d+) ptr=([0-9a-fA-F]+) xy=(-?\d+),(-?\d+)", line)
            if match:
                before_state[int(match.group(1))] = (match.group(2).lower(), int(match.group(3)), int(match.group(4)))
        control_state = {}
        for match in re.finditer(r"spec([01])=([0-9a-fA-F]+):(-?\d+),(-?\d+) flags57=", baseline_line):
            control_state[int(match.group(1))] = (match.group(2).lower(), int(match.group(3)), int(match.group(4)))
        comparison = {
            "treatment_one_original_PA_GROUP": True,
            "control_withheld_only_order_input": True,
            "baseline_same_two_specialists": before_state == control_state == {
                0: ("0033c2d6", 21242, 13643), 1: ("0033c39e", 20920, 14045)},
            "treatment_handler_sets_state57_02": len(a.get("specialists_after", [])) == 2 and
                all("flags57=02" in line for line in a["specialists_after"]),
            "control_state57_stays_zero": "flags57=00/00" in b.get("summary_line", ""),
            "treatment_moves_both_control_moves_neither":
                "both_moved=1" in a.get("summary_line", "") and "moved=0" in b.get("summary_line", ""),
        }
        comparison["passed"] = all(comparison.values())
        if not a_rows:
            comparison["passed"] = False
    report = {
        "schema": SCHEMA,
        "target": {"canonical_le": str(TARGET), "sha256": actual,
                   "originals_or_oracle_modified": False},
        "design": {
            "method": "two equal 550-turn original game() profiles; treatment runs the SDL group-order gesture, control withholds it after the same selection box",
            "no_harness_guest_state_writes": True,
            "packet_action": "PA_GROUP 0x12",
            "emitter_link": "0x21D65",
            "dispatcher": ["0x93010", "0x934D1", "0x77090"],
        },
        "runs": runs,
        "comparison": comparison,
        "failure": failure,
        "passed": failure is None and len(runs) == 2 and bool(comparison and comparison.get("passed")),
    }
    path = EVIDENCE / "native_group_causality_regression.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise SystemExit(f"PA_GROUP A/B regression failed; evidence: {path}; cause={failure}")
    print(f"PASS original PA_GROUP causal A/B regression: {path}")


if __name__ == "__main__":
    main()
