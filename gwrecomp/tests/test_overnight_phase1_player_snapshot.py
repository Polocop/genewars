"""Bounded native Turn-425 Player-record capture for the 500-cost investigation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
EXPECTED = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
STEM = "overnight_phase1_player_snapshot"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    target = EVIDENCE / "genewars-1_1.exe"
    if sha(target) != EXPECTED:
        raise SystemExit("canonical target hash mismatch")
    common = EVIDENCE / "native_ifctitle_creature_probe.json"
    prior_common = common.read_bytes() if common.exists() else None
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith(("GWRECOMP_IFCLEVEL_", "GWRECOMP_CAMPAIGN_")):
            env.pop(key, None)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "GWRECOMP_IFCLEVEL_CONTINUE": "1",
        "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP": "1",
        "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN": "430",
        "GWRECOMP_IFCLEVEL_REPLAY_STEM": STEM,
        "GWRECOMP_IFCLEVEL_SECOND_SPEC_PICK": "0",
        "GWRECOMP_IFCLEVEL_DIRECT_PICK_CLICK": "0",
        "GWRECOMP_IFCLEVEL_HOVER_PICK": "0",
        "GWRECOMP_OVERNIGHT_PHASE1_PLAYER_SNAPSHOT": "1",
    })
    started = time.perf_counter()
    proc = None
    saved_common = None
    try:
        proc = subprocess.run(
            [str(ROOT / ".venv" / "Scripts" / "python.exe"),
             str(ROOT / "tests" / "test_ifctitle_creature_probe.py")],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=1200,
        )
        if common.exists():
            saved_common = common.read_bytes()
    finally:
        if prior_common is None:
            common.unlink(missing_ok=True)
        else:
            common.write_bytes(prior_common)
    elapsed = time.perf_counter() - started
    # The native test itself writes these stem-named logs. Keep them intact:
    # writing the driver's captured output to the same names used to erase the
    # actual harness trace and made the trace appear missing despite a good run.
    native_stdout = EVIDENCE / f"{STEM}.stdout.log"
    native_stderr = EVIDENCE / f"{STEM}.stderr.log"
    native_result = EVIDENCE / f"{STEM}.json"
    replay_result_copy = EVIDENCE / f"{STEM}.replay.json"
    if native_result.exists():
        replay_result_copy.write_bytes(native_result.read_bytes())
    driver_stdout = EVIDENCE / f"{STEM}.driver.stdout.log"
    driver_stderr = EVIDENCE / f"{STEM}.driver.stderr.log"
    driver_stdout.write_text(proc.stdout if proc else "", encoding="utf-8")
    driver_stderr.write_text(proc.stderr if proc else "", encoding="utf-8")
    raw = EVIDENCE / "overnight_phase1_player_record_turn_425.raw"
    native_err_text = native_stderr.read_text(encoding="utf-8", errors="replace") if native_stderr.exists() else ""
    snapshot = next((line for line in native_err_text.splitlines()
                     if line.startswith("TRACE overnight_phase1_player_snapshot ")), None)
    raw_bytes = raw.read_bytes() if raw.exists() else b""
    word_hits = [f"0x{i:03X}" for i in range(max(0, len(raw_bytes)-1))
                 if int.from_bytes(raw_bytes[i:i+2], "little") == 2000]
    dword_hits = [f"0x{i:03X}" for i in range(max(0, len(raw_bytes)-3))
                  if int.from_bytes(raw_bytes[i:i+4], "little") == 2000]
    result = {
        "schema": "gw-overnight-phase1-player-capture/v1",
        "target_sha256": EXPECTED,
        "profile": "original recompiled game() loop, host-bound at Turn 430; observation only",
        "exit_code": proc.returncode if proc else None,
        "wall_clock_seconds": round(elapsed, 3),
        "turn_425_snapshot_trace": snapshot,
        "player_record_length": len(raw_bytes),
        "player_record_word_2000_offsets": word_hits,
        "player_record_dword_2000_offsets": dword_hits,
        "player_record_raw": str(raw.relative_to(ROOT)) if raw.exists() else None,
        "player_record_raw_sha256": sha(raw) if raw.exists() else None,
        "replay_evidence": str(replay_result_copy.relative_to(ROOT)) if replay_result_copy.exists() else None,
        "native_stdout": str(native_stdout.relative_to(ROOT)),
        "native_stderr": str(native_stderr.relative_to(ROOT)),
        "driver_stdout": str(driver_stdout.relative_to(ROOT)),
        "driver_stderr": str(driver_stderr.relative_to(ROOT)),
        "preservation": {"canonical_le_modified": False, "GeneWarsFX_modified": False,
                         "Oracle_modified": False},
        "passed": bool(proc and proc.returncode == 0 and snapshot and len(raw_bytes) == 0x70D),
    }
    (EVIDENCE / "overnight_phase1_player_snapshot.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if not result["passed"]:
        raise SystemExit("Turn-425 Player snapshot failed; inspect saved logs/evidence")
    print("PASS bounded native Turn-425 Player record snapshot; no guest state was modified")


if __name__ == "__main__":
    main()
