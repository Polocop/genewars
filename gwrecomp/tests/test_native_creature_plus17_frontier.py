"""Minimal read-only continuation probe for the neutral-creature +0x17 gate.

Uses the existing original-code replay in matched no-order mode and enables
only the sparse terrain-refresh caller/guard observations. No guest memory is
written by this runner.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
TARGET = EVIDENCE / "genewars-1_1.exe"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
COMMON_RESULT = EVIDENCE / "native_ifctitle_creature_probe.json"
STEM = "native_creature_plus17_frontier7"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    actual = sha256(TARGET)
    if actual != TARGET_SHA256:
        raise SystemExit(f"canonical LE hash changed: {actual}")
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("GWRECOMP_IFCLEVEL_") or key in {
            "GW_FULL_TRACE", "GW_CAMPAIGN_CREATURE_BRANCH_TRACE"
        }:
            env.pop(key, None)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "GWRECOMP_IFCLEVEL_CONTINUE": "1",
        "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP": "1",
        "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN": "550",
        "GWRECOMP_IFCLEVEL_CREATURE_GUARD_GROUP": "1",
        "GWRECOMP_IFCLEVEL_GROUP_CONTROL_NO_ORDER": "1",
        "GWRECOMP_IFCLEVEL_REPLAY_STEM": STEM,
    })
    saved = COMMON_RESULT.read_bytes() if COMMON_RESULT.exists() else None
    started = time.perf_counter()
    failure = None
    try:
        proc = subprocess.run(
            [str(ROOT / ".venv" / "Scripts" / "python.exe"),
             str(ROOT / "tests" / "test_ifctitle_creature_probe.py")],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=900,
        )
        elapsed = round(time.perf_counter() - started, 3)
        wrapper_stdout = EVIDENCE / f"{STEM}.wrapper.stdout.log"
        wrapper_stderr = EVIDENCE / f"{STEM}.wrapper.stderr.log"
        wrapper_stdout.write_text(proc.stdout, encoding="utf-8")
        wrapper_stderr.write_text(proc.stderr, encoding="utf-8")
        native_stderr = EVIDENCE / f"{STEM}.stderr.log"
        if not native_stderr.exists():
            native_stderr.write_text(proc.stderr, encoding="utf-8")
        text = native_stderr.read_text(encoding="utf-8", errors="replace")
        summary = next((line for line in text.splitlines()
                        if line.startswith("TRACE creature17_terrain_route_counts ")), None)
        if proc.returncode != 0:
            raise AssertionError(f"probe wrapper exit={proc.returncode}; see {wrapper_stderr}")
        if summary is None or "stop_turn=550" not in summary:
            raise AssertionError(f"missing 550-turn producer census; see {native_stderr}")
        counts = {key.lower(): int(value) for key, value in
                  re.findall(r"([0-9a-fA-F]{8})=(\d+)", summary)}
        required_sites = (0x5BE20, 0x5BE48, 0x5C338, 0x5CAF0, 0x5D5AE,
                          0x5DD30, 0x5DE34, 0x5E130, 0x5E42E, 0x5E450,
                          0x5E462, 0x5E4C0, 0x5E550, 0x5E557, 0x5E55C, 0x5E796, 0x5E799, 0x5E7C6, 0x5E7CD, 0x5E7E7,
                          0x5E7F3, 0x5E804, 0x5E807, 0x5E8EE, 0x7A350,
                          0x7A530, 0x80FE0, 0x5DBC0)
        missing = [f"0x{site:08x}" for site in required_sites if f"{site:08x}" not in counts]
        if missing:
            raise AssertionError(f"sparse branch/call sites absent from fast callback: {missing}")
        gate_rows = [line for line in text.splitlines()
                     if line.startswith("TRACE creature17_first_refresh_gate ")]
        guard_counts = {site: counts.get(f"{site:08x}", -1) for site in
                        (0x5E462,0x5E7CD,0x5E7E7,0x5E7F3,0x5E804,0x5E807,0x5E8EE)}
        # The native sparse hooks prove path order. 5E7F3's original bytes are
        # CMP [EDX+6E3],0; SETE AH; TEST AH,AH; JNE 5E8FD. Since 5E804 (the
        # fall-through continuation) never executes and no fault/frontier
        # occurs, that JNE is taken, which implies the field compared at 5E7E7
        # was zero. Global lazy-flag snapshots are intentionally not used.
        player_rows = [line for line in text.splitlines()
                       if line.startswith("TRACE creature17_player_record ")]
        player_fields = {}
        for line in player_rows:
            m = re.search(r"eip=([0-9a-fA-F]+).*?base=([0-9a-fA-F]+) field=([0-9a-fA-F]+) value=([0-9a-fA-F]{2}) local_index=(\d+) expected_local_base=([0-9a-fA-F]+) field49d_dword=([0-9a-fA-F]+) b2=([0-9a-fA-F]{2}) b3=([0-9a-fA-F]{2}) b4a2=([0-9a-fA-F]{2})", line)
            if m:
                player_fields[m.group(1).lower()] = {
                    "base": "0x"+m.group(2).lower(), "field_address": "0x"+m.group(3).lower(),
                    "value": int(m.group(4),16), "local_player_index": int(m.group(5)),
                    "expected_local_player_base": "0x"+m.group(6).lower(),
                    "field_49d_dword": "0x"+m.group(7).lower(),
                    "byte_2": int(m.group(8),16), "byte_3": int(m.group(9),16),
                    "byte_4a2": int(m.group(10),16)}
        if "0005e7f3" not in player_fields:
            raise AssertionError(f"missing direct read of [EDX+0x6E3] at 0x5E7F3; see {native_stderr}")
        first_rejected_guard = {
            "eip": "0x0005E7F3", "next_fallthrough_site": "0x0005E804",
            "observed_counts": {f"0x{site:08x}": count for site,count in guard_counts.items()},
            "branch_taken": guard_counts[0x5E7F3] == 550 and guard_counts[0x5E804] == 0,
            "compared_player_record_byte": "[EDX+0x6E3]",
            "value_observed_directly": player_fields.get("0005e7f3", {}).get("value"),
            "base_observed_directly": player_fields.get("0005e7f3", {}).get("base"),
            "inference_crosscheck": "CMP [EDX+6E3],0; SETE AH; TEST AH,AH; JNE skips to 0x5E8FD. The 0x5E804 continuation is absent on all 550 entries while this profile has no fault/frontier.",
        }
        # This probe establishes which original producer branches were
        # actually observed; it does not call a producer or force +0x17.
        no_producer = counts.get("00080fe0", -1) == 0 and counts.get("0005dbc0", -1) == 0
        report = {
            "schema": "gw-native-creature-plus17-frontier-probe/v1",
            "canonical_le_sha256": actual,
            "profile": "FAST_BOUNDARY_PROBE; original game() to turn 550; no-order control; observational only",
            "wrapper_exit_code": proc.returncode,
            "wall_clock_seconds": elapsed,
            "native_summary": summary,
            "site_counts": {f"0x{k}": v for k, v in counts.items()},
            "global_register_snapshots_not_used_for_branch_decision": gate_rows,
            "first_rejected_guard": first_rejected_guard,
            "producer_not_entered": no_producer,
            "candidate_plus17_zero": "creature=0032cf86 value=00" in text,
            "direct_player_record_reads": player_fields,
            "player_record_writer_site_0x5e550_count": counts.get("0005e550", -1),
            "player_record_writer_post_store_site_0x5e557_count": counts.get("0005e557", -1),
            "no_guest_state_writes_by_probe": True,
            "native_stderr": str(native_stderr),
            "wrapper_stdout": str(wrapper_stdout),
            "wrapper_stderr": str(wrapper_stderr),
            "next_predicate": "Compare the direct value at 0x5E7F3 with the conditional writer 0x5E550. If the writer is skipped, the first branch in 0x5E4C0..0x5E550 is the next causal gate; trace its original producer and do not write the record or creature fields from the harness.",
            "passed": no_producer and "creature=0032cf86 value=00" in text and
                all(count == 550 for site,count in guard_counts.items()
                    if site in (0x5E462,0x5E7CD,0x5E7E7,0x5E7F3)) and
                all(guard_counts[site] == 0 for site in (0x5E804,0x5E807,0x5E8EE)) and
                first_rejected_guard["branch_taken"],
        }
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
        report = {
            "schema": "gw-native-creature-plus17-frontier-probe/v1",
            "canonical_le_sha256": actual,
            "failure": failure,
            "passed": False,
        }
    finally:
        if saved is None:
            COMMON_RESULT.unlink(missing_ok=True)
        else:
            COMMON_RESULT.write_bytes(saved)
    path = EVIDENCE / f"{STEM}.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise SystemExit(f"creature +0x17 frontier probe failed; evidence={path}; cause={failure}")
    print(f"PASS minimal original-creature +0x17 frontier probe: {path}")


if __name__ == "__main__":
    main()
