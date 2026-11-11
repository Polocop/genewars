#!/usr/bin/env python3
"""Run at most one bounded W3-298 Staging replay through oracle_guard."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_298_smacker_pit_capture import analyze, parse_trace, validate_first_hit

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
STAGING = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
CORE = STAGING / "src/cpu/core_dyn_x86.cpp"
GUARD = ROOT / "tools/oracle_guard.py"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
TRACE = MOUNT / "W3_298_SOUND_PIT_20261010_01.jsonl"
RUN_ID = "w3-298-natural-sound-pit-20261010-01"
RESULT = ROOT / "evidence/w3_298_smacker_pit_capture.json"
REPORT = ROOT / "reports/coordination/w3_298_smacker_pit_capture.md"
EVIDENCE_DIR = ROOT / "evidence/oracle_runs"
STDOUT = EVIDENCE_DIR / f"{RUN_ID}.stdout.json"
STDERR = EVIDENCE_DIR / f"{RUN_ID}.stderr.txt"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
TIMEOUT_S = 45


def _preflight() -> tuple[dict, str]:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError("GWORACLE verification failed")
    if int(sandbox.get("capacity_bytes", 0)) < 15 * 1024**3:
        raise RuntimeError("GWORACLE VHDX capacity below 15 GiB")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, CORE, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if any(path.exists() for path in (TRACE, RESULT, REPORT, STDOUT, STDERR)):
        raise FileExistsError("refusing to overwrite W3-298 output")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
        raise RuntimeError("the original CUE mount is not marked read-only")
    revision = subprocess.run(
        ["git", "-C", str(STAGING), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned source revision mismatch: {revision}")
    # Refuse to begin if another emulator process could contaminate the run.
    procs = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "@(Get-CimInstance Win32_Process -Filter \"name='dosbox.exe'\" | "
         "Where-Object { $_.ExecutablePath -eq '" + str(DOSBOX) + "' }).Count"],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip()
    if procs not in {"0", ""}:
        raise RuntimeError(f"instrumented DOSBox already running ({procs})")
    return sandbox, revision


def _run_guarded(binary_sha: str) -> dict:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(1024 * 1024),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_W3_298_CAPTURE": "1",
    })
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-298 one bounded natural Smacker sound/PIT capture",
        "--commit-sha", REVISION, "--target-sha", GW_SHA256,
        "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(EVIDENCE_DIR), "--max-file-text-mib", "1",
        "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
        "--timeout-s", str(TIMEOUT_S), "--growth-text-mibs", "8",
        "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    with STDOUT.open("xb") as out, STDERR.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=TIMEOUT_S + 10, check=False)
    return json.loads(STDOUT.read_text(encoding="utf-8"))


def main() -> int:
    sandbox, revision = _preflight()
    binary_sha_before = sha(DOSBOX)
    core_sha_before = sha(CORE)
    guard = _run_guarded(binary_sha_before)
    if sha(DOSBOX) != binary_sha_before or sha(CORE) != core_sha_before:
        raise RuntimeError("instrumented executable or source changed during replay")
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_trace(raw)
    validate_first_hit(rows)
    analysis = analyze(rows)
    event_rows = [row for row in rows if row.get("event", "").startswith("W3_298_")]
    guard_summary = {key: guard.get(key) for key in (
        "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
        "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
        "killed_processes", "duration_s", "evidence_path", "ok")}
    result = {
        "schema": "w3-298-smacker-sound-pit-capture/v1", "task": "W3-298",
        "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if event_rows else "INCONCLUSIVE",
        "provenance": {"target_sha256": GW_SHA256, "fixture_path": str(FIXTURE),
                       "fixture_size": FIXTURE.stat().st_size,
                       "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                       "cue_read_only": True, "staging_revision": revision,
                       "instrumented_binary": str(DOSBOX),
                       "instrumented_binary_sha256": binary_sha_before,
                       "core_dyn_x86_cpp_sha256": core_sha_before},
        "preflight": {"sandbox": sandbox, "timeout_seconds": TIMEOUT_S,
                      "trace_byte_cap": 1_048_576, "selected_event_cap": 32,
                      "global_trace": False, "global_port_trace": False,
                      "bulk_memdump": False, "guest_modified": False},
        "guard": guard_summary,
        "trace": {"path": str(TRACE), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "row_count": len(rows), "selected_event_count": len(event_rows),
                  "selected_events": event_rows},
        "analysis": analysis,
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-298 — natural Smacker sound gate and PIT callback\n\n"
        f"Conclusion: **{analysis['conclusion']}**; evidence **{result['evidence_level']}**.\n\n"
        f"- Guarded run: `{RUN_ID}`, {guard.get('cause')} / {guard.get('exit_reason')} "
        f"after {guard.get('duration_s')} seconds.\n"
        f"- Original target SHA-256: `{GW_SHA256}`; Staging `{revision}`; "
        f"binary SHA-256: `{binary_sha_before}`.\n"
        f"- Trace: {len(raw)} bytes / {len(rows)} total rows / "
        f"{len(event_rows)} selected W3-298 rows.\n"
        f"- MAIN mapping anchor rows: {analysis['main_anchor_count']}.\n"
        f"- First-hit checkpoints: `{analysis['checkpoint_names_in_order']}`.\n"
        f"- Gate branches: `{analysis['branches']}`. PIT events: `{analysis['pit_events']}`.\n"
        "- No synthetic response, global trace, bulk memory dump, or guest modification was used.\n",
        encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "conclusion": analysis["conclusion"],
                      "guard_cause": guard.get("cause"), "selected_events": len(event_rows),
                      "trace_bytes": len(raw)}, ensure_ascii=False))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-298 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
