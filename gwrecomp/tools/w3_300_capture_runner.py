#!/usr/bin/env python3
"""One W3-300 replay with an explicit opt-in activation marker, guarded."""
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
from tools.w3_300_activation_capture import analyze, parse_trace, validate_first_hit

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
STAGING = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
CORE = STAGING / "src/cpu/core_dyn_x86.cpp"
GUARD = ROOT / "tools/oracle_guard.py"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
TRACE = MOUNT / "W3_300_SOUND_HOOK_20261010_01.jsonl"
RUN_ID = "w3-300-sound-hook-activation-20261010-01"
RESULT = ROOT / "evidence/w3_300_sound_hook_activation.json"
REPORT = ROOT / "reports/coordination/w3_300_sound_hook_activation.md"
RUNS = ROOT / "evidence/oracle_runs"
GUARD_RUN = RUNS / f"oracle_runs_{RUN_ID}.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
TIMEOUT = 45


def preflight() -> dict:
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError("GWORACLE verification failed")
    if int(sandbox.get("capacity_bytes", 0)) < 15 * 1024**3:
        raise RuntimeError("GWORACLE is below the required capacity")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, CORE, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if any(path.exists() for path in (TRACE, RESULT, REPORT, GUARD_RUN)):
        raise FileExistsError("refusing to overwrite W3-300 outputs")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA or sha(CUE) != CUE_SHA:
        raise RuntimeError("functional config or original CUE identity mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
        raise RuntimeError("original CUE mount is not read-only")
    revision = subprocess.run(["git", "-C", str(STAGING), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10,
                              check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned revision mismatch: {revision}")
    active = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "@(Get-CimInstance Win32_Process -Filter \"name='dosbox.exe'\" | "
         "Where-Object { $_.ExecutablePath -eq '" + str(DOSBOX) + "' }).Count"],
        capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if active not in {"0", ""}:
        raise RuntimeError(f"instrumented Staging process already active ({active})")
    return sandbox


def run_guarded(binary_sha: str) -> dict:
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
        "GWRECOMP_W3_300_CAPTURE": "1",
    })
    argv = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
            "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
            "--operation", "W3-300 one activation-marker sound/PIT capture",
            "--commit-sha", REVISION, "--target-sha", GW_SHA,
            "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA,
            "--evidence-dir", str(RUNS), "--max-file-text-mib", "1",
            "--max-file-bin-mib", "64", "--max-run-gib", "1",
            "--host-floor-gib", "100", "--timeout-s", str(TIMEOUT),
            "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    RUNS.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                               text=True, timeout=TIMEOUT + 10, check=False)
    if completed.returncode not in (0, 1):
        raise RuntimeError(f"oracle_guard launcher returned {completed.returncode}: {completed.stderr[-2000:]}")
    return json.loads(completed.stdout)


def main() -> int:
    sandbox = preflight()
    binary_sha = sha(DOSBOX)
    core_sha = sha(CORE)
    guard = run_guarded(binary_sha)
    if sha(DOSBOX) != binary_sha or sha(CORE) != core_sha:
        raise RuntimeError("instrumented binary/source changed during the guarded run")
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_trace(raw)
    validate_first_hit(rows)
    summary = analyze(rows)
    result = {
        "schema": "w3-300-sound-hook-activation/v1", "task": "W3-300",
        "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if summary["main_activation_marker_count"] else "INCONCLUSIVE",
        "provenance": {"target_sha256": GW_SHA, "fixture_size": FIXTURE.stat().st_size,
                       "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                       "cue_read_only": True, "staging_revision": REVISION,
                       "binary_path": str(DOSBOX), "binary_sha256": binary_sha,
                       "core_source_sha256": core_sha},
        "preflight": {"sandbox": sandbox, "timeout_seconds": TIMEOUT,
                      "trace_byte_cap": 1_048_576, "selected_event_cap": 48,
                      "global_trace": False, "global_port_trace": False,
                      "bulk_memdump": False, "guest_modified": False},
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
            "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
            "killed_processes", "duration_s", "evidence_path", "ok")},
        "guard_evidence_path": str(GUARD_RUN),
        "trace": {"path": str(TRACE), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "row_count": len(rows)},
        "analysis": summary,
    }
    GUARD_RUN_JSON = json.loads(GUARD_RUN.read_text(encoding="utf-8")) if GUARD_RUN.exists() else {}
    result["guard_record_summary"] = {key: GUARD_RUN_JSON.get(key) for key in (
        "cause", "exit_reason", "detail", "duration_s", "sandbox_verified", "killed_processes")}
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-300 — sound-hook runtime activation markers\n\n"
        f"Classification: **{summary['classification']}**. Guard cause: `{guard.get('cause')}` after {guard.get('duration_s')} s.\n\n"
        f"- MAIN activation marker count: {summary['main_activation_marker_count']}.\n"
        f"- Target dispatch markers: {summary['dispatch_site_count']} at `{summary['dispatch_site_links']}`.\n"
        f"- W3-298 sound/PIT recorder rows: {summary['w3_298_sound_event_count']}; total selected events: {summary['selected_event_count']}/48.\n"
        f"- Last generic checkpoint: `{summary['last_generic_checkpoint']}`. Last DOS API: `{summary['last_dos_api']}`.\n"
        "- This evidence makes no framebuffer-pixel, menu, or gameplay claim.\n"
        f"- Trace: {len(raw)} bytes; SHA-256 `{result['trace']['sha256']}`.\n",
        encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": summary["classification"],
                      "selected_events": summary["selected_event_count"],
                      "guard_cause": guard.get("cause")}))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-300 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
