#!/usr/bin/env python3
"""One guarded replay with only high-volume DOS file-I/O trace suppressed."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
TRACE = MOUNT / "W3_078_FILEIO_FILTER_20261008_01.jsonl"
RUN_ID = "w3-078-fileio-filter-20261008-01"
RESULT = ROOT / "evidence/w3_078_file_trace_filter.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
EXPECTED_DOSBOX_SHA256 = "879ce55c2aea1ba3e309a52bd1b9425170a065450ce74599f8144f4dd0de68bc"
sys.path.insert(0, str(ROOT))
from tools.w3_077_int21_caller_capture import correlate_ah43_events, main_rebase_from_trace, read_trace
from tools.w3_078_file_trace_filter import summarize_events


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sandbox() -> dict:
    completed = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
                               cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if completed.returncode:
        raise RuntimeError(f"GWORACLE verification failed: {completed.stderr[-1000:]}")
    result = json.loads(completed.stdout)
    if result.get("verified") is not True or result.get("volume", result.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {result}")
    return result


def preflight() -> dict:
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite prior W3-078 evidence")
    fixture = {"bytes": FIXTURE.stat().st_size, "sha256": sha256(FIXTURE)}
    config_hash, binary_hash = sha256(CONFIG), sha256(DOSBOX)
    if fixture != {"bytes": GW_SIZE, "sha256": GW_SHA256}:
        raise ValueError(f"authentic GW.EXE mismatch: {fixture}")
    if config_hash != CONFIG_SHA256:
        raise ValueError(f"functional DOSBox config mismatch: {config_hash}")
    if binary_hash != EXPECTED_DOSBOX_SHA256:
        raise ValueError(f"instrumented DOSBox hash mismatch; expected filtered build {EXPECTED_DOSBOX_SHA256}, got {binary_hash}")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging revision mismatch: {revision}")
    header = (SOURCE / "src/dos/exec_trace.h").read_text(encoding="utf-8")
    if "GWRECOMP_EXEC_TRACE_FILE_IO" not in header:
        raise ValueError("file-I/O trace filter is not present in source")
    return {"sandbox": sandbox, "fixture_path": str(FIXTURE), "fixture": fixture,
            "config": str(CONFIG), "config_sha256": config_hash,
            "dosbox": str(DOSBOX), "dosbox_sha256": binary_hash,
            "staging_revision": revision, "trace": str(TRACE),
            "trace_cap_bytes": 1_048_576, "timeout_seconds": 120,
            "file_io_trace_filter": "disabled high-volume event records only; default remains enabled"}


def run_guard(pre: dict) -> tuple[dict, int]:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": "1048576",
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    stdout_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json"
    stderr_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-078 bounded replay with high-volume file trace disabled",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", pre["dosbox_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(ROOT / "evidence/oracle_runs"),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "120",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                 timeout=135, check=False)
    return json.loads(stdout_path.read_text(encoding="utf-8")), process.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    pre = preflight()
    if args.preflight_only:
        print(json.dumps(pre, indent=2))
        return 0
    guard, returncode = run_guard(pre)
    events = read_trace(TRACE) if TRACE.exists() else []
    summary = summarize_events(events)
    main_rebase = main_rebase_from_trace(events)
    w1 = json.loads((ROOT / "evidence/native_dos_ah43_frontier_work2.json").read_text(encoding="utf-8"))
    w1_link = int(w1["w1_next_frontier"]["trap_va"], 16)
    ah43 = correlate_ah43_events(events, expected_rebase=main_rebase, w1_frontier_link=w1_link)
    sound_calls = [item for item in ah43
                   if (item.get("requested_path") or "").casefold() == r"c:\genewars\sound.ini"]
    trace_meta = {"exists": TRACE.exists(), "bytes": TRACE.stat().st_size if TRACE.exists() else 0,
                  "sha256": sha256(TRACE) if TRACE.exists() else None}
    if trace_meta["bytes"] > 1_048_576:
        raise RuntimeError(f"trace exceeded 1 MiB: {trace_meta}")
    playintro_or_game_reached = any(
        e.get("checkpoint") in {"PLAYINTRO_CALLSITE", "PLAYINTRO_ENTRY", "GAME_CALLSITE"}
        for e in summary["target_checkpoints"])
    page_or_int10_reached = any(
        e.get("checkpoint") in {"VIDEO_VESA_SET_PAGE_ENTRY", "VIDEO_INT10_FIRST_ENTRY",
                                 "VIDEO_INT10_SECOND_ENTRY"}
        for e in summary["target_checkpoints"])
    evidence = {"schema": "w3-078-file-trace-filter/v1", "task": "W3-078",
                "classification": "ORIGINAL_OBSERVED" if playintro_or_game_reached or page_or_int10_reached else "INCONCLUSIVE",
                "original_setup_observed": bool(summary["target_checkpoints"]),
                "preflight": pre, "run_id": RUN_ID, "guard_returncode": returncode,
                "guard": guard, "trace": trace_meta, "summary": summary,
                "main_code_rebase": main_rebase,
                "setup_game": next((e for e in summary["target_checkpoints"]
                                     if e.get("checkpoint") == "SETUP_GAME_ENTRY"), None),
                "playintro_or_game_reached": playintro_or_game_reached,
                "page_or_int10_reached": page_or_int10_reached,
                "sound_ini_calls": sound_calls,
                "comparison": {"prior_w3_075_bytes": 264094, "prior_w3_075_events": 850,
                               "prior_dos_file_read": 318, "prior_dos_file_seek": 260,
                               "prior_dos_file_read_batch": 67,
                               "prior_file_io_total": 645,
                               "interpretation": "Trace volume is a measured difference; only a later original checkpoint can show whether it helped progress."}}
    RESULT.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": evidence["classification"],
                      "trace": trace_meta, "event_counts": summary["event_counts"],
                      "last_checkpoint": (summary["last_target_checkpoint"] or {}).get("checkpoint"),
                      "playintro_or_game_reached": evidence["playintro_or_game_reached"],
                      "page_or_int10_reached": evidence["page_or_int10_reached"],
                      "guard_exit_reason": guard.get("exit_reason"), "guard_cause": guard.get("cause")}, indent=2))
    return returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
