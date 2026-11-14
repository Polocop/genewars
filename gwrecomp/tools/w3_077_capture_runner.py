#!/usr/bin/env python3
"""One guarded original replay for pre-dispatch INT 21h AH=43 caller state."""
from __future__ import annotations

import hashlib
import argparse
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
TRACE = MOUNT / "W3_077_INT21_CALLER_20261008_01.jsonl"
RUN_ID = "w3-077-int21-caller-20261008-01"
RESULT = ROOT / "evidence/w3_077_int21_caller_capture.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
DOSBOX_SHA256 = "01bb4c4224dc3473527449c084dad70938f02429fa2c36612aab3ebb7e99a619"
sys.path.insert(0, str(ROOT))
from tools.w3_077_int21_caller_capture import (
    correlate_ah43_events, main_rebase_from_trace, read_trace,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sandbox() -> dict:
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                             str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
                            cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"GWORACLE verification failed: {result.stderr[-1000:]}")
    data = json.loads(result.stdout)
    if data.get("verified") is not True or data.get("volume", data.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {data}")
    return data


def preflight() -> dict:
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite prior W3-077 evidence")
    fixture = {"bytes": FIXTURE.stat().st_size, "sha256": sha256(FIXTURE)}
    config_hash, dosbox_hash = sha256(CONFIG), sha256(DOSBOX)
    if fixture != {"bytes": GW_SIZE, "sha256": GW_SHA256}:
        raise ValueError(f"authentic GW.EXE mismatch: {fixture}")
    if config_hash != CONFIG_SHA256 or dosbox_hash != DOSBOX_SHA256:
        raise ValueError(f"configuration/binary fingerprint mismatch: {config_hash}, {dosbox_hash}")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging revision mismatch: {revision}")
    if not str(TRACE).startswith(str(MOUNT) + os.sep):
        raise ValueError("trace path is outside GWORACLE")
    return {"sandbox": sandbox, "fixture_path": str(FIXTURE), "fixture": fixture,
            "config": str(CONFIG), "config_sha256": config_hash,
            "dosbox": str(DOSBOX), "dosbox_sha256": dosbox_hash,
            "staging_revision": revision, "trace": str(TRACE),
            "trace_cap_bytes": 1_048_576, "ah43_cpu_event_cap": 8,
            "timeout_seconds": 120}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--postprocess-existing", action="store_true",
                        help="reconcile an already completed guarded trace; never launches DOSBox")
    args = parser.parse_args()
    if args.postprocess_existing:
        if not TRACE.is_file() or not RESULT.is_file():
            raise FileNotFoundError("existing W3-077 trace/result pair is required")
        existing = json.loads(RESULT.read_text(encoding="utf-8"))
        events = read_trace(TRACE)
        main_rebase = main_rebase_from_trace(events)
        w1 = json.loads((ROOT / "evidence/native_dos_ah43_frontier_work2.json").read_text(encoding="utf-8"))
        w1_frontier = int(w1["w1_next_frontier"]["trap_va"], 16)
        matched = correlate_ah43_events(events, expected_rebase=main_rebase,
                                        w1_frontier_link=w1_frontier)
        sound = [e for e in matched if (e.get("requested_path") or "").casefold() == r"c:\genewars\sound.ini"]
        anchor = next((e for e in events if e.get("event") == "target_code_anchor"
                       and e.get("anchor") == "MAIN_ENTRY"), None)
        main_checkpoint = next((e for e in events if e.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"
                                and e.get("link_va") == 0x93F30), None)
        existing["classification"] = "ORIGINAL_OBSERVED" if any(
            e["mapping_valid"] and e["matches_w1_frontier"] for e in sound) else "INCONCLUSIVE"
        existing["target_main_mapping"] = {"target_anchor": anchor,
                                           "main_entry_checkpoint": main_checkpoint,
                                           "code_rebase": main_rebase,
                                           "same_run_anchor_agrees": main_rebase is not None}
        existing["pre_dispatch_events"] = [e for e in events if e.get("event") == "original_cpu_int21_ah43_entry"]
        existing["callback_events"] = [e for e in events if e.get("event") == "original_int21_ah43"]
        existing["correlated_events"] = matched
        existing["sound_ini_callers"] = [{
            "return_link_va": e["return_link_va"],
            "int_instruction_link_va_candidate": e["int_instruction_link_va_candidate"],
            "matches_w1_frontier": e["matches_w1_frontier"],
            "sequence": e["callback"].get("sequence"),
            "ordinal": e["callback"].get("ordinal"),
        } for e in sound if e["mapping_valid"]]
        existing["postprocessing"] = "Derived from preserved trace only; no new DOSBox invocation. The pre-dispatch old_eip is post-instruction per CPU_SW_Interrupt's GETIP caller; the candidate INT instruction address is old_eip-2 and is cross-checked against W1's exact-target frontier."
        RESULT.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": str(RESULT), "classification": existing["classification"],
                          "sound_ini_callers": existing["sound_ini_callers"]}, indent=2))
        return 0
    pre = preflight()
    if args.preflight_only:
        print(json.dumps(pre, indent=2))
        return 0
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
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    out = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json"
    err = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-077 pre-dispatch INT21 AH43 caller capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", pre["dosbox_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(ROOT / "evidence/oracle_runs"),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "120",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with out.open("xb") as stdout, err.open("xb") as stderr:
        process = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                 timeout=135, check=False)
    guard = json.loads(out.read_text(encoding="utf-8"))
    events = read_trace(TRACE) if TRACE.exists() else []
    main_rebase = main_rebase_from_trace(events)
    w1 = json.loads((ROOT / "evidence/native_dos_ah43_frontier_work2.json").read_text(encoding="utf-8"))
    w1_frontier = int(w1["w1_next_frontier"]["trap_va"], 16)
    matched = correlate_ah43_events(events, expected_rebase=main_rebase,
                                    w1_frontier_link=w1_frontier)
    sound = [e for e in matched if (e.get("requested_path") or "").casefold() == r"c:\genewars\sound.ini"]
    trace_meta = {"exists": TRACE.exists(), "bytes": TRACE.stat().st_size if TRACE.exists() else 0,
                  "sha256": sha256(TRACE) if TRACE.exists() else None,
                  "event_count": len(events)}
    cpu_events = [e for e in events if e.get("event") == "original_cpu_int21_ah43_entry"]
    callback_events = [e for e in events if e.get("event") == "original_int21_ah43"]
    if trace_meta["bytes"] > 1_048_576 or len(cpu_events) > 8 or len(callback_events) > 8:
        raise RuntimeError(f"capture exceeded bounds: {trace_meta}")
    classification = "ORIGINAL_OBSERVED" if any(
        e["mapping_valid"] and e["matches_w1_frontier"] for e in sound) else "INCONCLUSIVE"
    anchor = next((e for e in events if e.get("event") == "target_code_anchor"
                   and e.get("anchor") == "MAIN_ENTRY"), None)
    main_checkpoint = next((e for e in events if e.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"
                            and e.get("link_va") == 0x93F30), None)
    evidence = {"schema": "w3-077-original-ah43-caller/v1", "task": "W3-077",
                "classification": classification, "preflight": pre, "run_id": RUN_ID,
                "guard_returncode": process.returncode, "guard": guard, "trace": trace_meta,
                "target_main_mapping": {"target_anchor": anchor,
                                        "main_entry_checkpoint": main_checkpoint,
                                        "code_rebase": main_rebase,
                                        "same_run_anchor_agrees": main_rebase is not None},
                "pre_dispatch_events": [e for e in events if e.get("event") == "original_cpu_int21_ah43_entry"],
                "callback_events": [e for e in events if e.get("event") == "original_int21_ah43"],
                "correlated_events": matched,
                "sound_ini_callers": [{
                    "return_link_va": e["return_link_va"],
                    "int_instruction_link_va_candidate": e["int_instruction_link_va_candidate"],
                    "matches_w1_frontier": e["matches_w1_frontier"],
                    "sequence": e["callback"].get("sequence"),
                    "ordinal": e["callback"].get("ordinal"),
                } for e in sound if e["mapping_valid"]],
                "limitations": "Only same-run mapped CPU_Interrupt events correlated to later DOS AH=43 callback events can establish a caller; callback CS:EIP alone is not a game caller."}
    RESULT.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": classification,
                      "trace": trace_meta, "sound_ini_calls": len(sound),
                      "mapped_callers": evidence["sound_ini_callers"],
                      "guard_exit_reason": guard.get("exit_reason"),
                      "guard_cause": guard.get("cause")}, indent=2))
    return process.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
