#!/usr/bin/env python3
"""Single bounded original AH=44 DOSBox Staging replay via oracle_guard."""
from __future__ import annotations

import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_072_setup_this_checkpoints import sample_this_value

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
TRACE = MOUNT / "W3_072_SETUP_THIS_20261008_02.jsonl"
RUN_ID = "w3-072-setup-this-20261008-02"
RESULT = ROOT / "evidence/w3_072_setup_this_capture_02.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def correlate_ah44(callsites: list[dict], events: list[dict]) -> list[dict]:
    pairs = []
    for callsite in callsites:
        matching = next((event for event in events
                         if event.get("sequence", 0) > callsite.get("sequence", 0)
                         and event.get("process_psp") == callsite.get("process_psp")
                         and event.get("in_ax") == callsite.get("eax", -1) % 0x10000
                         and event.get("in_bx") == callsite.get("ebx", -1) % 0x10000
                         and event.get("in_cx") == callsite.get("ecx", -1) % 0x10000
                         and event.get("in_dx") == callsite.get("edx", -1) % 0x10000), None)
        if matching:
            pairs.append({"callsite_sequence": callsite.get("sequence"),
                          "ah44_sequence": matching.get("sequence"),
                          "link_va": callsite.get("link_va"),
                          "same_register_request": True,
                          "callsite": callsite, "service": matching})
    return pairs


def effective_cf(event: dict) -> bool:
    """CF returned by INT 21h, from the saved IRET frame, not reg_flags."""
    if "iret_flags" not in event:
        raise ValueError("missing saved IRET flags")
    return bool(event["iret_flags"] & 1)


def verify_sandbox() -> dict:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
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
        raise FileExistsError("refusing to overwrite previous W3-072 evidence")
    fixture_bytes, fixture_hash = FIXTURE.stat().st_size, sha256(FIXTURE)
    config_hash = sha256(CONFIG)
    if (fixture_bytes, fixture_hash) != (GW_SIZE, GW_SHA256):
        raise ValueError(f"GW.EXE mismatch: {fixture_bytes}, {fixture_hash}")
    if config_hash != CONFIG_SHA256:
        raise ValueError(f"functional config mismatch: {config_hash}")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging revision mismatch: {revision}")
    if not MOUNT.is_dir() or not str(TRACE).startswith(str(MOUNT) + os.sep):
        raise ValueError("trace is not contained by the verified VHDX mount")
    return {"sandbox": sandbox, "fixture": str(FIXTURE), "fixture_bytes": fixture_bytes,
            "fixture_sha256": fixture_hash, "config": str(CONFIG),
            "config_sha256": config_hash, "dosbox": str(DOSBOX),
            "dosbox_sha256": sha256(DOSBOX), "staging_revision": revision,
            "trace": str(TRACE), "trace_max_bytes": 1048576,
            "ah44_event_cap": 8, "callsite_checkpoint_cap": 8,
            "trace_cap_bytes": 1048576, "timeout_seconds": 120}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    pre = preflight()
    if args.preflight_only:
        print(json.dumps(pre, indent=2))
        return 0
    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            environment.pop(key, None)
    environment.update({
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
    if environment["GWRECOMP_GW_FILE_SIZE"] != "1251658":
        raise ValueError("GWRECOMP_GW_FILE_SIZE mismatch")
    out_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json"
    err_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
               "--run-id", RUN_ID, "--operation", "W3-072 targeted setup_game this-slot capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", pre["dosbox_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(ROOT / "evidence/oracle_runs"),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "120",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with out_path.open("xb") as stdout, err_path.open("xb") as stderr:
        process = subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout,
                                 stderr=stderr, timeout=135, check=False)
    guard = json.loads(out_path.read_text(encoding="utf-8"))
    trace = {"exists": TRACE.is_file(), "bytes": TRACE.stat().st_size if TRACE.exists() else 0,
             "sha256": sha256(TRACE) if TRACE.exists() else None}
    events = []
    callsites = []
    runtime_events = []
    if TRACE.exists():
        for line in TRACE.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "original_int21_ah44":
                events.append(event)
            if event.get("checkpoint") == "DOS_AH44_CALLSITE":
                callsites.append(event)
            if event.get("event") == "target_runtime_checkpoint":
                runtime_events.append(event)
    pairs = correlate_ah44(callsites, events)
    this_checkpoints = [event for event in runtime_events
                        if event.get("checkpoint") in {
                            "SETUP_GAME_ENTRY", "SETUP_THIS_GLOBAL_READ",
                            "SETUP_THIS_GLOBAL_WRITE"}]
    this_slot_observations = [{
        "checkpoint": event.get("checkpoint"),
        "link_va": event.get("link_va"),
        "runtime_eip": event.get("eip"),
        "cs": event.get("cs"),
        "ds": event.get("ds"),
        "data_rebase": event.get("data_rebase"),
        "this_value_u32": sample_this_value(event),
        "samples": [sample for sample in event.get("selected_global_samples", [])
                    if sample.get("link_offset") == 0x00114ca8],
    } for event in this_checkpoints]
    result = {"schema": "w3-072-setup-this-slot/v1", "task": "W3-072",
              "classification": "ORIGINAL_OBSERVED" if pairs else "INCONCLUSIVE",
              "preflight": pre, "run_id": RUN_ID, "guard_returncode": process.returncode,
              "guard": guard, "trace": trace,
              "runtime_mapping": {"main_entry": next((e for e in runtime_events if e.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None),
                                  "setup_game": next((e for e in runtime_events if e.get("checkpoint") == "SETUP_GAME_ENTRY"), None),
                                  "this_checkpoints": this_checkpoints,
                                  "this_slot_observations": this_slot_observations,
                                  "ah44_callsite": callsites[0] if callsites else None},
              "ah44_events": events, "callsite_events": callsites, "correlated_pairs": pairs,
              "ah44_event_count": len(events), "callsite_count": len(callsites),
              "instrumentation": {"filter": "INT 21h AH=44 and link VA 0xC8973, independent of generic 128 DOS event cap",
                                  "ah44_event_cap": 8, "callsite_cap": 8, "trace_cap_bytes": 1048576,
                                  "original_execution_only": True,
                                  "correlation": "preceding protected-mode callsite checkpoint with matching AX/BX/CX/DX and target PSP"}}
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "guard_exit_reason": guard.get("exit_reason"), "trace": trace,
                      "ah44_event_count": len(events), "callsite_count": len(callsites),
                      "correlated_pair_count": len(pairs)}, indent=2))
    return process.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {error}", file=sys.stderr)
        raise SystemExit(2)



