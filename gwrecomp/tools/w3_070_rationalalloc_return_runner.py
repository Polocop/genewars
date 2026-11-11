#!/usr/bin/env python3
"""One bounded guarded replay for a one-shot RationalAlloc RET/caller pair."""
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
TRACE = MOUNT / "W3_070_RATIONALALLOC_RETURN_20261008_03.jsonl"
RUN_ID = "w3-070-rationalalloc-return-20261008-03"
RESULT = ROOT / "evidence/w3_070_rationalalloc_return_capture_03.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def validate_invocation_link(events: list[dict]) -> dict | None:
    pre = next((event for event in events
                if event.get("checkpoint") == "RATIONALALLOC_PRE_RET"), None)
    ret = next((event for event in events
                if event.get("checkpoint") == "RATIONALALLOC_RET_INSTRUCTION"
                and event.get("ret_matches_pre_ret") is True), None)
    caller = next((event for event in events
                   if event.get("checkpoint") in ("RATIONALALLOC_RETURN_TO_CALLER",
                                                   "RATIONALALLOC_EXPECTED_CALLER_CANDIDATE")), None)
    if not (pre and caller):
        return None
    expected = pre.get("expected_return_link_va")
    stack_target_runtime = pre.get("epilogue_return_address")
    net_esp = caller.get("esp", 0) - pre.get("esp", 0)
    epilogue_bytes = str(pre.get("bytes", "")).lower().startswith("83c4045f5e5a595bc3")
    directly_observed_return = (
        expected not in (None, 0)
        and caller.get("link_va") == expected
        and caller.get("eip") == stack_target_runtime
        and caller.get("eax") == pre.get("eax")
        and net_esp == 28
        and epilogue_bytes
        and caller.get("sequence", 0) == pre.get("sequence", 0) + 1
    )
    if not directly_observed_return:
        return None
    return {"pre_ret_sequence": pre.get("sequence"),
            "expected_return_link_va": expected,
            "expected_return_runtime": stack_target_runtime,
            "ret_sequence": ret.get("sequence") if ret else None,
            "caller_sequence": caller.get("sequence"),
            "caller_link_va": caller.get("link_va"),
            "caller_eax": caller.get("eax"),
            "net_esp_advance": net_esp,
            "ret_opcode_checkpoint_observed": ret is not None,
            "causally_linked": True,
            "proof": "pre-RET stack target, verified epilogue bytes, immediately following expected caller EIP, +28 ESP advance, and preserved EAX"}


def read_trace(path: Path) -> tuple[list[dict], list[dict]]:
    all_events = []
    target_events = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            all_events.append(record)
            if record.get("event") == "target_runtime_checkpoint":
                target_events.append(record)
    return all_events, target_events


def runtime_mapping(events: list[dict]) -> dict:
    main = next((event for event in events if event.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    setup = next((event for event in events if event.get("checkpoint") == "SETUP_GAME_ENTRY"), None)
    if not main:
        return {"verified": False}
    rebase = main.get("eip", 0) - main.get("link_va", 0)
    return {"verified": bool(rebase and (not setup or setup.get("eip", 0) - setup.get("link_va", 0) == rebase)),
            "main_link_va": main.get("link_va"), "main_runtime_eip": main.get("eip"),
            "setup_link_va": setup.get("link_va") if setup else None,
            "setup_runtime_eip": setup.get("eip") if setup else None,
            "code_rebase": rebase}


def preflight(allow_existing: bool = False) -> dict:
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                             str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
                            cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("GWORACLE verification failed: " + result.stderr[-1000:])
    sandbox = json.loads(result.stdout)
    if sandbox.get("verified") is not True or sandbox.get("volume", sandbox.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {sandbox}")
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if not allow_existing and (TRACE.exists() or RESULT.exists()):
        raise FileExistsError("refusing to overwrite W3-070 evidence")
    if FIXTURE.stat().st_size != GW_SIZE or digest(FIXTURE) != GW_SHA256:
        raise ValueError("authentic GW.EXE fingerprint mismatch")
    if digest(CONFIG) != CONFIG_SHA256:
        raise ValueError("functional config fingerprint mismatch")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"Staging revision mismatch: {revision}")
    return {"sandbox": sandbox, "fixture_sha256": digest(FIXTURE), "fixture_bytes": FIXTURE.stat().st_size,
            "config_sha256": digest(CONFIG), "runtime_sha256": digest(DOSBOX),
            "source_revision": revision, "trace_path": str(TRACE),
            "trace_max_bytes": 1048576, "timeout_seconds": 120}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--analyze-existing", action="store_true",
                        help="re-evaluate the completed capture without running DOSBox")
    args = parser.parse_args()
    check = preflight(allow_existing=args.analyze_existing)
    if args.preflight_only:
        print(json.dumps(check, indent=2))
        return 0
    if args.analyze_existing:
        if not TRACE.is_file() or not RESULT.is_file():
            raise FileNotFoundError("existing W3-070 trace/result pair is missing")
        prior = json.loads(RESULT.read_text(encoding="utf-8"))
        all_events, target_events = read_trace(TRACE)
        checkpoints = [event for event in target_events
                       if str(event.get("checkpoint", "")).startswith("RATIONALALLOC_")]
        linked = validate_invocation_link(checkpoints)
        prior["classification"] = "ORIGINAL_OBSERVED" if linked else "INCONCLUSIVE"
        prior["rationalalloc_checkpoints"] = checkpoints
        prior["checkpoint_count"] = len(checkpoints)
        prior["trace_event_count"] = len(all_events)
        prior["runtime_mapping"] = runtime_mapping(target_events)
        prior["invocation_link"] = linked
        prior["analysis_note"] = (
            "The RET opcode was not isolated as a separate callback. Its execution is evidenced by the verified epilogue bytes, pre-RET stack target, immediately following expected caller EIP, +28 ESP advance, and preserved EAX."
            if linked else "No complete same-invocation pre-RET to caller control-flow proof was found.")
        RESULT.write_text(json.dumps(prior, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": str(RESULT), "classification": prior["classification"],
                          "runtime_mapping": prior["runtime_mapping"],
                          "invocation_link": linked, "trace_bytes": TRACE.stat().st_size}, indent=2))
        return 0
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({"GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
                "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
                "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
                "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
               "GWRECOMP_EXEC_TRACE_MAX_BYTES": "1048576",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
                "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
                "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30"})
    out_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json"
    err_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-070 one-shot RationalAlloc RET/caller capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", check["runtime_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(ROOT / "evidence/oracle_runs"),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "120", "--growth-text-mibs", "8",
               "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with out_path.open("xb") as stdout, err_path.open("xb") as stderr:
        process = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                 timeout=135, check=False)
    guard = json.loads(out_path.read_text(encoding="utf-8"))
    all_events, target_events = read_trace(TRACE)
    events = [event for event in target_events
              if str(event.get("checkpoint", "")).startswith("RATIONALALLOC_")]
    result = {"schema": "w3-070-rationalalloc-return-capture/v1",
              "classification": "INCONCLUSIVE",
              "preflight": check, "run_id": RUN_ID, "guard_returncode": process.returncode,
              "guard": guard, "trace": {"path": str(TRACE), "bytes": TRACE.stat().st_size if TRACE.exists() else 0,
                                         "sha256": digest(TRACE) if TRACE.exists() else None},
              "rationalalloc_checkpoints": events,
              "checkpoint_count": len(events),
              "trace_event_count": len(all_events),
              "runtime_mapping": runtime_mapping(target_events),
              "limitations": ["AX=0501 entry/return remains sourced from the earlier W3-068 capture; this replay measures a fresh RationalAlloc epilogue and tries to associate its actual RET/caller."]}
    invocation_link = validate_invocation_link(events)
    if invocation_link:
        result["classification"] = "ORIGINAL_OBSERVED"
        result["invocation_link"] = invocation_link
    if TRACE.exists() and TRACE.stat().st_size > 1048576:
        raise ValueError("captured trace exceeded its 1 MiB hard bound")
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "checkpoint_count": len(events), "trace": result["trace"],
                      "guard_exit_reason": guard.get("exit_reason"), "guard_cause": guard.get("cause")}, indent=2))
    return process.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {error}", file=sys.stderr)
        raise SystemExit(2)
