#!/usr/bin/env python3
"""One guarded, bounded original caller capture for W3-081."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_081_original_ah44_caller import summarize

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
TRACE = MOUNT / "W3_081_AH44_CALLER_20261008_01.jsonl"
RUN_ID = "w3-081-original-ah44-caller-20261008-01"
RESULT = ROOT / "evidence/w3_081_original_ah44_caller.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sandbox() -> dict:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode:
        raise RuntimeError(f"GWORACLE verification failed: {proc.stderr[-1000:]}")
    result = json.loads(proc.stdout)
    if result.get("verified") is not True or result.get("volume", result.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {result}")
    return result


def preflight() -> dict:
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-081 evidence")
    fixture_bytes, fixture_hash = FIXTURE.stat().st_size, sha256(FIXTURE)
    config_hash = sha256(CONFIG)
    if (fixture_bytes, fixture_hash) != (GW_SIZE, GW_SHA256):
        raise ValueError(f"GW.EXE mismatch: {fixture_bytes}, {fixture_hash}")
    if config_hash != CONFIG_SHA256:
        raise ValueError(f"functional config mismatch: {config_hash}")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10,
                              check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging revision mismatch: {revision}")
    if not MOUNT.is_dir() or not str(TRACE).startswith(str(MOUNT) + os.sep):
        raise ValueError("trace is not contained by the verified VHDX mount")
    return {"sandbox": sandbox, "fixture": str(FIXTURE), "fixture_bytes": fixture_bytes,
            "fixture_sha256": fixture_hash, "config": str(CONFIG),
            "config_sha256": config_hash, "dosbox": str(DOSBOX),
            "dosbox_sha256": sha256(DOSBOX), "staging_revision": revision,
            "trace": str(TRACE), "trace_max_bytes": 1_048_576,
            "timeout_seconds": 120,
            "configured_autoexec": ["mount C: GWORACLE", "imgmount D: original CUE read-only",
                                    "C:", "CD \\GENEWARS", "GENEWARS.EXE (no launcher tail)",
                                    "D:", "DIR"],
            "prior_effective_child_argv": ["C:\\GENEWARS\\GW.EXE", "-k", "38928"],
            "prior_psp_tail": " -k 38928"}


def read_trace(path: Path) -> list[dict]:
    events = []
    if not path.is_file():
        return events
    if path.stat().st_size > 1_048_576:
        raise ValueError("trace exceeded its 1 MiB cap")
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
    return events


def main() -> int:
    pre = preflight()
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
    if env["GWRECOMP_GW_FILE_SIZE"] != "1251658":
        raise ValueError("GWRECOMP_GW_FILE_SIZE mismatch")
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr_path = evidence_dir / f"{RUN_ID}.stderr.txt"
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT),
               "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-081 original AH=4400 stream caller capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", pre["dosbox_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "120",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout,
                              stderr=stderr, timeout=135, check=False)
    guard = json.loads(stdout_path.read_text(encoding="utf-8"))
    events = read_trace(TRACE)
    summary = summarize(events)
    trace_meta = {"exists": TRACE.is_file(),
                  "bytes": TRACE.stat().st_size if TRACE.exists() else 0,
                  "sha256": sha256(TRACE) if TRACE.exists() else None}
    result = {
        "schema": "w3-081-original-ah44-stream-caller/v1",
        "task": "W3-081",
        "classification": summary["classification"],
        "preflight": pre,
        "run_id": RUN_ID,
        "guard_returncode": proc.returncode,
        "guard": guard,
        "trace": trace_meta,
        "execution_provenance": {
            "launcher": "GENEWARS.EXE from C:\\GENEWARS, no launcher tail, as configured",
            "measured_prior_main_argv": ["C:\\GENEWARS\\GW.EXE", "-k", "38928"],
            "measured_prior_psp_tail": " -k 38928",
            "current_replay_values": summary["effective_child_argv"],
            "current_replay_psp_tail": summary["psp_command_tail"],
            "cwd": "GENEWARS per configured CD; runtime callback field is checked separately",
        },
        **summary,
        "event_count": len(events),
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "guard_exit_reason": guard.get("exit_reason"),
                      "trace": trace_meta,
                      "main_mapping": summary["main_mapping"],
                      "target_checkpoints": [e.get("checkpoint") for e in summary["target_checkpoints"]],
                      "last_checkpoint": summary["last_target_checkpoint"].get("checkpoint")
                      if summary["last_target_checkpoint"] else None}, indent=2))
    return proc.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
