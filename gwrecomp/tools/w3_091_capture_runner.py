#!/usr/bin/env python3
"""One guarded, bounded capture of original INT 21h AH=44/BX=1 callers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_091_ah4400_bx1_caller import parse_trace, summarize

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
TRACE = MOUNT / "W3_091_AH4400_BX1_CALLER_20261009_01.jsonl"
RUN_ID = "w3-091-ah4400-bx1-caller-20261009-01"
RESULT = ROOT / "evidence/w3_091_ah4400_bx1_caller.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
MAX_BYTES = 1_048_576
HOST_FLOOR = 100 * 1024**3


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    if result.get("host_free_bytes", 0) < HOST_FLOOR:
        raise RuntimeError(f"host free-space floor failed: {result.get('host_free_bytes')}")
    return result


def preflight() -> dict:
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-091 evidence")
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
    return {
        "sandbox": sandbox, "fixture": str(FIXTURE), "fixture_bytes": fixture_bytes,
        "fixture_sha256": fixture_hash, "config": str(CONFIG), "config_sha256": config_hash,
        "dosbox": str(DOSBOX), "dosbox_sha256": sha256(DOSBOX),
        "staging_revision": revision, "trace": str(TRACE),
        "trace_max_bytes": MAX_BYTES, "cpu_entry_max": 8, "timeout_seconds": 30,
        "configured_launch": [
            "mount C: GWORACLE", "imgmount D: original CUE read-only",
            "C:", "CD \\GENEWARS", "GENEWARS.EXE (no launcher tail)", "D:", "DIR"
        ],
    }


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
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_BYTES),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
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
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-091 targeted original AH=4400/BX=1 caller capture",
        "--commit-sha", REVISION, "--target-sha", GW_SHA256,
        "--runtime-sha", pre["dosbox_sha256"], "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
        "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
        "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
        "--poll-hz", "1",
    ]
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout,
                              stderr=stderr, timeout=40, check=False)
    guard = json.loads(stdout_path.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.is_file() else b""
    events = parse_trace(raw)
    capture = summarize(events)
    result = {
        "schema": "w3-091-ah4400-bx1-caller/v1",
        "task": "W3-091",
        "run_id": RUN_ID,
        "preflight": pre,
        "guard_returncode": proc.returncode,
        "guard": guard,
        "trace": {
            "path": str(TRACE), "exists": TRACE.is_file(), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "raw_event_count": sum(bool(line.strip()) for line in raw.splitlines()),
            "filtered_event_count": len(events),
        },
        "capture": capture,
        "instrumented_runtime_sha256": sha256(DOSBOX),
        "staging_revision": REVISION,
        "scope": {
            "oracle_guard_used": True, "guest_executable_modified": False,
            "config_modified": False, "source_install_modified": False,
            "global_instruction_trace": False, "memory_dump": False,
        },
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": str(RESULT), "classification": capture["classification"],
        "matches_native_link_c8973": capture["matches_native_link_c8973"],
        "guard_exit_reason": guard.get("exit_reason"), "trace": result["trace"],
    }, indent=2))
    return 0 if capture["classification"] == "ORIGINAL_CALLER_AND_RESPONSE_CORRELATED" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
