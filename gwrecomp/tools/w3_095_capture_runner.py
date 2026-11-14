#!/usr/bin/env python3
"""Single guarded W3-095 PSP-tail observation at original AX=4400/BX=1."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_091_ah4400_bx1_caller import parse_trace

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
TRACE = MOUNT / "W3_095_ORIGINAL_PSP_TAIL_20261009_01.jsonl"
RUN_ID = "w3-095-original-psp-tail-20261009-01"
RESULT = ROOT / "evidence/w3_095_original_psp_tail.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
MAX_BYTES = 1_048_576
HOST_FLOOR = 100 * 1024**3


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sandbox() -> dict:
    done = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                           "-File", str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
                          cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if done.returncode:
        raise RuntimeError(f"GWORACLE verification failed: {done.stderr[-1000:]}")
    data = json.loads(done.stdout)
    if data.get("verified") is not True or data.get("volume", data.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {data}")
    if int(data.get("host_free_bytes", 0)) < HOST_FLOOR:
        raise RuntimeError("host free-space floor failed")
    return data


def main() -> int:
    sandbox = verify_sandbox()
    for p in (FIXTURE, CONFIG, DOSBOX, GUARD):
        if not p.is_file():
            raise FileNotFoundError(p)
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-095 artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha256(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE fixture identity mismatch")
    if sha256(CONFIG) != CONFIG_SHA256:
        raise RuntimeError("functional W3-067 config identity mismatch")
    rev = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                         capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if rev != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {rev}")
    binary_hash = sha256(DOSBOX)
    trace_path = str(TRACE)
    if not MOUNT.is_dir() or not trace_path.startswith(str(MOUNT) + os.sep):
        raise RuntimeError("trace path is outside verified VHDX mount")
    preflight = {
        "sandbox": sandbox, "fixture": str(FIXTURE), "fixture_bytes": FIXTURE.stat().st_size,
        "fixture_sha256": GW_SHA256, "config": str(CONFIG), "config_sha256": CONFIG_SHA256,
        "staging_executable": str(DOSBOX), "staging_sha256": binary_hash,
        "source_revision": rev, "trace": trace_path, "trace_cap_bytes": MAX_BYTES,
        "timeout_seconds": 30, "launch_config": "verified W3-067 functional config; GENEWARS.EXE",
    }
    env = dict(os.environ)
    for k in tuple(env):
        if k.startswith("GWRECOMP_ANCHOR_") or k.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(k, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": trace_path,
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_BYTES),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    run_evidence = ROOT / "evidence/oracle_runs"
    run_evidence.mkdir(parents=True, exist_ok=True)
    stdout_path = run_evidence / f"{RUN_ID}.stdout.json"
    stderr_path = run_evidence / f"{RUN_ID}.stderr.txt"
    if stdout_path.exists() or stderr_path.exists():
        raise FileExistsError("refusing to overwrite guard logs")
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-095 bounded active PSP tail at original AX=4400/BX=1",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", binary_hash, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(run_evidence), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                              timeout=40, check=False)
    guard = json.loads(stdout_path.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.is_file() else b""
    if len(raw) > MAX_BYTES:
        raise RuntimeError(f"trace exceeded cap: {len(raw)}")
    events = parse_trace(raw)
    event = next((e for e in events if e.get("event") == "w3_095_original_psp_tail"), None)
    result = {
        "schema": "w3-095-original-psp-tail/v1", "task": "W3-095", "run_id": RUN_ID,
        "preflight": preflight, "guard_returncode": proc.returncode, "guard": guard,
        "trace": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                   "raw_event_count": sum(bool(x.strip()) for x in raw.splitlines()),
                   "filtered_event_count": len(events)},
        "capture": {"classification": "ORIGINAL_PSP_TAIL_CAPTURED" if event and event.get("tail_sample_valid") else
                                      "INCONCLUSIVE_NO_VALID_PSP_TAIL",
                    "event": event},
        "limitations": ["PSP tail does not establish full startup CPU or memory seed parity.",
                        "Configured AUTOEXEC text is not substituted for the measured PSP bytes."],
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["capture"]["classification"],
                      "tail_status": event.get("tail_status") if event else None,
                      "tail_length": event.get("tail_length") if event else None,
                      "guard_cause": guard.get("cause"), "trace_bytes": len(raw)}, indent=2))
    return 0 if event and event.get("tail_sample_valid") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
