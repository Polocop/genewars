#!/usr/bin/env python3
"""One bounded, guarded original Staging capture for setup_game and DOS file I/O."""
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
TRACE = MOUNT / "W3_SETUP_ORIGINAL_20261008_01.jsonl"
RESULT = ROOT / "evidence/w3_setup_original_capture_20261008.json"
RUN_ID = "w3-setup-original-20261008-01"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sandbox() -> dict:
    p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
                       cwd=ROOT, capture_output=True, text=True, timeout=30)
    if p.returncode:
        raise RuntimeError(f"sandbox verification failed: {p.stderr[-1200:]}")
    data = json.loads(p.stdout)
    if data.get("verified") is not True or data.get("label", data.get("volume")) != "GWORACLE":
        raise RuntimeError(f"sandbox is not the verified GWORACLE VHDX: {data}")
    return data


def make_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(1024 * 1024),
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    if env["GWRECOMP_GW_FILE_SIZE"] != "1251658":
        raise ValueError("GWRECOMP_GW_FILE_SIZE must equal 1251658")
    return env


def preflight() -> dict:
    sandbox = verify_sandbox()
    for p in (FIXTURE, CONFIG, DOSBOX, GUARD):
        if not p.is_file():
            raise FileNotFoundError(f"required file missing: {p}")
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite prior capture evidence")
    fixture_size = FIXTURE.stat().st_size
    fixture_hash = sha256(FIXTURE)
    config_hash = sha256(CONFIG)
    if fixture_size != GW_SIZE or fixture_hash != GW_SHA256:
        raise ValueError(f"GW.EXE mismatch: bytes={fixture_size}, sha256={fixture_hash}")
    if config_hash != CONFIG_SHA256:
        raise ValueError(f"functional config hash mismatch: {config_hash}")
    rev = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                         cwd=ROOT, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if rev != REVISION:
        raise ValueError(f"Staging revision mismatch: {rev}")
    # Bind execution to the already-created, verified VHDX mount; never create a plain fallback.
    if not MOUNT.is_dir() or not str(TRACE).startswith(str(MOUNT) + os.sep):
        raise ValueError("VHDX mount or trace containment path is invalid")
    env = make_env()
    return {"sandbox": sandbox, "fixture_bytes": fixture_size, "fixture_sha256": fixture_hash,
            "config_sha256": config_hash, "runtime_sha256": sha256(DOSBOX),
            "source_revision": rev, "GWRECOMP_GW_FILE_SIZE": env["GWRECOMP_GW_FILE_SIZE"],
            "trace_path": str(TRACE), "trace_limit_bytes": 1048576}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    check = preflight()
    if args.preflight_only:
        print(json.dumps(check, indent=2))
        return 0
    env = make_env()
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
               "--run-id", RUN_ID, "--operation", "W3 focused setup_game and DOS file capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", check["runtime_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(ROOT / "evidence/oracle_runs"),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "120",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    out_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json"
    err_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("xb") as out, err_path.open("xb") as err:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                              timeout=135, check=False)
    guard = json.loads(out_path.read_text(encoding="utf-8"))
    trace_info = {"exists": TRACE.is_file(),
                  "bytes": TRACE.stat().st_size if TRACE.exists() else 0,
                  "sha256": sha256(TRACE) if TRACE.exists() else None}
    result = {"schema": "w3-setup-original-capture/v1", "preflight": check,
              "run_id": RUN_ID, "guard_returncode": proc.returncode,
              "guard": guard, "trace": trace_info,
              "instrumentation": {"setup_entry_link_va": "0x94AC0",
                                  "first_callee_link_va": "0x14BF0",
                                  "dos_api_filter": "enabled at setup_game entry; max 128 events",
                                  "global_trace": False}}
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "guard_exit_reason": guard.get("exit_reason"),
                      "guard_cause": guard.get("cause"), **trace_info}, indent=2))
    return proc.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
