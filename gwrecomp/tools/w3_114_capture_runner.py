#!/usr/bin/env python3
"""One bounded guarded replay for the corrected W3-114 target order."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import parse_trace_jsonl, sha, verify_sandbox
from tools.w3_111_playintro_return_capture import TARGETS, parse_target_events, source_coverage, summarize
from tools.w3_113_playintro_dynrec_coverage import build_evidence as build_coverage

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
TRACE = MOUNT / "W3_114_PLAYINTRO_ORDER_20261009_01.jsonl"
RUN_ID = "w3-114-playintro-order-20261009-01"
RESULT = ROOT / "evidence/w3_114_playintro_target_order.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
MAX_TRACE = 1_048_576


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    guard_record = evidence_dir / f"oracle_runs_{RUN_ID}.json"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr, guard_record)):
        raise FileExistsError("refusing to overwrite W3-114 capture artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config/CUE identity mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8"):
        raise RuntimeError("CUE mount is not read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned source revision mismatch: {revision}")
    window = build_coverage()["updated_window"]
    if not window["entry_in_one_cycle_window"] or not window["all_targets_covered"]:
        raise RuntimeError("PlayIntro probe window preflight failed")
    if not all(item["observable"] for item in source_coverage(CORE.read_text(encoding="utf-8")).values()):
        raise RuntimeError("one or more target addresses lack callback coverage")
    runtime_hash = sha(DOSBOX)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-114 PlaySmacker target-order capture", "--commit-sha", REVISION,
               "--target-sha", GW_SHA256, "--runtime-sha", runtime_hash, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE:
        raise RuntimeError("trace size cap exceeded")
    rows = parse_trace_jsonl(raw)
    events = parse_target_events(rows)
    if len(events) > 12:
        raise RuntimeError("target event cap exceeded")
    seen = [row.get("link_va") for row in events]
    order = [0x92983, 0x92A11, 0x9FEAF, 0x962FC, 0x962FF, 0x92A16,
             0x92A24, 0x92ADD, 0x92996, 0x929A9, 0x929C8, 0x94347]
    observed_order = all(a in seen and b in seen and seen.index(a) < seen.index(b)
                         for a, b in zip(order, order[1:]))
    first_missing = next((link for link in order if link not in seen), None)
    result = {
        "schema": "w3-114-playintro-target-order/v1",
        "task": "W3-114",
        "run_id": RUN_ID,
        "target_sha256": GW_SHA256,
        "source": {"revision": revision, "core_sha256": sha(CORE), "runtime_sha256": runtime_hash},
        "preflight": {"sandbox": sandbox, "fixture_sha256": sha(FIXTURE), "config_sha256": sha(CONFIG),
                      "cue_sha256": sha(CUE), "cue_read_only": True, "playintro_window": window,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE, "event_cap": 12},
        "guard": {key: guard.get(key) for key in (
            "sandbox_verified", "sandbox_capacity", "host_free_before", "host_free_after", "limits",
            "exit_reason", "cause", "detail", "duration_s", "killed_processes", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "raw_event_count": len(rows), "target_events": events,
                  "target_summary": summarize(events), "observed_order": [f"0x{x:08X}" for x in seen],
                  "required_order": [f"0x{x:08X}" for x in order]},
        "capture": {"required_order_complete": observed_order,
                    "first_missing_target": None if first_missing is None else f"0x{first_missing:08X}",
                    "dynamic_last_eip_at_timeout": None, "menu_or_presented_frame_claimed": False},
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "events": len(events),
                      "first_missing": result["capture"]["first_missing_target"],
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
