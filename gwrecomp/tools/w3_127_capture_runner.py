#!/usr/bin/env python3
"""Single bounded oracle-guarded restart coverage diagnostic."""
from __future__ import annotations

import hashlib
import json
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_127_restart_coverage import (
    contract_summary, parse_jsonl, restart_events, source_coverage, summarize,
)

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-127-restart-coverage-20261009-01"
TRACE = MOUNT / "W3_127_RESTART_COVERAGE_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_127_restart_coverage.json"
MAX_TRACE = 1_048_576


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--postprocess-existing", action="store_true")
    args = parser.parse_args()
    if args.postprocess_existing:
        if not TRACE.is_file() or not RESULT.is_file():
            raise FileNotFoundError("existing W3-127 trace and evidence are required")
        raw = TRACE.read_bytes()
        rows = parse_jsonl(raw, MAX_TRACE)
        events = restart_events(rows)
        result = json.loads(RESULT.read_text(encoding="utf-8"))
        summary = contract_summary(events)
        result["trace"]["restart_events"] = events
        result["trace"]["summary"] = summary
        result["capture"] = {"main_mapping_and_callback_gaps_decided": bool(summary["post_anchor_link_vas"]),
                              "allocator_callee_entry_and_return_observed": summary["callee_then_return_observed"],
                              "callsite_restart_observed": summary["callsite_restart_observed"],
                              "menu_or_framebuffer_claimed": False}
        RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": str(RESULT), "postprocessed": True, "summary": summary}, indent=2))
        return 0
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8"):
        raise RuntimeError("original CUE is not mounted read-only")
    source_root = CORE.parents[2]
    revision = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    coverage = source_coverage(CORE.read_text(encoding="utf-8"))
    if not all(coverage.values()):
        raise RuntimeError(f"restart diagnostic source coverage failed: {coverage}")
    prior = ROOT / "evidence/w3_125_lbmemoryalloc_boundary.json"
    prior_trace = ROOT / "build/dosboxx_oracle/C/W3_125_LBMEMORYALLOC_BOUNDARY_20261009_01.jsonl"
    prior_manifest = json.loads(prior.read_text(encoding="utf-8"))
    prior_raw = prior_trace.read_bytes()
    if hashlib.sha256(prior_raw).hexdigest() != prior_manifest["trace"]["sha256"]:
        raise RuntimeError("W3-125 trace hash mismatch")
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    guard_record = evidence_dir / f"oracle_runs_{RUN_ID}.json"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr, guard_record)):
        raise FileExistsError("refusing to overwrite W3-127 artifacts")
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
               "--operation", "W3-127 bounded restart coverage diagnostic", "--commit-sha", REVISION,
               "--target-sha", GW_SHA256, "--runtime-sha", runtime_hash, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_jsonl(raw, MAX_TRACE)
    events = restart_events(rows)
    summary = contract_summary(events)
    result = {
        "schema": "w3-127-restart-coverage/v1", "task": "W3-127", "run_id": RUN_ID,
        "target_sha256": GW_SHA256,
        "prior_w3_125_trace_sha256": hashlib.sha256(prior_raw).hexdigest(),
        "source": {"revision": revision, "core_sha256": sha(CORE), "runtime_sha256": runtime_hash},
        "preflight": {"sandbox": sandbox, "fixture_sha256": sha(FIXTURE),
                      "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                      "cue_read_only": True, "source_coverage": coverage,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE, "diagnostic_event_cap": 16},
        "guard": {key: guard.get(key) for key in (
            "sandbox_verified", "sandbox_capacity", "host_free_before", "host_free_after", "limits",
            "exit_reason", "cause", "detail", "duration_s", "killed_processes", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "raw_event_count": len(rows), "restart_events": events,
                  "summary": summary},
        "capture": {"main_mapping_and_callback_gaps_decided": bool(summary["post_anchor_link_vas"]),
                    "allocator_callee_entry_and_return_observed": summary["callee_then_return_observed"],
                    "callsite_restart_observed": summary["callsite_restart_observed"],
                    "menu_or_framebuffer_claimed": False},
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "summary": summarize(events),
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
