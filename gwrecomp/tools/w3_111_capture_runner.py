#!/usr/bin/env python3
"""One bounded Staging original replay through oracle_guard for W3-111."""
from __future__ import annotations

import hashlib
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import parse_trace_jsonl, sha, verify_sandbox
from tools.w3_111_playintro_return_capture import TARGETS, parse_target_events, source_coverage, summarize

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
TRACE = MOUNT / "W3_111_PLAYINTRO_RETURN_20261009_01.jsonl"
RUN_ID = "w3-111-playintro-return-20261009-01"
RESULT = ROOT / "evidence/w3_111_playintro_return_capture.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
MAX_TRACE = 1_048_576


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--postprocess-existing",
        action="store_true",
        help="parse the already completed guarded run without launching DOSBox again",
    )
    args = parser.parse_args()
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-111 result evidence")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic W3-067 fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config/CUE identity mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8"):
        raise RuntimeError("original CUE mount is not read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    source_map = source_coverage(CORE.read_text(encoding="utf-8"))
    if not all(entry["observable"] for entry in source_map.values()):
        raise RuntimeError("one or more target addresses lack source-verified callback and one-cycle coverage")
    binary_hash = sha(DOSBOX)
    preflight = {
        "sandbox": sandbox,
        "fixture_sha256": GW_SHA256,
        "config_sha256": CONFIG_SHA256,
        "cue_sha256": CUE_SHA256,
        "cue_mount_read_only": True,
        "staging_revision": revision,
        "core_source_sha256": sha(CORE),
        "dosbox_sha256": binary_hash,
        "trace_cap_bytes": MAX_TRACE,
        "target_event_cap": 12,
        "timeout_seconds": 30,
        "target_coverage": {f"0x{address:08X}": value for address, value in source_map.items()},
        "command_tail": "not injected; original GENEWARS.EXE launch from verified functional config",
    }
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
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    guard_record = evidence_dir / f"oracle_runs_{RUN_ID}.json"
    existing_outputs = [stdout, stderr, guard_record, TRACE]
    if args.postprocess_existing:
        if not all(path.is_file() for path in existing_outputs):
            raise FileNotFoundError("postprocess requested but guarded-run artifacts are incomplete")
    else:
        if TRACE.exists() or any(path.exists() for path in (stdout, stderr, guard_record)):
            raise FileExistsError("refusing to overwrite W3-111/oracle evidence; use postprocess-only for an existing run")
        command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
                   "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
                   "--operation", "W3-111 targeted PlaySmacker return capture", "--commit-sha", REVISION,
                   "--target-sha", GW_SHA256, "--runtime-sha", binary_hash, "--fixture-sha", GW_SHA256,
                   "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
                   "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
                   "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
        with stdout.open("xb") as out, stderr.open("xb") as err:
            subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE:
        raise RuntimeError(f"trace exceeds cap: {len(raw)}")
    rows = parse_trace_jsonl(raw)
    events = parse_target_events(rows)
    if len(events) > 12:
        raise RuntimeError("W3-111 target event cap exceeded")
    previous = [row for row in rows if row.get("w3_107_targeted_main_transition") is True]
    previous_links = {row.get("link_va") for row in previous}
    links = {row.get("link_va") for row in events}
    if 0x9FDF9 not in previous_links:
        classification = "MODE_CONTINUATION_NOT_OBSERVED"
    elif 0x9FEAF not in links:
        classification = "NEXT_TARGET_AFTER_9FDF9_NOT_OBSERVED"
    elif 0x92A16 not in links:
        classification = "SCREEN_SETUP_WRAPPER_RETURN_NOT_OBSERVED"
    elif 0x92ADD not in links:
        classification = "PLAYSMACKER_MEDIA_CALL_NOT_OBSERVED"
    elif 0x929C8 not in links:
        classification = "PLAYINTRO_RETURN_NOT_OBSERVED"
    elif 0x94347 not in links:
        classification = "MAIN_GAME_CALL_NOT_OBSERVED"
    else:
        classification = "MAIN_GAME_CALL_REACHED"
    result = {
        "schema": "w3-111-playintro-return-capture/v1",
        "task": "W3-111",
        "run_id": RUN_ID,
        "preflight": preflight,
        "guard": {key: guard.get(key) for key in (
            "sandbox_verified", "sandbox_capacity", "host_free_before", "host_free_after", "limits",
            "exit_reason", "cause", "detail", "duration_s", "killed_processes", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "raw_event_count": len(rows), "target_events": events,
                  "target_summary": summarize(events),
                  "w3_107_prior_links": [f"0x{x:08X}" for x in sorted(x for x in previous_links if isinstance(x, int))]},
        "capture": {"classification": classification,
                    "missing_targets": [f"0x{x:08X}" for x in sorted(set(TARGETS) - links)],
                    "same_run_mapping_consistent": summarize(events)["mapping_consistent"],
                    "dynamic_last_eip_at_timeout": None,
                    "page_mapping_or_framebuffer_claimed": False},
        "scope": {"oracle_guard_used": True, "original_replay_count": 1,
                  "global_instruction_trace": False, "bulk_memory_dump": False,
                  "guest_or_fixture_modified": False, "source_install_modified": False},
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": classification,
                      "target_events": len(events), "guard_cause": guard.get("cause")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
