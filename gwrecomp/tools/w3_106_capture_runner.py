#!/usr/bin/env python3
"""Run at most one bounded original W3-106 replay via oracle_guard."""
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
from tools.w3_106_draw_page_capture import parse_target_events, sequence_matches, validate_mapping

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT / ".." / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
TRACE = MOUNT / "W3_106_GAME_PAGE_20261009_01.jsonl"
RUN_ID = "w3-106-game-page-20261009-01"
RESULT = ROOT / "evidence/w3_106_draw_page_capture.json"
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
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-106 artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256:
        raise RuntimeError("functional W3-067 config identity mismatch")
    if sha(CUE) != CUE_SHA256 or "-ro" not in CONFIG.read_text(encoding="utf-8"):
        raise RuntimeError("original CUE identity or read-only mount check failed")
    revision = subprocess.run(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], capture_output=True,
        text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")

    binary_hash = sha(DOSBOX)
    preflight = {
        "sandbox": sandbox, "fixture_bytes": FIXTURE.stat().st_size,
        "fixture_sha256": GW_SHA256, "config_sha256": CONFIG_SHA256,
        "cue_path": str(CUE), "cue_sha256": CUE_SHA256, "cue_mount_read_only": True,
        "staging_sha256": binary_hash, "source_revision": revision,
        "core_source_sha256": sha(CORE), "trace_cap_bytes": MAX_TRACE,
        "timeout_seconds": 30, "python": sys.executable,
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
    if stdout.exists() or stderr.exists():
        raise FileExistsError("refusing to overwrite guard output")
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-106 natural game-to-page checkpoints", "--commit-sha", REVISION,
        "--target-sha", GW_SHA256, "--runtime-sha", binary_hash, "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
        "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "30",
        "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE:
        raise RuntimeError(f"trace exceeds cap: {len(raw)}")
    rows = parse_trace_jsonl(raw)
    target = parse_target_events(rows)
    modes = [row for row in rows if row.get("checkpoint") == "VIDEO_VESA_MODE_CALLSITE"
             and (row.get("eax", 0) & 0xffff) == 0x101 and row.get("edx") == 0x180]
    rebases = []
    for event in modes:
        rebases.append(validate_mapping(event))
    for event in target:
        rebases.append(validate_mapping(event))
    links = [row.get("link_va") for row in target]
    if not links:
        classification = "GAME_ENTRY_NOT_OBSERVED"
    elif not sequence_matches(links):
        classification = "PARTIAL_OR_UNEXPECTED_TARGET_SEQUENCE"
    elif links[-1] == 0xa3ab9:
        classification = "FULL_NATURAL_PAGE_AND_INT10_SEQUENCE"
    else:
        classification = "PARTIAL_NATURAL_CALLER_SEQUENCE"
    result = {
        "schema": "w3-106-draw-page-capture/v1", "task": "W3-106", "run_id": RUN_ID,
        "preflight": preflight,
        "guard": {key: guard.get(key) for key in (
            "sandbox_verified", "sandbox_capacity", "host_free_before", "host_free_after", "limits",
            "exit_reason", "cause", "detail", "duration_s", "killed_processes", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows), "target_event_count": len(target),
                  "target_order": [row.get("checkpoint") for row in target], "target_events": target},
        "capture": {"classification": classification, "mode_call_count": len(modes),
                    "mode_calls": modes, "main_code_rebase": rebases[0] if rebases else None,
                    "runtime_rebases": sorted(set(rebases)),
                    "page_entry_observed": any(row.get("link_va") == 0xa3a5c for row in target),
                    "int10_sites_observed": [hex(row["link_va"]) for row in target
                                             if row.get("link_va") in (0xa3a91, 0xa3a93, 0xa3ab7, 0xa3ab9)],
                    "framebuffer_mapping_or_write_observed": False,
                    "visible_frame_or_menu_observed": False},
        "scope": {"guard_used": True, "new_original_replay_count": 1,
                  "guest_or_fixture_modified": False, "global_trace": False, "bulk_memory_dump": False},
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": classification,
                      "target_order": result["trace"]["target_order"], "guard_cause": guard.get("cause")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
