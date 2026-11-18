#!/usr/bin/env python3
"""Single protected original replay for the post-present guest checkpoint."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_269_post_present_checkpoint import (
    MAX_TRACE_BYTES, MAX_TRACE_EVENTS, parse_bounded_trace,
)
from tools.w3_266_capture_runner import (
    CONFIG, CONFIG_SHA256, CUE, CUE_SHA256, DOSBOX, EVIDENCE_DIR, FIXTURE,
    GUARD, GW_SHA256, GW_SIZE, MOUNT, REVISION, STAGING,
)
from tools.w3_267_viewport_hash import analyze_rows
from tools.w3_269_post_present_checkpoint import MAX_TARGET_EVENTS, validate_trace

RUN_ID = "w3-269-post-present-checkpoint-20261009-01"
TRACE = MOUNT / "W3_269_POST_PRESENT_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_269_post_present_checkpoint.json"
STDOUT = EVIDENCE_DIR / f"{RUN_ID}.stdout.json"
STDERR = EVIDENCE_DIR / f"{RUN_ID}.stderr.txt"
DOSBOX = ROOT / "build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe"
SOURCE_FILES = (
    "src/cpu/core_dyn_x86.cpp",
    "src/gui/render/opengl_renderer.cpp",
    "src/dos/exec_trace.h",
)


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if any(path.exists() for path in (TRACE, RESULT, STDOUT, STDERR)):
        raise FileExistsError("refusing to overwrite W3-269 run artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE identity mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
        raise RuntimeError("functional CD mount is not read-only")
    revision = subprocess.run(["git", "-C", str(STAGING), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned source revision mismatch: {revision}")

    source_hashes = {rel: sha(STAGING / rel) for rel in SOURCE_FILES}
    binary_sha = sha(DOSBOX)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
        if key.startswith("GWRECOMP_W3_262_") or key.startswith("GWRECOMP_W3_264_") or \
                key.startswith("GWRECOMP_W3_267_") or key.startswith("GWRECOMP_W3_269_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
        "GWRECOMP_W3_262_CAPTURE": "1",
        "GWRECOMP_W3_262_TRACE_PATH": str(TRACE),
        "GWRECOMP_W3_262_RUN_ID": RUN_ID,
        "GWRECOMP_W3_267_CAPTURE_VIEWPORT": "1",
        "GWRECOMP_W3_269_CAPTURE": "1",
        "GWRECOMP_W3_269_RUN_ID": RUN_ID,
    })
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-269 one bounded present-to-next-guest checkpoint",
        "--commit-sha", REVISION, "--target-sha", GW_SHA256,
        "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(EVIDENCE_DIR),
        "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
        "--host-floor-gib", "100", "--timeout-s", "45", "--growth-text-mibs", "8",
        "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    with STDOUT.open("xb") as out, STDERR.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=55, check=False)
    guard = json.loads(STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("guard output trace exceeded 1 MiB")
    rows = parse_bounded_trace(raw)
    analysis = validate_trace(raw, rows)
    viewport_analysis = analyze_rows(rows) if rows else {"same_run_full_frame_verified": False}
    result = {
        "schema": "w3-269-post-present-guest-checkpoint/v1",
        "task": "W3-269",
        "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if analysis["first_guest_checkpoint_seen"] else "INCONCLUSIVE",
        "provenance": {
            "target_sha256": GW_SHA256,
            "fixture_bytes": FIXTURE.stat().st_size,
            "config_sha256": sha(CONFIG),
            "cue_sha256": sha(CUE),
            "staging_source_revision": revision,
            "source_sha256": source_hashes,
            "instrumented_binary": str(DOSBOX.relative_to(ROOT)),
            "instrumented_binary_sha256": binary_sha,
            "prior_viewport_evidence": "evidence/w3_267_viewport_hash.json",
        },
        "preflight": {
            "sandbox": sandbox,
            "cue_read_only": True,
            "timeout_seconds": 45,
            "target_event_cap": MAX_TARGET_EVENTS,
            "trace_cap_bytes": MAX_TRACE_BYTES,
            "global_trace": False,
            "bulk_memdump": False,
        },
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
            "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
            "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {
            "path": str(TRACE.relative_to(ROOT)),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "event_count": len(rows),
            "events": rows,
        },
        "analysis": {
            **analysis,
            "same_run_full_frame_verified": viewport_analysis.get("same_run_full_frame_verified", False),
            "main_mapping_events": [r for r in rows if r.get("event") == "main_mapping"],
            "playintro_game_transition_events": [r for r in rows if r.get("event") == "w3_269_game_transition_checkpoint"],
        },
        "scope": {
            "original_replays_this_task": 1,
            "all_dosbox_via_oracle_guard": True,
            "guest_modified": False,
            "menu_verified": False,
            "gameplay_verified": False,
        },
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "analysis": result["analysis"],
                      "guard_cause": guard.get("cause"), "event_count": len(rows),
                      "trace_bytes": len(raw)}, indent=2))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-269 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
