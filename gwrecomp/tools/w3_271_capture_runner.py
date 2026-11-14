#!/usr/bin/env python3
"""One bounded, oracle_guard-only replay through the natural media return."""
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
from tools.w3_266_capture_runner import (
    CONFIG, CONFIG_SHA256, CUE, CUE_SHA256, DOSBOX as _DOSBOX, EVIDENCE_DIR,
    FIXTURE, GW_SHA256, GW_SIZE, MOUNT, REVISION, STAGING,
)
from tools.w3_267_viewport_hash import analyze_rows as analyze_viewport
from tools.w3_269_post_present_checkpoint import (
    MAX_TARGET_EVENTS as PREVIOUS_TARGET_CAP,
    validate_trace as validate_present_trace,
)
from tools.w3_271_after_media_frontier import (
    MAX_TRACE_BYTES, MAX_TRACE_ROWS, analyze_rows, parse_bounded_jsonl,
)

DOSBOX = ROOT / "build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
RUN_ID = "w3-271-after-media-frontier-20261009-01"
TRACE = MOUNT / "W3_271_AFTER_MEDIA_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_271_after_media_frontier.json"
STDOUT = EVIDENCE_DIR / f"{RUN_ID}.stdout.json"
STDERR = EVIDENCE_DIR / f"{RUN_ID}.stderr.txt"
TARGET_SHA256 = GW_SHA256
SOURCE_FILES = (
    "src/cpu/core_dyn_x86.cpp",
    "src/gui/render/opengl_renderer.cpp",
    "src/dos/exec_trace.h",
    "src/dos/dos_files.cpp",
)


def compact(row: dict) -> dict:
    keys = (
        "sequence", "event", "run_id", "process_psp", "psp", "cs", "eip",
        "runtime_linear", "code_rebase", "link_va", "target_ordinal",
        "marker_consumption_ordinal", "mapping_matches", "target_seen",
        "current_link_va", "target_link_va", "before_link_va", "after_link_va",
        "ordinal", "normal_core_return", "fnv1a64", "nonzero_pixels",
        "sample_width_px", "sample_height_px", "full_visible_viewport_covered",
    )
    out = {key: row[key] for key in keys if key in row}
    for key in ("link_va", "current_link_va", "target_link_va",
                "before_link_va", "after_link_va"):
        if isinstance(out.get(key), int):
            out[key] = f"0x{out[key]:08X}"
    return out


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if any(path.exists() for path in (TRACE, RESULT, STDOUT, STDERR)):
        raise FileExistsError("refusing to overwrite W3-271 run artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE identity mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
        raise RuntimeError("functional CD mount is not read-only")
    revision = subprocess.run(
        ["git", "-C", str(STAGING), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned source revision mismatch: {revision}")

    source_hashes = {rel: sha(STAGING / rel) for rel in SOURCE_FILES}
    binary_sha = sha(DOSBOX)
    env = dict(os.environ)
    prefixes = (
        "GWRECOMP_ANCHOR_", "GWRECOMP_EXEC_TRACE_", "GWRECOMP_W3_262_",
        "GWRECOMP_W3_264_", "GWRECOMP_W3_267_", "GWRECOMP_W3_269_",
        "GWRECOMP_W3_271_",
    )
    for key in tuple(env):
        if key.startswith(prefixes):
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
        # The target is post-media control flow; high-volume DOS read/seek
        # records do not answer this question and are suppressed by the source.
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_W3_262_CAPTURE": "1",
        "GWRECOMP_W3_262_TRACE_PATH": str(TRACE),
        "GWRECOMP_W3_262_RUN_ID": RUN_ID,
        "GWRECOMP_W3_267_CAPTURE_VIEWPORT": "1",
        "GWRECOMP_W3_269_CAPTURE": "1",
        "GWRECOMP_W3_269_RUN_ID": RUN_ID,
    })
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, str(GUARD), "run",
        "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:",
        "--run-id", RUN_ID,
        "--operation", "W3-271 one bounded original post-media return capture",
        "--commit-sha", REVISION, "--target-sha", TARGET_SHA256,
        "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(EVIDENCE_DIR),
        "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
        "--max-run-gib", "1", "--host-floor-gib", "100",
        "--timeout-s", "120", "--growth-text-mibs", "8",
        "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    with STDOUT.open("xb") as out, STDERR.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=130, check=False)
    guard = json.loads(STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("guard output trace exceeded 1 MiB")
    rows = parse_bounded_jsonl(raw)
    analysis = analyze_rows(rows, len(raw))
    present_analysis = validate_present_trace(raw, rows) if rows else {
        "post_present_order_valid": False,
        "first_guest_checkpoint_seen": False,
    }
    viewport = analyze_viewport(rows) if rows else {
        "same_run_full_frame_verified": False,
    }
    selected_names = {
        "main_mapping", "copy_pre", "copy_post",
        "opengl_backbuffer_pre_swap", "w3_269_post_present_marker_set",
        "backend_present_return", "w3_269_first_guest_checkpoint_after_present",
        "w3_269_game_transition_checkpoint", "W3_167_CACHE_SPAN_HIT",
        "W3_193_ECD40_STEP_RESULT", "W3_198_ECD40_CONTINUATION_STEP",
        "W3_198_ECD40_CONTINUATION_STOP",
    }
    selected = [compact(row) for row in rows if row.get("event") in selected_names]
    result = {
        "schema": "w3-271-after-media-frontier/v1",
        "task": "W3-271",
        "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if analysis["main_mapping_seen"] else "INCONCLUSIVE",
        "provenance": {
            "target_sha256": TARGET_SHA256,
            "fixture_bytes": FIXTURE.stat().st_size,
            "config_sha256": sha(CONFIG),
            "cue_sha256": sha(CUE),
            "cue_read_only": True,
            "staging_source_revision": revision,
            "source_sha256": source_hashes,
            "instrumented_binary": str(DOSBOX.relative_to(ROOT)),
            "instrumented_binary_sha256": binary_sha,
        },
        "preflight": {
            "sandbox": sandbox, "timeout_seconds": 120,
            "trace_cap_bytes": MAX_TRACE_BYTES,
            "trace_row_cap": MAX_TRACE_ROWS,
            "target_event_cap": 16,
            "high_volume_file_io_suppressed": True,
            "global_trace": False, "bulk_memdump": False,
            "guest_modified": False,
        },
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity",
            "host_free_before", "host_free_after", "limits", "exit_reason",
            "cause", "detail", "exit_code", "killed_processes", "duration_s",
            "evidence_path", "ok",
        )},
        "trace": {
            "path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "event_count": len(rows), "selected_events": selected,
        },
        "analysis": {
            **analysis,
            "post_present_validation": present_analysis,
            "same_run_full_frame_verified": viewport.get("same_run_full_frame_verified", False),
            "event_limit": MAX_TRACE_ROWS,
        },
        "scope": {
            "original_replays_this_task": 1,
            "menu_verified": False, "gameplay_verified": False,
            "classification": (
                "POST_MEDIA_RETURN_REACHED" if analysis["post_media_return_seen"] else
                "INCONCLUSIVE_BEFORE_POST_MEDIA_RETURN"
            ),
        },
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": str(RESULT), "analysis": result["analysis"],
        "guard_cause": guard.get("cause"),
        "event_count": len(rows), "trace_bytes": len(raw),
    }, indent=2))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-271 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
