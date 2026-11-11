#!/usr/bin/env python3
"""One guarded W3-266 replay for full bounded renderer input and viewport."""
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
from tools.w3_264_opengl_frame_capture import MAX_EVENTS, MAX_TRACE_BYTES, parse_trace
from tools.w3_266_full_frame_capture import validate_same_present

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
STAGING = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
DOSBOX = ROOT / "build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
TRACE = MOUNT / "W3_266_FULL_FRAME_20261009_01.jsonl"
RUN_ID = "w3-266-full-frame-20261009-01"
RESULT = ROOT / "evidence/w3_266_full_frame_capture.json"
EVIDENCE_DIR = ROOT / "evidence/oracle_runs"
STDOUT = EVIDENCE_DIR / f"{RUN_ID}.stdout.json"
STDERR = EVIDENCE_DIR / f"{RUN_ID}.stderr.txt"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD):
        if not path.is_file():
            raise FileNotFoundError(path)
    if any(path.exists() for path in (TRACE, RESULT, STDOUT, STDERR)):
        raise FileExistsError("refusing to overwrite W3-266 artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or CUE identity mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
        raise RuntimeError("functional CD mount is not marked read-only")
    revision = subprocess.run(["git", "-C", str(STAGING), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned revision mismatch: {revision}")
    binary_sha = sha(DOSBOX)
    source_files = ("src/cpu/core_dyn_x86.cpp", "src/hardware/video/vga_memory.cpp",
                    "src/gui/render/opengl_renderer.cpp", "src/gui/sdl_gui.cpp")
    source_hashes = {rel: sha(STAGING / rel) for rel in source_files}
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
        if key.startswith("GWRECOMP_W3_262_") or key.startswith("GWRECOMP_W3_264_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
        "GWRECOMP_W3_262_CAPTURE": "1",
        "GWRECOMP_W3_262_TRACE_PATH": str(TRACE),
        "GWRECOMP_W3_262_RUN_ID": RUN_ID,
        "GWRECOMP_W3_264_CAPTURE_OPENGL": "1",
    })
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-266 one copy-armed full renderer-input capture",
        "--commit-sha", REVISION, "--target-sha", GW_SHA256, "--runtime-sha", binary_sha,
        "--fixture-sha", GW_SHA256, "--evidence-dir", str(EVIDENCE_DIR),
        "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
        "--host-floor-gib", "100", "--timeout-s", "45", "--growth-text-mibs", "8",
        "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    with STDOUT.open("xb") as out, STDERR.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=55, check=False)
    guard = json.loads(STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_trace(raw)
    analysis = validate_same_present(rows)
    result = {
        "schema": "w3-266-full-renderer-input-and-viewport/v1", "task": "W3-266",
        "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if rows else "INCONCLUSIVE",
        "provenance": {"fixture_bytes": FIXTURE.stat().st_size, "target_sha256": GW_SHA256,
                       "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                       "staging_source_revision": revision,
                       "instrumented_binary": str(DOSBOX.relative_to(ROOT)),
                       "instrumented_binary_sha256": binary_sha,
                       "instrumented_source_sha256": source_hashes},
        "preflight": {"sandbox": sandbox, "timeout_seconds": 45,
                      "event_cap": MAX_EVENTS, "trace_cap_bytes": MAX_TRACE_BYTES,
                      "renderer_input_cap_bytes": 1_048_576,
                      "generic_trace": False, "global_trace": False, "memdump": False},
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
            "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
            "killed_processes", "duration_s", "evidence_path", "ok")},
        "guard_files": {"stdout": str(STDOUT.relative_to(ROOT)), "stdout_sha256": sha(STDOUT),
                        "stderr": str(STDERR.relative_to(ROOT)), "stderr_bytes": STDERR.stat().st_size},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows), "events": rows},
        "analysis": analysis,
        "scope": {"original_replays_this_task": 1, "all_dosbox_via_guard": True,
                  "fixture_or_cue_modified": False, "desktop_screenshot_proven": False},
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "analysis": analysis,
                      "guard_cause": guard.get("cause"), "events": len(rows), "bytes": len(raw)}, indent=2))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-266 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
