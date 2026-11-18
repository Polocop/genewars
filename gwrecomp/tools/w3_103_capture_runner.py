#!/usr/bin/env python3
"""One bounded original replay for the W3-103 VESA page/INT10 frontier."""
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

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
TRACE = MOUNT / "W3_103_VESA_PAGE_20261009_01.jsonl"
RUN_ID = "w3-103-vesa-page-20261009-01"
RESULT = ROOT / "evidence/w3_103_vesa_page_capture.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
MAX_TRACE = 1_048_576
HOST_FLOOR = 100 * 1024**3


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-103 artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256:
        raise RuntimeError("functional W3-067 config identity mismatch")
    revision = subprocess.run(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")

    runtime_hash = sha(DOSBOX)
    preflight = {
        "sandbox": sandbox,
        "fixture": str(FIXTURE),
        "fixture_bytes": FIXTURE.stat().st_size,
        "fixture_sha256": GW_SHA256,
        "config": str(CONFIG),
        "config_sha256": CONFIG_SHA256,
        "staging_exe": str(DOSBOX),
        "staging_sha256": runtime_hash,
        "source_revision": revision,
        "core_source_sha256": sha(CORE),
        "trace": str(TRACE),
        "trace_cap_bytes": MAX_TRACE,
        "timeout_seconds": 30,
        "runner_python": sys.executable,
        "explicit_console_python": True,
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
    stdout_path = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr_path = evidence_dir / f"{RUN_ID}.stderr.txt"
    if stdout_path.exists() or stderr_path.exists():
        raise FileExistsError("refusing to overwrite guard output")
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
        "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
        "--run-id", RUN_ID, "--operation", "W3-103 target VESA page and INT10 capture",
        "--commit-sha", REVISION, "--target-sha", GW_SHA256,
        "--runtime-sha", runtime_hash, "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
        "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
        "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
        "--poll-hz", "1",
    ]
    with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=40, check=False)
    guard = json.loads(stdout_path.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE:
        raise RuntimeError(f"trace exceeds cap: {len(raw)}")
    rows = parse_trace_jsonl(raw)
    target = [row for row in rows if row.get("event") == "target_runtime_checkpoint"
              and row.get("w3_103_targeted_page") is True]
    mode_call = next((row for row in rows if row.get("checkpoint") == "VIDEO_VESA_MODE_CALLSITE"
                      and (row.get("eax", 0) & 0xffff) == 0x101 and row.get("edx") == 0x180), None)
    page = next((row for row in target if row.get("link_va") == 0xA3A5C), None)
    int10 = {hex(row["link_va"]): row for row in target if row.get("link_va") in
             (0xA3A91, 0xA3A93, 0xA3AB7, 0xA3AB9)}
    if mode_call is None:
        classification = "TARGET_MODE_CALLSITE_ABSENT"
    elif page is None:
        classification = "MODE_0X101_REACHED_PAGE_ENTRY_ABSENT"
    elif len(int10) == 4:
        classification = "PAGE_AND_BOTH_INT10_PAIRS_CAPTURED"
    else:
        classification = "PAGE_ENTRY_WITH_PARTIAL_INT10_CAPTURE"
    result = {
        "schema": "w3-103-vesa-page-capture/v1",
        "task": "W3-103",
        "run_id": RUN_ID,
        "preflight": preflight,
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity",
            "host_free_before", "host_free_after", "limits", "exit_reason", "cause",
            "detail", "exit_code", "killed_processes", "duration_s", "evidence_path", "ok")},
        "guard_artifacts": {
            "stdout_path": str(stdout_path.relative_to(ROOT)),
            "stdout_bytes": stdout_path.stat().st_size,
            "stdout_sha256": sha(stdout_path),
            "stderr_path": str(stderr_path.relative_to(ROOT)),
            "stderr_bytes": stderr_path.stat().st_size,
        },
        "trace": {
            "path": str(TRACE.relative_to(ROOT)),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "event_count": len(rows),
            "page_target_event_count": len(target),
            "page_target_order": [row.get("checkpoint") for row in target],
            "page_target_events": target,
        },
        "capture": {
            "classification": classification,
            "mode_0x101_edx_0x180_callsite": mode_call,
            "page_function_entry_a3a5c": page,
            "int10_checkpoints": int10,
            "main_code_rebase": (mode_call["eip"] - mode_call["link_va"]) if mode_call else None,
            "page_mapping_observed": False,
            "guest_framebuffer_write_observed": False,
            "visible_frame_observed": False,
            "menu_observed": False,
        },
        "scope": {
            "guard_used": True,
            "new_original_replay_count": 1,
            "guest_executable_modified": False,
            "fixture_or_config_modified": False,
            "source_install_modified": False,
            "global_instruction_trace": False,
            "bulk_memory_dump": False,
            "bios_response_synthesized": False,
        },
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": classification,
                      "target_order": result["trace"]["page_target_order"],
                      "trace_bytes": len(raw), "guard_cause": guard.get("cause"),
                      "guard_exit": guard.get("exit_reason")}, indent=2))
    return 0 if mode_call else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
