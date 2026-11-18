#!/usr/bin/env python3
"""Single protected W3-289 original replay with compact Smacker instrumentation."""

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
    CONFIG, CONFIG_SHA256, CUE, CUE_SHA256, FIXTURE, GW_SHA256, GW_SIZE,
    REVISION, STAGING, EVIDENCE_DIR,
)
from tools.w3_289_smacker_later_callee_capture import analyze, parse_trace, source_instrumentation_valid, trace_digest

MOUNT = ROOT / "build/dosboxx_oracle/C"
DOSBOX = ROOT / "build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
RUN_ID = "w3-289-smacker-later-callee-20261010-01"
TRACE = MOUNT / "W3_289_SMACKER_LATER_CALLEE_20261010_01.jsonl"
RESULT = ROOT / "evidence/w3_289_smacker_later_callee_capture.json"
REPORT = ROOT / "reports/coordination/w3_289_smacker_later_callee_capture.md"
STDOUT = EVIDENCE_DIR / f"{RUN_ID}.stdout.json"
STDERR = EVIDENCE_DIR / f"{RUN_ID}.stderr.txt"
CORE = STAGING / "src/cpu/core_dyn_x86.cpp"


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    if int(sandbox.get("capacity_bytes", 0)) < 15 * 1024**3 or sandbox.get("label") != "GWORACLE":
        raise RuntimeError("GWORACLE verification/capacity failed")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if any(path.exists() for path in (TRACE, RESULT, STDOUT, STDERR)):
        raise FileExistsError("refusing to overwrite W3-289 artifacts")
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW fixture mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional CONFIG/CUE identity mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
        raise RuntimeError("CUE mount is not read-only")
    revision = subprocess.run(["git", "-C", str(STAGING), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    source = CORE.read_text(encoding="utf-8")
    if not source_instrumentation_valid(source):
        raise RuntimeError("W3-289 bounded callee instrumentation did not validate")

    source_sha = sha(CORE)
    binary_sha = sha(DOSBOX)
    env = dict(os.environ)
    prefixes = (
        "GWRECOMP_ANCHOR_", "GWRECOMP_EXEC_TRACE_", "GWRECOMP_W3_262_",
        "GWRECOMP_W3_264_", "GWRECOMP_W3_267_", "GWRECOMP_W3_269_",
        "GWRECOMP_W3_271_", "GWRECOMP_W3_274_", "GWRECOMP_W3_275_",
        "GWRECOMP_W3_276_", "GWRECOMP_W3_277_", "GWRECOMP_W3_278_",
        "GWRECOMP_W3_279_", "GWRECOMP_W3_280_", "GWRECOMP_W3_281_",
        "GWRECOMP_W3_285_", "GWRECOMP_W3_289_",
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
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(1024 * 1024),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_W3_262_CAPTURE": "1",
        "GWRECOMP_W3_262_TRACE_PATH": str(TRACE),
        "GWRECOMP_W3_262_RUN_ID": RUN_ID,
        "GWRECOMP_W3_269_CAPTURE": "1",
        "GWRECOMP_W3_269_RUN_ID": RUN_ID,
        "GWRECOMP_W3_279_BRANCH_STEP": "1",
        "GWRECOMP_W3_285_CAPTURE": "1",
        "GWRECOMP_W3_289_CAPTURE": "1",
    })
    if any(k.startswith("GWRECOMP_W3_267_CAPTURE_VIEWPORT") for k in env):
        raise RuntimeError("optional viewport capture must remain disabled")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
        "--config", str(CONFIG), "--staging-dir", str(MOUNT),
        "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-289 one-shot later Smacker branch-sensitive callee capture",
        "--commit-sha", REVISION, "--target-sha", GW_SHA256,
        "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(EVIDENCE_DIR), "--max-file-text-mib", "1",
        "--max-file-bin-mib", "64", "--max-run-gib", "1",
        "--host-floor-gib", "100", "--timeout-s", "120",
        "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    with STDOUT.open("xb") as out, STDERR.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=130, check=False)
    guard = json.loads(STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_trace(raw)
    analysis = analyze(rows)
    result = {
        "schema": "w3-289-smacker-later-callee-capture/v1",
        "task": "W3-289", "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if analysis["callee_entry_seen"] else "INCONCLUSIVE",
        "provenance": {
            "target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
            "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE), "cue_read_only": True,
            "staging_revision": revision, "instrumentation_core_sha256": source_sha,
            "binary_sha256": binary_sha,
        },
        "preflight": {"sandbox": sandbox, "timeout_s": 120, "trace_byte_cap": 1048576,
                      "trace_row_cap": 2048, "selected_event_cap": 10, "step_instruction_cap": 16,
                      "optional_w3_267_viewport_readback": False, "global_trace": False,
                      "bulk_memdump": False, "guest_modified": False},
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
            "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
            "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)).replace("\\", "/"),
                  "bytes": len(raw), "sha256": trace_digest(raw) if raw else None, "rows": len(rows)},
        "analysis": analysis,
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    callee = analysis["callee"]
    REPORT.write_text("\n".join([
        "# W3-289 — Later Smacker callee capture", "",
        f"Conclusion: **{analysis['conclusion']}**. Evidence: **{result['evidence_level']}**.", "",
        f"- Run: `{RUN_ID}`; guard `{guard.get('cause')}` after {guard.get('duration_s')}s.",
        f"- Fixture GW.EXE SHA-256: `{GW_SHA256}`; Staging `{REVISION}`; binary SHA-256: `{binary_sha}`.",
        f"- Trace: {len(raw)} bytes / {len(rows)} rows; SHA-256 `{trace_digest(raw) if raw else None}`.",
        f"- Fresh MAIN code rebase: `{analysis['code_rebase']}`.",
        f"- Later W3-275/W3-278 latch chain: `{analysis['later_caller_latches_complete']}`; sequences `{analysis['latch_sequences']}`.",
        f"- Actual later branch destination: `{analysis['observed_branch_destination']}`.",
        f"- Callee: `{callee.get('callee')}` at link VA `{hex(callee.get('link_va'))}`; runtime `{hex(callee.get('runtime_linear'))}`." if callee else "- Later callee: not observed in this bounded run.",
        "- This capture does not establish the return to AE306, framebuffer pixels, menu, gameplay, or native parity.",
        "",
    ]), encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "conclusion": analysis["conclusion"],
                      "guard_cause": guard.get("cause"), "trace_bytes": len(raw), "trace_rows": len(rows)}))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-289 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
