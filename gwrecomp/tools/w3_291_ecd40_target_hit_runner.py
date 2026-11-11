#!/usr/bin/env python3
"""One-shot W3-291 original replay, launched exclusively through oracle_guard."""

from __future__ import annotations

import json
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_266_capture_runner import (
    CONFIG, CONFIG_SHA256, CUE, CUE_SHA256, EVIDENCE_DIR, FIXTURE, GW_SHA256, GW_SIZE,
    REVISION, STAGING,
)
from tools.w3_291_ecd40_target_hit_capture import analyze, digest, parse_trace

MOUNT = ROOT / "build/dosboxx_oracle/C"
DOSBOX = ROOT / "build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
RUN_ID = "w3-291-ecd40-target-hit-20261010-01"
TRACE = MOUNT / "W3_291_ECD40_TARGET_HIT_20261010_01.jsonl"
RESULT = ROOT / "evidence/w3_291_ecd40_target_hit_capture.json"
REPORT = ROOT / "reports/coordination/w3_291_ecd40_target_hit_capture.md"
STDOUT = EVIDENCE_DIR / f"{RUN_ID}.stdout.json"
STDERR = EVIDENCE_DIR / f"{RUN_ID}.stderr.txt"
CORE = STAGING / "src/cpu/core_dyn_x86.cpp"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finalize-existing", action="store_true",
                        help="analyze the already completed guarded run without launching any process")
    args = parser.parse_args()
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    if args.finalize_existing:
        guard_path = EVIDENCE_DIR / f"oracle_runs_{RUN_ID}.json"
        if not TRACE.is_file() or not guard_path.is_file():
            raise FileNotFoundError("existing W3-291 trace or oracle_guard evidence is missing")
        if RESULT.exists() or REPORT.exists():
            raise FileExistsError("refusing to overwrite finalized W3-291 evidence")
        guard = json.loads(guard_path.read_text(encoding="utf-8"))
        sandbox = guard.get("sandbox", {})
        revision = guard.get("provenance", {}).get("commit_sha")
        if revision != REVISION or guard.get("provenance", {}).get("target_sha") != GW_SHA256:
            raise RuntimeError("existing guarded run provenance does not match the pinned fixture/revision")
        source_hash = sha(CORE)
        binary_hash = sha(DOSBOX)
        if guard.get("provenance", {}).get("runtime_sha") != binary_hash:
            raise RuntimeError("current instrumented binary differs from the guarded run hash")
    else:
        sandbox = verify_sandbox()
        if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE" or int(sandbox.get("capacity_bytes", 0)) < 15 * 1024**3:
            raise RuntimeError("GWORACLE verification/capacity failed")
        for path in (CONFIG, CUE, FIXTURE, DOSBOX, GUARD, CORE):
            if not path.is_file():
                raise FileNotFoundError(path)
        if any(path.exists() for path in (TRACE, RESULT, STDOUT, STDERR)):
            raise FileExistsError("refusing to overwrite W3-291 artifacts")
        if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
            raise RuntimeError("authentic W3-067 GW fixture mismatch")
        if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
            raise RuntimeError("functional CONFIG/CUE identity mismatch")
        if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
            raise RuntimeError("CUE must remain mounted read-only")
        revision = subprocess.run(["git", "-C", str(STAGING), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        if revision != REVISION:
            raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
        source_hash = sha(CORE)
        binary_hash = sha(DOSBOX)
    source = CORE.read_text(encoding="utf-8")
    if "GWRECOMP_W3_291_CAPTURE" not in source or "w3_291_ecd40_target_hit" not in source:
        raise RuntimeError("W3-291 source hook missing")
    if not args.finalize_existing:
        env = dict(os.environ)
        prefixes = (
            "GWRECOMP_ANCHOR_", "GWRECOMP_EXEC_TRACE_", "GWRECOMP_W3_262_", "GWRECOMP_W3_264_",
            "GWRECOMP_W3_267_", "GWRECOMP_W3_269_", "GWRECOMP_W3_271_", "GWRECOMP_W3_274_",
            "GWRECOMP_W3_275_", "GWRECOMP_W3_276_", "GWRECOMP_W3_277_", "GWRECOMP_W3_278_",
            "GWRECOMP_W3_279_", "GWRECOMP_W3_280_", "GWRECOMP_W3_281_", "GWRECOMP_W3_285_",
            "GWRECOMP_W3_289_", "GWRECOMP_W3_291_",
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
            "GWRECOMP_W3_291_CAPTURE": "1",
        })
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
            "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
            "--operation", "W3-291 one-shot ECD40 target-hit boundary capture",
            "--commit-sha", REVISION, "--target-sha", GW_SHA256, "--runtime-sha", binary_hash,
            "--fixture-sha", GW_SHA256, "--evidence-dir", str(EVIDENCE_DIR),
            "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
            "--host-floor-gib", "100", "--timeout-s", "120", "--growth-text-mibs", "8",
            "--growth-bin-mibs", "24", "--poll-hz", "1",
        ]
        with STDOUT.open("xb") as out, STDERR.open("xb") as err:
            subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=130, check=False)
        guard = json.loads(STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_trace(raw)
    analysis = analyze(rows)
    result = {
        "schema": "w3-291-ecd40-target-hit-capture/v1", "task": "W3-291", "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if analysis["target_hit_seen"] else "INCONCLUSIVE",
        "provenance": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                       "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE), "cue_read_only": True,
                       "staging_revision": revision, "instrumentation_source_sha256": source_hash,
                       "binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "timeout_s": 120, "trace_byte_cap": 1048576,
                      "trace_row_cap": 2048, "selected_event_cap": 1,
                      "w3_279_step": False, "w3_285_capture": False, "w3_289_capture": False,
                      "viewport_capture": False, "global_trace": False, "bulk_memdump": False,
                      "guest_modified": False},
        "guard": {k: guard.get(k) for k in ("run_id", "operation", "sandbox_verified", "sandbox_capacity",
                 "host_free_before", "host_free_after", "limits", "exit_reason", "cause", "detail",
                 "exit_code", "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)).replace("\\", "/"), "bytes": len(raw),
                  "sha256": digest(raw) if raw else None, "rows": len(rows)},
        "analysis": analysis,
    }
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    hit = analysis["target_hit"]
    lines = [
        "# W3-291 — ECD40 target-hit boundary", "",
        f"Conclusion: **{analysis['conclusion']}**; evidence **{result['evidence_level']}**.", "",
        f"- Run `{RUN_ID}`; guard `{guard.get('cause')}` / `{guard.get('exit_reason')}` after {guard.get('duration_s')} s.",
        f"- Fixture SHA-256 `{GW_SHA256}`; Staging `{REVISION}`; instrumentation source `{source_hash}`; binary `{binary_hash}`.",
        f"- Trace: {len(raw)} bytes / {len(rows)} rows; SHA-256 `{digest(raw) if raw else None}`; fresh code rebase `{analysis['code_rebase']}`.",
        f"- Last emitted event: `{analysis['last_emitted_event']}`.",
        f"- Initial W3-193 step: `{analysis['initial_step_result']}`; continuation armed by exact successor: `{analysis['continuation_armed_by_initial_step']}`; W3-198 stop: `{analysis['continuation_stop']}`.",
        f"- ECD40 target-hit record: `{hit}`." if hit else "- No ECD40 target-hit event was observed in this bounded replay.",
        "- This event proves only arrival at the instrumented ECD40 branch; no later Smacker callee, framebuffer pixels, menu, or gameplay is inferred.",
        "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "conclusion": analysis["conclusion"],
                      "guard_cause": guard.get("cause"), "trace_bytes": len(raw), "trace_rows": len(rows)}))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-291 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
