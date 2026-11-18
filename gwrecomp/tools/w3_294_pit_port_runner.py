#!/usr/bin/env python3
"""Run the single bounded W3-294 PIT observation through oracle_guard only."""

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
    CONFIG, CONFIG_SHA256, CUE, CUE_SHA256, EVIDENCE_DIR, FIXTURE,
    GW_SHA256, GW_SIZE, REVISION, STAGING,
)
from tools.w3_294_pit_port_capture import analyze, parse_trace

MOUNT = ROOT / "build/dosboxx_oracle/C"
DOSBOX = ROOT / "build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
TRACE_NAME = "W3_294_PIT_PORT_20261010_01.jsonl"
RUN_ID = "w3-294-pit-port-20261010-01"
TRACE = MOUNT / TRACE_NAME
RESULT = ROOT / "evidence/w3_294_pit_port_capture.json"
REPORT = ROOT / "reports/coordination/w3_294_pit_port_capture.md"
STDOUT = EVIDENCE_DIR / f"{RUN_ID}.stdout.json"
STDERR = EVIDENCE_DIR / f"{RUN_ID}.stderr.txt"
CORE = STAGING / "src/cpu/core_dyn_x86.cpp"
DECODER = STAGING / "src/cpu/core_dyn_x86/decoder.h"
TIMEOUT_S = 45
MAX_FILE_TEXT_MIB = 1
MAX_FILE_BIN_MIB = 64
MAX_RUN_GIB = 1
HOST_FLOOR_GIB = 100


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_preflight() -> tuple[dict, str, str]:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"expected console python.exe, got {sys.executable}")
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError("GWORACLE sandbox verification failed")
    if int(sandbox.get("capacity_bytes", 0)) < 15 * 1024**3:
        raise RuntimeError("GWORACLE VHDX capacity is below the required 15 GiB floor")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DECODER):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or _hash(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic W3-067 guest fixture does not match the pinned target")
    if _hash(CONFIG) != CONFIG_SHA256 or _hash(CUE) != CUE_SHA256:
        raise RuntimeError("functional CONFIG/CUE hash mismatch")
    if "-ro" not in CONFIG.read_text(encoding="utf-8").casefold():
        raise RuntimeError("original CUE must remain mounted read-only")
    revision = subprocess.run(
        ["git", "-C", str(STAGING), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging source revision mismatch: {revision}")
    if any(path.exists() for path in (TRACE, RESULT, REPORT, STDOUT, STDERR)):
        raise FileExistsError("refusing to overwrite a previous W3-294 artifact")
    return sandbox, _hash(CORE), _hash(DECODER)


def _run_guarded(binary_sha: str) -> dict:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_"):
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
        "GWRECOMP_W3_294_CAPTURE": "1",
    })
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-294 one bounded natural PIT port I/O capture",
        "--commit-sha", REVISION, "--target-sha", GW_SHA256,
        "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
        "--evidence-dir", str(EVIDENCE_DIR),
        "--max-file-text-mib", str(MAX_FILE_TEXT_MIB),
        "--max-file-bin-mib", str(MAX_FILE_BIN_MIB),
        "--max-run-gib", str(MAX_RUN_GIB), "--host-floor-gib", str(HOST_FLOOR_GIB),
        "--timeout-s", str(TIMEOUT_S), "--growth-text-mibs", "8",
        "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    with STDOUT.open("xb") as out, STDERR.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=TIMEOUT_S + 10, check=False)
    return json.loads(STDOUT.read_text(encoding="utf-8"))


def main() -> int:
    sandbox, core_sha, decoder_sha = _check_preflight()
    binary_sha_before = _hash(DOSBOX)
    guard = _run_guarded(binary_sha_before)
    binary_sha_after = _hash(DOSBOX)
    if binary_sha_after != binary_sha_before:
        raise RuntimeError("instrumented DOSBox binary changed during guarded run")
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_trace(raw) if raw else []
    analysis = analyze(rows)
    guard_summary = {key: guard.get(key) for key in (
        "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
        "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
        "killed_processes", "duration_s", "evidence_path", "ok",
    )}
    evidence = {
        "schema": "w3-294-pit-port-capture/v1",
        "task": "W3-294",
        "run_id": RUN_ID,
        "evidence_level": "ORIGINAL_OBSERVED" if analysis["sequence_complete"] else "INCONCLUSIVE",
        "provenance": {
            "target_sha256": GW_SHA256,
            "fixture_path": str(FIXTURE.relative_to(ROOT)).replace("\\", "/"),
            "fixture_size": FIXTURE.stat().st_size,
            "config_path": str(CONFIG.relative_to(ROOT)).replace("\\", "/"),
            "config_sha256": _hash(CONFIG),
            "cue_path": str(CUE),
            "cue_sha256": _hash(CUE),
            "cue_read_only": True,
            "staging_revision": REVISION,
            "core_dyn_x86_cpp_sha256": core_sha,
            "decoder_h_sha256": decoder_sha,
            "instrumented_binary_sha256": binary_sha_before,
        },
        "preflight": {
            "sandbox": sandbox,
            "timeout_seconds": TIMEOUT_S,
            "trace_byte_cap": 1024 * 1024,
            "trace_row_cap": 4096,
            "target_event_cap": 1024,
            "viewport_sampling": False,
            "global_port_trace": False,
            "bulk_memdump": False,
            "guest_modified": False,
        },
        "guard": guard_summary,
        "trace": {
            "path": str(TRACE.relative_to(ROOT)).replace("\\", "/"),
            "bytes": len(raw),
            "sha256": _hash(TRACE) if TRACE.exists() else None,
            "row_count": len(rows),
        },
        "analysis": analysis,
    }
    RESULT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report_lines = [
        "# W3-294 — original PIT port sequence",
        "",
        f"Conclusion: **{analysis['conclusion']}**; evidence **{evidence['evidence_level']}**.",
        "",
        f"- Guard run `{RUN_ID}`: {guard.get('cause')} / {guard.get('exit_reason')} after {guard.get('duration_s')} s.",
        f"- Fixture SHA-256 `{GW_SHA256}`; Staging `{REVISION}`; instrumented binary SHA-256 `{binary_sha_before}`.",
        f"- Trace: {len(raw)} bytes, {len(rows)} rows; SHA-256 `{evidence['trace']['sha256']}`.",
        f"- Fresh MAIN mapping: `{analysis['code_rebase']}`; post-present checkpoint: `{analysis['post_present_checkpoint']}`.",
        f"- Natural port events: `{analysis['port_event_count']}`; natural JNE outcomes: `{analysis['branch_event_count']}`; complete loop iterations: `{analysis['complete_loop_iterations']}`.",
        f"- Port observations: `{analysis['port_events']}`.",
        f"- Branch observations: `{analysis['branch_events']}`.",
        "- No PIT response was synthesized. This capture alone does not establish native parity, framebuffer pixels, menu, or gameplay.",
        "",
    ]
    REPORT.write_text("\n".join(report_lines), encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "conclusion": analysis["conclusion"],
                      "guard_cause": guard.get("cause"), "trace_bytes": len(raw),
                      "trace_rows": len(rows)}, ensure_ascii=False))
    return 0 if guard.get("sandbox_verified") is True else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-294 failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
