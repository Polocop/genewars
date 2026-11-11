#!/usr/bin/env python3
"""One guarded, bounded original post-SMACKOPEN branch capture."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_143_postopen_branch import MAX_TRACE_BYTES, parse_jsonl, summarize

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-148-screen-swap-20261009-01"
TRACE = MOUNT / "W3_148_SCREEN_SWAP_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_148_screen_swap_result.json"


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DISASM):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    disasm = DISASM.read_text(encoding="utf-8", errors="replace").lower()
    for token in ("jump_ae39a:", "jump_ae3c9:", "je     jump_ae4ce",
                  "call   smackopen"):
        if token not in disasm:
            raise RuntimeError(f"static post-SMACKOPEN branch check failed: {token}")
    if not re.search(r"(?im)^\s*SMACKOPEN:\s*/\*\s*0xc62f0\s*\*/", disasm):
        raise RuntimeError("exact-target SMACKOPEN entry label check failed")
    source = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ('"W3_143_SMACKOPEN_SUCCESS_FLAG_ZERO"',
                  '"W3_143_SMACKOPEN_SUCCESS_FLAG_ONE"', '"W3_143_SMACKOPEN_FAILURE"',
                  '"W3_142_SMACKTOBUFFER_ENTRY"', "w3_143_postopen_capture_armed",
                  "candidate_link_va == 0x000ae39a",
                  "candidate_link_va == 0x000ae3c9",
                  "candidate_link_va == 0x000ae4ce",
                  "w3_143_postopen_probe_window",
                  "candidate_link_va == 0x000c5140",
                  "w3_146_transfer_probe_window",
                  "w3_146_transfer_probe_armed = true;",
                  "candidate_link_va == 0x000c5bd0",
                  "w3_147_frame_probe_window",
                  "w3_147_frame_probe_armed = true;",
                  "candidate_link_va == 0x000ae466",
                  "candidate_link_va == 0x000ae47f",
                  "candidate_link_va == 0x0009ffe0",
                  "w3_148_swap_probe_window",
                  "w3_148_swap_probe_armed = true;",
                  "W3_148_SMACKDOFRAME_RETURN"):
        if token not in source:
            raise RuntimeError(f"one-shot post-open instrumentation missing {token}")
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-148 artifacts")
    binary_hash = sha(DOSBOX)
    core_hash = sha(CORE)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-148 original SMACKDOFRAME return and screen swap capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256, "--runtime-sha", binary_hash,
               "--fixture-sha", GW_SHA256, "--evidence-dir", str(evidence_dir),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "30", "--growth-text-mibs", "8",
               "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_jsonl(raw)
    capture = summarize(rows)
    frame_entry = next((row for row in rows
                        if row.get("event") == "target_runtime_checkpoint" and
                        row.get("checkpoint") == "W3_142_SMACKDOFRAME_ENTRY" and
                        row.get("link_va") == 0xC5BD0), None)
    capture["smack_do_frame_entry"] = frame_entry
    capture["smack_do_frame_runtime_rebase"] = (
        frame_entry["eip"] - frame_entry["link_va"] if frame_entry else None)
    capture["frame_processing_reached"] = frame_entry is not None
    capture["same_runtime_rebase"] = capture["same_runtime_rebase"] and (
        frame_entry is None or
        capture["smack_do_frame_runtime_rebase"] == int(capture["runtime_rebases"][0], 16))
    for key, checkpoint, link_va in (
        ("smack_do_frame_return", "W3_148_SMACKDOFRAME_RETURN", 0xAE466),
        ("screen_swap_callsite", "W3_142_LBSCREENSWAP_CALLSITE", 0xAE47F),
        ("screen_swap_entry", "W3_142_LBSCREENSWAP_ENTRY", 0x9FFE0),
    ):
        row = next((item for item in rows
                    if item.get("event") == "target_runtime_checkpoint" and
                    item.get("checkpoint") == checkpoint and
                    item.get("link_va") == link_va), None)
        capture[key] = row
        if row:
            capture["same_runtime_rebase"] = capture["same_runtime_rebase"] and (
                row["eip"] - row["link_va"] == int(capture["runtime_rebases"][0], 16))
    capture["screen_swap_reached"] = capture["screen_swap_entry"] is not None
    result = {
        "schema": "w3-148-screen-swap/v1", "task": "W3-148", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": revision, "instrumented_core_sha256": core_hash,
                   "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True, "timeout_seconds": 30,
                      "trace_cap_bytes": MAX_TRACE_BYTES, "target_event_cap": 3,
                      "global_trace": False, "fixture_or_original_modified": False},
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
            "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
            "killed_processes", "duration_s", "evidence_path", "ok")},
        "guard_output": {"stdout_path": str(stdout.relative_to(ROOT)), "stdout_sha256": sha(stdout),
                         "stderr_path": str(stderr.relative_to(ROOT)), "stderr_bytes": stderr.stat().st_size},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows)},
        "capture": capture,
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": capture["classification"],
                      "branch": capture["postopen_branch"].get("checkpoint") if capture["postopen_branch"] else None,
                      "transfer_followed": capture["transfer_followed"], "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)




