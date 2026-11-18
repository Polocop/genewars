#!/usr/bin/env python3
"""One guarded replay with a single-instruction dynrec window at original INT 31."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_143_postopen_branch import MAX_TRACE_BYTES, parse_jsonl
from tools.w3_182_original_ax0300_capture_runner import (
    CONFIG, CONFIG_SHA256, CUE, CUE_SHA256, DOSBOX, FRAME_BYTES, GW_SHA256,
    GW_SIZE, GUARD, REVISION, SOURCE, W1_EVIDENCE, W3_140_EVIDENCE,
    _w1_context, _w3_140_context,
)

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
RUN_ID = "w3-184-original-ax0300-window-20261009-01"
TRACE = MOUNT / "W3_184_ORIGINAL_AX0300_WINDOW_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_184_original_ax0300_window.json"
GUARD_JSON = ROOT / "evidence/oracle_runs/oracle_runs_w3-184-original-ax0300-window-20261009-01.json"
GUARD_STDOUT = GUARD_JSON.with_name(GUARD_JSON.stem + ".stdout.json")
GUARD_STDERR = GUARD_JSON.with_name(GUARD_JSON.stem + ".stderr.txt")
TARGET_SHA256 = GW_SHA256
WINDOW_START = 0xBC74D
INT_LINK = 0xBC765
RETURN_LINK = 0xBC767


def classify(rows: list[dict[str, Any]]) -> dict[str, Any]:
    main = next((row for row in rows if row.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    entries = [row for row in rows if row.get("checkpoint") == "W3_182_DPMI0300_ENTRY"]
    returns = [row for row in rows if row.get("checkpoint") == "W3_182_DPMI0300_RETURN"]
    if len(entries) > 1 or len(returns) > 1:
        return {"classification": "INVALID_DUPLICATE_EVENTS", "entry_count": len(entries),
                "return_count": len(returns)}
    last = rows[-1] if rows else None
    if not entries:
        return {"classification": "NOT_OBSERVED", "reason": "original INT31 checkpoint absent",
                "main": main, "last_event": last}
    entry = entries[0]
    rebase = int(main["eip"]) - int(main["link_va"]) if main else None
    mapping_valid = (main is not None and int(entry.get("link_va", -1)) == INT_LINK and
                     int(entry.get("eip", -1)) - rebase == INT_LINK and
                     int(entry.get("process_psp", -1)) == int(main["process_psp"]))
    opcode = str(entry.get("bytes", "")).lower()
    service_valid = (int(entry.get("eax", 0)) & 0xffff) == 0x0300
    frame_hex = str(entry.get("w3_182_frame_hex", ""))
    try:
        frame_valid = (entry.get("w3_182_frame_valid") is True and
                       int(entry.get("w3_182_frame_bytes", 0)) == FRAME_BYTES and
                       len(bytes.fromhex(frame_hex)) == FRAME_BYTES)
    except ValueError:
        frame_valid = False
    returned = returns[0] if returns else None
    return_valid = (returned is not None and int(returned.get("link_va", -1)) == RETURN_LINK and
                    int(returned.get("eip", -1)) == int(entry["eip"]) + 2 and
                    int(returned.get("process_psp", -1)) == int(entry.get("process_psp", -2)) and
                    int(returned.get("sequence", -1)) > int(entry.get("sequence", 0)))
    valid = mapping_valid and service_valid and opcode.startswith("cd31")
    environment_hex = str(entry.get("w3_184_environment_hex", ""))
    try:
        environment_sample_bounds_valid = (entry.get("w3_184_environment_valid") is True and
                                           int(entry.get("w3_184_environment_bytes", 0)) == 86 and
                                           len(bytes.fromhex(environment_hex)) == 86)
    except ValueError:
        environment_sample_bounds_valid = False
    return {"classification": "ORIGINAL_RETURN_OBSERVED" if valid and return_valid else
            ("ORIGINAL_ENTRY_OBSERVED" if valid else "ENTRY_INVALID"),
            "reason": "natural INT31 entry captured; return is reported only if next instruction is observed",
            "main_code_rebase": hex(rebase) if rebase is not None else None,
            "mapping_valid": mapping_valid, "service_valid": service_valid,
            "opcode_verified": opcode.startswith("cd31"), "entry_valid": valid,
            "entry": entry, "frame_valid": frame_valid,
            "frame_hex": frame_hex if frame_valid else None,
            "psp_tail": entry.get("psp_tail_text"),
            "psp_environment_field_raw": entry.get("w3_184_environment_segment"),
            "environment_sample_address": entry.get("w3_184_environment_linear"),
            "environment_sample_bounds_valid": environment_sample_bounds_valid,
            "environment_sample_sha256": hashlib.sha256(bytes.fromhex(environment_hex)).hexdigest()
            if environment_sample_bounds_valid else None,
            "environment_identity": "UNKNOWN; PSP:2C field was shifted as a real-mode segment without a same-run descriptor check",
            "return_observed": returned is not None, "return_valid": return_valid,
            "return": returned, "last_event": last}


def _preflight() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, W1_EVIDENCE,
                 W3_140_EVIDENCE, TRACE.parent):
        if not path.exists():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic W3-067 fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("W3-067 config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    source = CORE.read_text(encoding="utf-8", errors="replace")
    tokens = ("w3_184_int31_probe_window", "candidate_link_va >= 0x000bc74d",
              "candidate_link_va <= 0x000bc765", "linked_candidate_link_va >= 0x000bc74d",
              "linked_candidate_link_va <= 0x000bc765", "W3_182_DPMI0300_ENTRY",
              "w3_184_environment_valid", "w3_184_environment_hex", "psp_tail_text")
    for token in tokens:
        if token not in source:
            raise RuntimeError(f"bounded W3-184 probe missing {token}")
    w1, w3 = _w1_context(), _w3_140_context()
    if w3.get("original_psp_tail") != w1.get("command_tail"):
        raise RuntimeError("native/original command-tail context did not reconcile")
    for path in (TRACE, RESULT, GUARD_JSON, GUARD_STDOUT, GUARD_STDERR):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite W3-184 artifact: {path}")
    return sandbox, w1, w3


def main() -> int:
    if any(arg in ("-h", "--help") for arg in sys.argv[1:]):
        print("Usage: w3_184_original_ax0300_window_runner.py [--help]")
        print("Running without --help performs one fixed guarded original replay.")
        return 0
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox, w1, w3 = _preflight()
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    binary_sha = sha(DOSBOX)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({"GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
                "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
                "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
                "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
                "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
                "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
                "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
                "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
                "GWRECOMP_W3_171_ENABLE_SAMPLES": "0"})
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-184 original INT31 bounded-window capture", "--commit-sha", REVISION,
               "--target-sha", GW_SHA256, "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "30",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    stdout_path = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr_path = evidence_dir / f"{RUN_ID}.stderr.txt"
    if stdout_path.exists() or stderr_path.exists():
        raise FileExistsError("refusing to overwrite W3-184 guard output")
    with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout_path.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("trace exceeded configured 1 MiB cap")
    rows = parse_jsonl(raw)
    outcome = classify(rows)
    if outcome.get("entry"):
        outcome["psp_tail_matches_w3_140"] = outcome.get("psp_tail") == w3.get("original_psp_tail")
        outcome["environment_sample_hash_matches_w3_140"] = (
            outcome.get("environment_sample_sha256") == w3.get("environment_sha256"))
    result = {**outcome, "schema": "w3-184-original-ax0300-window/v1", "task": "W3-184",
              "run_id": RUN_ID,
              "source": {"target_sha256": TARGET_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                         "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                         "staging_revision": REVISION, "instrumented_core_sha256": sha(CORE),
                         "staging_binary_sha256": binary_sha},
              "context": {"w1_069_native": w1, "w3_140_original": w3,
                          "same_run_equivalence": False},
              "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                            "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                            "probe_window": [hex(WINDOW_START), hex(INT_LINK)],
                            "frame_sample_cap_bytes": FRAME_BYTES, "global_trace": False,
                            "guest_state_modified": False},
              "guard": {k: guard.get(k) for k in ("run_id", "operation", "sandbox_verified",
                         "sandbox_capacity", "host_free_before", "host_free_after", "limits",
                         "exit_reason", "cause", "detail", "exit_code", "killed_processes",
                         "duration_s", "evidence_path", "ok")},
              "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                        "event_count": len(rows)},
              "limitations": ["The captured ES:EDI bytes remain raw; no DPMI response semantics are invented.",
                              "A post-INT state is reported only if link VA 0xBC767 naturally executes.",
                              "No assertion is made about menu, framebuffer or gameplay."]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "entry_valid": result.get("entry_valid"),
                      "return_observed": result.get("return_observed"),
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
