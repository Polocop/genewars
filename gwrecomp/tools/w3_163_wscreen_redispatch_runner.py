#!/usr/bin/env python3
"""One guarded replay validating the bounded W3-163 BR_Link redispatch."""
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
from tools.w3_143_postopen_branch import MAX_TRACE_BYTES, parse_jsonl

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-163-wscreen-redispatch-20261009-01"
TRACE = MOUNT / "W3_163_WSCREEN_REDISPATCH_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_163_wscreen_link_redispatch.json"
WINDOW = (0x94CDA, 0x94DC1)


def find(rows: list[dict], checkpoint: str, link_va: int) -> dict | None:
    return next((row for row in rows if row.get("event") == "target_runtime_checkpoint"
                 and row.get("checkpoint") == checkpoint and row.get("link_va") == link_va), None)


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10,
                              check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    core_text = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("linked_candidate_link_va >= 0x00094cda",
                  "linked_candidate_link_va <= 0x00094dc1",
                  "goto restart_core;", "w3_161_instruction_boundary_probe_active"):
        if token not in core_text:
            raise RuntimeError(f"W3-163 bounded redirect missing: {token}")

    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-163 artifacts")
    binary_hash, core_hash = sha(DOSBOX), sha(CORE)
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
               "--operation", "W3-163 bounded W_SCREEN BR_Link redispatch",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", binary_hash, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
               "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("trace exceeded configured byte cap")
    rows = parse_jsonl(raw)
    names = {
        "gate_117662": ("W3_160_WSCREEN_GATE_117662", 0x94CE1),
        "gate_1174a4": ("W3_160_WSCREEN_GATE_1174A4", 0x94CEE),
        "gate_fallthrough": ("W3_160_WSCREEN_GATE_FALLTHROUGH", 0x94CF4),
        "loader_block": ("W3_160_WSCREEN_LOADER_BLOCK", 0x94D9F),
        "callsite": ("W3_158_WSCREEN_CALLSITE", 0x94DBC),
        "w3157_loader_entry": ("W3_157_WSCREEN_LOADER_ENTRY", 0x15090),
        "w3157_loader_return": ("W3_157_WSCREEN_LOADER_RETURN", 0x94DC1),
        "w3158_loader_entry": ("W3_158_WSCREEN_LOADER_ENTRY", 0x15090),
        "w3158_loader_return": ("W3_158_WSCREEN_CALL_RETURN", 0x94DC1),
        "main_entry": ("MAIN_ENTRY_CHECKPOINT", 0x93F30),
    }
    captures = {name: find(rows, *location) for name, location in names.items()}
    anchor = next((r for r in rows if r.get("event") == "target_code_anchor"
                   and r.get("anchor") == "MAIN_ENTRY"), None)
    main = captures["main_entry"]
    code_rebase = anchor["eip"] - anchor["link_va"] if anchor else 0
    data_rebase = (main or {}).get("data_rebase", 0)
    gate1, gate2 = captures["gate_117662"], captures["gate_1174a4"]
    loader_entry = captures["w3157_loader_entry"] or captures["w3158_loader_entry"]
    loader_return = captures["w3157_loader_return"] or captures["w3158_loader_return"]
    return_link = (loader_entry.get("return_address", 0) - code_rebase) if loader_entry and code_rebase else None
    loader_pair = bool(loader_entry and loader_return and return_link == 0x94DC1
                       and loader_return.get("link_va") == 0x94DC1
                       and loader_entry.get("w3_157_descriptor_name") == "*W_SCREEN")
    active = [r for r in rows if r.get("event") == "target_runtime_checkpoint"
              and r.get("w3_161_instruction_boundary_probe_active") is True]
    gates_valid = bool(gate1 and gate2 and gate1.get("w3_160_globals_valid")
                       and gate2.get("w3_160_globals_valid")
                       and gate1.get("w3_160_branch_valid") and gate2.get("w3_160_branch_valid"))
    skip_pair = bool(gates_valid and gate1.get("w3_160_branch_taken") is False
                     and gate2.get("w3_160_branch_taken") is False
                     and captures["gate_fallthrough"])
    call_return_matches = bool(captures["callsite"] and loader_entry and
                               loader_entry.get("return_address") == code_rebase + 0x94DC1)
    complete = bool(anchor and main and data_rebase and (loader_pair or skip_pair))
    trace_sequences = [row.get("sequence") for row in rows if row.get("sequence") is not None]
    result = {
        "schema": "w3-163-original-wscreen-redispatch/v1", "task": "W3-163", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE), "staging_revision": revision,
                   "instrumented_core_sha256": core_hash, "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True, "timeout_seconds": 30,
                      "trace_cap_bytes": MAX_TRACE_BYTES, "probe_window_link_va_inclusive": ["0x94cda", "0x94dc1"],
                      "fixture_or_original_modified": False, "global_trace": False},
        "guard": {key: guard.get(key) for key in ("run_id", "operation", "sandbox_verified", "sandbox_capacity",
                   "host_free_before", "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
                   "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None, "event_count": len(rows)},
        "mapping": {"code_rebase": code_rebase or None, "data_rebase": data_rebase or None,
                    "freshly_observed": bool(anchor and main and data_rebase)},
        "checkpoints": captures, "instruction_boundary_events": active,
        "validation": {"gate_globals_and_flags_observed": gates_valid,
                       "loader_entry_return_pair_observed": loader_pair,
                       "loader_return_link_va": "0x%X" % return_link if return_link is not None else None,
                       "callsite_checkpoint_observed": captures["callsite"] is not None,
                       "callsite_return_correlated": call_return_matches,
                       "complete_skip_path_observed": skip_pair,
                       "trace_sequence_increasing": trace_sequences == sorted(trace_sequences)},
        "capture_complete": complete,
        "limitations": ["One original replay only; 30-second guard timeout and 1 MiB trace cap.",
                        "The W3-163 redirect changes only dispatcher routing for linked target destinations in the bounded MAIN interval.",
                        "Absent gate checkpoints do not prove branch values when a complete loader entry/return was independently observed.",
                        "No guest state or original fixture was modified; no global trace or memory dump was used."]}
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "mapping": result["mapping"],
                      "gate_117662": bool(gate1), "gate_1174a4": bool(gate2),
                      "loader_pair": loader_pair, "callsite": bool(captures["callsite"]),
                      "capture_complete": complete, "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
