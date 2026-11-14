#!/usr/bin/env python3
"""Run one guarded, bounded original replay for the W3-167 W_SCREEN gate."""
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
DECODER = SOURCE / "src/cpu/core_dyn_x86/decoder.h"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-167-wscreen-cached-span-20261009-01"
TRACE = MOUNT / "W3_167_WSCREEN_CACHED_SPAN_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_167_wscreen_cached_span.json"
WINDOW = (0x94CDA, 0x94DC1)


def in_probe_window(link_va: int) -> bool:
    return WINDOW[0] <= link_va <= WINDOW[1]


def find(rows: list[dict], checkpoint: str, link_va: int) -> dict | None:
    return next((row for row in rows
                 if row.get("event") == "target_runtime_checkpoint"
                 and row.get("checkpoint") == checkpoint
                 and row.get("link_va") == link_va), None)


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DECODER):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b",
                     CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10,
                              check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    core = CORE.read_text(encoding="utf-8", errors="replace")
    decoder = DECODER.read_text(encoding="utf-8", errors="replace")
    required = (
        "candidate_link_va >= 0x00094cda && candidate_link_va <= 0x00094dc1",
        "w3_161_probe_window ||",
        "w3_161_instruction_boundary_probe_active",
        "W3_167_CACHE_SPAN_HIT",
        "w3_167_cache_span_step",
        "CPU_Cycles = 1",
        "sync_dh_fpu_and_run_normal_core()",
        "goto restart_core",
    )
    for token in required:
        if token not in core:
            raise RuntimeError(f"bounded restart instrumentation missing: {token}")
    decoder_required = (
        "w3_165_is_wscreen_boundary(decode.code - w3_165_rebase)",
        "W3_167_DECODER_SPLIT_MATCH",
        "w3_167_decode_split_logged_mask",
        "dyn_set_eip_end();",
        "dyn_save_critical_regs();",
        "gen_return(BR_Normal);",
        "decode.code > decode.code_start",
    )
    for token in decoder_required:
        if token not in decoder:
            raise RuntimeError(f"bounded decoder split missing: {token}")

    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-167 artifacts")
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
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT),
               "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-167 cached W_SCREEN span and gate capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", binary_hash, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "30",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
               "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("trace exceeded configured byte cap")
    rows = parse_jsonl(raw)
    cache_span_events = [row for row in rows if row.get("event") == "W3_167_CACHE_SPAN_HIT"]
    decoder_split_events = [row for row in rows if row.get("event") == "W3_167_DECODER_SPLIT_MATCH"]
    names = {
        "gate_117662": ("W3_160_WSCREEN_GATE_117662", 0x94CE1),
        "gate_1174a4": ("W3_160_WSCREEN_GATE_1174A4", 0x94CEE),
        "gate_fallthrough": ("W3_160_WSCREEN_GATE_FALLTHROUGH", 0x94CF4),
        "loader_block": ("W3_160_WSCREEN_LOADER_BLOCK", 0x94D9F),
        "callsite": ("W3_158_WSCREEN_CALLSITE", 0x94DBC),
        "loader_entry": ("W3_158_WSCREEN_LOADER_ENTRY", 0x15090),
        "call_return": ("W3_158_WSCREEN_CALL_RETURN", 0x94DC1),
    }
    captures = {key: find(rows, *loc) for key, loc in names.items()}
    anchor = next((row for row in rows if row.get("event") == "target_code_anchor"
                   and row.get("anchor") == "MAIN_ENTRY"), None)
    main_entry = find(rows, "MAIN_ENTRY_CHECKPOINT", 0x93F30)
    code_rebase = anchor["eip"] - anchor["link_va"] if anchor else 0
    active = [row for row in rows if row.get("event") == "target_runtime_checkpoint"
              and row.get("w3_161_instruction_boundary_probe_active") is True]
    active_window_valid = bool(active) and all(in_probe_window(row.get("link_va", -1))
                                               for row in active)
    data_rebases = [row.get("w3_160_data_rebase") for row in captures.values()
                    if row and row.get("w3_160_data_rebase")]
    data_rebase = data_rebases[0] if data_rebases else (main_entry or {}).get("data_rebase", 0)
    consistent_data = bool(data_rebase) and all(value == data_rebase for value in data_rebases)
    expected_global_offsets = {"117662": data_rebase + 0x117662,
                               "1174a4": data_rebase + 0x1174A4}
    globals_valid = all(
        row and row.get("w3_160_globals_valid")
        and row.get("w3_160_global_117662_offset") == expected_global_offsets["117662"]
        and row.get("w3_160_global_1174a4_offset") == expected_global_offsets["1174a4"]
        for row in (captures["gate_117662"], captures["gate_1174a4"]))
    call = captures["callsite"]
    entry = captures["loader_entry"]
    returned = captures["call_return"]
    complete_loader = bool(captures["loader_block"] and call and entry and returned)
    gate1 = captures["gate_117662"]
    gate2 = captures["gate_1174a4"]
    gate1_matches = bool(gate1 and gate1.get("w3_160_branch_valid")
                         and gate1.get("w3_160_branch_taken") == ((gate1.get("eflags", 0) & 0x40) == 0))
    gate2_matches = bool(gate2 and gate2.get("w3_160_branch_valid")
                         and gate2.get("w3_160_branch_taken") ==
                         (gate2.get("w3_160_global_1174a4_value") != 0))
    call_return_match = bool(entry and returned and
                             entry.get("w3_158_raw_return_address") == code_rebase + 0x94DC1)
    skip_complete = bool(gate1 and gate2 and captures["gate_fallthrough"]
                         and gate1.get("w3_160_branch_taken") is False
                         and gate2.get("w3_160_branch_taken") is False)
    gate_path_complete = bool(anchor and main_entry and active_window_valid and globals_valid
                              and consistent_data and gate1_matches and gate2_matches
                              and (complete_loader or skip_complete)
                              and (not complete_loader or call_return_match))
    discriminator_measured = bool(cache_span_events or decoder_split_events)
    complete = bool(anchor and code_rebase and guard.get("sandbox_verified")
                    and discriminator_measured)
    sequence = [captures[key]["sequence"] for key in names if captures[key]]
    result = {
        "schema": "w3-167-original-wscreen-instruction-boundary/v1",
        "task": "W3-167", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": revision, "instrumented_core_sha256": core_hash,
                   "instrumented_decoder_sha256": sha(DECODER),
                   "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                      "probe_window_link_va_inclusive": [hex(WINDOW[0]), hex(WINDOW[1])],
                      "fixture_or_original_modified": False, "global_trace": False},
        "guard": {key: guard.get(key) for key in
                  ("run_id", "operation", "sandbox_verified", "sandbox_capacity",
                   "host_free_before", "host_free_after", "limits", "exit_reason",
                   "cause", "detail", "exit_code", "killed_processes", "duration_s",
                   "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows)},
        "mapping": {"code_rebase": code_rebase or None,
                    "data_rebase": data_rebase or None,
                    "data_rebase_consistent": consistent_data,
                    "freshly_observed": bool(anchor and data_rebase)},
        "main_checkpoint": main_entry, "checkpoints": captures,
        "instruction_boundary_events": active,
        "cache_span_events": cache_span_events,
        "decoder_split_events": decoder_split_events,
        "validation": {"active_window_valid": active_window_valid,
                       "gate_globals_valid": globals_valid,
                       "gate1_branch_matches_eflags": gate1_matches,
                       "gate2_branch_matches_global": gate2_matches,
                       "loader_return_matches_callsite": call_return_match,
                       "checkpoint_sequence_increasing": sequence == sorted(sequence),
                       "complete_loader_path": complete_loader,
                       "complete_skip_path": skip_complete,
                       "gate_path_complete": gate_path_complete,
                       "coverage_discriminator_measured": discriminator_measured},
        "capture_complete": complete,
        "limitations": ["One original replay, guarded to 30 seconds and 1 MiB trace.",
                        "The instrumented region alone uses one-cycle normal-core restarts.",
                        "No guest state was modified and no broad memory dump or global trace was taken.",
                        "Missing checkpoints do not prove a gate was false or the call unreachable."]}
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "active_probe_events": len(active),
                      "gate_117662": bool(gate1), "gate_1174a4": bool(gate2),
                      "loader_path": complete_loader, "skip_path": skip_complete,
                      "cache_span_events": len(cache_span_events),
                      "decoder_split_events": len(decoder_split_events),
                      "capture_complete": complete, "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
