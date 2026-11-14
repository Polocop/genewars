#!/usr/bin/env python3
"""One guarded original replay measuring the W_SCREEN gate globals and path."""
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
RUN_ID = "w3-160-wscreen-gate-20261009-01"
TRACE = MOUNT / "W3_160_WSCREEN_GATE_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_160_wscreen_gate_capture.json"


def expected_global_offset(data_rebase: int, link_va: int) -> int:
    return data_rebase + link_va


def branch_taken(eflags: int) -> bool:
    """Both target gates are JNE; ZF=0 means branch taken."""
    return (eflags & 0x40) == 0


def mapped_byte_bounds_valid(offset: int, selector_limit: int, linear: int,
                             physical_memory_bytes: int) -> bool:
    return 0 <= offset <= selector_limit and 0 <= linear < physical_memory_bytes


def gate1_expected_taken(value_117662: int) -> bool:
    return (value_117662 & 1) != 0


def gate2_expected_taken(value_1174a4: int) -> bool:
    return value_1174a4 != 0


def find(rows: list[dict], checkpoint: str, link_va: int) -> dict | None:
    return next((row for row in rows if row.get("event") == "target_runtime_checkpoint" and
                 row.get("checkpoint") == checkpoint and row.get("link_va") == link_va), None)


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
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
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    core = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("W3_160_WSCREEN_GATE_117662", "W3_160_WSCREEN_GATE_1174A4",
                  "W3_160_WSCREEN_GATE_FALLTHROUGH", "W3_160_WSCREEN_LOADER_BLOCK",
                  "w3_160_global_117662_value", "w3_160_global_1174a4_value"):
        if token not in core:
            raise RuntimeError(f"W3-160 instrumentation missing {token}")

    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-160 artifacts")
    binary_hash = sha(DOSBOX)
    core_hash = sha(CORE)
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
                "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30"})
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-160 original W_SCREEN gate and call path",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256, "--runtime-sha", binary_hash,
               "--fixture-sha", GW_SHA256, "--evidence-dir", str(evidence_dir),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "30", "--growth-text-mibs", "8",
               "--growth-bin-mibs", "24", "--poll-hz", "1"]
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
        "loader_entry": ("W3_158_WSCREEN_LOADER_ENTRY", 0x15090),
        "call_return": ("W3_158_WSCREEN_CALL_RETURN", 0x94DC1),
        "first_copy_pre": ("W3_151_COPY_NONVESA_PRE", 0xA0013),
    }
    captures = {key: find(rows, *value) for key, value in names.items()}
    anchor = next((r for r in rows if r.get("event") == "target_code_anchor" and
                   r.get("anchor") == "MAIN_ENTRY"), None)
    main = find(rows, "MAIN_ENTRY_CHECKPOINT", 0x93F30)
    code_rebase = anchor["eip"] - anchor["link_va"] if anchor else 0
    data_rebases = [r.get("w3_160_data_rebase", r.get("data_rebase", 0))
                    for r in captures.values() if r and r.get("w3_160_data_rebase", r.get("data_rebase", 0))]
    data_rebase = data_rebases[0] if data_rebases else 0
    same_data_rebase = all(v == data_rebase for v in data_rebases)
    gate1, gate2 = captures["gate_117662"], captures["gate_1174a4"]
    if gate1:
        gate1_valid = bool(gate1.get("w3_160_globals_valid") and
                           gate1.get("w3_160_global_117662_offset") == expected_global_offset(data_rebase, 0x117662) and
                           gate1.get("w3_160_global_1174a4_offset") == expected_global_offset(data_rebase, 0x1174A4))
    else:
        gate1_valid = False
    if gate2:
        gate2_valid = bool(gate2.get("w3_160_globals_valid") and
                           gate2.get("w3_160_global_117662_offset") == expected_global_offset(data_rebase, 0x117662) and
                           gate2.get("w3_160_global_1174a4_offset") == expected_global_offset(data_rebase, 0x1174A4))
    else:
        gate2_valid = False
    order = [captures[k]["sequence"] for k in ("gate_117662", "gate_1174a4", "gate_fallthrough",
                                                   "loader_block", "callsite", "loader_entry", "call_return")
             if captures[k]]
    gate_path = "unknown"
    if gate1 and gate1.get("w3_160_branch_taken") is True and captures["loader_block"]:
        gate_path = "first_gate_taken_loader_block_reached"
    elif gate1 and gate1.get("w3_160_branch_taken") is False and gate2 and gate2.get("w3_160_branch_taken") is True and captures["loader_block"]:
        gate_path = "second_gate_taken_loader_block_reached"
    elif gate1 and gate1.get("w3_160_branch_taken") is False and gate2 and gate2.get("w3_160_branch_taken") is False and captures["gate_fallthrough"]:
        gate_path = "both_gates_fell_through"
    entry = captures["loader_entry"]
    relation = {
        "gate1_globals_valid": gate1_valid, "gate2_globals_valid": gate2_valid,
        "gate1_branch_matches_zf": bool(gate1 and gate1.get("w3_160_branch_taken") == branch_taken(gate1.get("eflags", 0))),
        "gate2_branch_matches_global": bool(gate2 and gate2.get("w3_160_branch_taken") ==
                                             (gate2.get("w3_160_global_1174a4_value") != 0)),
        "gate_path": gate_path,
        "event_order_increasing": order == sorted(order),
        "call_return_matches_entry": bool(entry and entry.get("w3_158_raw_return_address") == code_rebase + 0x94DC1),
        "loader_descriptor_name": entry.get("w3_158_descriptor_name") if entry else None,
        "loader_edx": entry.get("edx") if entry else None,
        "expected_loader_edx": expected_global_offset(data_rebase, 0x104054) if data_rebase else None,
    }
    skipped_path_captured = gate_path == "both_gates_fell_through" and bool(captures["gate_fallthrough"])
    loader_path_captured = (gate_path in ("first_gate_taken_loader_block_reached",
                                           "second_gate_taken_loader_block_reached") and
                            bool(captures["loader_block"] and captures["callsite"] and
                                 captures["loader_entry"] and captures["call_return"]))
    path_linked = skipped_path_captured or loader_path_captured
    complete = bool(anchor and main and gate1 and gate1_valid and same_data_rebase and path_linked and
                    relation["gate1_branch_matches_zf"] and
                    (not gate2 or relation["gate2_branch_matches_global"]))
    result = {
        "schema": "w3-160-original-wscreen-gate/v1", "task": "W3-160", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE), "staging_revision": revision,
                   "instrumented_core_sha256": core_hash, "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True, "timeout_seconds": 30,
                      "trace_cap_bytes": MAX_TRACE_BYTES, "fixture_or_original_modified": False,
                      "global_trace": False},
        "guard": {key: guard.get(key) for key in ("run_id", "operation", "sandbox_verified",
                   "sandbox_capacity", "host_free_before", "host_free_after", "limits", "exit_reason",
                   "cause", "detail", "exit_code", "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None, "event_count": len(rows)},
        "mapping": {"code_rebase": code_rebase or None, "data_rebase": data_rebase or None,
                    "data_rebase_consistent": same_data_rebase, "freshly_observed": bool(anchor and data_rebase)},
        "main_checkpoint": main,
        "checkpoints": captures,
        "relation": relation,
        "capture_complete": complete,
        "limitations": ["The replay is bounded to 30 seconds.",
                        "No guest memory was modified or dumped; only two mapped bytes were sampled at gate checkpoints.",
                        "A timeout after the last checkpoint does not prove unreachable code outside this run."]}
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "gate1": bool(gate1), "gate2": bool(gate2),
                      "loader_block": bool(captures["loader_block"]), "callsite": bool(captures["callsite"]),
                      "gate_path": gate_path, "capture_complete": complete,
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
