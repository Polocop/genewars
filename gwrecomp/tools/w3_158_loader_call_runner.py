#!/usr/bin/env python3
"""One guarded, bounded replay distinguishing the W_SCREEN callsite and callee."""
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
RUN_ID = "w3-158-wscreen-call-20261009-01"
TRACE = MOUNT / "W3_158_WSCREEN_CALL_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_158_loader_call_discriminator.json"


def event_relation(callsite: dict | None, entry: dict | None, returned: dict | None,
                   code_rebase: int, data_rebase: int) -> dict:
    ordered = bool(callsite and entry and returned and
                   callsite.get("sequence", 0) < entry.get("sequence", 0) < returned.get("sequence", 0))
    expected_return = expected_runtime(code_rebase, 0x94DC1) if code_rebase else None
    expected_edx = data_rebase + 0x104054 if data_rebase else None
    raw_return = entry.get("w3_158_raw_return_address") if entry else None
    return {
        "ordered_same_run": ordered,
        "expected_return_runtime": expected_return,
        "entry_raw_return_runtime": raw_return,
        "return_address_matches_static_call": raw_return == expected_return if entry else None,
        "expected_edx_descriptor_runtime": expected_edx,
        "entry_edx": entry.get("edx") if entry else None,
        "edx_matches_descriptor": entry.get("edx") == expected_edx if entry else None,
        "descriptor_name": entry.get("w3_158_descriptor_name") if entry else None,
        "previous_w3_157_filter_would_match": bool(entry and raw_return == expected_return and
                                                     entry.get("edx") == expected_edx and
                                                     entry.get("w3_158_descriptor_name") == "*W_SCREEN"),
    }


def find(rows: list[dict], name: str, link_va: int) -> dict | None:
    return next((row for row in rows if row.get("event") == "target_runtime_checkpoint" and
                 row.get("checkpoint") == name and row.get("link_va") == link_va), None)


def expected_runtime(code_rebase: int, link_va: int) -> int:
    return code_rebase + link_va


def simulate_gate(link_va: int, state: dict) -> str | None:
    """Synthetic mirror of the three one-shot checkpoint gates."""
    if link_va == 0x94DBC and not state.get("callsite_seen"):
        state.update(callsite_seen=True, loader_pending=True, entry_seen=False, return_seen=False)
        return "callsite"
    if link_va == 0x15090 and state.get("loader_pending") and not state.get("entry_seen"):
        state["entry_seen"] = True
        return "loader_entry"
    if link_va == 0x94DC1 and state.get("loader_pending") and not state.get("return_seen"):
        state.update(return_seen=True, loader_pending=False)
        return "call_return"
    return None


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
    source = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("W3_158_WSCREEN_CALLSITE", "W3_158_WSCREEN_LOADER_ENTRY",
                  "W3_158_WSCREEN_CALL_RETURN", "candidate_link_va == 0x00094dbc",
                  "candidate_link_va == 0x00015090", "w3_158_raw_return_address"):
        if token not in source:
            raise RuntimeError(f"W3-158 instrumentation missing {token}")

    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-158 artifacts")
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
               "--operation", "W3-158 original W_SCREEN callsite/entry discriminator",
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
    callsite = find(rows, "W3_158_WSCREEN_CALLSITE", 0x94DBC)
    entry = find(rows, "W3_158_WSCREEN_LOADER_ENTRY", 0x15090)
    returned = find(rows, "W3_158_WSCREEN_CALL_RETURN", 0x94DC1)
    main_anchor = next((r for r in rows if r.get("event") == "target_code_anchor" and
                        r.get("anchor") == "MAIN_ENTRY"), None)
    copy = find(rows, "W3_151_COPY_NONVESA_PRE", 0xA0013)
    vesa = find(rows, "W3_151_VESA_BRANCH", 0xA0000)
    code_rebase = (main_anchor["eip"] - main_anchor["link_va"] if main_anchor else
                   (vesa["eip"] - vesa["link_va"] if vesa else 0))
    data_rebase = vesa.get("data_rebase", 0) if vesa else 0
    relation = event_relation(callsite, entry, returned, code_rebase, data_rebase)
    result = {
        "schema": "w3-158-loader-call-discriminator/v1", "task": "W3-158", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": revision, "instrumented_core_sha256": core_hash,
                   "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                      "global_trace": False, "fixture_or_original_modified": False},
        "guard": {key: guard.get(key) for key in ("run_id", "operation", "sandbox_verified",
                   "sandbox_capacity", "host_free_before", "host_free_after", "limits",
                   "exit_reason", "cause", "detail", "exit_code", "killed_processes",
                   "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows)},
        "mapping": {"code_rebase": code_rebase or None, "data_rebase": data_rebase or None,
                    "freshly_observed": bool(main_anchor and vesa)},
        "checkpoints": {"callsite": callsite, "loader_entry": entry,
                        "call_return": returned, "first_copy_pre": copy},
        "relation": relation,
        "capture_complete": bool(callsite and entry and returned and relation["ordered_same_run"]),
        "limitations": ["No memory was sampled or dumped.",
                        "A missing callsite in this bounded run does not prove the call is unreachable in all executions.",
                        "This capture does not establish pixel content or visible presentation."]}
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "callsite": bool(callsite),
                      "loader_entry": bool(entry), "call_return": bool(returned),
                      "capture_complete": result["capture_complete"],
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
