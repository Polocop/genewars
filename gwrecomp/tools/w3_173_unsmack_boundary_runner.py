#!/usr/bin/env python3
"""One guarded replay for the natural _Unsmack call/return boundary."""
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

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
RUN_ID = "w3-173-unsmack-boundary-20261009-01"
TRACE = MOUNT / "W3_173_UNSMACK_BOUNDARY_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_173_unsmack_boundary.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
WINDOWS = (0, 32000, 63984)


def _valid_sample(row: dict[str, Any] | None, *, psp: int, data_rebase: int,
                  point: str) -> tuple[bool, str]:
    if row is None or row.get("w3_173_sample_point") != point:
        return False, "sample_checkpoint_missing"
    if int(row.get("process_psp", -1)) != psp:
        return False, "psp_mismatch"
    if int(row.get("data_rebase", -1)) != data_rebase:
        return False, "data_rebase_mismatch"
    if not row.get("ds_descriptor_valid") or not row.get("w3_173_wscreen_pointer_valid"):
        return False, "descriptor_or_pointer_invalid"
    if not row.get("w3_173_sample_bounds_valid") or not row.get("w3_173_sample_valid"):
        return False, "sample_bounds_invalid"
    if int(row.get("w3_173_sample_bytes", -1)) != 48:
        return False, "sample_size_invalid"
    windows = row.get("w3_173_sample_windows")
    if not isinstance(windows, list) or [int(w.get("offset", -1)) for w in windows] != list(WINDOWS):
        return False, "window_offsets_invalid"
    try:
        if any(int(w.get("bytes", -1)) != 16 or len(bytes.fromhex(w.get("hex", ""))) != 16
               for w in windows):
            return False, "window_length_invalid"
    except ValueError:
        return False, "window_hex_invalid"
    return True, "valid"


def classify(rows: list[dict[str, Any]]) -> dict[str, Any]:
    main = next((r for r in rows if r.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    call = next((r for r in rows if r.get("checkpoint") == "W3_173_SMACKDOFRAME_UNSMACK_CALL_BLOCK"), None)
    entry = next((r for r in rows if r.get("checkpoint") == "W3_173_UNSMACK_ENTRY"), None)
    ret = next((r for r in rows if r.get("checkpoint") == "W3_173_UNSMACK_RETURN"), None)
    frame_return = next((r for r in rows if r.get("checkpoint") == "W3_148_SMACKDOFRAME_RETURN"), None)
    if not main:
        return {"classification": "UNKNOWN", "reason": "MAIN anchor missing", "call_block": call,
                "unsmack_entry": entry, "unsmack_return": ret}
    code_rebase = int(main["eip"]) - int(main["link_va"])
    psp = int(main["process_psp"])
    data_rebase = int(entry.get("data_rebase", 0)) if entry else int(main.get("data_rebase", 0))
    if not entry:
        return {"classification": "NOT_OBSERVED", "reason": "_Unsmack entry not captured",
                "call_block_observed": call is not None,
                "frame_return_sequence": frame_return.get("sequence") if frame_return else None,
                "code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "psp": psp,
                "call_block": call, "unsmack_entry": None, "unsmack_return": ret}
    if int(entry.get("link_va", -1)) != 0xEDB20 or int(entry.get("eip", -1)) - code_rebase != 0xEDB20:
        return {"classification": "UNKNOWN", "reason": "_Unsmack mapping mismatch", "call_block": call,
                "unsmack_entry": entry, "unsmack_return": ret}
    entry_ok, entry_reason = _valid_sample(entry, psp=psp, data_rebase=data_rebase, point="unsmack_entry")
    if not ret:
        return {"classification": "ENTRY_ONLY", "reason": "dynamic return checkpoint missing",
                "entry_sample_valid": entry_ok, "entry_sample_reason": entry_reason,
                "call_block_observed": call is not None, "code_rebase": hex(code_rebase),
                "data_rebase": hex(data_rebase), "psp": psp,
                "call_block": call, "unsmack_entry": entry, "unsmack_return": None}
    ret_ok, ret_reason = _valid_sample(ret, psp=psp, data_rebase=data_rebase, point="unsmack_return")
    matching_return = (int(ret.get("eip", -1)) == int(entry.get("w3_173_expected_return_runtime", -2)) and
                       int(ret.get("link_va", -1)) == int(entry.get("w3_173_expected_return_link_va", -2)))
    return_mapping = int(ret.get("eip", -1)) - code_rebase == int(ret.get("link_va", -2))
    ordered = int(entry.get("sequence", 0)) < int(ret.get("sequence", 0))
    same_pointer = int(entry.get("w3_173_wscreen_pointer", -1)) == int(ret.get("w3_173_wscreen_pointer", -2))
    if not (entry_ok and ret_ok and matching_return and return_mapping and ordered and same_pointer):
        return {"classification": "UNKNOWN", "reason": "entry/return validation failed",
                "entry_sample_valid": entry_ok, "entry_sample_reason": entry_reason,
                "return_sample_valid": ret_ok, "return_sample_reason": ret_reason,
                "matching_return": matching_return, "return_mapping_valid": return_mapping,
                "event_order_valid": ordered,
                "same_pointer": same_pointer, "code_rebase": hex(code_rebase),
                "data_rebase": hex(data_rebase), "psp": psp,
                "call_block": call, "unsmack_entry": entry, "unsmack_return": ret}
    changed = [int(a["offset"]) for a, b in zip(entry["w3_173_sample_windows"], ret["w3_173_sample_windows"])
               if bytes.fromhex(a["hex"]) != bytes.fromhex(b["hex"])]
    return {"classification": "SAMPLED_BYTES_CHANGED" if changed else "SAMPLED_BYTES_STABLE",
            "reason": "valid natural entry and dynamically matched return",
            "code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "psp": psp,
            "call_block_observed": call is not None,
            "call_block_sequence": call.get("sequence") if call else None,
            "entry_sequence": entry["sequence"], "return_sequence": ret["sequence"],
            "frame_return_sequence": frame_return.get("sequence") if frame_return else None,
            "entry_sample_valid": True, "return_sample_valid": True,
            "matching_return": True, "return_mapping_valid": True, "same_pointer": True,
            "sample_bytes_total": int(entry["w3_173_sample_bytes"]) + int(ret["w3_173_sample_bytes"]),
            "sampled_offsets_changed": changed,
            "call_block": call, "unsmack_entry": entry, "unsmack_return": ret}


def _preflight() -> dict[str, Any]:
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic W3-067 fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    for token in ("W3_173_SMACKDOFRAME_UNSMACK_CALL_BLOCK", "W3_173_UNSMACK_ENTRY",
                  "W3_173_UNSMACK_RETURN", "w3_173_total_sample_bytes + 48 <= 96",
                  "GWRECOMP_W3_171_ENABLE_SAMPLES"):
        if token not in CORE.read_text(encoding="utf-8", errors="replace"):
            raise RuntimeError(f"W3-173 instrumentation missing {token}")
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-173 artifacts")
    return sandbox


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = _preflight()
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if stdout.exists() or stderr.exists():
        raise FileExistsError("refusing to overwrite W3-173 guard output")
    binary_sha = sha(DOSBOX)
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
        "GWRECOMP_W3_171_ENABLE_SAMPLES": "0",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-173 natural _Unsmack entry/return sample", "--commit-sha", REVISION,
               "--target-sha", GW_SHA256, "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "30",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("trace exceeded 1 MiB guard cap")
    rows = parse_jsonl(raw)
    result = classify(rows)
    result.update({
        "schema": "w3-173-unsmack-boundary/v1", "task": "W3-173", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": REVISION, "instrumented_core_sha256": sha(CORE),
                   "staging_binary_sha256": binary_sha},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True, "timeout_seconds": 30,
                      "trace_cap_bytes": MAX_TRACE_BYTES, "sample_offsets": list(WINDOWS),
                      "sample_window_bytes": 16, "max_new_sample_bytes": 96,
                      "legacy_w3_171_sampling_disabled": True, "global_trace": False,
                      "guest_state_modified": False},
        "guard": {key: guard.get(key) for key in ("run_id", "operation", "sandbox_verified",
                 "sandbox_capacity", "host_free_before", "host_free_after", "limits", "exit_reason",
                 "cause", "detail", "exit_code", "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None, "event_count": len(rows)},
        "limitations": ["Only three 16-byte WScreen windows were sampled at valid _Unsmack entry/return points.",
                        "Sparse samples do not characterize the full 64000-byte WScreen buffer.",
                        "The guard may terminate the run after evidence capture; natural process completion is not implied."]
    })
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result.get("classification"),
                      "call_block_observed": result.get("call_block_observed"),
                      "sample_bytes_total": result.get("sample_bytes_total"),
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
