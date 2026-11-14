#!/usr/bin/env python3
"""One bounded, guarded replay sampling WScreen at two natural checkpoints."""
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
RUN_ID = "w3-171-wscreen-frame-boundary-20261009-01"
TRACE = MOUNT / "W3_171_WSCREEN_FRAME_BOUNDARY_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_171_wscreen_frame_boundary.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
WINDOWS = (0, 32000, 63984)
EXPECTED = {
    "frame_return": ("W3_148_SMACKDOFRAME_RETURN", 0xAE466),
    "copy_pre": ("W3_151_COPY_NONVESA_PRE", 0xA0013),
}


def validate_checkpoint(row: dict[str, Any] | None, *, name: str, link_va: int,
                        psp: int, code_rebase: int, data_rebase: int,
                        point: str) -> tuple[bool, str]:
    if row is None or row.get("checkpoint") != name or int(row.get("link_va", -1)) != link_va:
        return False, "checkpoint_missing_or_wrong_address"
    if int(row.get("process_psp", -1)) != psp:
        return False, "process_psp_mismatch"
    if int(row.get("eip", -1)) - code_rebase != link_va:
        return False, "code_mapping_mismatch"
    if int(row.get("w3_171_data_rebase", -1)) != data_rebase:
        return False, "data_mapping_mismatch"
    if row.get("w3_171_sample_point") != point:
        return False, "sample_point_mismatch"
    if not (row.get("w3_171_wscreen_global_valid") and
            row.get("w3_171_wscreen_pointer_valid") and
            row.get("w3_171_sample_bounds_valid") and
            row.get("w3_171_sample_valid")):
        return False, "descriptor_or_pointer_bounds_invalid"
    if point == "copy_pre" and not row.get("w3_171_pointer_matches_copy_source"):
        return False, "copy_source_pointer_mismatch"
    if int(row.get("w3_171_sample_bytes", -1)) != 48:
        return False, "sample_byte_count_mismatch"
    windows = row.get("w3_171_sample_windows")
    if not isinstance(windows, list) or [int(w.get("offset", -1)) for w in windows] != list(WINDOWS):
        return False, "sample_offsets_mismatch"
    if any(int(w.get("bytes", -1)) != 16 or len(bytes.fromhex(w.get("hex", ""))) != 16
           for w in windows):
        return False, "sample_window_length_mismatch"
    return True, "valid"


def compare_samples(frame_row: dict[str, Any] | None, copy_row: dict[str, Any] | None,
                    *, psp: int, code_rebase: int, data_rebase: int) -> dict[str, Any]:
    frame_valid, frame_reason = validate_checkpoint(
        frame_row, name=EXPECTED["frame_return"][0], link_va=EXPECTED["frame_return"][1],
        psp=psp, code_rebase=code_rebase, data_rebase=data_rebase, point="smackdoframe_return")
    copy_valid, copy_reason = validate_checkpoint(
        copy_row, name=EXPECTED["copy_pre"][0], link_va=EXPECTED["copy_pre"][1],
        psp=psp, code_rebase=code_rebase, data_rebase=data_rebase, point="copy_pre")
    if not (frame_valid and copy_valid):
        return {"classification": "UNKNOWN", "frame_valid": frame_valid,
                "frame_reason": frame_reason, "copy_valid": copy_valid,
                "copy_reason": copy_reason, "sample_bytes_total": 0}
    if int(frame_row["sequence"]) >= int(copy_row["sequence"]):
        return {"classification": "UNKNOWN", "frame_valid": False,
                "frame_reason": "event_order_invalid", "copy_valid": copy_valid,
                "copy_reason": copy_reason, "sample_bytes_total": 0}
    if int(frame_row["w3_171_wscreen_pointer"]) != int(copy_row["w3_171_wscreen_pointer"]):
        return {"classification": "UNKNOWN", "frame_valid": False,
                "frame_reason": "wscreen_pointer_changed", "copy_valid": copy_valid,
                "copy_reason": copy_reason, "sample_bytes_total": 0}
    differences = []
    for before, after in zip(frame_row["w3_171_sample_windows"], copy_row["w3_171_sample_windows"]):
        if bytes.fromhex(before["hex"]) != bytes.fromhex(after["hex"]):
            differences.append(int(before["offset"]))
    return {"classification": "SAMPLED_BYTES_CHANGED" if differences else "SAMPLED_BYTES_STABLE",
            "frame_valid": True, "frame_reason": "valid", "copy_valid": True,
            "copy_reason": "valid", "sample_bytes_total": 96,
            "sampled_offsets_changed": differences,
            "same_wscreen_pointer": True,
            "sequence_order_valid": True}


def _assert_preflight() -> dict[str, Any]:
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
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b",
                     CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    got_revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=10,
                                  check=True).stdout.strip()
    if got_revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {got_revision}")
    core = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("W3_148_SMACKDOFRAME_RETURN", "W3_151_COPY_NONVESA_PRE",
                  "w3_171_sample_point", "w3_171_wscreen_pointer_valid",
                  "w3_171_sample_bounds_valid", "w3_171_total_sample_bytes + 48 <= 96",
                  "w3_171_sample_windows"):
        if token not in core:
            raise RuntimeError(f"bounded frame-boundary sampler missing {token}")
    if any(path.exists() for path in (TRACE, RESULT)):
        raise FileExistsError("refusing to overwrite W3-171 artifacts")
    return sandbox


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = _assert_preflight()
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if stdout.exists() or stderr.exists():
        raise FileExistsError("refusing to overwrite W3-171 guard output")
    core_sha = sha(CORE)
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
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
               "--run-id", RUN_ID, "--operation", "W3-171 WScreen frame-boundary samples",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
               "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("trace exceeded configured 1 MiB cap")
    rows = parse_jsonl(raw)
    main_entry = next((r for r in rows if r.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    frame_row = next((r for r in rows if r.get("checkpoint") == EXPECTED["frame_return"][0]
                      and r.get("link_va") == EXPECTED["frame_return"][1]), None)
    copy_row = next((r for r in rows if r.get("checkpoint") == EXPECTED["copy_pre"][0]
                     and r.get("link_va") == EXPECTED["copy_pre"][1]), None)
    code_rebase = int(main_entry["eip"] - main_entry["link_va"]) if main_entry else 0
    data_rebase = int(main_entry.get("data_rebase", 0)) if main_entry else 0
    if frame_row and frame_row.get("w3_171_data_rebase"):
        data_rebase = int(frame_row["w3_171_data_rebase"])
    comparison = compare_samples(frame_row, copy_row, psp=int(main_entry["process_psp"]),
                                 code_rebase=code_rebase, data_rebase=data_rebase) if main_entry else {
                                     "classification": "UNKNOWN", "reason": "MAIN anchor missing"}
    result = {
        "schema": "w3-171-original-wscreen-frame-boundary/v1", "task": "W3-171",
        "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": REVISION, "instrumented_core_sha256": core_sha,
                   "staging_binary_sha256": binary_sha},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                      "sample_offsets": list(WINDOWS), "sample_window_bytes": 16,
                      "max_sample_bytes_total": 96, "global_trace": False,
                      "guest_state_modified": False},
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
            "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
            "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows)},
        "mapping": {"code_rebase": hex(code_rebase) if code_rebase else None,
                    "data_rebase": hex(data_rebase) if data_rebase else None,
                    "fresh_main_anchor": main_entry is not None,
                    "psp": main_entry.get("process_psp") if main_entry else None},
        "samples": {"smackdoframe_return": frame_row, "copy_pre": copy_row},
        "comparison": comparison,
        "limitations": ["Only the three fixed 16-byte windows were read at each requested checkpoint.",
                        "Sparse window equality/difference does not characterize the complete WScreen buffer.",
                        "This capture does not prove host VGA mapping, pixel interpretation, visible presentation, menu, or gameplay."],
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": comparison.get("classification"),
                      "frame_sample_valid": comparison.get("frame_valid"),
                      "copy_sample_valid": comparison.get("copy_valid"),
                      "sample_bytes_total": comparison.get("sample_bytes_total"),
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
