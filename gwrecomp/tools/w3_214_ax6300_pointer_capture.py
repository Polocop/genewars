"""One bounded guarded capture of the original AX=6300 returned DS:SI pointer."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_143_postopen_branch import parse_jsonl
from tools.w3_182_original_ax0300_capture_runner import (
    CONFIG, CONFIG_SHA256, CUE, CUE_SHA256, DOSBOX, FRAME_BYTES, GW_SHA256,
    GW_SIZE, GUARD, REVISION, SOURCE, W1_EVIDENCE, W3_140_EVIDENCE,
    _w1_context, _w3_140_context,
)

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
DOS_SOURCE = SOURCE / "src/dos/dos.cpp"
RUN_ID = "w3-214-ax6300-pointer-20261009-01"
TRACE = MOUNT / "W3_214_AX6300_POINTER_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_214_ax6300_pointer_capture.json"
GUARD_JSON = ROOT / "evidence/oracle_runs/oracle_runs_w3-214-ax6300-pointer-20261009-01.json"
GUARD_STDOUT = GUARD_JSON.with_name(GUARD_JSON.stem + ".stdout.json")
GUARD_STDERR = GUARD_JSON.with_name(GUARD_JSON.stem + ".stderr.txt")
ENTRY_LINK = 0xBC765
RETURN_LINK = 0xBC767
MAIN_LINK = 0xAF96C
MAX_TRACE_BYTES = 1_048_576
SAMPLE_BYTES = 16


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mains = [r for r in rows if r.get("event") == "target_code_anchor" and
             r.get("anchor") == "MAIN_ENTRY" and r.get("link_va") == MAIN_LINK]
    entries = [r for r in rows if r.get("checkpoint") == "W3_182_DPMI0300_ENTRY"]
    returns = [r for r in rows if r.get("checkpoint") == "W3_182_DPMI0300_RETURN"]
    main = mains[0] if len(mains) == 1 else None
    entry = entries[0] if len(entries) == 1 else None
    returned = returns[0] if len(returns) == 1 else None
    rebase = main.get("candidate_rebase") if main else None
    mapping_valid = bool(main and main.get("byte_signature_matches") is True and
                         entry and returned and
                         int(entry.get("eip", -1)) - rebase == ENTRY_LINK and
                         int(returned.get("eip", -1)) - rebase == RETURN_LINK and
                         int(entry.get("process_psp", -1)) == int(main.get("process_psp", -2)) and
                         int(returned.get("process_psp", -1)) == int(main.get("process_psp", -2)))
    frame_valid = bool(returned and returned.get("w3_182_frame_valid") is True and
                       int(returned.get("w3_182_frame_bytes", 0)) == FRAME_BYTES and
                       len(str(returned.get("w3_182_frame_hex", ""))) == FRAME_BYTES * 2)
    frame_bytes = bytes.fromhex(returned["w3_182_frame_hex"]) if frame_valid else b""
    inner_eax = int.from_bytes(frame_bytes[28:32], "little") if frame_valid else None
    inner_flags = int.from_bytes(frame_bytes[32:34], "little") if frame_valid else None
    frame_ds = int.from_bytes(frame_bytes[36:38], "little") if frame_valid else None
    frame_si = int.from_bytes(frame_bytes[4:6], "little") if frame_valid else None
    pointer_valid = bool(returned and returned.get("w3_214_capture_enabled") is True and
                         returned.get("w3_214_pointer_valid") is True and
                         frame_valid)
    bounds_valid = bool(pointer_valid and returned.get("w3_214_pointer_bounds_valid") is True and
                         int(returned.get("w3_214_sample_bytes", 0)) == SAMPLE_BYTES and
                         len(str(returned.get("w3_214_sample_hex", ""))) == SAMPLE_BYTES * 2)
    source_match = bool(pointer_valid and returned.get("w3_214_matches_dos_dbcs_table") is True and
                        int(returned.get("w3_214_inner_ds", -1)) ==
                        int(returned.get("w3_214_dos_dbcs_segment", -2)) and
                        int(returned.get("w3_214_inner_si", -1)) ==
                        int(returned.get("w3_214_dos_dbcs_offset", -2)) and
                        int(returned.get("w3_214_inner_linear", -1)) ==
                        int(returned.get("w3_214_dos_dbcs_linear", -2)))
    inner_service_valid = bool(frame_valid and inner_eax is not None and
                               (inner_eax & 0xFFFF) == 0x6300 and
                               inner_flags is not None and (inner_flags & 1) == 0 and
                               frame_ds == int(returned.get("w3_214_inner_ds", -1)) and
                               frame_si == int(returned.get("w3_214_inner_si", -1)))
    launch_chain = [r for r in rows if r.get("event") == "dos_execute" and
                    str(r.get("executable", "")).upper() in
                    {"GENEWARS.EXE", "GW.EXE", "DOS4GW.EXE"}]
    complete = (mapping_valid and frame_valid and inner_service_valid and pointer_valid and
                bounds_valid and source_match)
    return {
        "classification": "ORIGINAL_DBCS_POINTER_CAPTURED" if complete else "INCONCLUSIVE",
        "main_code_rebase": rebase,
        "main_anchor_signature_match": bool(main and main.get("byte_signature_matches")),
        "mapping_valid": mapping_valid,
        "entry_count": len(entries),
        "return_count": len(returns),
        "frame_valid": frame_valid,
        "returned_int21": {"eax": inner_eax, "ax": inner_eax & 0xFFFF if inner_eax is not None else None,
                           "eflags": inner_flags, "cf": bool(inner_flags & 1) if inner_flags is not None else None,
                           "ds": frame_ds, "si": frame_si,
                           "service_valid": inner_service_valid},
        "pointer_valid": pointer_valid,
        "real_mode_bounds_valid": bounds_valid,
        "matches_dos_tables_dbcs": source_match,
        "entry": entry,
        "return": returned,
        "launch_chain": launch_chain,
        "last_event": rows[-1] if rows else None,
        "missing": [name for name, ok in (
            ("unique MAIN anchor", main is not None),
            ("natural AX=0300 entry", entry is not None),
            ("natural return at 0xBC767", returned is not None),
            ("valid bounded returned DS:SI sample", bounds_valid),
            ("same-run match with dos.tables.dbcs", source_match)) if not ok],
        "limitations": [
            "The 86-byte authenticated environment and PSP tail from W3-140 are cross-run context; W3-184 independently observed the same tail but its PSP:2C sample was not the returned DS:SI payload.",
            "The sampled table bytes describe this DOSBox Staging original replay; they are not generalized to other DOS versions.",
        ],
    }


def preflight() -> dict[str, Any]:
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DOS_SOURCE,
                 W1_EVIDENCE, W3_140_EVIDENCE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic W3-067 fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    config_text = CONFIG.read_text(encoding="utf-8")
    if "GENEWARS.EXE" not in config_text.upper() or "-RO" not in config_text.upper():
        raise RuntimeError("functional launcher or read-only CUE mount not verified")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    dos_source = DOS_SOURCE.read_text(encoding="utf-8", errors="replace")
    for token in ("case 0x63", "RealSegment(dos.tables.dbcs)",
                  "RealOffset(dos.tables.dbcs)", "CALLBACK_SCF(false)"):
        if token not in dos_source:
            raise RuntimeError(f"pinned DOS AX=6300 implementation missing {token}")
    core = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("GWRECOMP_W3_214_CAPTURE_ONLY", "GWRECOMP_W3_214_CAPTURE_DBCS_POINTER",
                  "w3_214_matches_dos_dbcs_table", "w3_214_pointer_bounds_valid"):
        if token not in core:
            raise RuntimeError(f"W3-214 instrumentation missing {token}")
    w1, w3_140 = _w1_context(), _w3_140_context()
    if w3_140.get("original_psp_tail") != w1.get("command_tail"):
        raise RuntimeError("original and native request command tails do not reconcile")
    for path in (TRACE, RESULT, GUARD_JSON, GUARD_STDOUT, GUARD_STDERR):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite W3-214 artifact: {path}")
    return {
        "sandbox": sandbox, "source_revision": revision,
        "target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
        "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
        "instrumented_core_sha256": sha(CORE), "dos_source_sha256": sha(DOS_SOURCE),
        "runtime_sha256": sha(DOSBOX), "psp_tail": w3_140["original_psp_tail"],
        "w3_140_environment_sha256": w3_140["environment_sha256"],
        "w3_140_environment_bytes": w3_140["environment_sample_bytes"],
        "environment_is_cross_run": True,
        "trace_path": str(TRACE), "trace_cap_bytes": MAX_TRACE_BYTES,
        "sample_cap_bytes": SAMPLE_BYTES, "timeout_seconds": 10,
    }


def run_capture() -> dict[str, Any]:
    check = preflight()
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
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
        "GWRECOMP_W3_214_CAPTURE_ONLY": "1",
        "GWRECOMP_W3_214_CAPTURE_DBCS_POINTER": "1",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-214 natural original AX=6300 returned DBCS pointer sample",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", check["runtime_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "10", "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
               "--poll-hz", "1"]
    with GUARD_STDOUT.open("xb") as out, GUARD_STDERR.open("xb") as err:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                              timeout=20, check=False)
    guard = json.loads(GUARD_STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_jsonl(raw)
    capture = summarize(rows)
    retained_guard = {key: guard.get(key) for key in (
        "run_id", "sandbox_verified", "sandbox", "limits", "exit_reason", "cause",
        "duration_s", "killed_processes", "host_free_before", "host_free_after",
        "max_staging_seen", "ok", "evidence_path") if key in guard}
    result = {
        "schema": "w3-214-original-ax6300-pointer/v1", "task": "W3-214",
        "run_id": RUN_ID, "source": check,
        "guard": retained_guard, "guard_process_returncode": proc.returncode,
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows), "max_bytes": MAX_TRACE_BYTES},
        "capture": capture,
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    result = preflight() if "--preflight-only" in sys.argv[1:] else run_capture()
    print(json.dumps({"task": "W3-214", "run_id": RUN_ID,
                      "guard": result.get("guard"), "trace": result.get("trace"),
                      "capture": result.get("capture")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-214 FAIL CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
