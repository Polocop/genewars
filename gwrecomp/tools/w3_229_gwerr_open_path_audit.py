#!/usr/bin/env python3
"""Build a bounded source/trace audit for W3-229; never launches the oracle."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/w3_228_gwerr_caller_capture.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_228_GWERR_CALLER_20261009_01.jsonl"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src"
OUTPUT = ROOT / "evidence/w3_229_gwerr_open_path_audit.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_trace(path: Path) -> list[dict]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def _callsite_inventory(source_root: Path) -> list[dict]:
    calls = []
    for path in sorted(source_root.rglob("*.cpp")):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            if "DOS_OpenFile(" not in line:
                continue
            if re.search(r"\bbool\s+DOS_OpenFile\s*\(", line):
                continue
            rel = path.relative_to(source_root).as_posix()
            service = "internal DOSBox caller; not a guest interrupt attribution"
            if rel == "dos/dos.cpp":
                service = "INT 21h AH=3Dh dispatch (direct call)"
            elif rel == "dos/dos_files.cpp" and index + 1 == 1050:
                service = "DOS_CreateFile helper (called by create/open-create paths)"
            elif rel == "dos/dos_files.cpp" and index + 1 == 1235:
                service = "DOS_OpenFileExtended helper (INT 21h AH=6Ch dispatch)"
            elif rel == "dos/dos_files.cpp" and index + 1 == 1757:
                service = "DOS_FCBOpen helper (FCB open/reopen path)"
            elif rel == "dos/dos_files.cpp" and index + 1 == 1972:
                service = "DOS_FCBGetFileSize helper (FCB/internal path)"
            calls.append({
                "source": rel,
                "line": index + 1,
                "expression": line.strip(),
                "service_or_context": service,
            })
    return calls


def build_audit(evidence_path: Path = EVIDENCE,
                trace_path: Path = TRACE,
                source_root: Path = SOURCE) -> dict:
    source_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    events = _read_trace(trace_path)
    handle_open = [e for e in events if e.get("event") == "dos_handle_open"
                   and e.get("process_psp") == 7811
                   and e.get("path", "").upper().endswith("GW.ERR")]
    ah3d_for_gwerr = [e for e in events if e.get("event") == "setup_dos_api"
                      and e.get("operation") == "INT21_AH3D"
                      and "GW.ERR" in e.get("requested_path", "").upper()]
    all_ah3d = [e for e in events if e.get("event") == "setup_dos_api"
                and e.get("operation") == "INT21_AH3D"]
    cpu_open = [e for e in events if e.get("event") == "original_cpu_int21_gwerr_open_entry"]
    checkpoints = [e for e in events if e.get("event") == "target_runtime_checkpoint"]
    fb = [e for e in source_evidence["execution_frontier"].get("video_checkpoints", [])
          if e.get("checkpoint") == "VIDEO_FRAMEBUFFER_ASSIGN_AFTER"]
    last = max(checkpoints, key=lambda e: e.get("sequence", -1), default=None)
    sites = _callsite_inventory(source_root)
    code = (source_root / "dos/dos.cpp").read_text(encoding="utf-8", errors="replace")
    files = (source_root / "dos/dos_files.cpp").read_text(encoding="utf-8", errors="replace")
    evidence_hash = sha256(evidence_path)
    trace_hash = sha256(trace_path)
    return {
        "schema": "gwrecomp.w3-229-gwerr-open-path-audit/v1",
        "task": "W3-229",
        "classification": "SERVICE_UNKNOWN_AH6C_PLAUSIBLE_NOT_PROVEN",
        "evidence_level": "ORIGINAL_OBSERVED",
        "provenance": {
            "source_task": "W3-228",
            "source_evidence": str(evidence_path.relative_to(ROOT)).replace("\\", "/"),
            "source_evidence_sha256": evidence_hash,
            "trace": str(trace_path.relative_to(ROOT)).replace("\\", "/"),
            "trace_sha256": trace_hash,
            "trace_bytes": trace_path.stat().st_size,
            "staging_revision": source_evidence["preflight"]["staging_revision"],
            "target_sha256": source_evidence["preflight"]["fixture_sha256"],
            "run_id": source_evidence["run_id"],
        },
        "observed": {
            "gwerr_handle_open": handle_open,
            "gwerr_ah3d_dispatch_rows": ah3d_for_gwerr,
            "all_ah3d_dispatch_rows_in_trace": len(all_ah3d),
            "w3_228_cpu_entry_rows": cpu_open,
            "target_psp": source_evidence["capture"]["open_event"]["process_psp"],
            "dispatch_hook_result": source_evidence["capture"]["classification"],
            "trace_event_count": len(events),
            "trace_cap_bytes": source_evidence["preflight"]["trace_max_bytes"],
            "trace_under_cap": trace_path.stat().st_size < source_evidence["preflight"]["trace_max_bytes"],
            "sequence_51_has_following_ah3d_record": any(e.get("sequence", -1) > 51 for e in all_ah3d),
        },
        "source_dispatch_facts": {
            "ah3d": {
                "source": "third_party/dosbox-staging-w3-059-instrumented/src/dos/dos.cpp",
                "line_range": [1086, 1105],
                "behavior": "INT 21h AH=3Dh reads pathname DS:DX, calls DOS_OpenFile(name, AL, ...), then emits setup_dos_api INT21_AH3D after the generic open call.",
                "verified_source_patterns": all(x in code for x in ["case 0x3d", "DOS_OpenFile(name1, reg_al, &entry)", 'trace_setup_dos_api("INT21_AH3D"']),
            },
            "ah6c": {
                "source": "third_party/dosbox-staging-w3-059-instrumented/src/dos/dos.cpp",
                "line_range": [1789, 1798],
                "behavior": "INT 21h AH=6Ch reads pathname DS:SI and calls DOS_OpenFileExtended; that helper calls DOS_OpenFile with flags & 0xff. The dispatcher has no matching setup_dos_api event in this path.",
                "verified_source_patterns": "DOS_OpenFileExtended(name1, reg_bx, reg_cl, reg_dx" in code and "DOS_OpenFile(name, (uint8_t)(flags&0xff), entry)" in files,
                "assessment": "Plausible because the generic GW.ERR event reports flags=1, but no AH=6Ch entry registers were captured; not proven.",
            },
            "fcb": {
                "source": "third_party/dosbox-staging-w3-059-instrumented/src/dos/dos.cpp and src/dos/dos_files.cpp",
                "behavior": "AH=0F dispatches DOS_FCBOpen; FCB open uses DOS_OpenFile(..., OPEN_READWRITE, ..., true), while FCB create routes through DOS_CreateFile. Generic flags=1 does not match the observed FCB-open helper's OPEN_READWRITE value in this source.",
                "assessment": "FCB route is less consistent with flags=1 but cannot be excluded solely from the generic event without dispatch-entry capture.",
            },
            "generic_event": {
                "source": "third_party/dosbox-staging-w3-059-instrumented/src/dos/dos_files.cpp",
                "line_range": [1180, 1190],
                "behavior": "dos_handle_open is emitted within DOS_OpenFile with path, PSP handle entry, internal handle, and flags; it does not encode the DOS interrupt/service that reached DOS_OpenFile.",
            },
            "dos_openfile_callsite_inventory": sites,
            "dos_openfile_callsite_count": len(sites),
            "source_hashes": {
                "dos.cpp": sha256(source_root / "dos/dos.cpp"),
                "dos_files.cpp": sha256(source_root / "dos/dos_files.cpp"),
            },
        },
        "execution_frontier": {
            "timeout_seconds": source_evidence["preflight"]["timeout_seconds"],
            "stop_cause": source_evidence["execution_frontier"]["dosbox_stop_cause"],
            "stop_detail": source_evidence["execution_frontier"]["dosbox_stop_detail"],
            "last_target_checkpoint": last,
            "framebuffer_assign_after": [{
                "sequence": e.get("sequence"),
                "eip": e.get("eip"),
                "link_va": e.get("link_va"),
                "pointer_value_u32": next((s.get("value_u32") for s in e.get("framebuffer_global_samples", [])
                                            if s.get("value_u32") is not None), None),
                "sample_bytes": e.get("sample_bytes"),
            } for e in fb],
            "first_framebuffer_verified": False,
            "menu_verified": False,
            "gameplay_verified": False,
        },
        "conclusion": {
            "proven": "The original process opened GENEWARS\\GW.ERR and DOSBox-Staging recorded flags=1 and PSP handle 2. No matching AH=3Dh dispatch row or W3-228 pre-dispatch CPU row exists. Other AH=3Dh events occur later in the same trace, and the trace is below its byte cap.",
            "not_proven": "The originating DOS service, AH=6Ch specifically, the caller, its input registers, and any causal relationship to the native divergence.",
            "next_instrumentation": "Add bounded target-PSP pre-dispatch records for INT 21h AH=3Dh (DS:DX) and AH=6Ch (DS:SI), plus FCB AH=0F/AH=16 dispatch entry, all filtered to the exact normalized GW.ERR path and one event. Keep the generic handle event for correlation; replay only after that hook is compiled and synthetically validated.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = build_audit()
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.write:
        OUTPUT.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
