#!/usr/bin/env python3
"""Audit only the already-recorded W3-231 GW.ERR and AX=4400 BX=1 events."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import hashlib
import json
import os
from pathlib import Path

ROOT = Path((_GW_ROOT))
W3_231 = ROOT / "evidence/w3_231_gwerr_dispatch_capture.json"
W3_221 = ROOT / "evidence/original_ax4400_bx1_alignment_w3_221.json"
W1_074 = ROOT / "evidence/native_address_ax4400_w1_074.json"
W1_077 = ROOT / "evidence/native_gwerr_lifecycle_w1_077.json"
OUT = ROOT / "evidence/w3_232_gwerr_ax4400_chronology.json"
REPORT = ROOT / "reports/coordination/w3_232_gwerr_ax4400_chronology.md"
MAX_TRACE = 1024 * 1024
MAX_EVENTS = 4096


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_same_run(events: list[dict]) -> dict:
    if len(events) > MAX_EVENTS:
        raise ValueError("event count exceeds bounded audit limit")
    dispatch = next((e for e in events if e.get("event") ==
                     "w3_230_gwerr_dos_dispatch_entry" and
                     e.get("service") == "INT21_AH3D" and
                     e.get("requested_path", "").upper() == "GW.ERR"), None)
    if dispatch is None:
        raise ValueError("original GW.ERR AH=3D dispatch event is absent")
    opened = next((e for e in events if e.get("event") == "dos_handle_open" and
                   e.get("sequence", -1) > dispatch.get("sequence", -1) and
                   e.get("process_psp") == dispatch.get("process_psp") and
                   e.get("path", "").upper() == "GENEWARS\\GW.ERR"), None)
    if opened is None:
        raise ValueError("same-PSP GW.ERR handle-open event is absent")
    caller = next((e for e in events if e.get("event") ==
                   "original_cpu_int21_ah44_bx1_entry" and
                   e.get("sequence", -1) > opened.get("sequence", -1) and
                   e.get("process_psp") == dispatch.get("process_psp") and
                   e.get("eax") == 0x4400 and e.get("ebx") == 1 and
                   e.get("mapping_valid") is True and
                   e.get("int21_bytes_verified") is True and
                   e.get("int_instruction_link_va") == 0xC8973), None)
    if caller is None:
        raise ValueError("mapped original AX=4400 BX=1 INT at link VA C8973 absent")
    callback = next((e for e in events if e.get("event") == "setup_dos_api" and
                     e.get("sequence", -1) > caller.get("sequence", -1) and
                     e.get("process_psp") == caller.get("process_psp") and
                     e.get("operation") == "INT21_AH44" and
                     e.get("in_ax") == 0x4400 and e.get("in_bx") == 1 and
                     e.get("ordinal") == caller.get("setup_dos_api_callback_ordinal")), None)
    if callback is None:
        raise ValueError("same-PSP matching post-entry AH=44 callback absent")
    if not (dispatch["sequence"] < opened["sequence"] < caller["sequence"] < callback["sequence"]):
        raise ValueError("unexpected same-run event order")
    if len({dispatch.get("process_psp"), opened.get("process_psp"),
            caller.get("process_psp"), callback.get("process_psp")}) != 1:
        raise ValueError("events do not share one PSP")
    if dispatch.get("in_ax") != 0x3D01:
        raise ValueError("GW.ERR dispatch AX does not match captured AH=3D01")
    return {
        "same_run": True,
        "process_psp": dispatch["process_psp"],
        "event_order": [dispatch["sequence"], opened["sequence"],
                        caller["sequence"], callback["sequence"]],
        "gwerr_dispatch": {k: dispatch.get(k) for k in (
            "sequence", "service", "in_ax", "in_bx", "in_cx", "in_dx",
            "in_eflags", "cs", "eip", "cs_base", "code_linear", "ds",
            "ds_base", "requested_path", "context_note")},
        "gwerr_open": {k: opened.get(k) for k in (
            "sequence", "path", "requested_path", "entry", "internal_handle", "flags")},
        "ax4400_bx1_entry": {k: caller.get(k) for k in (
            "sequence", "cpu_entry_ordinal", "setup_dos_api_callback_ordinal",
            "process_psp", "cs_selector", "cs_base", "old_eip", "linear",
            "main_code_rebase", "mapping_valid", "return_link_va",
            "int_opcode_0", "int_opcode_1", "int21_bytes_verified",
            "int_instruction_link_va", "eax", "ebx", "ecx", "edx", "esi",
            "edi", "ebp", "esp", "ds", "es", "ss", "eflags",
            "sample_status", "sample_length", "sample_bytes_hex",
            "value_at_plus_0x10_valid", "value_at_plus_0x10")},
        "ax4400_callback": {k: callback.get(k) for k in (
            "sequence", "ordinal", "operation", "in_ax", "in_bx", "in_cx",
            "in_dx", "in_eflags", "out_ax", "out_bx", "out_cx", "out_dx",
            "out_eflags", "cf", "result", "entry", "resolved_path",
            "default_drive", "cwd", "dos_error")},
        "limitations": {
            "ah3d_dos_return_ax_cf": "not captured",
            "protected_mode_caller_of_ah3d": "unknown; callback CS:EIP is DOS dispatcher context",
            "ax4400_callback_is_post_iret_guest_state": False,
            "causality_from_gwerr_to_ax4400_state": "not established; only same-run temporal order is measured",
        },
    }


def build_evidence() -> dict:
    w3 = json.loads(W3_231.read_text(encoding="utf-8"))
    trace_info = w3["trace"]
    trace_path = Path(trace_info["path"])
    if not trace_path.is_file():
        raise FileNotFoundError(trace_path)
    trace_bytes = trace_path.stat().st_size
    if trace_bytes > MAX_TRACE or trace_bytes != trace_info["bytes"]:
        raise ValueError("W3-231 trace size does not match bounded manifest")
    trace_hash = sha256(trace_path)
    if trace_hash != trace_info["sha256"]:
        raise ValueError("W3-231 trace SHA-256 mismatch")
    lines = trace_path.read_bytes().splitlines()
    events = [json.loads(line) for line in lines if line.strip()]
    if len(events) != trace_info["event_count"]:
        raise ValueError("W3-231 trace event count mismatch")
    w3_221 = json.loads(W3_221.read_text(encoding="utf-8"))
    w1_074 = json.loads(W1_074.read_text(encoding="utf-8"))
    w1_077 = json.loads(W1_077.read_text(encoding="utf-8"))
    chronology = extract_same_run(events)
    return {
        "schema": "gwrecomp.same-run-gwerr-to-ax4400-bx1-chronology-w3-232/v1",
        "task": "W3-232",
        "classification": "ORIGINAL_OBSERVED_SAME_RUN_ORDER_NO_CAUSALITY",
        "evidence_level": "ORIGINAL_OBSERVED",
        "source_evidence": {
            "w3_231": {"path": str(W3_231), "sha256": sha256(W3_231),
                        "trace_path": str(trace_path), "trace_bytes": trace_bytes,
                        "trace_sha256": trace_hash, "event_count": len(events),
                        "run_id": w3.get("run_id")},
            "w3_221": {"path": str(W3_221), "sha256": sha256(W3_221),
                        "classification": w3_221.get("classification")},
            "w1_074": {"path": str(W1_074), "sha256": sha256(W1_074)},
            "w1_077": {"path": str(W1_077), "sha256": sha256(W1_077)},
        },
        "fixture": {
            "gw_sha256": w3["preflight"]["fixture_sha256"],
            "staging_revision": w3["preflight"]["staging_revision"],
            "runtime_sha256": w3["preflight"]["dosbox_sha256"],
            "config_sha256": w3["preflight"]["config_sha256"],
            "cue_sha256": w3["preflight"]["cue_sha256"],
            "cue_read_only_mount": w3["preflight"]["cue_read_only"],
            "launch": w3["preflight"]["launch"],
            "guard_used": w3["scope"]["oracle_guard_used"],
            "sandbox_verified": w3["scope"]["sandbox_verified"],
        },
        "chronology": chronology,
        "cross_run_comparison": w3_221["native_comparison"],
        "native_gwerr_observation": "W1-077 reports native AH=3Dh failure (DOS error 2) followed by AH=3Ch create in a separate native run. W3-232 does not establish that this caused the native BX sequence divergence.",
        "interpretation": {
            "measured": "Within one original Staging replay, AH=3D01 for GW.ERR and handle entry 2 occur before a mapped AX=4400 BX=1 call at link VA 0xC8973; its correlated DOS callback reports AX=DX=0x80D3 and CF=0.",
            "not_demonstrated": ["AH=3D guest-visible AX/CF return", "protected-mode caller of AH=3D", "causal link from GW.ERR to the later BX=1 state", "native/original seed equivalence"],
        },
    }


def write_atomic(path: Path, content: str) -> None:
    temp = path.with_name(path.name + ".tmp")
    with temp.open("x", encoding="utf-8", newline="\n") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def run() -> dict:
    evidence = build_evidence()
    encoded = json.dumps(evidence, indent=2, ensure_ascii=False) + "\n"
    if len(encoded.encode("utf-8")) > 64 * 1024:
        raise ValueError("evidence JSON exceeded 64 KiB")
    report = """# W3-232 — Same-run GW.ERR to AX=4400 BX=1 chronology

**Result:** ORIGINAL_OBSERVED_SAME_RUN_ORDER_NO_CAUSALITY.

The recorded W3-231 Staging run shows the original `INT 21h AH=3D` request for `GW.ERR` at event 51 and the corresponding generic handle-open at event 52. In the same PSP and replay, a verified mapped `INT 21h AX=4400 BX=1` occurs at event 104; its DOS callback is recorded at event 107.

The target identity, Staging revision, functional config, CUE hash, read-only CUE mount, guard, and measured `-k 38928` launch are inherited from the hash-verified W3-231 evidence. This task parses existing evidence only and runs no emulator.

At the mapped AH=44 entry, the INT instruction is link VA `0xC8973`, and the return link is `0xC8975`. The entry records AX=`0x4400`, BX=`1`, EFLAGS=`0x246`, PSP `7811`, and verified CS mapping/rebase. The same-run callback row records AX=DX=`0x80D3`, CF clear, handle entry 1 resolved to `CON`, CWD `GENEWARS`. This is the DOS callback snapshot; the evidence does not claim a guest post-IRET register snapshot.

W3-221 already measured the original BX=1 caller and compared it to W1-074. W3-232 adds the immediately preceding original GW.ERR open to that same-run chronology. W1-077's native AH=3D failure followed by AH=3C create is a separate execution. The sequence is temporal evidence only: it does not prove the GW.ERR operation caused the later native/original BX divergence.

First framebuffer, menu, and gameplay remain unverified in W3-231 (zero pixel bytes sampled). No task state or dependency outside WORK3 was changed.
"""
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(OUT, encoded)
    write_atomic(REPORT, report)
    return evidence


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, ensure_ascii=False))
