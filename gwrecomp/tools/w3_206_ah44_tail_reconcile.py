"""Read-only extraction of the natural BX=1 call already in W3-203 trace."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W3_203 = ROOT / "evidence/w3_203_bscreen_free_sample.json"
TRACE_REL = "build/dosboxx_oracle/C/W3_203_BSCREEN_FREE_20261009_01.jsonl"
W3_095 = ROOT / "evidence/w3_095_original_psp_tail.json"
W1_NATIVE = ROOT / "evidence/native_ah44_bx1_callsite_work1.json"


def audit() -> dict:
    manifest = json.loads(W3_203.read_text(encoding="utf-8"))
    w3_095 = json.loads(W3_095.read_text(encoding="utf-8"))
    native = json.loads(W1_NATIVE.read_text(encoding="utf-8"))
    trace_path = ROOT / TRACE_REL
    raw = trace_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["trace"]["sha256"]:
        raise ValueError("W3-203 trace hash mismatch")
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    original = next((r for r in rows if r.get("event") == "original_cpu_int21_ah44_bx1_entry"
                     and r.get("cs_selector") == 0x160 and r.get("int_instruction_link_va") == 0xC8973), None)
    tail = next((r for r in rows if r.get("event") == "w3_095_original_psp_tail"
                 and r.get("callsite_link_va") == "0xc8973"), None)
    callback = next((r for r in rows if r.get("event") == "setup_dos_api"
                     and r.get("operation") == "INT21_AH44" and r.get("ordinal") == 24
                     and r.get("process_psp") == 7811), None)
    chktty = next((r for r in rows if r.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL"), None)
    if not (original and tail and callback):
        raise ValueError("missing same-run original request, PSP tail, or matching DOS callback")
    stream_pointer = int(original["edx"])
    if not (original["process_psp"] == tail["process_psp"] == callback["process_psp"] == 7811
            and original["setup_dos_api_callback_ordinal"] == callback["ordinal"] == 24
            and original["eax"] == callback["in_ax"] == 0x4400
            and original["ebx"] == callback["in_bx"] == 1
            and callback["out_ax"] == callback["out_dx"] == 0x80D3
            and callback["cf"] is False
            and tail["tail_sample_valid"] is True
            and bytes.fromhex(tail["tail_bytes_hex"]) == b" -k 38928"):
        raise ValueError("same-run BX=1/tail/callback contract failed reconciliation")
    # The captured __chktty_ callsite in this run passed another stream field
    # value and a different stream object; do not attribute it to this BX=1.
    caller_linked = bool(chktty and chktty.get("eax") == 1 and chktty.get("edx") == stream_pointer)
    native_frontier = native["frontier"]["request_registers"]
    return {
        "schema": "w3-206-original-ah44-bx1-tail-reconciliation/v1",
        "task": "W3-206",
        "classification": "ORIGINAL_BX1_TAIL_AND_RESPONSE_RECONFIRMED_CALLER_UNKNOWN",
        "source_hashes": {
            "w3_203_manifest": hashlib.sha256(W3_203.read_bytes()).hexdigest(),
            "trace": hashlib.sha256(raw).hexdigest(),
            "w3_095": hashlib.sha256(W3_095.read_bytes()).hexdigest(),
            "w1_053_native": hashlib.sha256(W1_NATIVE.read_bytes()).hexdigest(),
        },
        "original": {
            "run_id": manifest["run_id"],
            "instrumented_binary_sha256": manifest["preflight_identity"]["binary_sha256"],
            "trace_event_count": len(rows),
            "trace_bytes": len(raw),
            "main_code_rebase": hex(original["main_code_rebase"]),
            "link_va": hex(original["int_instruction_link_va"]),
            "psp": original["process_psp"],
            "cpu_entry_sequence": original["sequence"],
            "callback_sequence": callback["sequence"],
            "callback_ordinal": callback["ordinal"],
            "eax": hex(original["eax"]),
            "ebx": hex(original["ebx"]),
            "ecx": hex(original["ecx"]),
            "edx_stream_pointer": hex(stream_pointer),
            "eflags": hex(original["eflags"]),
            "int_opcode_verified": original["int21_bytes_verified"],
            "same_run_psp_tail": tail["tail_bytes_hex"],
            "tail_text": bytes.fromhex(tail["tail_bytes_hex"]).decode("ascii"),
            "tail_event_sequence": tail["sequence"],
            "ds_descriptor_valid": original["ds_descriptor_valid"],
            "ds_descriptor_base": hex(original["ds_descriptor_base"]),
            "sample_bytes": original["sample_length"],
            "stream_field_plus_0x10": original["value_at_plus_0x10"],
            "dos_callback": {
                "input_ax": hex(callback["in_ax"]), "input_bx": hex(callback["in_bx"]),
                "input_dx": hex(callback["in_dx"]), "output_ax": hex(callback["out_ax"]),
                "output_dx": hex(callback["out_dx"]), "cf": callback["cf"],
                "handle": callback["entry"], "resolved_path": callback["resolved_path"],
                "default_drive": callback["default_drive"], "cwd": callback["cwd"],
            },
            "caller": {
                "__chktty_checkpoint_present": chktty is not None,
                "__chktty_eax_at_isatty_call": hex(chktty["eax"]) if chktty else None,
                "__chktty_stream_pointer": hex(chktty["edx"]) if chktty else None,
                "same_dynamic_caller_proven": caller_linked,
                "limitation": "The traced __chktty_ isatty-call checkpoint uses handle 5 and a different stream pointer; it is not attributed to the BX=1 request.",
            },
        },
        "native_comparison": {
            "target_sha256": native["target_sha256"],
            "command_tail": native["command_tail"],
            "link_va": native["frontier"]["guest_eip"],
            "eax": native_frontier["eax"],
            "ebx": native_frontier["ebx"],
            "edx_stream_pointer": native_frontier["edx"],
            "same_tail_and_request_class": native["command_tail"] == " -k 38928" and
                                            native_frontier["ebx"] == "00000001",
            "same_dynamic_invocation_or_full_seed_proven": False,
        },
        "guard": {key: manifest.get("guard", {}).get(key) for key in
                  ("operation", "sandbox_verified", "limits", "cause", "killed_processes", "ok")},
        "interpretation": "Original AX=4400/BX=1 at 0xC8973, PSP tail, stream field +0x10, and same-ordinal return are reconfirmed in one W3-203 run. This does not identify the dynamic caller for that exact request or prove native/original state equivalence.",
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
