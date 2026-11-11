"""Recover true cdecl _Unsmack arguments from the pre-prologue guest stack."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "evidence/w3_173_unsmack_boundary.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_173_UNSMACK_BOUNDARY_20261009_01.jsonl"


def corrected() -> dict:
    evidence = json.loads(RESULT.read_text(encoding="utf-8"))
    entry = evidence["unsmack_entry"]
    returned = evidence["unsmack_return"]
    raw = TRACE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence["trace"]["sha256"]:
        raise ValueError("preserved raw W3-173 trace hash mismatch")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    trace_entry = next((r for r in rows if r.get("checkpoint") == "W3_173_UNSMACK_ENTRY"), None)
    if trace_entry != entry:
        raise ValueError("structured entry differs from preserved raw trace")
    if entry.get("link_va") != 0xEDB20 or not entry.get("stack_words_u32"):
        raise ValueError("expected _Unsmack entry stack capture is missing")
    words = entry["stack_words_u32"]
    if len(words) < 4 or int(words[0]) != int(entry["return_address"]):
        raise ValueError("stack does not contain return address followed by three arguments")
    prologue = bytes.fromhex(entry["bytes"])
    if prologue[:3] != bytes.fromhex("558bec"):
        raise ValueError("_Unsmack entry bytes do not show push EBP; mov EBP,ESP")
    if int(entry["stack_linear"]) != int(entry["esp"]):
        raise ValueError("entry stack linear address does not match SS:ESP")
    static = json.loads((ROOT / "evidence/w3_172_smack_unsmack_dataflow.json").read_text(encoding="utf-8"))
    return {
        "schema": "w3-174-unsmack-argument-correction/v1",
        "task": "W3-174",
        "supersedes": {
            "task": "W3-173",
            "evidence": "evidence/w3_173_unsmack_boundary.json",
            "invalid_fields": ["unsmack_entry.w3_173_arg1", "unsmack_entry.w3_173_arg2", "unsmack_entry.w3_173_arg3"],
            "reason": "Capture at entry EIP 0xEDB20 precedes PUSH EBP / MOV EBP,ESP; EBP still refers to caller frame, so the EBP-relative reads are not callee arguments."
        },
        "provenance": {
            "run_id": evidence["run_id"],
            "trace_path": evidence["trace"]["path"],
            "trace_sha256": evidence["trace"]["sha256"],
            "entry_sequence": entry["sequence"],
            "entry_link_va": "0xEDB20",
            "entry_instruction_bytes": entry["bytes"],
            "prologue_bytes": prologue[:3].hex(),
            "esp": hex(entry["esp"]),
            "stack_linear": hex(entry["stack_linear"]),
            "captured_stack_words_u32": [hex(int(w)) for w in words[:4]],
        },
        "correct_arguments": [
            {"parameter": 1, "entry_stack_slot": "SS:ESP+4", "value": hex(int(words[1])),
             "static_caller_source": "[caller ESI+0x3E0]"},
            {"parameter": 2, "entry_stack_slot": "SS:ESP+8", "value": hex(int(words[2])),
             "static_caller_source": "[caller ESI+0x39C]"},
            {"parameter": 3, "entry_stack_slot": "SS:ESP+12", "value": hex(int(words[3])),
             "static_caller_source": "[caller ESI+0x3A0]"},
        ],
        "argument_semantics": "UNKNOWN; these are observed cdecl entry values and statically mapped caller structure fields, but their higher-level meaning has not been demonstrated.",
        "preserved_valid_facts": {
            "call_block_link_va": "0xC5C62",
            "entry_link_va": "0xEDB20",
            "dynamic_return_link_va": hex(int(returned["link_va"])),
            "entry_sequence": entry["sequence"],
            "return_sequence": returned["sequence"],
            "mapping": {"code_rebase": evidence["code_rebase"],
                        "data_rebase": evidence["data_rebase"],
                        "psp": evidence["psp"]},
            "wscreen_pointer": hex(entry["w3_173_wscreen_pointer"]),
            "sample_classification": evidence["classification"],
            "sampled_offsets_changed": evidence["sampled_offsets_changed"],
        },
        "static_caller_parameter_order": static["static"]["callee_parameter_order"],
        "raw_trace_entry_matches_structured_evidence": True,
        "limitations": ["No replay was performed for this correction.",
                        "The prior EBP-relative values remain in the original W3-173 artifact but are explicitly invalidated here.",
                        "No semantic interpretation of the three pointer-like argument values is claimed."],
    }


if __name__ == "__main__":
    print(json.dumps(corrected(), indent=2))
