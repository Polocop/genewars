"""Static reconciliation of observed _Unsmack entry pointers and decoder dispatch."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
W3_172 = ROOT / "evidence/w3_172_smack_unsmack_dataflow.json"
W3_173 = ROOT / "evidence/w3_173_unsmack_boundary.json"
W3_174 = ROOT / "evidence/w3_174_unsmack_args_correction.json"


def section(text: str, start: str, end: str) -> str:
    a = text.index(start)
    return text[a:text.index(end, a + len(start))]


def audit() -> dict:
    target_sha = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    disasm_sha = hashlib.sha256(DISASM.read_bytes()).hexdigest()
    if target_sha != "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f":
        raise ValueError("exact target identity mismatch")
    if disasm_sha != "dcad6dc4e0f836dba0fa0a63664b1e350c05592dc02b2ceeaa4c6788f68d5271":
        raise ValueError("pinned exact-target disassembly hash mismatch")
    asm = DISASM.read_text(encoding="utf-8")
    frame = section(asm, "SMACKDOFRAME:\t/* 0xc5bd0 */", "func_c5cb0:")
    unsmack = section(asm, "_Unsmack:\t/* 0xedb20 */", "j_SmackDoPCM:")
    frame_excerpt = section(frame, "jump_c5c62:", "jump_c5c89:")
    dispatch_excerpt = section(unsmack, "jump_ede94:", "jump_edec0:")
    init_excerpt = section(unsmack, "_Unsmack:\t/* 0xedb20 */", "jump_edc1d:")
    expected_tokens = ("mov    0x3e0(%esi),%ebx", "mov    0x39c(%esi),%edx",
                       "mov    0x3a0(%esi),%eax", "mov    0xc(%ebp),%esi",
                       "mov    0x10(%ebp),%edi",
                       "mov    0x8(%ebp),%esi", "jmp    *data_10c950(,%ecx,4)")
    combined = frame_excerpt + unsmack
    if not all(t in combined for t in expected_tokens):
        raise ValueError("expected argument/dataflow anchors are missing")
    corrected = json.loads(W3_174.read_text(encoding="utf-8"))
    original = json.loads(W3_173.read_text(encoding="utf-8"))
    static_prior = json.loads(W3_172.read_text(encoding="utf-8"))
    args = corrected["correct_arguments"]
    values = [int(a["value"], 16) for a in args]
    screen = int(original["unsmack_entry"]["w3_173_wscreen_pointer"])
    return {
        "schema": "w3-175-decoder-pointer-dataflow/v1",
        "task": "W3-175",
        "classification": "ARGUMENT_FLOW_OBSERVED_DISPATCH_DESTINATION_UNKNOWN",
        "target": {"path": str(TARGET.relative_to(ROOT)), "sha256": target_sha,
                   "bytes": TARGET.stat().st_size},
        "disassembly": {"path": str(DISASM.relative_to(ROOT)), "sha256": disasm_sha},
        "observed_arguments": args,
        "observed_wscreen": hex(screen),
        "argument_values_equal_wscreen": [v == screen for v in values],
        "exact_target_static_flow": {
            "call_block_link_va": "0xC5C62",
            "unsmack_link_va": "0xEDB20",
            "caller_push_order_excerpt": frame_excerpt,
            "callee_initialization_excerpt": init_excerpt,
            "indirect_dispatch_excerpt": dispatch_excerpt,
            "parameter_observations": [
                {"parameter": 1, "caller_field": "[ESI+0x3E0]", "entry_value": args[0]["value"],
                 "callee_use": "loaded as ESI, dereferenced at entry, then adjusted by 0x7410"},
                {"parameter": 2, "caller_field": "[ESI+0x39C]", "entry_value": args[1]["value"],
                 "callee_use": "saved to data_10C9A4; used as a base in decode-table lookups"},
                {"parameter": 3, "caller_field": "[ESI+0x3A0]", "entry_value": args[2]["value"],
                 "callee_use": "loaded as EDI and read during decoder stream/header setup"},
            ],
            "dispatch": "At link label jump_ede94, _Unsmack selects a handler via data_10C950 indexed by ECX and performs an indirect JMP.",
            "destination_finding": "UNKNOWN: no proven reaching definition connects a dispatch handler's write address to WScreen 0x394920.",
        },
        "dynamic_same_run": {
            "run_id": original["run_id"],
            "trace_sha256": original["trace"]["sha256"],
            "entry_sequence": original["unsmack_entry"]["sequence"],
            "return_sequence": original["unsmack_return"]["sequence"],
            "entry_return_link_va": corrected["preserved_valid_facts"]["dynamic_return_link_va"],
            "wscreen_samples": original["unsmack_entry"]["w3_173_sample_windows"],
            "sample_classification": original["classification"],
            "decoded_callback_target_observed": False,
        },
        "next_minimal_dynamic_point": {
            "static_label": "jump_ede94",
            "link_va": "0xEDE94",
            "capture": "At this single first natural dispatch, record ECX, data-rebased [0x10C950+ECX*4] target, and the selected callback entry; do not trace all decoder instructions or memory writes.",
            "reason": "This resolves which statically enumerated SmackInternal handler ran; destination dataflow can then be restricted to that handler.",
        },
        "provenance": {"w3_172_static_hash": static_prior["disassembly"]["sha256"],
                       "w3_173_source_sha256": original["source"]["target_sha256"],
                       "w3_174_raw_trace_verified": corrected["raw_trace_entry_matches_structured_evidence"]},
        "limitations": ["The observed argument values are not given higher-level semantic names.",
                        "Non-equality with WScreen does not rule out indirect writes through a structure or callback.",
                        "No new replay or emulated write observation was performed."],
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
