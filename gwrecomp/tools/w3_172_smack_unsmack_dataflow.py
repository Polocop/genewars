"""Bounded exact-target audit for SMACKDOFRAME -> _Unsmack argument flow."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
W3_170 = ROOT / "evidence/w3_170_screen_buffer_producer_audit.json"
W3_171 = ROOT / "evidence/w3_171_wscreen_frame_boundary.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def section(text: str, start: str, end: str) -> str:
    a = text.index(start)
    b = text.index(end, a + len(start))
    return text[a:b]


def audit() -> dict:
    target_sha = sha(TARGET)
    if target_sha != "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f":
        raise ValueError("exact GeneWars 1.1 target hash mismatch")
    disasm_sha = sha(DISASM)
    if disasm_sha != "dcad6dc4e0f836dba0fa0a63664b1e350c05592dc02b2ceeaa4c6788f68d5271":
        raise ValueError("pinned disassembly hash mismatch")
    asm = DISASM.read_text(encoding="utf-8")
    doframe = section(asm, "SMACKDOFRAME:\t/* 0xc5bd0 */", "func_c5cb0:")
    unsmack = section(asm, "_Unsmack:\t/* 0xedb20 */", "j_SmackDoPCM:")
    required = (
        "mov    0x3a0(%esi),%eax\n\t\tpush   %eax",
        "mov    0x39c(%esi),%edx\n\t\tpush   %edx",
        "mov    0x3e0(%esi),%ebx\n\t\tpush   %ebx",
        "call   _Unsmack",
    )
    if not all(x in doframe for x in required):
        raise ValueError("SMACKDOFRAME argument setup changed or missing")
    if "jmp    *data_10c950(,%ecx,4)" not in unsmack:
        raise ValueError("_Unsmack indirect decoder dispatch missing")
    if "mov    0x10(%ebp),%edi" not in unsmack or "mov    0x8(%ebp),%esi" not in unsmack:
        raise ValueError("_Unsmack parameter reads changed")

    w170 = json.loads(W3_170.read_text(encoding="utf-8"))
    w171 = json.loads(W3_171.read_text(encoding="utf-8"))
    frame = w171["samples"]["smackdoframe_return"]
    copy = w171["samples"]["copy_pre"]
    if not (frame["w3_171_sample_valid"] and copy["w3_171_sample_valid"]):
        raise ValueError("W3-171 same-run sample points are not both valid")
    return {
        "schema": "w3-172-smack-unsmack-dataflow/v1",
        "task": "W3-172",
        "classification": "STATIC_ARGUMENT_FLOW_PARTIAL_DESTINATION_UNKNOWN",
        "target": {"path": str(TARGET.relative_to(ROOT)), "sha256": target_sha, "bytes": TARGET.stat().st_size},
        "disassembly": {"path": str(DISASM.relative_to(ROOT)), "sha256": disasm_sha},
        "static": {
            "smackdoframe_entry_link_va": "0xC5BD0",
            "call_block_link_va": "0xC5C62",
            "unsmack_entry_link_va": "0xEDB20",
            "caller_push_order": [
                {"push_order": 1, "expression": "[ESI+0x3A0]", "register": "EAX"},
                {"push_order": 2, "expression": "[ESI+0x39C]", "register": "EDX"},
                {"push_order": 3, "expression": "[ESI+0x3E0]", "register": "EBX"},
            ],
            "callee_parameter_order": [
                {"stack": "[EBP+0x08]", "value": "caller [ESI+0x3E0]", "observed_use": "loaded into ESI, then dereferenced and offset by 0x7410"},
                {"stack": "[EBP+0x0C]", "value": "caller [ESI+0x39C]", "observed_use": "saved as data_10C9A4 and used as base for decoder table reads"},
                {"stack": "[EBP+0x10]", "value": "caller [ESI+0x3A0]", "observed_use": "loaded into EDI and dereferenced during stream/header setup"},
            ],
            "decoder_dispatch": "_Unsmack selects a callback table through data_10C950 and performs an indirect JMP; exact callback/write destination is not resolved in this task.",
            "w_screen_argument_role": "UNKNOWN: static excerpts do not connect these three structure fields to the dynamically observed WScreen pointer.",
            "static_excerpts": {
                "call_block": section(doframe, "jump_c5c62:", "jump_c5c89:"),
                "unsmack_entry_and_dispatch": section(unsmack, "_Unsmack:\t/* 0xedb20 */", "jump_edec0:") + "jump_edec0:" + unsmack.split("jump_edec0:", 1)[1]
            },
            "w3_170_disassembly_sha256": w170["static_reference"].get("sha256", "not recorded in W3-170 schema"),
        },
        "dynamic_same_run": {
            "source_evidence": str(W3_171.relative_to(ROOT)),
            "run_id": w171["run_id"],
            "psp": w171["mapping"]["psp"],
            "code_rebase": w171["mapping"]["code_rebase"],
            "data_rebase": w171["mapping"]["data_rebase"],
            "w_screen_pointer_frame_and_copy": hex(frame["w3_171_wscreen_pointer"]),
            "frame_sequence": frame["sequence"],
            "copy_pre_sequence": copy["sequence"],
            "frame_sample_windows": frame["w3_171_sample_windows"],
            "copy_sample_windows": copy["w3_171_sample_windows"],
            "sampled_classification": w171["comparison"]["classification"],
            "guard_cause": w171["guard"]["cause"],
        },
        "conclusion": {
            "original_dynamic_fact": "At the measured SMACKDOFRAME return and first copy pre-site, the same WScreen pointer 0x394920 had zero bytes at offsets 0, 32000, and 63984; those samples were stable in this run.",
            "static_inference": "The frame routine conditionally calls _Unsmack with three structure-derived values; _Unsmack dispatches through a callback table. Current static evidence does not identify the destination buffer or prove the call was taken in the captured first frame.",
            "next_discriminating_observation": "On a separately authorized bounded replay, capture only the natural call/skip decision at SMACKDOFRAME's _Unsmack call block and, if taken, sample the same three validated WScreen windows immediately before and after that call. Do not infer the instruction VA from the block label; derive it from the pinned disassembly first.",
        },
        "limitations": ["Static arguments are structure fields, not proven WScreen aliases.", "Sampled bytes do not characterize all 64000 bytes.", "The guard timeout occurred after both requested W3-171 samples; natural process completion was not observed."],
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
