"""Bounded exact-target static follow-up for the observed Smacker gate."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import capstone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_270_post_present_static_frontier import map_le_link_va
EXE = ROOT / "build/dosboxx_oracle/C/GENEWARS/GW.EXE"
MAP = ROOT / "evidence/genewars-1_1.map"
CAPTURE = ROOT / "evidence/w3_280_play_smk_step.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_280_PLAY_SMK_STEP_20261010_01.jsonl"
OUT = ROOT / "evidence/w3_284_smacker_dispatch_static.json"
REPORT = ROOT / "reports/coordination/w3_284_smacker_dispatch_static.md"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
TRACE_SHA = "414c6d57321d4baea813b4123e994ad92dbb79d00c90b4c45a3ed6063532bb1f"
START = 0xAE2E3
CALLEE = 0xAE308
CALLEE_MAX_BYTES = 96


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_at(data: bytes, start: int, length: int) -> tuple[dict[str, int], bytes, list[dict[str, Any]]]:
    mapping = map_le_link_va(data, start)
    end_mapping = map_le_link_va(data, start + length - 1)
    if (mapping["object"], mapping["page_index_zero_based"]) != (end_mapping["object"], end_mapping["page_index_zero_based"]):
        raise ValueError("requested static window crosses an LE page; split it at page boundary")
    if end_mapping["file_offset"] != mapping["file_offset"] + length - 1:
        raise ValueError("requested static window is not file-contiguous")
    raw = data[mapping["file_offset"]:mapping["file_offset"] + length]
    if len(raw) != length:
        raise ValueError("static window is truncated")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    insns = [{
        "link_va": ins.address,
        "bytes": ins.bytes.hex(),
        "mnemonic": ins.mnemonic,
        "operands": ins.op_str,
        "size": ins.size,
    } for ins in decoder.disasm(raw, start)]
    return mapping, raw, insns


def parse_publics(text: str) -> dict[int, str]:
    symbols: dict[int, str] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].startswith("0001:"):
            try:
                symbols[int(fields[0].split(":", 1)[1], 16)] = fields[1]
            except ValueError:
                continue
    return symbols


def infer_second_gate(ebx: int) -> dict[str, Any]:
    """Derive a branch result from captured EBX and exact target instruction bytes."""
    target = 0xAE2F2 if (ebx & 0xFF & 0x84) == 0 else 0xAE2E8
    return {
        "evidence_level": "STATIC_INFERENCE_FROM_ORIGINAL_OBSERVED_STATE",
        "observed_ebx": f"0x{ebx:08X}",
        "tested_bl_mask": "0x84",
        "je_target": "0x000AE2F2",
        "inferred_destination": f"0x{target:08X}",
        "dynamically_observed": False,
    }


def second_compare_paths_converge() -> bool:
    # JE at 0xAE2FC targets 0xAE301. Its not-taken path executes the 3-byte
    # AND at 0xAE2FE, whose fall-through is also 0xAE301.
    return 0xAE2FE + 3 == 0xAE301


def build() -> dict[str, Any]:
    image = EXE.read_bytes()
    target_sha = digest(image)
    if target_sha != TARGET_SHA:
        raise ValueError("guest GW.EXE target hash mismatch")
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    if capture.get("provenance", {}).get("target_sha256") != TARGET_SHA:
        raise ValueError("W3-280 capture is not bound to exact target")
    trace_raw = TRACE.read_bytes()
    if len(trace_raw) > 1024 * 1024 or len(trace_raw.splitlines()) > 2048 or digest(trace_raw) != TRACE_SHA:
        raise ValueError("W3-280 trace hash or size limit mismatch")
    rows = [json.loads(line) for line in trace_raw.splitlines() if line.strip()]
    observed = [r for r in rows if r.get("sequence") == 399 and r.get("event") == "w3_278_branch_target"]
    if len(observed) != 1 or observed[0].get("link_va") != START:
        raise ValueError("unique original-observed sequence-399 branch target missing")
    state = observed[0]
    if int(state["ebx"]) != 0:
        raise ValueError("expected captured EBX=0 no longer matches trace")

    windows = []
    for start, length in ((START, CALLEE - START), (CALLEE, CALLEE_MAX_BYTES)):
        mapping, raw, decoded = decode_at(image, start, length)
        windows.append({
            "start_link_va": f"0x{start:08X}",
            "length_bytes": length,
            "file_offset": mapping["file_offset"],
            "le_object": mapping["object"],
            "object_base": mapping["object_base"],
            "object_size": mapping["object_size"],
            "page_size": mapping["page_size"],
            "page_index_zero_based": mapping["page_index_zero_based"],
            "page_number_one_based": mapping["page_number_one_based"],
            "page_flags": mapping["page_flags"],
            "bytes_sha256": digest(raw),
            "bytes_hex": raw.hex(),
            "disassembly": decoded,
        })

    publics = parse_publics(MAP.read_text(encoding="utf-8", errors="replace"))
    return {
        "schema": "w3-284-smacker-dispatch-static/v1",
        "task": "W3-284",
        "evidence_level": "ORIGINAL_OBSERVED_AND_STATIC_ONLY",
        "provenance": {
            "target_path": str(EXE.relative_to(ROOT)).replace("\\", "/"),
            "target_size": len(image),
            "target_sha256": target_sha,
            "map_path": str(MAP.relative_to(ROOT)).replace("\\", "/"),
            "map_sha256": digest(MAP.read_bytes()),
            "source_capture": "evidence/w3_280_play_smk_step.json",
            "source_trace": "build/dosboxx_oracle/C/W3_280_PLAY_SMK_STEP_20261010_01.jsonl",
            "source_trace_sha256": digest(trace_raw),
        },
        "original_observed": {
            "sequence": state["sequence"],
            "event": state["event"],
            "link_va": f"0x{int(state['link_va']):08X}",
            "runtime_linear": f"0x{int(state['runtime_linear']):08X}",
            "code_rebase": f"0x{int(state['code_rebase']):08X}",
            "cs": f"0x{int(state['cs']):04X}",
            "ebx": f"0x{int(state['ebx']):08X}",
            "ecx": f"0x{int(state['ecx']):08X}",
            "eflags": f"0x{int(state['eflags']):08X}",
        },
        "static_windows": windows,
        "branch_analysis": {
            "after_0xAE2E3_test_bl_0x84": infer_second_gate(int(state["ebx"])),
            "second_compare": {
                "entry": "0x000AE2F2",
                "global_read": "[0x0009CABC]",
                "compare": "ECX == 1 at 0x000AE2FC",
                "taken_target": "0x000AE301",
                "fallthrough_adjustment": "AND BH,0xFE at 0x000AE2FE",
                "both_paths_fall_through_or_branch_to": "0x000AE301",
                "paths_converge": second_compare_paths_converge(),
                "global_value": "UNKNOWN; not captured",
            },
            "common_callsite": {
                "link_va": "0x000AE301",
                "static_target": "0x000AE308",
                "exact_map_public_at_target": publics.get(CALLEE),
                "dynamically_observed": False,
            },
            "next_dynamic_checkpoint_recommendation": {
                "link_va": "0x000AE308",
                "reason": "both outcomes of the 0xAE2FC comparison converge at CALL 0xAE308; recording the callee entry would confirm continuation beyond the measured gate with one target event",
                "status": "RECOMMENDED_NOT_OBSERVED",
            },
        },
        "limits": [
            "The W3-280 sequence-399 state at 0xAE2E3 is original-observed; the JE result at 0xAE2E6 is inferred from that EBX and exact target bytes, not dynamically captured.",
            "The value read from [0x9CABC], the call at 0xAE301, and the callee entry at 0xAE308 are not dynamically observed in this evidence.",
            "Static code bytes and MAP public labels do not prove a runtime call or function completion.",
            "No media return, framebuffer pixels, menu, or gameplay is established.",
            "No DOSBox, Oracle, build, or guest-file write was performed.",
        ],
    }


def render_report(result: dict[str, Any]) -> str:
    observed = result["original_observed"]
    branch = result["branch_analysis"]
    target_name = branch["common_callsite"]["exact_map_public_at_target"] or "no exact public symbol"
    lines = [
        "# W3-284 — static dispatch after the measured Smacker gate",
        "",
        "Evidence level: ORIGINAL_OBSERVED_AND_STATIC_ONLY. No Oracle or build.",
        "",
        f"- Exact target GW.EXE: {result['provenance']['target_size']} bytes, SHA-256 `{result['provenance']['target_sha256']}`.",
        f"- W3-280 trace: SHA-256 `{result['provenance']['source_trace_sha256']}`.",
        f"- Original-observed state: sequence {observed['sequence']} at `{observed['link_va']}`; EBX `{observed['ebx']}`, ECX `{observed['ecx']}`, EFLAGS `{observed['eflags']}`.",
        "",
        "## Bounded LE mapping and disassembly",
    ]
    for window in result["static_windows"]:
        lines += ["", f"Window `{window['start_link_va']}` ({window['length_bytes']} bytes, file offset `0x{window['file_offset']:X}`, LE object {window['le_object']}, page {window['page_number_one_based']})"]
        lines.append("| Link VA | Bytes | Instruction |")
        lines.append("|---:|---|---|")
        for ins in window["disassembly"]:
            lines.append(f"| `0x{ins['link_va']:08X}` | `{ins['bytes']}` | `{ins['mnemonic']} {ins['operands']}` |")
    lines += [
        "",
        "## Control-flow result",
        "",
        f"The captured EBX at `0xAE2E3` is zero. The exact bytes decode as `TEST BL,0x84; JE 0xAE2F2`; therefore the JE is predicted taken from the captured input state. This is an instruction-level inference, not a recorded destination.",
        "",
        f"At `0xAE2F2`, the code reads `[0x9CABC]` and compares ECX with 1. The taken path goes to `0xAE301`; the not-taken path executes the three-byte `AND BH,0xFE` at `0xAE2FE` and falls through to the same `0xAE301` callsite. Both paths converge at the static `CALL 0xAE308`. The global value and this call/entry remain unobserved.",
        "",
        f"MAP public at `0xAE308`: `{target_name}`. This names the address only; it does not prove runtime execution or a function boundary beyond the public label.",
        "",
        "## Next checkpoint",
        "",
        "If another capture is justified, use one one-shot target at callee entry `0xAE308`, armed from the measured sequence-399 state and freshly verified mapping. It tests continuation beyond this branch with minimal event volume. Do not infer media completion from that entry.",
        "",
        "Menu, gameplay, first framebuffer pixels, and media-call return remain unverified.",
        "",
        "## Limits",
        "",
    ]
    lines.extend(f"- {item}" for item in result["limits"])
    lines += ["", "Structured evidence: `evidence/w3_284_smacker_dispatch_static.json`.", ""]
    return "\n".join(lines)


def main() -> int:
    result = build()
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    REPORT.write_text(render_report(result), encoding="utf-8")
    print(json.dumps({
        "evidence": str(OUT), "report": str(REPORT),
        "target_sha256": result["provenance"]["target_sha256"],
        "ebx_zero_je_inference": result["branch_analysis"]["after_0xAE2E3_test_bl_0x84"]["inferred_destination"],
        "next_checkpoint": result["branch_analysis"]["next_dynamic_checkpoint_recommendation"]["link_va"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
