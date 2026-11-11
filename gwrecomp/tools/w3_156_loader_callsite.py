#!/usr/bin/env python3
"""Resolve the exact W_SCREEN loader call and return from the pinned target bytes."""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
CODE_BYTES = ROOT / "evidence/genewars-1_1.bytes"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
FRONTIER = ROOT / "evidence/w3_150_screen_write_frontier.json"
SAMPLES = ROOT / "evidence/w3_154_source_destination_samples.json"
RESULT = ROOT / "evidence/w3_156_wscreen_loader_callsite.json"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
OBJECT1_LINK_BASE = 0x10000
RESOURCE_CALL = 0x94D9F
LOADER_ENTRY = 0x15090
ASCREEN_DESCRIPTOR = 0x104054


def rel32_target(call_va: int, instruction: bytes) -> int:
    if len(instruction) != 5 or instruction[0] != 0xE8:
        raise ValueError("expected a five-byte near CALL rel32")
    displacement = struct.unpack_from("<i", instruction, 1)[0]
    return call_va + 5 + displacement


def disassemble_at(data: bytes, link_va: int, base: int = OBJECT1_LINK_BASE) -> list[dict]:
    offset = link_va - base
    if offset < 0 or offset >= len(data):
        raise ValueError("link VA is outside extracted object bytes")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return [{"link_va": ins.address, "bytes": ins.bytes.hex(),
             "mnemonic": ins.mnemonic, "operands": ins.op_str}
            for ins in md.disasm(data[offset:offset + 64], link_va)]


def main() -> int:
    target_bytes = TARGET.read_bytes()
    target_sha = hashlib.sha256(target_bytes).hexdigest()
    if target_sha != TARGET_SHA256:
        raise RuntimeError(f"target hash mismatch: {target_sha}")
    code_bytes = CODE_BYTES.read_bytes()
    instructions = disassemble_at(code_bytes, RESOURCE_CALL)
    call = next((i for i in instructions if i["link_va"] == 0x94DBC), None)
    if not call or call["bytes"] != "e8cf02f8ff" or call["mnemonic"] != "call":
        raise RuntimeError("exact W_SCREEN loader call bytes did not match the known target")
    resolved = rel32_target(call["link_va"], bytes.fromhex(call["bytes"]))
    if resolved != LOADER_ENTRY:
        raise RuntimeError(f"relative call target mismatch: {resolved:#x}")
    around = [i for i in instructions if 0x94D9F <= i["link_va"] <= 0x94DC1]
    loader = disassemble_at(code_bytes, LOADER_ENTRY)
    header = struct.unpack_from("<I", target_bytes, 0x3C)[0]
    le_signature = target_bytes[header:header + 2]
    # Exact-target/code-object identity is corroborated by known original bytes at W3-150's LbScreenSwap anchor.
    swap_anchor_bytes = code_bytes[0x9FFE0 - OBJECT1_LINK_BASE:
                                  0x9FFE0 - OBJECT1_LINK_BASE + 8]
    swap_anchor = disassemble_at(code_bytes, 0x9FFE0)[0]
    if swap_anchor_bytes.hex() != "535152565783ec04":
        raise RuntimeError("extracted object mapping failed the W3-150 code anchor")
    samples = json.loads(SAMPLES.read_text(encoding="utf-8"))
    frontier = json.loads(FRONTIER.read_text(encoding="utf-8"))
    result = {
        "schema": "w3-156-wscreen-loader-callsite/v1", "task": "W3-156",
        "provenance": {"target_sha256": target_sha,
                       "target_path": str(TARGET.relative_to(ROOT)),
                       "extracted_code_bytes_sha256": hashlib.sha256(code_bytes).hexdigest(),
                       "disassembly_sha256": hashlib.sha256(DISASM.read_bytes()).hexdigest(),
                       "le_header_offset": hex(header), "le_signature_bytes": le_signature.hex(),
                       "code_object": 1, "code_object_link_base": hex(OBJECT1_LINK_BASE),
                       "mapping_anchor": {"link_va": hex(0x9FFE0), "bytes": swap_anchor_bytes.hex(),
                                          "evidence": "evidence/w3_150_screen_write_frontier.json"}},
        "w_screen_loader": {"resource_descriptor_link_va": hex(ASCREEN_DESCRIPTOR),
                            "descriptor_name": "*W_SCREEN",
                            "edx_setup_immediate": "0x00104054",
                            "call_link_va": hex(call["link_va"]),
                            "call_bytes": call["bytes"], "call_mnemonic": call["mnemonic"],
                            "target_link_va": hex(resolved),
                            "loader_entry_link_va": hex(LOADER_ENTRY),
                            "return_checkpoint_link_va": hex(call["link_va"] + 5),
                            "target_verified_by_rel32": True,
                            "surrounding_instructions": around,
                            "loader_entry_instructions": loader[:12]},
        "runtime_reference": {"prior_capture_code_rebase": samples["mapping"]["code_rebase"],
                              "prior_capture_return_runtime_eip":
                                  hex(int(samples["mapping"]["code_rebase"]) + call["link_va"] + 5),
                              "must_reverify_mapping_on_new_replay": True},
        "static_vs_dynamic": {
            "static": "At 0x94D9F the setup sequence places the aWScreen descriptor in EDX, then calls the exact LbDataLoadAll_ entry; the instruction immediately after the call is the return checkpoint.",
            "original_observed": "W3-154 later measured WScreen=0x394920 and three zero source/destination sample pairs at LbScreenSwap copy completion.",
            "not_established": "No existing capture observes LbDataLoadAll_ entry/return for this resource, assignment timing, or the first write to its pointed-to bytes."},
        "prior_frontier_target_sha256": frontier["provenance"]["target_sha256"]
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"call": result["w_screen_loader"]["call_link_va"],
                      "return": result["w_screen_loader"]["return_checkpoint_link_va"],
                      "entry": result["w_screen_loader"]["loader_entry_link_va"],
                      "output": str(RESULT)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
