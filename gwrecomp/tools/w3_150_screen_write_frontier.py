"""Exact-target static audit for the first LbScreenSwap memory-copy paths."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from le_loader import load_le  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # noqa: E402

TARGET = ROOT / "evidence/genewars-1_1.exe"
MAP = ROOT / "evidence/genewars-1_1.map"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
START = 0x9FFE0
END = 0xA0090
GLOBAL_SYMBOLS = {
    "_lbDisplay": 0x19CA58,
    "lbDisplay__WScreen": 0x19CA5C,
    "lbDisplay__GraphicsScreenWidth": 0x19CA78,
    "lbDisplay__GraphicsScreenHeight": 0x19CA7C,
    "lbDisplay__VesaIsSetUp": 0x19CABE,
}
INTERESTING = {0x9FFF9, 0xA0000, 0xA0002, 0xA0008, 0xA000A,
               0xA0010, 0xA0013, 0xA0015, 0xA0017, 0xA003C,
               0xA004E, 0xA0051, 0xA005D, 0xA005F, 0xA0069,
               0xA007C, 0xA0081, 0xA008E}
EXPECTED_BYTES = {0xA0000: "7515", 0xA0013: "f3a5", 0xA005D: "f3a5",
                  0xA0015: "eb65", 0xA005F: "81c300000100", 0xA008E: "c3"}


def audit() -> dict:
    for path in (TARGET, MAP, DISASM):
        if not path.is_file():
            raise FileNotFoundError(path)
    target_bytes = TARGET.read_bytes()
    target_hash = hashlib.sha256(target_bytes).hexdigest()
    if target_hash != TARGET_SHA256:
        raise RuntimeError(f"exact target hash mismatch: {target_hash}")
    image = load_le(TARGET)
    owner = image.object_containing(START)
    if owner is None or not owner.executable or image.object_containing(END - 1) != owner:
        raise RuntimeError("LbScreenSwap is not wholly within one verified executable LE object")
    offset = START - image.mem_base
    code = bytes(image.mem[offset:offset + END - START])
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    instructions = list(md.disasm(code, START))
    by_va = {ins.address: ins for ins in instructions}
    if not instructions or instructions[0].address != START:
        raise RuntimeError("disassembly did not begin at exact LbScreenSwap entry")
    if by_va.get(END - 2) is None or by_va[END - 2].mnemonic != "ret":
        raise RuntimeError("exact return boundary at 0xA008E was not decoded")
    for va, expected in EXPECTED_BYTES.items():
        ins = by_va.get(va)
        if ins is None or ins.bytes.hex() != expected:
            raise RuntimeError(f"exact instruction signature mismatch at 0x{va:08X}")
    decoded = []
    for va in sorted(INTERESTING):
        ins = by_va.get(va)
        if ins:
            decoded.append({"link_va": f"0x{va:08X}", "bytes": ins.bytes.hex(),
                            "mnemonic": ins.mnemonic, "operands": ins.op_str})
    map_text = MAP.read_text(encoding="utf-8", errors="replace")
    mapped = {}
    for name, va in GLOBAL_SYMBOLS.items():
        line = next((line.strip() for line in map_text.splitlines()
                     if name in line and f"{va:08X}" in line.upper()), None)
        if not line:
            raise RuntimeError(f"exact MAP symbol/address mismatch: {name} @ 0x{va:08X}")
        obj = image.object_containing(va)
        if obj is None:
            raise RuntimeError(f"MAP data symbol outside loaded LE objects: {name}")
        mapped[name] = {"link_va": f"0x{va:08X}", "map_line": line,
                        "le_object": obj.index, "object_offset": f"0x{va - obj.base:X}"}
    return {
        "schema": "w3-150-lbscreenswap-static-frontier/v1",
        "task": "W3-150",
        "provenance": {"target_path": str(TARGET.relative_to(ROOT)),
                       "target_sha256": target_hash,
                       "map_sha256": hashlib.sha256(MAP.read_bytes()).hexdigest(),
                       "disassembly_sha256": hashlib.sha256(DISASM.read_bytes()).hexdigest(),
                       "decoder": "LE loader + Capstone 5, 32-bit x86, decoded mapped exact-target bytes"},
        "function": {"name": "LbScreenSwap_", "link_start": "0x0009FFE0",
                     "link_end_exclusive": "0x000A0090",
                     "le_object": owner.index, "decoded_instruction_count": len(instructions)},
        "instructions": decoded,
        "globals": mapped,
        "control_flow": {
            "branch": {"link_va": "0x000A0000", "instruction": "jne 0xA0017",
                       "condition": "lbDisplay__VesaIsSetUp byte is nonzero",
                       "taken_path": "VESA page/chunk loop beginning 0xA0017",
                       "fallthrough_path": "single REP MOVSD at 0xA0013"},
            "copy_paths": [
                {"pre_write": "0x000A0013", "instruction": "REP MOVSD ES:[EDI] <- DS:[ESI]",
                 "source": "lbDisplay__WScreen loaded at 0xA0002",
                 "destination": "_lbDisplay loaded at 0xA000A",
                 "count": "ECX = GraphicsScreenWidth * GraphicsScreenHeight / 4 dwords",
                 "post_write_checkpoint": "0x000A0015"},
                {"pre_write": "0x000A005D", "instruction": "REP MOVSD ES:[EDI] <- DS:[ESI]",
                 "source": "ESI copied from EBX; EBX initialized from lbDisplay__WScreen at 0xA0017 and advanced by 64 KiB per page",
                 "destination": "_lbDisplay loaded at 0xA0051",
                 "count": "ECX = current page chunk in bytes / 4 dwords",
                 "post_write_checkpoint": "0x000A005F",
                 "preceding_page_setup": "LbVesaSetPage_ call at 0xA0049"}],
            "return_instructions": ["0x000A003B", "0x000A008E"]
        },
        "runtime_mapping": {"code_rebase_observed_in_W3_149": "0x001EB000",
                            "data_rebase_observed_in_W3_149": "0x001DA000",
                            "require_fresh_measurement_each_replay": True,
                            "runtime_global_address_rule": "link VA + freshly measured data rebase; do not apply code rebase to globals"},
        "next_capture_plan": {
            "one_replay": True,
            "capture_only": ["0xA0000 branch", "0xA0013 pre-write", "0xA0015 post-write",
                             "0xA005D pre-write", "0xA005F post-write"],
            "at_each_site": "CS:EIP/link VA, mapping, GPR, EFLAGS, DS/ES descriptors, relevant globals and bounded stack",
            "after_copy": "sample at most 16 bytes from the measured destination start, saved at pre-write; only after validating descriptor and bounds",
            "limitations": ["W3-149 did not capture VesaIsSetUp or the branch outcome",
                            "static code does not establish that either copy ran in the replay",
                            "a memory sample is not by itself proof of visible presentation"]
        }
    }


if __name__ == "__main__":
    result = audit()
    out = ROOT / "evidence/w3_150_screen_write_frontier.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(out), "function": result["function"],
                      "copy_sites": [x["pre_write"] for x in result["control_flow"]["copy_paths"]]}, indent=2))
