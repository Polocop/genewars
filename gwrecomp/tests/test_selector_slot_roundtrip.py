"""Compile and run the original, LE-fixed DS save/restore instructions."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "third_party" / "pcrecomp")]
from le_loader import load_le
from tools.disasm.disasm32 import BasicBlock, Disassembler, Function, Instruction
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter

TARGET = ROOT / "evidence" / "genewars-1_1.exe"
WRITE_VA = 0xAFB06
READ_VA = 0xAFC38
SLOT_LINK = 0xAFC41
FLAT_BASE = 0
MEMORY_SIZE = 0x02A00000


def lifted_function(image, va, name, instruction_count, synthetic_ret=False):
    obj = image.objects[0]
    code = bytes(image.object_data(1))
    section = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
    dis = Disassembler(code, 0, [section])
    decoded = list(dis.disassemble_at(va, max_bytes=16))
    if len(decoded) < instruction_count:
        raise AssertionError(f"could not decode {name} at 0x{va:x}")
    insns = [Instruction(x.address, x.size, x.mnemonic, x.op_str,
                         bytes(x.bytes), x.operands)
             for x in decoded[:instruction_count]]
    if synthetic_ret:
        end0 = insns[-1].address + insns[-1].size
        insns.append(Instruction(end0, 1, "ret", "", b"\xC3", []))
    start = insns[0].address
    end = insns[-1].address + insns[-1].size
    block = BasicBlock(start, end, insns, is_exit=True)
    return Lifter().lift_function(Function(start, end, name, {start: block},
                                           size=end - start))


def main():
    image = load_le(TARGET, object_rebases={1: 0x1EB000, 3: 0x1DA000})
    write_fn = lifted_function(image, WRITE_VA, "gw_original_save_ds", 1, synthetic_ret=True)
    read_fn = lifted_function(image, READ_VA, "gw_original_restore_ds", 2)
    slot_linear = image.link_to_linear(SLOT_LINK)
    slot_offset = slot_linear - image.mem_base
    # The loader has applied the object's verified +0x1EB000 delta to both
    # LE fixups. This is the byte source passed to the lifter below.
    write_disp = int.from_bytes(bytes(image.object_data(1))[WRITE_VA + 4 - image.objects[0].base:
                                                               WRITE_VA + 8 - image.objects[0].base], "little")
    read_disp = int.from_bytes(bytes(image.object_data(1))[READ_VA + 4 - image.objects[0].base:
                                                              READ_VA + 8 - image.objects[0].base], "little")
    if write_disp != slot_linear or read_disp != slot_linear:
        raise AssertionError(f"LE fixup mismatch: write=0x{write_disp:x}, read=0x{read_disp:x}, slot=0x{slot_linear:x}")
    if "es_base + (0x29ac41)" not in write_fn.lower():
        raise AssertionError("saved DS instruction did not use the LE-fixed ES offset")
    if "cs_base + (0x29ac41)" not in read_fn.lower():
        raise AssertionError("restored DS instruction did not use the LE-fixed CS offset")

    fixture = ROOT / "build" / "selector_slot_roundtrip_lift.c"
    fixture.write_text(
        '#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_context.h"\n'
        + write_fn + "\n" + read_fn + "\n", encoding="utf-8")
    harness = ROOT / "tests" / "test_selector_slot_roundtrip.c"
    exe = ROOT / "build" / "test_selector_slot_roundtrip.exe"
    env = {**os.environ, "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    cmd = [r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0",
           "-I", str(ROOT / "runtime"), "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
           "-o", str(exe), str(harness), str(fixture),
           str(ROOT / "runtime" / "recomp_context.c"), str(ROOT / "runtime" / "gw_interrupts.c"),
           str(ROOT / "runtime" / "gw_segments.c"), str(ROOT / "runtime" / "gw_pit8254.c"),
           str(ROOT / "runtime" / "recomp_bridge.c")]
    for args in (cmd, [str(exe)]):
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True)
        print(result.stdout, end="")
        print(result.stderr, end="")
        if result.returncode:
            raise SystemExit(result.returncode)

    receipt = {
        "schema": "gw-selector-save-restore-isolated/v1",
        "target_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
        "authority": "shipped-artifact instructions; experimental execution context",
        "natural_replay": False,
        "functions_executed": [
            {"function": "FUN_000AF9E4 instruction slice", "link_va": hex(WRITE_VA),
             "instruction": "mov word ptr ES:[0x29AC41], DS", "source": "LE-loaded/fixup-applied bytes"},
            {"function": "FUN_000AFC38", "link_va": hex(READ_VA),
             "instructions": ["mov DS, word ptr CS:[0x29AC41]", "ret"], "source": "LE-loaded/fixup-applied bytes"}],
        "slot": {"link_va": hex(SLOT_LINK), "guest_linear": hex(slot_linear),
                 "effective_address_relation": "ES_BASE + slot_offset == CS_BASE + slot_offset when flat selector bases are equal"},
        "selector_context": {"cs": "0x160", "es": "0x168", "initial_ds_cases": ["0x24", "0x168"],
                             "all_bases": hex(FLAT_BASE), "status": "experimental; 0x168 was observed at an earlier MAIN checkpoint, not at these exact functions"},
        "fixups": {"write_displacement": hex(write_disp), "read_displacement": hex(read_disp),
                   "object_1_delta": "0x1EB000"},
        "compile_exit": 0, "run_exit": 0, "passed": True,
        "ghidra": {"provider": "REA 6.4.0 / Ghidra 12.1.4",
                   "save_instruction_evidence": "ev_2b0c8678d18c3d69b60d3f83e1d7a16d9006b9864db9f90825c04bdceb05912c",
                   "restore_instruction_evidence": "ev_a7e2df5cfe32d08ef17788df2cd9f99dc50b18ac39290fafb114d3491e40b2a8",
                   "restore_callers": ["FUN_000D2B98"]},
        "limitations": ["Does not execute the surrounding DOS initialization in FUN_000AF9E4.",
                        "No current Oracle capture supplies ES/CS descriptor bases at these exact instruction sites."]}
    (ROOT / "evidence" / "selector_slot_roundtrip_isolated.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
