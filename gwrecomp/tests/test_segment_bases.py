"""Lift the real GeneWars ES:[0x5c] startup sequence and test its descriptor base."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime"))
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from le_loader import load_le
from guest_boot import GENEWARS_11_MEASURED_OBJECT_DELTAS
from tools.disasm.disasm32 import BasicBlock, Function, Instruction
from tools.lift.lift32 import Lifter
from tools.pe.pe_analyze import Section
from capstone.x86 import X86_REG_EAX, X86_REG_EBP, X86_REG_FS


def main():
    image_path = ROOT / "evidence" / "genewars-1_1.exe"
    image = load_le(image_path, object_rebases=GENEWARS_11_MEASURED_OBJECT_DELTAS)
    obj = image.objects[0]
    code = bytes(image.object_data(1))
    section = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
    from tools.disasm.disasm32 import Disassembler
    dis = Disassembler(code, 0, [section])
    raw = list(dis.disassemble_at(0x000AFA30, max_bytes=14))
    if len(raw) < 2 or raw[0].address != 0xAFA30 or raw[1].address != 0xAFA37:
        raise AssertionError("could not recover exact startup segment instructions")
    if "es:" not in raw[1].op_str or "0x5c" not in raw[1].op_str:
        raise AssertionError(f"target instruction changed unexpectedly: {raw[1]}")
    if "0x2e576c" not in raw[0].op_str or image.link_to_linear(0x10B76C) != 0x2E576C:
        raise AssertionError(f"LE fixup did not relocate the selector slot to the measured data object: {raw[0]}")
    insns = [
        Instruction(x.address, x.size, x.mnemonic, x.op_str, bytes(x.bytes), x.operands)
        for x in raw[:2]
    ]
    insns.append(Instruction(0x000AFA3E, 1, "ret", "", b"\xC3", []))
    block = BasicBlock(0x000AFA30, 0x000AFA3F, insns, is_exit=True)
    function = Function(0x000AFA30, 0x000AFA3F, "gw_segment_probe", {0x000AFA30: block}, size=15)
    body = Lifter().lift_function(function)
    if "RECOMP_SEG_ES" not in body or "ES_BASE + (0x5C)" not in body:
        raise AssertionError("segment selector/base was not used by generated target instructions")

    lifter = Lifter()
    ebp_addr = lifter._fmt_mem_addr(SimpleNamespace(base=X86_REG_EBP, index=0, scale=1, disp=4, segment=0))
    eax_addr = lifter._fmt_mem_addr(SimpleNamespace(base=X86_REG_EAX, index=0, scale=1, disp=4, segment=0))
    fs_addr = lifter._fmt_mem_addr(SimpleNamespace(base=0, index=0, scale=1, disp=0, segment=X86_REG_FS))
    assert ebp_addr.startswith("SS_BASE +") and eax_addr.startswith("DS_BASE +") and fs_addr.startswith("FS_BASE +")

    fixture = ROOT / "build" / "segment_probe.c"
    fixture.write_text('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_context.h"\n' + body + "\n", encoding="utf-8")
    cache = ROOT / "cache"
    cache.mkdir(exist_ok=True)
    env = {
        **os.environ, "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(cache), "TMP": str(cache), "TMPDIR": str(cache),
        "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
    }
    exe = ROOT / "build" / "test_segment_bases.exe"
    cmd = [
        r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(exe), str(ROOT / "tests" / "test_segment_bases.c"),
        str(ROOT / "runtime" / "recomp_context.c"), str(ROOT / "runtime" / "gw_interrupts.c"),
        str(ROOT / "runtime" / "gw_segments.c"), str(ROOT / "runtime" / "gw_pit8254.c"), str(fixture),
    ]
    compiled = subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)
    if compiled.returncode:
        print(compiled.stdout, end=""); print(compiled.stderr, end=""); raise SystemExit(compiled.returncode)
    result = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(result.stdout, end=""); print(result.stderr, end="")
    if result.returncode: raise SystemExit(result.returncode)
    evidence = {
        "execution_mode": "focused_compiled_lift_fixture",
        "natural_replay": False,
        "fixture_state_is_synthetic": True,
        "test": "actual GeneWars 1.1 startup instructions MOV ES,[...] then ES:[0x5c] with selector resolver",
        "target_sha256": hashlib.sha256(image_path.read_bytes()).hexdigest(),
        "instructions": [{"va": f"0x{x.address:08X}", "text": f"{x.mnemonic} {x.op_str}"} for x in insns[:2]],
        "checks": ["measured object 1/3 map applies the LE fixup for DS:[0x10b76c] to guest linear 0x2e576c", "ES selector resolves base", "ES:[0x5c] reads configured memory", "unresolved selector records exact segment fault", "default EBP uses SS", "default EAX uses DS", "FS override preserved", "context preserves all segment bases"],
        "object_locations_verified": [1, 3],
        "object_locations_unknown": [2, 4],
        "dispatcher_entry_va": f"0x{0xAFA30:08X}",
        "selector_slot_guest_linear": f"0x{image.link_to_linear(0x10B76C):08X}",
        "compile_exit": 0, "run_exit": 0, "passed": True,
    }
    (ROOT / "evidence" / "segment_bases.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("PASS actual GeneWars segment instructions, resolver, precise fault, and context round-trip")


if __name__ == "__main__":
    main()
