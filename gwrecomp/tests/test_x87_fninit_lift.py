"""Exercise FNINIT's modeled state reset and Watcom's FNSTCW-visible CW."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "third_party" / "python"), str(ROOT / "third_party" / "pcrecomp")]

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.disasm.disasm32 import Instruction
from tools.lift.lift32 import Lifter
from tools.lift.lift32_cpu import Lifter as CpuLifter


def decode(code: bytes):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insn = next(md.disasm(code, 0xBBE48))
    return insn


raw = decode(bytes.fromhex("DB E3"))  # original x87 FNINIT encoding
insn = Instruction(raw.address, raw.size, raw.mnemonic, raw.op_str,
                   bytes(raw.bytes), raw.operands)
lifted = "\n".join(Lifter().lift_instruction(insn))
assert "g_fpu_cw = 0x037Fu" in lifted, lifted
assert "g_fp_top = 0" in lifted, lifted
assert "memset(g_st_i64, 0, sizeof(g_st_i64))" in lifted, lifted

# The independent CPU-struct lifter must preserve the same architected reset
# and FNSTCW must read that CPU's current control word, not a fixed constant.
cpu_lifter = CpuLifter(None, 0)
cpu_fninit = "\n".join(cpu_lifter.translate(raw, set()))
assert "c->fpu_cw = 0x037Fu" in cpu_fninit, cpu_fninit
assert "c->fpu_top = 0" in cpu_fninit, cpu_fninit
raw_cw = decode(bytes.fromhex("D9 3C 24"))  # FNSTCW word ptr [ESP]
cpu_fnstcw = "\n".join(cpu_lifter.translate(raw_cw, set()))
assert "c->fpu_cw" in cpu_fnstcw and "0x027F" not in cpu_fnstcw, cpu_fnstcw

fixture = ROOT / "build" / "x87_fninit_fixture.c"
exe = ROOT / "build" / "test_x87_fninit.exe"
env = {**os.environ, "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
fixture.write_text(
    '#define RECOMP_GENERATED_CODE\n'
    '#include "recomp_types.h"\n'
    'uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_ebp,g_esi,g_edi,g_cur_func;\n'
    'uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;\n'
    'uint32_t g_fs_base,g_gs_base; ptrdiff_t g_mem_base;\n'
    'double g_st[8]; int g_fp_top;\n'
    'int gw_recomp_guest_instruction(unsigned int va) { (void)va; return 1; }\n'
    'static void run_guest_fninit(void) {\n' + lifted + '\n}\n'
    'int main(void) {\n'
    '  g_fpu_cw=0x027Fu; g_fp_top=3;\n'
    '  for (int i=0;i<8;i++) { g_st[i]=(double)(i+1); g_st_i64[i]=i+100; }\n'
    '  run_guest_fninit();\n'
    '  if (g_fpu_cw!=0x037Fu || g_fp_top!=0) return 1;\n'
    '  for (int i=0;i<8;i++) if (g_st[i]!=0.0 || g_st_i64[i]!=0) return 2;\n'
    '  return 0;\n}\n', encoding="utf-8")
cmd = [r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0",
       "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
       "-o", str(exe), str(fixture)]
p = subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)
if p.returncode:
    print(p.stdout, p.stderr, file=sys.stderr)
    raise SystemExit(p.returncode)
p = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
if p.returncode:
    print(p.stdout, p.stderr, file=sys.stderr)
    raise SystemExit(p.returncode)
print("PASS x87 FNINIT resets control word, stack depth, values and exact-i64 shadow; CPU lifter FNSTCW is state-backed")
target = ROOT / "evidence" / "genewars-1_1.exe"
report = {
    "schema": "gw-x87-fninit-regression/v1",
    "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    "lifter_sha256": hashlib.sha256((ROOT / "third_party" / "pcrecomp" / "tools" / "lift" / "lift32.py").read_bytes()).hexdigest(),
    "cpu_lifter_sha256": hashlib.sha256((ROOT / "third_party" / "pcrecomp" / "tools" / "lift" / "lift32_cpu.py").read_bytes()).hexdigest(),
    "generated_fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
    "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
    "compile_exit": 0,
    "run_exit": 0,
    "checks": ["FNINIT sets CW=0x037F", "FNINIT clears virtual x87 stack depth and values",
               "FNINIT clears exact-i64 shadow", "CPU lifter FNSTCW reads c->fpu_cw",
               "CPU lifter FNINIT resets status/control/stack"],
    "passed": True,
}
(ROOT / "evidence" / "x87_fninit_lifter_regression.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
