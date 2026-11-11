"""Compile and execute lifted 32-bit BSF/BSR semantics."""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.lift.lift32 import Lifter


decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
instructions = list(decoder.disasm(bytes.fromhex("0f bd c1"), 0x96275))
assert len(instructions) == 1 and instructions[0].mnemonic == "bsr"
lifted = Lifter().lift_instruction(instructions[0])
assert "UNIMPLEMENTED" not in "\n".join(lifted)

source = r'''
#include <stdint.h>
enum { FK_NONE=0, FK_EFLAGS=6 };
uint32_t eax, ecx, _flag_k, _flag_a, _flag_b, _cf;
int gw_recomp_guest_instruction(unsigned int va) { return va == 0x96275u; }
void run_bsr(void) {
''' + "\n".join(lifted) + r'''
}
int main(void) {
    eax=0xdeadbeefu; ecx=0x09c67100u; run_bsr();
    if (eax != 27u || _flag_k != FK_EFLAGS || _flag_a != 0u) return 1;
    eax=0x12345678u; ecx=0; run_bsr();
    if (eax != 0x12345678u || _flag_k != FK_EFLAGS || _flag_a != 0x40u) return 2;
    return 0;
}
'''

build = ROOT / "build"
build.mkdir(exist_ok=True)
(build / "test_lifter_bsr.c").write_text(source, encoding="utf-8")
exe = build / "test_lifter_bsr.exe"
cache = ROOT / "cache"
cache.mkdir(exist_ok=True)
env = {
    **os.environ,
    "TEMP": str(cache), "TMP": str(cache), "TMPDIR": str(cache),
    "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
}
compiler = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")
if not compiler.is_file():
    raise SystemExit(f"32-bit MinGW compiler unavailable: {compiler}")
compiled = subprocess.run([str(compiler), "-std=c11", "-Wall", "-Werror", "-o", str(exe),
                           str(build / "test_lifter_bsr.c")], cwd=ROOT, env=env,
                          text=True, capture_output=True)
if compiled.returncode:
    raise SystemExit(compiled.stdout + compiled.stderr)
run = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
if run.returncode:
    raise SystemExit(f"BSR lifted execution failed: {run.returncode}\n{run.stdout}{run.stderr}")
print("BSR lifted execution passed: source 0x09c67100 -> index 27; zero preserves destination and sets ZF")
