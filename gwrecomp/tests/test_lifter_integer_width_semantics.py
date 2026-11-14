"""Execute lifted x86 integer-width edge cases for multiply/divide/SETcc."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_CLANG_X64=_gw_os.environ.get("GWRECOMP_CLANG_X64") or _gw_os.environ.get("GWRECOMP_CLANG") or __import__("shutil").which("clang") or "clang.exe"

from pathlib import Path
import subprocess
import tempfile
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from tools.lift.lift32 import Lifter  # noqa: E402


CASES = [
    # name, instruction sequence, initial registers, observed expression, expected
    ("imul16_signed_no_overflow", ["66 0F AF C3"],
     "eax=0x12340003u; ebx=0xFFFFu;", "LO16(eax) | (_cf << 16)", 0x0000FFFD),
    ("imul16_immediate_overflow", ["66 6B C3 02"],
     "eax=0xA5A50000u; ebx=0xB1E0u;", "LO16(eax) | (_cf << 16)", 0x000163C0),
    ("imul32_overflow", ["69 C3 02 00 00 00"],
     "eax=0u; ebx=0x40000000u;", "eax ^ (_cf << 31)", 0x00000000),
    ("imul32_negative", ["0F AF C3"],
     "eax=0xFFFFFFFFu; ebx=3u;", "eax | (_cf << 31)", 0xFFFFFFFD),
    ("idiv8_signed", ["F6 F9"],
     "eax=0xFFFEu; ecx=2u;", "LO16(eax)", 0x00FF),
    ("idiv8_overflow", ["F6 F9"],
     "eax=0x0100u; ecx=1u;", "LO16(eax)", 0),
    ("idiv16_signed", ["66 F7 FB"],
     "eax=0xFFFFFF9Cu; edx=0xFFFFFFFFu; ebx=6u;",
     "LO16(eax) | (LO16(edx) << 16)", 0xFFFCFFF0),
    ("idiv16_overflow", ["66 F7 FB"],
     "eax=0u; edx=1u; ebx=1u;", "LO16(eax) | (LO16(edx) << 16)", 0),
    ("idiv32_signed", ["F7 FB"],
     "eax=0xFFFFFF9Cu; edx=0xFFFFFFFFu; ebx=6u;",
     "eax ^ edx", 0x0000000C),
    ("idiv32_overflow", ["F7 FB"],
     "eax=0u; edx=1u; ebx=1u;", "eax | edx", 0),
    ("idiv32_min_overflow", ["F7 FB"],
     "eax=0u; edx=0x80000000u; ebx=0xFFFFFFFFu;", "eax | edx", 0),
    ("div8_overflow", ["F6 F1"],
     "eax=0x0100u; ecx=1u;", "LO16(eax)", 0),
    ("div16_overflow", ["66 F7 F3"],
     "eax=0u; edx=1u; ebx=1u;", "LO16(eax) | (LO16(edx) << 16)", 0),
    ("div32_overflow", ["F7 F3"],
     "eax=0u; edx=1u; ebx=1u;", "eax | edx", 0),
    # A signed 16-bit CMP must feed SETL using sign-extended width-aligned operands.
    ("cmp16_setl_signed", ["66 39 D8", "0F 9C C0"],
     "eax=0xABCDFFF0u; ebx=1u;", "LO8(eax)", 1),
    ("cmp16_setg_signed", ["66 39 D8", "0F 9F C0"],
     "eax=0xABCDFFF0u; ebx=1u;", "LO8(eax)", 0),
]


def main() -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    functions: list[str] = []
    checks: list[str] = []
    for index, (name, encoded_rows, initial, expression, expected) in enumerate(CASES):
        lifter = Lifter()
        lifted: list[str] = []
        for j, encoded in enumerate(encoded_rows):
            insn = next(decoder.disasm(bytes.fromhex(encoded), 0x5000 + index * 0x40 + j * 4))
            lifted.extend(lifter.lift_instruction(insn))
        body = "\n".join("    " + line for line in lifted)
        functions.append(
            f"static void {name}(void) {{\n"
            "    uint32_t eax=0,ebx=0,ecx=0,edx=0,esi=0,edi=0,ebp=0,esp=0;\n"
            "    uint32_t _cf=0,_flag_a=0,_flag_b=0; int _flag_k=0; int32_t _df=1;\n"
            f"    {initial}\n{body}\n    observed=(int32_t)({expression});\n}}\n"
        )
        checks.append(
            f"{name}(); if ((uint32_t)observed != 0x{expected:08X}u) "
            f"{{ fprintf(stderr, \"{name}: got=%08X expected=0x{expected:08X}\\n\", "
            f"(uint32_t)observed); return {index + 1}; }}"
        )

    prelude = r"""
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#define LO8(x) ((uint8_t)(x))
#define LO16(x) ((uint16_t)(x))
#define SET_LO8(x,v) ((x)=(((x)&0xFFFFFF00u)|((uint8_t)(v))))
#define SET_LO16(x,v) ((x)=(((x)&0xFFFF0000u)|((uint16_t)(v))))
#define FK_EFLAGS 1
#define FK_CMP 2
#define FK_NARROW(kind,bits) (kind)
#define CMP_B(a,b) ((uint32_t)(a) < (uint32_t)(b))
#define CMP_L(a,b) ((int32_t)(a) < (int32_t)(b))
#define CMP_G(a,b) ((int32_t)(a) > (int32_t)(b))
#define CMP_EQ(a,b) ((uint32_t)(a) == (uint32_t)(b))
static int32_t observed;
static int gw_recomp_guest_instruction(unsigned int eip) { (void)eip; return 1; }
static int recomp_memory_fault_pending(void) { return 0; }
static void recomp_flags_out(void) {}
#define RECOMP_FLAGS_OUT() recomp_flags_out()
"""
    source_text = prelude + "\n".join(functions) + "\nint main(void) {\n" + "\n".join(checks) + "\nreturn 0;\n}\n"
    clang = Path((_GW_CLANG_X64))
    with tempfile.TemporaryDirectory(prefix="gw-lifter-int-width-") as temp:
        source = Path(temp) / "integer_width.c"
        exe = Path(temp) / "integer_width.exe"
        source.write_text(source_text, encoding="utf-8")
        compiled = subprocess.run([str(clang), "-std=c11", "-O0", str(source), "-o", str(exe)],
                                  check=False, timeout=30, capture_output=True, text=True)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        executed = subprocess.run([str(exe)], check=False, timeout=5)
        if executed.returncode:
            raise AssertionError(f"lifted integer-width case failed: {executed.returncode}")
    print("PASS lifted IMUL signed width/CF-OF, DIV-IDIV quotient overflow and signed CMP/SETL/SETG")


if __name__ == "__main__":
    main()
