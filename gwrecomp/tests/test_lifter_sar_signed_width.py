"""Exercise the lifter's signed shift/extension emitters on x86 edge cases."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from tools.lift.lift32 import Lifter  # noqa: E402


def main() -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    lifter = Lifter()
    cases = [
        # Legacy LE sites: signed 16-bit animation frame offsets.
        ("sar_bx_imm", "66 D1 FB", "ebx=0xFFF0u;", "return (int16_t)LO16(ebx);", -8,
         "int16_t", "LO16(ebx)"),
        ("sar_di_imm", "66 D1 FF", "edi=0x0000FFC2u;", "return (int16_t)LO16(edi);", -31,
         "int16_t", "LO16(edi)"),
        # Byte and word operands, both CL and immediate count encodings.
        ("sar_al_imm", "D0 F8", "eax=0xF0u;", "return (int8_t)LO8(eax);", -8,
         "int8_t", "LO8(eax)"),
        ("sar_al_cl", "D2 F8", "eax=0xF0u; ecx=2u;", "return (int8_t)LO8(eax);", -4,
         "int8_t", "LO8(eax)"),
        ("sar_ax_cl", "66 D3 F8", "eax=0xFFF0u; ecx=2u;", "return (int16_t)LO16(eax);", -4,
         "int16_t", "LO16(eax)"),
        ("sar_mem8_cl", "D2 7E 04", "esi=16u; ecx=2u; memory[20]=0xF0u;",
         "return (int8_t)memory[20];", -4, "int8_t", "MEM8(DS_BASE + (esi + 0x4))"),
        ("sar_mem8_imm", "C0 7E 04 03", "esi=16u; memory[20]=0xF0u;",
         "return (int8_t)memory[20];", -2, "int8_t", "MEM8(DS_BASE + (esi + 0x4))"),
        ("sar_mem16_imm", "66 C1 7E 04 01", "esi=16u; memory[20]=0xC2u; memory[21]=0xFFu;",
         "return (int16_t)*(uint16_t *)(memory+20);", -31, "int16_t",
         "MEM16(DS_BASE + (esi + 0x4))"),
        ("sar_mem16_cl", "66 D3 7E 04", "esi=16u; ecx=2u; memory[20]=0xC2u; memory[21]=0xFFu;",
         "return (int16_t)*(uint16_t *)(memory+20);", -16, "int16_t",
         "MEM16(DS_BASE + (esi + 0x4))"),
        # Keep the full-width forms covered alongside the byte/word forms:
        # register and memory destinations, immediate and CL counts.
        ("sar_eax_imm", "C1 F8 01", "eax=0xFFFFFFF0u;", "return (int32_t)eax;", -8,
         "int32_t", "eax"),
        ("sar_eax_cl", "D3 F8", "eax=0xFFFFFFF0u; ecx=2u;", "return (int32_t)eax;", -4,
         "int32_t", "eax"),
        ("sar_mem32_imm", "C1 7E 04 01", "esi=16u; *(uint32_t *)(memory+20)=0xFFFFFFC2u;",
         "return (int32_t)*(uint32_t *)(memory+20);", -31, "int32_t",
         "MEM32(DS_BASE + (esi + 0x4))"),
        ("sar_mem32_cl", "D3 7E 04", "esi=16u; ecx=2u; *(uint32_t *)(memory+20)=0xFFFFFFC2u;",
         "return (int32_t)*(uint32_t *)(memory+20);", -16, "int32_t",
         "MEM32(DS_BASE + (esi + 0x4))"),
    ]

    emitted_functions: list[str] = []
    for index, (name, encoded, init, result, expected, signed_type, operand) in enumerate(cases):
        instruction = next(decoder.disasm(bytes.fromhex(encoded), 0x1000 + index * 0x10))
        assert instruction.mnemonic == "sar", (name, instruction.mnemonic, instruction.op_str)
        lifted = "\n".join(lifter.lift_instruction(instruction))
        assert f"({signed_type})({operand})" in lifted, (name, lifted)
        body = "\n".join("    " + line for line in lifted.splitlines())
        emitted_functions.append(
            f"static void {name}(void) {{\n"
            f"    uint32_t eax=0,ebx=0,ecx=0,edi=0,esi=0;\n"
            f"    uint8_t memory[64]={{0}};\n"
            f"    uint32_t _cf=0,_flag_a=0,_flag_b=0; int _flag_k=0;\n"
            f"    {init}\n{body}\n    observed = {result.removeprefix('return ').removesuffix(';')};\n"
            f"    observed_pf = (_flag_a >> 2) & 1u;\n}}\n"
        )

    # Sign-extension/conversion instructions are also checked at their source
    # widths so a later refactor cannot regress them while fixing SAR.
    extension_cases = [
        ("movsx8", "0F BE C0", "eax=0x000000F0u;", "return (int32_t)eax;", -16,
         "(int8_t)LO8(eax)"),
        ("movsx16", "0F BF C0", "eax=0x0000FFC2u;", "return (int32_t)eax;", -62,
         "(int16_t)LO16(eax)"),
        ("cbw", "66 98", "eax=0x123400F0u;", "return (int16_t)LO16(eax);", -16,
         "(int8_t)LO8(eax)"),
        ("cwde", "98", "eax=0x1234FFC2u;", "return (int32_t)eax;", -62,
         "(int16_t)LO16(eax)"),
        ("cwd", "66 99", "eax=0x12348000u;", "return (int32_t)(edx & 0xFFFFu);", 0xFFFF,
         "edx = ((int16_t)LO16(eax) < 0) ? 0xFFFFu : 0;"),
        ("cdq", "99", "eax=0x80000000u;", "return (int32_t)edx;", -1,
         "(int32_t)eax < 0"),
    ]
    for index, (name, encoded, init, result, expected, marker) in enumerate(extension_cases):
        instruction = next(decoder.disasm(bytes.fromhex(encoded), 0x2000 + index * 0x10))
        lifted = "\n".join(lifter.lift_instruction(instruction))
        assert marker in lifted, (name, instruction.mnemonic, lifted)
        body = "\n".join("    " + line for line in lifted.splitlines())
        emitted_functions.append(
            f"static void {name}(void) {{\n"
            f"    uint32_t eax=0,edx=0;\n    {init}\n{body}\n"
            f"    observed = {result.removeprefix('return ').removesuffix(';')};\n}}\n"
        )

    runtime = r"""
#include <stdint.h>
#include <stdio.h>
#define LO8(x) ((uint8_t)(x))
#define LO16(x) ((uint16_t)(x))
#define SET_LO8(x,v) ((x)=(((x)&0xFFFFFF00u)|((uint8_t)(v))))
#define SET_LO16(x,v) ((x)=(((x)&0xFFFF0000u)|((uint16_t)(v))))
#define DS_BASE 0u
#define MEM8(x) (memory[(uint32_t)(x)])
#define MEM16(x) (*(uint16_t *)(memory+(uint32_t)(x)))
#define MEM32(x) (*(uint32_t *)(memory+(uint32_t)(x)))
#define RECOMP_SEG_DS 0
#define RECOMP_MEM_ACCESS_READWRITE 0
enum { FK_EFLAGS=1 };
static int32_t observed;
static uint32_t observed_pf;
static int gw_recomp_guest_instruction(uint32_t eip) { (void)eip; return 1; }
static void recomp_begin_memory_access_ex(int seg,uint32_t width,uint32_t eip,
    int access,uint32_t address,const char *mnemonic) {
    (void)seg;(void)width;(void)eip;(void)access;(void)address;(void)mnemonic;
}
static void recomp_end_memory_access(void) {}
static int recomp_memory_fault_pending(void) { return 0; }
static void recomp_flags_out(void) {}
#define RECOMP_FLAGS_OUT() recomp_flags_out()
static uint32_t recomp_flags_pack(uint32_t a,uint32_t cf,int af,int of) {
    (void)cf;(void)af;(void)of;
    uint8_t low=(uint8_t)a; unsigned ones=0;
    for(unsigned i=0;i<8;i++) ones+=(low>>i)&1u;
    return (a&~4u)|((ones&1u)?0u:4u);
}
static uint32_t recomp_pf(uint32_t value,unsigned shift) {
    uint8_t b=(uint8_t)(value>>shift); unsigned ones=0;
    for(unsigned i=0;i<8;i++) ones+=(b>>i)&1u;
    return (ones&1u)?0u:1u;
}
#define RECOMP_PF(v, shift) recomp_pf((uint32_t)(v),(unsigned)(shift))
"""
    checks = []
    for i, (name, _encoded, _init, _result, expected, *_tail) in enumerate(cases):
        expected_pf = 1 if (expected & 0xFF).bit_count() % 2 == 0 else 0
        checks.append(
            f"{name}(); if (observed != {expected}) {{ fprintf(stderr, \"{name}: got %d expected %d\\n\", observed, {expected}); return {i + 1}; }} "
            f"if (observed_pf != {expected_pf}u) {{ fprintf(stderr, \"{name}: PF got %u expected {expected_pf}\\n\", observed_pf); return {i + 101}; }}"
        )
    for j, (name, _encoded, _init, _result, expected, *_tail) in enumerate(extension_cases):
        i = len(cases) + j
        checks.append(
            f"{name}(); if (observed != {expected}) {{ fprintf(stderr, \"{name}: got %d expected %d\\n\", observed, {expected}); return {i + 1}; }}"
        )
    source_text = runtime + "\n".join(emitted_functions) + \
        "int main(void) {\n" + "\n".join(checks) + "\nreturn 0;\n}\n"
    clang = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang.exe")
    with tempfile.TemporaryDirectory(prefix="gw-sar-width-") as temp:
        source = Path(temp) / "sar_width.c"
        exe = Path(temp) / "sar_width.exe"
        source.write_text(source_text, encoding="utf-8")
        compiled = subprocess.run([str(clang), "-std=c11", "-O0", str(source), "-o", str(exe)],
                                  check=False, timeout=30, capture_output=True, text=True)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        executed = subprocess.run([str(exe)], check=False, timeout=5)
        if executed.returncode:
            names = [case[0] for case in cases + extension_cases]
            failing = names[executed.returncode - 1]
            excerpt = source_text[source_text.find(f"static void {failing}"):]
            raise AssertionError(f"translated instruction mismatch case={failing} code={executed.returncode}\n{excerpt[:1600]}")
    print("PASS signed-width operations: SAR byte/word register and memory, immediate/CL; MOVSX, CBW, CWDE, CWD, CDQ")


if __name__ == "__main__":
    main()
