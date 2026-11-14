"""Verify the operand-size-overridden PUSHF sequence used by Watcom AIL."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # noqa: E402
from tools.lift.lift32 import Lifter  # noqa: E402


def main() -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(bytes.fromhex("669c6658"), 0xC911B))
    assert [(item.mnemonic, item.bytes.hex()) for item in instructions] == [
        ("pushf", "669c"), ("pop", "6658")
    ]

    lifter = Lifter()
    push = "\n".join(lifter.lift_instruction(instructions[0]))
    pop = "\n".join(lifter.lift_instruction(instructions[1]))
    assert "PUSH16(esp, (uint16_t)(recomp_eflags(" in push, push
    assert "PUSH32(esp" not in push, push
    assert "RECOMP_SEG_SS, 2u" in push, push
    assert "SET_LO16(eax, POP16_VAL(esp))" in pop, pop
    assert "RECOMP_SEG_SS, 2u" in pop, pop
    print("PASS original 66 9C / 66 58 lifts to balanced 16-bit EFLAGS push and AX pop")


if __name__ == "__main__":
    main()
