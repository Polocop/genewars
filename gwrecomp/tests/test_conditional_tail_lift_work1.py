"""Verify conditional jumps out of a lifted function use the tail bridge."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "python"))
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.disasm.disasm32 import Instruction
from tools.lift.lift32 import Lifter


def lift_one(code: bytes):
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    raw = next(decoder.disasm(code, 0x100))
    instruction = Instruction(raw.address, raw.size, raw.mnemonic, raw.op_str,
                              bytes(raw.bytes), raw.operands)
    lifter = Lifter()
    lifter._labels = {0x100}  # 0x110 is outside this function's local labels
    return "\n".join(lifter.lift_instruction(instruction))


conditional = lift_one(bytes.fromhex("74 0e"))  # jz 0x110
unconditional = lift_one(bytes.fromhex("eb 0e"))  # jmp 0x110
expected = "RECOMP_ITAIL(0x00000110u); return;"
assert expected in conditional, conditional
assert expected in unconditional, unconditional
assert conditional.index("if (") < conditional.index(expected), conditional
print("PASS conditional and unconditional direct tail jumps use the same RECOMP_ITAIL bridge")
