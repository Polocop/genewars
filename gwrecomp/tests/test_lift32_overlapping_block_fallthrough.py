"""Keep CFG fallthrough correct when an x86 target overlaps an instruction."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from tools.disasm.disasm32 import BasicBlock, Function, Instruction
from tools.lift.lift32 import Lifter


def test_overlapping_decode_does_not_fall_through_into_alternate_block():
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded = [
        Instruction(i.address, i.size, i.mnemonic, i.op_str, bytes(i.bytes),
                    i.operands, i.id)
        for i in decoder.disasm(bytes.fromhex("89 cd 90 c3"), 0x1000)
    ]
    # The linear decode is `mov ebp,ecx; nop; ret`. A second valid CFG entry
    # begins at 0x1001, inside the MOV's immediate/decode span, like the
    # overlapping Watcom code at 0xAA0C8/0xAA0CA. Address-sorted C emission
    # places that alternate block after the linear block unless it closes the
    # first block with an explicit goto to its real fallthrough at 0x1003.
    overlap = Instruction(0x1001, 2, "int", "0x90", b"\xcd\x90", [], 0)
    function = Function(
        address=0x1000,
        end=0x1004,
        name="overlap_regression",
        blocks={
            0x1000: BasicBlock(0x1000, 0x1003, [decoded[0], decoded[1]], [0x1003]),
            0x1001: BasicBlock(0x1001, 0x1003, [overlap], [0x1003]),
            0x1003: BasicBlock(0x1003, 0x1004, [decoded[2]], [], True),
        },
        size=4,
    )

    lifted = Lifter().lift_function(function)
    linear_end = lifted.index("ebp = ecx;")
    explicit_edge = lifted.index("goto L_00001003; /* CFG fallthrough */", linear_end)
    alternate_entry = lifted.index("L_00001001:")
    assert linear_end < explicit_edge < alternate_entry


if __name__ == "__main__":
    test_overlapping_decode_does_not_fall_through_into_alternate_block()
    print("PASS overlapping CFG fallthrough remains on the linear x86 path")
