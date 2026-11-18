"""Regression for DOS/4GW RET trampolines into the LE INT vector table."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from tools.disasm.disasm32 import BasicBlock, Function, Instruction
from tools.lift.lift32 import Lifter


class DynamicRetThunkTests(unittest.TestCase):
    def test_real_guest_ret_target_is_dispatched_but_synthetic_return_is_preserved(self):
        instruction = Instruction(0xD226E, 1, "ret", "", b"\xC3", [])
        block = BasicBlock(0xD226E, 0xD226F, [instruction], is_exit=True)
        function = Function(0xD226E, 0xD226F, "ret_thunk_probe", {0xD226E: block}, size=1)
        body = Lifter().lift_function(function)
        self.assertIn("MEM32(SS_BASE + (esp))", body)
        # In local-register mode, publish the post-RET state before a native C
        # return on the synthetic sentinel path; otherwise RECOMP_CALL reloads
        # the stale callee-entry ESP. This is a lifter invariant even when a
        # particular harness currently builds with global register aliases.
        self.assertIn("esp += 4; RECOMP_REGS_OUT();", body)
        self.assertIn("_recomp_ret_va != RECOMP_RETADDR", body)
        self.assertIn("RECOMP_ITAIL(_recomp_ret_va)", body)
        harness = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        self.assertIn("va!=0x000D23A7u", harness)
        self.assertIn("guest_memory[va]!=0xCDu", harness)
        self.assertIn("guest_memory[va+1u]!=0x31u", harness)
        self.assertIn("guest_memory[va+2u]!=0xC3u", harness)
        self.assertIn("gw_interrupt_dispatch(0x31u,va)", harness)


if __name__ == "__main__":
    unittest.main()
