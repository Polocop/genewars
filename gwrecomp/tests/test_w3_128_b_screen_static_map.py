import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BScreenStaticMapTests(unittest.TestCase):
    def test_map_symbols_and_object_address(self):
        text = (ROOT / "evidence/genewars-1_1.map").read_text(encoding="utf-8", errors="replace")
        self.assertIn("0001:00092930       W?PlayIntro", text)
        self.assertIn("0001:000929D0       W?PlaySmacker", text)
        self.assertIn("0001:00091E00       LbMemoryAlloc_", text)
        self.assertIn("0003:00114CA0       W?b_screen", text)

    def test_disassembly_store_and_first_visible_consumer(self):
        asm = (ROOT / "evidence/genewars-1_1-le_disasm.s").read_text(encoding="utf-8", errors="replace")
        self.assertIn("call   LbMemoryAlloc_\n\t\tmov    %eax,b_screen\n\tjump_92b87:", asm)
        play_smacker = asm.index("PlaySmacker:\t/* 0x929d0 */")
        excerpt = asm[play_smacker:play_smacker + 600]
        self.assertIn("mov    b_screen,%eax\n\t\tcall   LbMemoryFree_", excerpt)

    def test_original_capture_is_not_overstated(self):
        evidence = json.loads((ROOT / "evidence/w3_127_restart_coverage.json").read_text(encoding="utf-8"))
        summary = evidence["trace"]["summary"]
        self.assertTrue(summary["callee_then_return_observed"])
        self.assertIn("0x00092B82", summary["post_anchor_link_vas"])
        self.assertFalse(evidence["capture"]["menu_or_framebuffer_claimed"])
        self.assertFalse(evidence["capture"].get("b_screen_runtime_value_measured", False))


if __name__ == "__main__":
    unittest.main()
