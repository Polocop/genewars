from __future__ import annotations

import unittest

from tools.verify_native_adf95_caller_w1_064 import ROOT, validate


class NativeAdf95CallerTests(unittest.TestCase):
    def test_fresh_native_capture(self):
        result = validate(ROOT / "evidence" / "native_adf95_caller_w1_064.json")
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["native_ax0501_request"], "0x00001000")
        self.assertFalse(result["dynamic_equivalence_claimed"])

    def test_native_adf95_dfe04_branch_is_not_misreported_as_original_match(self):
        result = validate(ROOT / "evidence" / "native_adf95_caller_w1_064.json")
        self.assertTrue(result["valid"], result)
        events = result["native_adf95_branch_events"]
        self.assertEqual([event["site"] for event in events], ["000dfe04", "000dfe08"])
        self.assertEqual(events[0]["eax"], "00000000")
        self.assertEqual(events[0]["edi"], "00000000")

    def test_generator_and_harness_own_dfe0d_probe(self):
        generator = (ROOT / "tools" / "lift_entry_closure.py").read_text(encoding="utf-8")
        harness = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        closure = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
        self.assertIn("0x000DFE0D:0x000ADF95", generator)
        self.assertIn("site==0x000DFE0Du && target==0x000ADF95u", harness)
        self.assertIn("GW_NATIVE_CAPTURE_ALLOC_CALLSITE(g_cur_func, 0x000ADF95u, 0x000DFE0Du)", closure)
        self.assertIn("GW_NATIVE_CAPTURE_BLOCK(0x000ADF95u)", closure)


if __name__ == "__main__":
    unittest.main()
