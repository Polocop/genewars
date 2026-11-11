from __future__ import annotations

import pathlib
import unittest

from tools.verify_native_ax0501_strict_w1_063 import ROOT, validate


class StrictAx0501CaptureTests(unittest.TestCase):
    def test_fresh_native_capture(self):
        result = validate(ROOT / "evidence" / "native_ax0501_strict_w1_063.json")
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["request_size_bytes"], "0x00001000")

    def test_stop_mode_precedes_every_response_path_and_retains_arena(self):
        harness = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        driver = (ROOT / "tests" / "test_native_guest_image.py").read_text(encoding="utf-8")
        callback = harness[harness.index("static gw_interrupt_result native_dos_callback"):]
        strict_pos = callback.index("#ifdef GW_NATIVE_STOP_AT_FIRST_AX0501")
        early_success_pos = callback.index("Bounded synthetic success for allocations")
        post_time_success_pos = callback.index("#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR_SUCCESS")
        self.assertLess(strict_pos, early_success_pos)
        self.assertLess(strict_pos, post_time_success_pos)
        self.assertIn("guest_memory[0x400000]", harness)
        self.assertIn("--stop-at-first-ax0501", driver)
        self.assertIn("GW_NATIVE_STOP_AT_FIRST_AX0501=1", driver)

    def test_generator_owns_all_heap_probes(self):
        source = (ROOT / "tools" / "lift_entry_closure.py").read_text(encoding="utf-8")
        for callsite in ("0x000AE038", "0x000AE287", "0x000C3D98", "0x000C3DB0"):
            self.assertIn(callsite, source)
        self.assertIn("GW_NATIVE_CAPTURE_ALLOC_RETURN", source)
        closure = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
        for callsite in ("0x000AE038u", "0x000AE287u", "0x000C3D98u", "0x000C3DB0u"):
            self.assertIn(callsite, closure)


if __name__ == "__main__":
    unittest.main()
