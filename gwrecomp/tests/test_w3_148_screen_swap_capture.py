import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_148_capture_runner.py"


class ScreenSwapCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_return_and_swap_sites_are_selected_and_named(self):
        selected = self.source.split("const bool selected_capture_site =", 1)[1].split(
            "// Before MAIN's runtime mapping", 1)[0]
        for address in ("0x000ae466", "0x000ae47f", "0x0009ffe0"):
            self.assertIn(f"candidate_link_va == {address}", selected)
        for name in ("W3_148_SMACKDOFRAME_RETURN", "W3_142_LBSCREENSWAP_CALLSITE",
                     "W3_142_LBSCREENSWAP_ENTRY"):
            self.assertIn(name, self.source)

    def test_window_is_armed_after_frame_and_disarmed_at_swap_entry(self):
        self.assertIn("w3_142_smack_do_frame_target", self.source)
        self.assertIn("w3_148_swap_probe_armed = true;", self.source)
        self.assertIn("w3_148_swap_probe_armed && w3_142_direct_capture_armed", self.source)
        self.assertIn("candidate_link_va >= 0x000c5bd0 && candidate_link_va <= 0x000c5c9d", self.source)
        self.assertIn("candidate_link_va >= 0x000ae466 && candidate_link_va <= 0x000ae47f", self.source)
        self.assertIn("w3_148_swap_probe_window ||", self.source)
        self.assertIn("w3_148_swap_probe_armed = false;", self.source)

    def test_runner_is_guarded_bounded_and_mapping_checked(self):
        self.assertIn('"w3-148-screen-swap-20261009-01"', self.runner)
        self.assertIn('str(GUARD), "run"', self.runner)
        self.assertIn('"--timeout-s", "30"', self.runner)
        self.assertIn('"--max-file-text-mib", "1"', self.runner)
        self.assertIn('"--host-floor-gib", "100"', self.runner)
        self.assertIn('"screen_swap_entry"', self.runner)
        self.assertIn('"screen_swap_reached"', self.runner)


if __name__ == "__main__":
    unittest.main()
