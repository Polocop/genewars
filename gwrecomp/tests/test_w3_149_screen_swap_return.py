import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_149_capture_runner.py"


class ScreenSwapReturnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_return_link_is_selected_and_named(self):
        selected = self.source.split("const bool selected_capture_site =", 1)[1].split(
            "// Before MAIN's runtime mapping", 1)[0]
        self.assertIn("candidate_link_va == 0x000ae484", selected)
        self.assertIn('checkpoint_name = "W3_149_LBSCREENSWAP_RETURN"', self.source)

    def test_probe_is_armed_at_entry_and_disarmed_at_return(self):
        self.assertIn("w3_149_swap_return_probe_armed = true;", self.source)
        self.assertIn("if (w3_149_swap_return_target)", self.source)
        self.assertIn("w3_149_swap_return_probe_armed = false;", self.source)
        self.assertIn("w3_149_swap_return_probe_armed &&", self.source)

    def test_probe_window_is_bounded_to_exact_function_and_return(self):
        self.assertIn("candidate_link_va >= 0x0009ffe0 && candidate_link_va <= 0x000a008f", self.source)
        self.assertIn("candidate_link_va == 0x000ae484", self.source)
        self.assertIn("w3_149_swap_return_probe_window ||", self.source)

    def test_runner_uses_guard_caps_and_requires_observed_return(self):
        for token in (
            '"w3-149-screen-swap-return-20261009-01"',
            'str(GUARD), "run"',
            '"--timeout-s", "30"',
            '"--max-file-text-mib", "1"',
            '"--host-floor-gib", "100"',
            '"W3_149_LBSCREENSWAP_RETURN"',
            '"screen_swap_returned"',
        ):
            self.assertIn(token, self.runner)
        self.assertIn('return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1', self.runner)


if __name__ == "__main__":
    unittest.main()
