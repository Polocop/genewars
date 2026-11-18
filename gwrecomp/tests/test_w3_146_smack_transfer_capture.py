import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_146_capture_runner.py"


class SmackTransferCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_entry_is_selected_and_armed_only_after_success(self):
        selected = self.source.split("const bool selected_capture_site =", 1)[1].split(
            "// Before MAIN's runtime mapping", 1)[0]
        self.assertIn("candidate_link_va == 0x000c5140", selected)
        self.assertIn("w3_143_smackopen_success_zero_target ||", self.source)
        self.assertIn("w3_143_smackopen_success_one_target)", self.source)
        self.assertIn("w3_146_transfer_probe_armed = true;", self.source)

    def test_transfer_window_is_measured_bounded_and_one_shot(self):
        self.assertIn("target_context && target_main_rebase", self.source)
        self.assertIn("w3_146_transfer_probe_armed && !w3_142_smack_to_buffer_seen", self.source)
        self.assertIn("candidate_link_va >= 0x000ae39a && candidate_link_va <= 0x000ae3c9", self.source)
        self.assertIn("candidate_link_va == 0x000c5140", self.source)
        self.assertIn("w3_146_transfer_probe_window ||", self.source)
        self.assertIn("w3_146_transfer_probe_armed = false;", self.source)
        self.assertIn("W3_142_SMACKTOBUFFER_ENTRY", self.source)

    def test_runner_uses_guard_and_existing_bounds(self):
        self.assertIn('"w3-146-smack-to-buffer-20261009-01"', self.runner)
        self.assertIn('str(GUARD), "run"', self.runner)
        self.assertIn('"--timeout-s", "30"', self.runner)
        self.assertIn('"--max-file-text-mib", "1"', self.runner)
        self.assertIn('"--max-file-bin-mib", "64"', self.runner)
        self.assertIn('"--host-floor-gib", "100"', self.runner)
        self.assertIn("w3_146_transfer_probe_window", self.runner)


if __name__ == "__main__":
    unittest.main()
