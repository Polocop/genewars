import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_147_capture_runner.py"


class SmackDoFrameCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_entry_is_selected_after_measured_buffer_entry(self):
        selected = self.source.split("const bool selected_capture_site =", 1)[1].split(
            "// Before MAIN's runtime mapping", 1)[0]
        self.assertIn("candidate_link_va == 0x000c5bd0", selected)
        self.assertIn("w3_142_smack_to_buffer_target", self.source)
        self.assertIn("w3_147_frame_probe_armed = true;", self.source)

    def test_probe_stays_in_measured_frame_path_and_disarms_once(self):
        self.assertIn("w3_147_frame_probe_armed && !w3_142_smack_do_frame_seen", self.source)
        self.assertIn("candidate_link_va >= 0x000ae3d0 && candidate_link_va <= 0x000ae460", self.source)
        self.assertIn("candidate_link_va == 0x000c5bd0", self.source)
        self.assertIn("w3_147_frame_probe_window ||", self.source)
        self.assertIn("w3_147_frame_probe_armed = false;", self.source)
        self.assertIn("W3_142_SMACKDOFRAME_ENTRY", self.source)

    def test_runner_is_guarded_and_mapping_checked(self):
        self.assertIn('"w3-147-smack-doframe-20261009-01"', self.runner)
        self.assertIn('str(GUARD), "run"', self.runner)
        self.assertIn('"--timeout-s", "30"', self.runner)
        self.assertIn('"--max-file-text-mib", "1"', self.runner)
        self.assertIn('"--max-file-bin-mib", "64"', self.runner)
        self.assertIn('"--host-floor-gib", "100"', self.runner)
        self.assertIn('"smack_do_frame_runtime_rebase"', self.runner)


if __name__ == "__main__":
    unittest.main()
