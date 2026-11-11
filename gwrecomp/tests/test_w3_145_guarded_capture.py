import unittest
from pathlib import Path

from tools.w3_144_restart_coverage import audit_source


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools/w3_145_capture_runner.py"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


class GuardedCapturePreflightTests(unittest.TestCase):
    def test_runner_is_unique_guarded_and_bounded(self):
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"w3-145-postopen-branch-20261009-01"', runner)
        self.assertIn('"run"', runner)
        self.assertIn('"--timeout-s", "30"', runner)
        self.assertIn('"--max-file-text-mib", "1"', runner)
        self.assertIn('"--max-file-bin-mib", "64"', runner)
        self.assertIn('"--max-run-gib", "1"', runner)
        self.assertIn('"--host-floor-gib", "100"', runner)
        self.assertIn('"--evidence-dir"', runner)
        self.assertIn('evidence/w3_145_smackopen_result.json', runner)
        self.assertNotIn("dosbox-x", runner.lower())

    def test_runner_requires_corrected_source_coverage(self):
        runner = RUNNER.read_text(encoding="utf-8")
        source = CORE.read_text(encoding="utf-8")
        coverage = audit_source(source)
        self.assertTrue(all(coverage["selected_capture_sites"].values()))
        self.assertTrue(coverage["one_shot_restart_window_present"])
        self.assertIn('"w3_143_postopen_probe_window"', runner)


if __name__ == "__main__":
    unittest.main()
