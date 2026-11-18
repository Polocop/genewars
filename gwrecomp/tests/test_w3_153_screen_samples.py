import unittest
from pathlib import Path
from tools.w3_153_capture_runner import sample_offsets, sample_bounds_valid

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_153_capture_runner.py"


class ScreenSamplesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_sparse_offsets_are_unique_and_capped(self):
        self.assertEqual(sample_offsets(64000), [0, 32000, 63984])
        self.assertEqual(sample_offsets(32), [0, 16])
        self.assertEqual(sample_offsets(16), [0])
        self.assertEqual(sample_offsets(15), [])
        self.assertLessEqual(len(sample_offsets(64000)) * 16, 48)

    def test_each_window_requires_all_bounds(self):
        self.assertTrue(sample_bounds_valid(0xA0000, 0, 16, 0xFFFFFFFF, 0x1000000))
        self.assertFalse(sample_bounds_valid(0xA0000, 0x1000, 16, 0xA0FFF, 0x1000000))
        self.assertFalse(sample_bounds_valid(0xA0000, 0, 16, 0xFFFFFFFF, 0xA000F))
        self.assertFalse(sample_bounds_valid(0xFFFFFFFF, 0, 16, 0xFFFFFFFF, 0x100000000))

    def test_runtime_globals_are_hash_bound_and_checked(self):
        for token in ("w3_153_screen_width", "w3_153_screen_height", "w3_153_wscreen",
                      "w3_153_display", "w3_153_geometry_matches_eax",
                      "w3_153_globals_match_copy"):
            self.assertIn(token, self.source)
        self.assertIn("target_data_rebase + 0x0019ca78", self.source)
        self.assertIn("target_data_rebase + 0x0019ca7c", self.source)
        self.assertIn("w3_153_geometry_matches_eax", self.source)

    def test_capture_has_three_checked_windows_and_no_full_dump(self):
        self.assertIn("const uint64_t sample_offsets[3]", self.source)
        self.assertIn("source_end_window", self.source)
        self.assertIn("destination_end", self.source)
        self.assertIn("w3_153_sample_bytes_total += 16", self.source)
        self.assertIn("w3_153_sample_windows", self.source)
        self.assertIn("sample_offsets", self.runner)
        self.assertIn('"max_bytes": 48', self.runner)

    def test_runner_is_guarded_and_capped(self):
        for token in ('str(GUARD), "run"', '"--timeout-s", "30"',
                      '"--max-file-text-mib", "1"', '"--host-floor-gib", "100"',
                      '"framebuffer_or_visible_output_proven": False'):
            if token.startswith('"framebuffer'):
                token = 'result["framebuffer_or_visible_output_proven"] = False'
            self.assertIn(token, self.runner)


if __name__ == "__main__":
    unittest.main()
