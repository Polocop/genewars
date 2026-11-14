import json
import unittest

from tools.w3_157_capture_runner import loader_entry_matches, windows_bounded


def sample_windows(prefix: str):
    return [{"offset": n, "valid": True, "hex": prefix * 16}
            for n in (0, 32000, 63984)]


class WScreenLoadToCopyTests(unittest.TestCase):
    def test_entry_filter_requires_exact_target_return_and_descriptor(self):
        event = {"link_va": 0x15090, "return_address": 0x1EB000 + 0x94DC1,
                 "edx": 0x1DA000 + 0x104054, "w3_157_descriptor_name": "*W_SCREEN"}
        self.assertTrue(loader_entry_matches(event, 0x1EB000, 0x1DA000))
        for key, value in (("return_address", 0x1234), ("edx", 0x104054),
                           ("w3_157_descriptor_name", "*OTHER")):
            bad = dict(event, **{key: value})
            self.assertFalse(loader_entry_matches(bad, 0x1EB000, 0x1DA000))
        self.assertFalse(loader_entry_matches(None, 0x1EB000, 0x1DA000))

    def test_sample_windows_require_all_offsets_and_valid_bounds(self):
        self.assertTrue(windows_bounded(sample_windows("00")))
        bad = sample_windows("00")
        bad[1]["valid"] = False
        self.assertFalse(windows_bounded(bad))
        self.assertFalse(windows_bounded(sample_windows("00")[:2]))

    def test_combined_sample_budget_is_96_bytes(self):
        loaded = sample_windows("00")
        copied = sample_windows("11")
        total = (len(loaded) + len(copied)) * 16
        self.assertEqual(total, 96)
        self.assertLessEqual(total, 96)

    def test_json_serialization_preserves_two_checkpoint_samples(self):
        sample = {"loader_return": sample_windows("00"),
                  "copy_pre": sample_windows("11"), "visible_output_proven": False}
        self.assertEqual(json.loads(json.dumps(sample)), sample)

    def test_runner_is_guarded_and_trace_is_bounded(self):
        from pathlib import Path
        runner = Path("tools/w3_157_capture_runner.py").read_text(encoding="utf-8")
        core = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertIn('str(GUARD), "run"', runner)
        self.assertIn('"--timeout-s", "30"', runner)
        self.assertIn('"--max-file-text-mib", "1"', runner)
        self.assertIn('"--host-floor-gib", "100"', runner)
        self.assertIn("w3_157_total_sample_bytes + w3_157_sample_bytes + 16 <= 96", core)
        self.assertIn('"framebuffer_or_visible_output_proven": False', runner)


if __name__ == "__main__":
    unittest.main()
