import json
import unittest
from pathlib import Path

from tools.w3_154_capture_runner import (parse_capture_rows, sample_bounds_valid,
                                         sample_offsets, summarize_pairs)

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_154_capture_runner.py"


class SourceDestinationSamplesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_offsets_are_sparse_and_nonoverlapping(self):
        self.assertEqual(sample_offsets(64000), [0, 32000, 63984])
        self.assertEqual(sample_offsets(16), [0])
        self.assertEqual(sample_offsets(15), [])
        self.assertLessEqual(len(sample_offsets(64000)) * 32, 96)

    def test_source_and_destination_bounds_are_required(self):
        self.assertTrue(sample_bounds_valid(0x394920, 32000, 16, 0xFFFFFFFF, 0x1000000))
        self.assertFalse(sample_bounds_valid(0xA0000, 63984, 16, 0xA0FFF, 0x1000000))
        self.assertFalse(sample_bounds_valid(0xFFFFFFFF, 0, 16, 0xFFFFFFFF, 0x100000000))
        self.assertIn("source_linear <= UINT32_MAX", self.source)
        self.assertIn("destination_linear <= UINT32_MAX", self.source)

    def test_pair_comparison_and_96_byte_cap(self):
        windows = [{"valid": True, "source_hex": "00" * 16, "destination_hex": "00" * 16},
                   {"valid": True, "source_hex": "11" * 16, "destination_hex": "22" * 16},
                   {"valid": False, "source_hex": "", "destination_hex": ""}]
        result = summarize_pairs(windows)
        self.assertEqual(result["bytes_total"], 64)
        self.assertEqual(result["max_bytes"], 96)
        self.assertFalse(result["all_pairs_equal"])

    def test_json_serialization_and_instrumentation_fields(self):
        for token in ("w3_154_source_destination_windows", "w3_154_sample_bytes_total",
                      "source_window_hex", "window_hex", "source_hex",
                      "destination_hex", "sample_offsets"):
            self.assertIn(token, self.source + self.runner)
        sample = {"windows": [{"offset": 0, "valid": True,
                               "source_hex": "00" * 16,
                               "destination_hex": "00" * 16, "equal": True}],
                  **summarize_pairs([{"valid": True, "source_hex": "00" * 16,
                                      "destination_hex": "00" * 16}])}
        self.assertEqual(json.loads(json.dumps(sample)), sample)

    def test_known_trace_serialization_recovery_is_narrow(self):
        raw = (b'{"event":"target_runtime_checkpoint",'
               b'"w3_154_source_destination_windows":[]'
               b'{"offset":0,"valid":true,"source_hex":"00",'
               b'"destination_hex":"00","equal":true}]}')
        rows, recovered = parse_capture_rows(raw)
        self.assertEqual(recovered, [1])
        self.assertEqual(rows[0]["w3_154_source_destination_windows"][0]["offset"], 0)
        with self.assertRaises(json.JSONDecodeError):
            parse_capture_rows(b'{"unrelated":[]{"bad":1}')

    def test_window_array_opens_before_appends(self):
        self.assertIn('w3_154_source_destination_windows = "[";', self.source)

    def test_guard_is_still_the_only_dosbox_launch_path(self):
        self.assertIn('str(GUARD), "run"', self.runner)
        self.assertIn('"--timeout-s", "30"', self.runner)
        self.assertIn('"--max-file-text-mib", "1"', self.runner)
        self.assertIn('"--host-floor-gib", "100"', self.runner)
        self.assertIn('result["framebuffer_or_visible_output_proven"] = False', self.runner)


if __name__ == "__main__":
    unittest.main()
