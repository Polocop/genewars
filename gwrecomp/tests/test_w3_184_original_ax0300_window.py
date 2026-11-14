import unittest
from unittest import mock

from tools.w3_184_original_ax0300_window_runner import classify, main


class OriginalAx0300WindowTests(unittest.TestCase):
    def setUp(self):
        self.main = {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 4,
                     "link_va": 0x93F30, "eip": 0x27EF30, "process_psp": 7811}
        self.entry = {"checkpoint": "W3_182_DPMI0300_ENTRY", "sequence": 8,
                      "link_va": 0xBC765, "eip": 0x2A7765, "process_psp": 7811,
                      "eax": 0x1A0300, "bytes": "cd310000", "w3_182_frame_valid": True,
                      "w3_182_frame_bytes": 48, "w3_182_frame_hex": "00" * 48,
                      "psp_tail_text": " -k 38928", "w3_184_environment_valid": True,
                      "w3_184_environment_bytes": 86, "w3_184_environment_hex": "00" * 86}
        self.returned = {"checkpoint": "W3_182_DPMI0300_RETURN", "sequence": 9,
                         "link_va": 0xBC767, "eip": 0x2A7767, "process_psp": 7811}

    def test_natural_entry_and_return_require_mapping_and_opcode(self):
        result = classify([self.main, self.entry, self.returned])
        self.assertEqual(result["classification"], "ORIGINAL_RETURN_OBSERVED")
        self.assertTrue(result["mapping_valid"])
        self.assertTrue(result["service_valid"])
        self.assertTrue(result["opcode_verified"])
        self.assertTrue(result["frame_valid"])
        self.assertTrue(result["environment_sample_bounds_valid"])
        self.assertIn("UNKNOWN", result["environment_identity"])
        self.assertEqual(result["psp_tail"], " -k 38928")
        self.assertTrue(result["return_valid"])

    def test_missing_entry_remains_not_observed(self):
        result = classify([self.main])
        self.assertEqual(result["classification"], "NOT_OBSERVED")

    def test_entry_without_natural_return_is_not_promoted(self):
        result = classify([self.main, self.entry])
        self.assertEqual(result["classification"], "ORIGINAL_ENTRY_OBSERVED")
        self.assertFalse(result["return_observed"])

    def test_bad_mapping_or_opcode_invalidates_entry(self):
        bad = dict(self.entry, eip=self.entry["eip"] + 1)
        self.assertEqual(classify([self.main, bad])["classification"], "ENTRY_INVALID")
        bad_opcode = dict(self.entry, bytes="90")
        self.assertEqual(classify([self.main, bad_opcode])["classification"], "ENTRY_INVALID")

    def test_invalid_frame_is_not_emitted(self):
        bad = dict(self.entry, w3_182_frame_valid=False, w3_182_frame_hex="")
        result = classify([self.main, bad])
        self.assertFalse(result["frame_valid"])
        self.assertIsNone(result["frame_hex"])

    def test_help_does_not_launch(self):
        with mock.patch("tools.w3_184_original_ax0300_window_runner.sys.argv",
                        ["runner.py", "--help"]):
            self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
