import unittest
from unittest import mock

from tools.w3_182_original_ax0300_capture_runner import classify, main


class OriginalDpmi0300CaptureTests(unittest.TestCase):
    def setUp(self):
        self.main = {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 4,
                     "link_va": 0x93F30, "eip": 0x27EF30, "process_psp": 7811}
        self.entry = {"checkpoint": "W3_182_DPMI0300_ENTRY", "sequence": 8,
                      "link_va": 0xBC765, "eip": 0x2A7765, "process_psp": 7811,
                      "eax": 0x1A0300, "bytes": "cd310000", "w3_182_frame_valid": True,
                      "w3_182_frame_bytes": 48, "w3_182_frame_hex": "00" * 48}
        self.ret = {"checkpoint": "W3_182_DPMI0300_RETURN", "sequence": 9,
                    "link_va": 0xBC767, "eip": 0x2A7767, "process_psp": 7811}

    def test_natural_entry_and_return_are_mapping_checked(self):
        result = classify([self.main, self.entry, self.ret])
        self.assertEqual(result["classification"], "ORIGINAL_AX0300_OBSERVED")
        self.assertTrue(result["mapping_valid"])
        self.assertTrue(result["service_valid"])
        self.assertTrue(result["int31_opcode_verified"])
        self.assertTrue(result["frame_valid"])
        self.assertTrue(result["return_valid"])

    def test_no_entry_stays_not_observed(self):
        result = classify([self.main])
        self.assertEqual(result["classification"], "NOT_OBSERVED")

    def test_bad_mapping_does_not_validate_capture(self):
        result = classify([self.main, dict(self.entry, eip=self.entry["eip"] + 1)])
        self.assertFalse(result["mapping_valid"])

    def test_invalid_frame_does_not_emit_sample(self):
        result = classify([self.main, dict(self.entry, w3_182_frame_valid=False,
                                           w3_182_frame_hex="")])
        self.assertFalse(result["frame_valid"])
        self.assertIsNone(result["frame_hex"])

    def test_help_never_runs_preflight(self):
        with mock.patch("tools.w3_182_original_ax0300_capture_runner.sys.argv",
                        ["runner.py", "--help"]):
            self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
