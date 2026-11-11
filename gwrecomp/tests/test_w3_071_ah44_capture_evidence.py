import json
import unittest

from tools.w3_071_ah44_capture_runner import correlate_ah44, effective_cf


class AH44CaptureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.callsite = {"sequence": 10, "checkpoint": "DOS_AH44_CALLSITE",
                         "link_va": 0xC8973, "process_psp": 0x1E83,
                         "eax": 0x4400, "ebx": 2, "ecx": 0x204000,
                         "edx": 1}
        self.service = {"sequence": 11, "event": "original_int21_ah44",
                        "process_psp": 0x1E83, "in_ax": 0x4400,
                        "in_bx": 2, "in_cx": 0x4000, "in_dx": 1,
                        "out_ax": 0x4400, "out_dx": 0x8000,
                        "cf": False, "ioctl_ok": True}

    def test_correlates_exact_ordered_request(self):
        pair = correlate_ah44([self.callsite], [self.service])
        self.assertEqual(len(pair), 1)
        self.assertEqual(pair[0]["link_va"], 0xC8973)
        self.assertTrue(pair[0]["same_register_request"])
        json.dumps(pair)

    def test_rejects_wrong_register_request(self):
        self.service["in_bx"] = 1
        self.assertEqual(correlate_ah44([self.callsite], [self.service]), [])

    def test_rejects_noncausal_order(self):
        self.service["sequence"] = 9
        self.assertEqual(correlate_ah44([self.callsite], [self.service]), [])

    def test_rejects_different_process(self):
        self.service["process_psp"] = 0x1234
        self.assertEqual(correlate_ah44([self.callsite], [self.service]), [])

    def test_uses_saved_iret_carry_not_register_flags(self):
        event = {"iret_flags": 0x0202, "out_register_eflags": 0x0203}
        self.assertFalse(effective_cf(event))
        event["iret_flags"] = 0x0203
        self.assertTrue(effective_cf(event))


if __name__ == "__main__":
    unittest.main()
