import unittest

from tools.w3_218_ah4400_tail_audit import audit


class Ah4400TailAuditTests(unittest.TestCase):
    def test_bounded_trace_handles_stay_separate_from_bx1_contract(self):
        data = audit()
        self.assertEqual(data["observed_bx_sequence"], [5, 5, 5, 5, 5, 2, 2, 2])
        self.assertFalse(data["bx1_observed_in_w3_214_trace"])
        self.assertEqual(data["w3_214_run"]["recorded_dos_launch_tail"], " -k 38928")
        self.assertEqual(data["distinct_w3_091_bx1_contract"]["response"]["ax"], "0x80d3")
        self.assertFalse(data["distinct_w3_091_bx1_contract"]["same_run_as_w3_214"])
        self.assertTrue(all(event["caller_link_va"] is None for event in data["ax4400_callbacks"]))
        self.assertTrue(any("timeout" in item.lower() for item in data["limits"]))


if __name__ == "__main__":
    unittest.main()
