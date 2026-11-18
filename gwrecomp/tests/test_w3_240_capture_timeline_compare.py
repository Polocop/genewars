import unittest

from tools.w3_240_capture_timeline_compare import summarize


class W3240CaptureTimelineCompareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = summarize()

    def test_raw_traces_are_hash_bound_to_evidence(self):
        for run in ("W3-236", "W3-239"):
            trace = self.result["captures"][run]["trace"]
            self.assertGreater(trace["event_count"], 0)
            self.assertEqual(len(trace["sha256"]), 64)
            self.assertLessEqual(trace["bytes"], 1024 * 1024)

    def test_fixture_fingerprints_and_main_rebase_match(self):
        shared = self.result["shared_measured_facts"]
        self.assertTrue(shared["target_sha256_equal"])
        self.assertTrue(shared["cue_sha256_equal"])
        self.assertTrue(shared["config_sha256_equal"])
        self.assertTrue(shared["main_code_rebase_equal"])

    def test_binary_and_capture_scope_differences_are_retained(self):
        self.assertFalse(self.result["differences"]["instrumented_runtime_binary_sha256_equal"])
        self.assertEqual(self.result["captures"]["W3-236"]["guard_exit"], "ABORTED_BY_DISK_GUARD")
        self.assertEqual(self.result["captures"]["W3-239"]["guard_exit"], "ABORTED_BY_DISK_GUARD")

    def test_first_w3_239_call_is_not_mispaired_to_w3_236_bx1(self):
        align = self.result["alignment_conclusion"]
        self.assertEqual(self.result["captures"]["W3-239"]["ax4400_request"]["event"]["ebx"], 5)
        self.assertEqual(int(self.result["captures"]["W3-239"]["ax4400_return"]["eax"], 16), 2)
        self.assertFalse(align["same_dynamic_invocation_proven"])
        self.assertIn("unpaired", align["W3_236_BX1_pairing"])


if __name__ == "__main__":
    unittest.main()
