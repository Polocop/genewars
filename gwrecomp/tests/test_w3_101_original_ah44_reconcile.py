import unittest

from tools.w3_101_original_ah44_reconcile import build


class OriginalAh44ReconciliationTests(unittest.TestCase):
    def test_provenance_and_tail_are_explicit(self):
        result = build()
        self.assertEqual(result["provenance"]["target_sha256"],
                         "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(result["launch"]["original_gw_tail_in_trace"], " -k 38928")
        self.assertTrue(result["launch"]["psp_tail_match_across_runs"])
        self.assertFalse(result["launch"]["launcher_equivalence"])

    def test_original_bx5_is_not_misrepresented_as_bx1(self):
        result = build()
        self.assertEqual(result["original"]["stream_field_10"], 5)
        self.assertFalse(result["original"]["original_bx1_callback_observed"])
        self.assertEqual(result["comparison"]["original_nearby_callback_request"]["in_bx"], 5)
        self.assertFalse(result["comparison"]["w2_086_unblocked"])

    def test_native_bx1_remains_a_separate_invocation(self):
        result = build()
        self.assertEqual(result["native"]["ah44_request"]["ebx"], "00000001")
        self.assertEqual(result["native"]["caller_and_callsite"]["callsite"], "0x000BA4E4")
        self.assertFalse(result["comparison"]["same_dynamic_ordinal_proven"])
        self.assertIn("UNKNOWN", result["comparison"]["causal_first_divergence"])


if __name__ == "__main__":
    unittest.main()
