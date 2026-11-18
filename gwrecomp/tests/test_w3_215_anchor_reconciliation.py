import unittest

from tools.w3_215_anchor_reconciliation import reconcile


class AnchorReconciliationTests(unittest.TestCase):
    def test_measured_anchor_and_scope_limitations(self):
        result = reconcile()
        original = result["original_w3_213"]
        self.assertEqual(original["sampled_global_10c828"], "0x00000010")
        self.assertEqual(original["sampled_mode_bytes"], {"0x10B78E": 1, "0x10B78F": 0, "0x10B790": 0})
        self.assertTrue(original["measured_address_matches"])
        self.assertEqual(original["sampling_point"], "CreateNewNHeap entry anchor only")
        self.assertEqual(result["separate_run_comparisons"]["w3_068_original"]["post_call_argument_slot"], "0x00001000")
        self.assertEqual(result["separate_run_comparisons"]["w1_native"]["threshold_10c828"], "0x8000")
        self.assertEqual(result["separate_run_comparisons"]["same_invocation_or_seed_equivalence"], "NOT_ESTABLISHED")
        self.assertTrue(any("not proven to be read" in item for item in result["missing"]))


if __name__ == "__main__":
    unittest.main()
