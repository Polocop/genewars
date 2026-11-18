import copy
import unittest

from tools.w3_189_wscreen_temporal_reconcile import build


class WScreenTemporalReconcileTests(unittest.TestCase):
    def test_real_existing_evidence_reconciles_without_replay(self):
        result = build()
        self.assertEqual(result["classification"], "ORIGINAL_OBSERVED_BOUNDED_SPARSE_WSCREEN_CHANGE")
        self.assertEqual(result["provenance"]["trace_events"], 379)
        self.assertEqual(result["w3_181_same_run"]["wscreen_pointer"], "0x394920")
        self.assertEqual([x["offset"] for x in result["w3_181_same_run"]["changed_windows"]], [32000, 63984])
        self.assertTrue(result["separate_run_comparison"]["not_merged"])
        self.assertIn("visible framebuffer", result["interpretation"]["not_established"])

    def test_result_keeps_b_screen_distinct(self):
        result = build()
        self.assertNotEqual(result["w3_181_same_run"]["wscreen_pointer"], result["separate_object"]["w3_188_b_screen_pointer"])
        self.assertEqual(result["separate_object"]["w3_188_nonzero_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
