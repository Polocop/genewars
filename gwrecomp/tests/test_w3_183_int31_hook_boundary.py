import unittest

from tools.w3_183_int31_hook_boundary import audit


class Int31HookBoundaryTests(unittest.TestCase):
    def test_exact_target_instruction_sequence_and_cached_link_mechanism(self):
        result = audit()
        self.assertEqual(result["int31_entry"], "0xBC765")
        self.assertEqual(result["call_return_entry"], "0xBC74D")
        self.assertTrue(result["straight_line_to_int31"])
        self.assertTrue(result["dynarec"]["cached_link_runs_block_directly"])
        self.assertTrue(result["dynarec"]["per_pc_checks_skipped_on_fast_link"])
        self.assertFalse(result["dynarec"]["BC765_forced_window_present"])
        self.assertEqual(result["replay"]["target_event_count"], 0)

    def test_report_does_not_promote_missing_checkpoint_to_absence(self):
        result = audit()
        self.assertEqual(result["classification"], "CHECKPOINT_CAN_MISS_CACHED_BLOCK_INTERIOR")
        self.assertIn("EXECUTION AT BC765 UNKNOWN", result["certainty"])
        self.assertFalse(result["replay"]["target_instruction_execution_proven"])


if __name__ == "__main__":
    unittest.main()
