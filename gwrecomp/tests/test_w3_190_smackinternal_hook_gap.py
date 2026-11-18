import unittest

from tools.w3_190_smackinternal_hook_gap import build


class SmackInternalHookGapTests(unittest.TestCase):
    def test_current_record_is_source_mismatch_and_not_a_causal_claim(self):
        result = build()
        self.assertEqual(result["classification"], "SOURCE_MISMATCH_CAUSE_UNRESOLVED")
        self.assertEqual(result["capture"]["trace_events"], 379)
        self.assertFalse(result["capture"]["source_hash_matches_captured_build"])
        self.assertEqual([x["sequence"] for x in result["observed_event_order"]], [346, 347, 379])
        self.assertFalse(result["trace_gap"]["guest_control_flow_skip_proven"])

    def test_candidate_is_currently_restart_checked_but_not_a_trace_proof(self):
        result = build()
        audit = result["current_source_audit"]
        self.assertTrue(audit["progress_candidate_gate_present"])
        self.assertTrue(audit["candidate_evaluated_from_restart_core_path"])
        self.assertFalse(audit["target_in_current_cache_span_target_list"])
        self.assertFalse(audit["applies_to_w3_181_build"])


if __name__ == "__main__":
    unittest.main()
