import unittest

from tools.w3_112_capture_frontier_audit import build_evidence


class CaptureFrontierAuditTests(unittest.TestCase):
    def test_hash_bound_original_frontier_and_predicate(self):
        result = build_evidence()
        first = result["first_target_audit"]
        self.assertEqual(result["classification"], "INCONCLUSIVE_FIRST_TARGET_NOT_OBSERVED_BEFORE_TIMEOUT")
        self.assertTrue(result["mapping"]["consistent"])
        self.assertEqual(result["mapping"]["code_rebases"], ["0x001EB000"])
        self.assertEqual(result["mapping"]["data_rebases"], ["0x001DA000"])
        self.assertTrue(first["selected_site_and_one_cycle_coverage"])
        self.assertTrue(first["w3_107_94342_predecessor_event"])
        self.assertTrue(first["ordering_predicate_satisfied_before_target"])
        self.assertFalse(first["present_in_trace"])
        self.assertFalse(result["static_dynamic_separation"]["menu_or_presented_frame_claimed"])

    def test_observed_checkpoints_are_separated_from_static_chain(self):
        result = build_evidence()
        observed = {row["link_va"]: row["observed"] for row in result["checkpoints"]}
        self.assertTrue(observed["0x00094342"])
        self.assertTrue(observed["0x00092930"])
        self.assertTrue(observed["0x0009FDCC"])
        self.assertTrue(observed["0x000A3A00"])
        self.assertTrue(observed["0x0009FDF9"])


if __name__ == "__main__":
    unittest.main()
