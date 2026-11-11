import json
import unittest

from tools.w3_169_trace_reconcile import audit


class W3TraceReconcileTests(unittest.TestCase):
    def test_hash_bound_original_trace_confirms_ordered_copy(self):
        result = audit()
        path = result["same_run_path"]
        self.assertEqual(path["checkpoints"][0]["checkpoint"], "W3_160_WSCREEN_GATE_117662")
        self.assertLess(path["checkpoints"][0]["sequence"], path["checkpoints"][-1]["sequence"])
        self.assertEqual(path["copy"]["completed_bytes"], 64000)
        self.assertEqual(path["copy"]["post_esi"], "0x3a4320")
        self.assertEqual(path["copy"]["post_edi"], "0xafa00")
        self.assertEqual(path["display_base_assignment"]["global_value"], "0xa0000")

    def test_copy_claim_stays_separate_from_visible_framebuffer(self):
        claims = audit()["same_run_path"]["claims"]
        self.assertTrue(claims["guest_screen_memory_copy_completed"])
        self.assertTrue(claims["guest_destination_is_assigned_0xa0000_candidate"])
        self.assertFalse(claims["host_vga_mapping_independently_verified"])
        self.assertFalse(claims["decoded_pixels_or_visible_presentation_proven"])
        self.assertFalse(claims["first_framebuffer_claim"])

    def test_related_runs_share_fixture_but_remain_distinct(self):
        related = audit()["cross_run_comparison"]
        for row in related.values():
            self.assertTrue(row["same_original_target"])
            self.assertTrue(row["same_config"])
            self.assertTrue(row["same_cue"])
            self.assertTrue(row["same_staging_revision"])
            self.assertTrue(row["different_run"])
            self.assertTrue(row["copy_confirmed"])

    def test_output_contract_is_json_compatible(self):
        result = audit()
        self.assertEqual(json.loads(json.dumps(result))["classification"], "ORIGINAL_OBSERVED")


if __name__ == "__main__":
    unittest.main()
