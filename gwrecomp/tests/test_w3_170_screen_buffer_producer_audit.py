import json
import unittest

from tools.w3_170_screen_buffer_producer_audit import audit


class ScreenBufferProducerAuditTests(unittest.TestCase):
    def test_hash_bound_static_and_dynamic_chain(self):
        result = audit()
        self.assertEqual(result["target"]["sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertTrue(all(result["static_reference"]["anchors"].values()))
        events = result["w3_168_same_run"]["events"]
        self.assertEqual([e["sequence"] for e in events], sorted(e["sequence"] for e in events))

    def test_screen_copy_source_matches_dynamic_wscreen_argument(self):
        result = audit()
        self.assertTrue(result["conclusion"]["first_copy_source_is_wscreen"])
        self.assertTrue(result["conclusion"]["same_run_smacktobuffer_wscreen_argument_and_copy_source_match"])
        self.assertEqual(result["w3_168_same_run"]["copy_completed_bytes"], 64000)

    def test_separate_zero_sample_run_is_not_merged(self):
        result = audit()
        self.assertNotEqual(result["w3_168_same_run"]["run_id"], result["w3_154_separate_run"]["run_id"])
        self.assertTrue(result["w3_154_separate_run"]["same_target_config_cue_revision"])
        self.assertEqual(result["conclusion"]["smackdoframe_written_sampled_wscreen_bytes"], "NOT MEASURED")

    def test_unknown_writer_and_no_visible_frame_claim_are_preserved(self):
        result = audit()
        self.assertEqual(result["conclusion"]["exact_writer_for_nonzero_wscreen_bytes"], "UNKNOWN")
        self.assertFalse(any("visible" in x.lower() and "proven" in x.lower() for x in result["limits"]))
        self.assertIn("sample only the verified WScreen pointer", result["conclusion"]["minimal_next_observation"])

    def test_result_is_json_serializable(self):
        self.assertEqual(json.loads(json.dumps(audit()))["classification"], "ORIGINAL_OBSERVED_WITH_STATIC_DATAFLOW")


if __name__ == "__main__":
    unittest.main()
