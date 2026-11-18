import unittest

from tools.w3_288_smacker_trigger_correction import correct_plan


class SmackerTriggerCorrectionTests(unittest.TestCase):
    def setUp(self):
        self.w287 = {"run_comparison": {"W3-280": {"core_dyn_x86_sha256": "old-core"}}}
        self.source = """
        static uint32_t w3_117_seen_mask = 0;
        !(w3_117_seen_mask & w3_117_target_bit)
        w3_117_seen_mask |= w3_117_target_bit;
        w3_269_game_targets_armed && target_context && target_main_rebase
        !w3_275_second_smacker_entry_seen && candidate_link_va == 0x000929d0
        w3_275_second_smacker_entry_seen && !w3_275_second_smacker_callsite_seen
        candidate_link_va == 0x00092add
        w3_275_capture_second_smacker("w3_275_second_smacker_callsite")
        """
        self.renderer = "VGA_W3_262_PresentCaptureActive() GWRECOMP_W3_269_CAPTURE GWRECOMP_W3_267_CAPTURE_VIEWPORT"
        self.w280 = [
            {"sequence": 389, "event": "w3_275_second_smacker_entry", "link_va": 600528},
            {"sequence": 393, "event": "w3_275_second_smacker_callsite", "link_va": 600797},
            {"sequence": 394, "event": "target_runtime_checkpoint", "checkpoint": "W3_117_PLAYSMACKER_CALLSITE", "link_va": 600797},
            {"sequence": 395, "event": "w3_275_second_smacker_media_entry", "link_va": 713424},
            {"sequence": 396, "event": "w3_278_later_play_smk_entry", "link_va": 713424},
            {"sequence": 399, "event": "w3_278_branch_target", "link_va": 713443},
        ]

    def test_uses_code_backed_latch_not_one_shot_ordinal(self):
        result = correct_plan(self.w287, self.w280, [], self.source, self.renderer, "same", "same")
        self.assertTrue(result["source_semantics"]["w3_117_one_shot_seen_mask_and_no_reset_found"])
        self.assertIn("w3_275_second_smacker_callsite", result["corrected_capture_design"]["arm_from"])

    def test_later_callsite_sequence_and_adjacent_record_are_distinct(self):
        result = correct_plan(self.w287, self.w280, [], self.source, self.renderer, "same", "same")
        seq = result["W3_280_same_run_sequence_check"]
        self.assertTrue(seq["matches"])
        self.assertTrue(seq["adjacent_rows_are_same_callsite_region_not_two_ordinal_occurrences"])

    def test_missing_w3_285_marker_does_not_infer_cause(self):
        result = correct_plan(self.w287, self.w280, [], self.source, self.renderer, "same", "same")
        self.assertFalse(result["W3_285_marker_observed"])
        self.assertIn("UNKNOWN", result["cause_of_missing_W3_285_later_invocation"])

    def test_different_source_hash_is_not_projected_back(self):
        result = correct_plan(self.w287, self.w280, [], self.source, self.renderer, "current", "recorded")
        self.assertFalse(result["source_semantics"]["matches_w3_285_recorded_core_source"])
        self.assertTrue(result["source_semantics"]["do_not_project_current_w3_117_semantics_back_to_w3_280"])

    def test_capture_plan_tracks_alternate_actual_callee(self):
        result = correct_plan(self.w287, self.w280, [], self.source, self.renderer, "same", "same")
        plan = result["corrected_capture_design"]
        self.assertTrue(any("0xAE4D8" in x for x in plan["then_capture"]))
        self.assertEqual(plan["max_selected_events"], 10)


if __name__ == "__main__":
    unittest.main()
