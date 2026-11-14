import unittest

from tools.w3_126_callback_coverage import CORE, audit_source, audit_trace


class CallbackCoverageAuditTests(unittest.TestCase):
    def test_source_selects_sites_and_has_limited_restart_mechanisms(self):
        result = audit_source(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(result["selected_sites_present"].values()), result)
        self.assertTrue(result["checkpoint_is_gated_by_current_restart_site"])
        self.assertTrue(result["video_window_includes_callsite"])
        self.assertTrue(result["one_cycle_normal_core_video_fallback"])
        self.assertTrue(result["fallback_restarts_only_on_zero_return"])
        self.assertTrue(result["new_block_limited_when_trace_candidate"])
        self.assertTrue(result["cached_block_reused_without_selected_site_split"])

    def test_raw_original_trace_hash_and_callback_gap(self):
        result = audit_trace()
        self.assertEqual(result["relevant_observed_link_vas"], ["0x00092B71", "0x00092B87"])
        self.assertTrue(result["anchor_and_later_join_observed"])
        self.assertEqual(result["expected_capture_links_missing"],
                         ["0x00092B7D", "0x00091E00", "0x00092B82"])

    def test_w3_125_registered_suite_now_imports_and_passes_contract_checks(self):
        from tests.test_w3_125_lbmemoryalloc_boundary import LbMemoryAllocBoundaryTests
        self.assertTrue(hasattr(LbMemoryAllocBoundaryTests, "test_guarded_replay_branch_path_and_missing_callee_hook_are_explicit"))


if __name__ == "__main__":
    unittest.main()
