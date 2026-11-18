from __future__ import annotations

import unittest

from tools.w3_268_playintro_frontier import build_evidence


class PlayIntroFrontierAuditTests(unittest.TestCase):
    def test_static_frontier_and_original_present_are_kept_distinct(self):
        result = build_evidence()
        self.assertEqual(result["original_static_control_flow"]["earliest_return_checkpoint"], "0x00092A16")
        self.assertEqual(result["latest_original_present"]["guest_eip_after_present"], "UNKNOWN_NOT_CAPTURED")
        self.assertEqual(result["original_static_control_flow"]["classification"], "STATIC_ONLY")

    def test_core_source_requires_one_cycle_and_restart_for_intro_range(self):
        window = build_evidence()["dynamic_core"]["playintro_window"]
        self.assertEqual(window["range"], ["0x00092930", "0x00092ADD"])
        self.assertTrue(window["one_cycle_normal_core"])
        self.assertTrue(window["restart_after_normal_core"])

    def test_previous_no_hit_runs_are_not_attributed_to_game_divergence(self):
        result = build_evidence()
        self.assertEqual(result["dynamic_core"]["historical_source_match"], {
            "W3-109": False,
            "W3-111": False,
            "W3-113": False,
            "W3-267": True,
        })
        self.assertIn("no last guest EIP", result["dynamic_core"]["conclusion"])
        first_call = result["original_static_control_flow"]["dynamic_first_callsite_w3_113"]
        self.assertTrue(first_call["observed"])
        self.assertEqual(first_call["link_va"], "0x00092983")

    def test_play_smacker_chain_is_original_observed_but_not_same_run_as_viewport(self):
        result = build_evidence()
        dynamic = result["original_static_control_flow"]["later_original_sequences"]
        self.assertIn("0x00092ADD", dynamic["ordered_link_vas"]["W3-118"])
        self.assertFalse(dynamic["same_invocation_as_w3_267_viewport"])

    def test_present_return_is_same_run_and_guest_resume_is_a_distinct_measurement(self):
        result = build_evidence()
        present = result["latest_original_present"]
        self.assertEqual(present["same_run_events"][-1], "backend_present_return")
        self.assertTrue(present["backend_present_returned"])
        self.assertEqual(result["next_discriminating_measurement"]["oracle_replay_authorized_by_this_task"], False)


if __name__ == "__main__":
    unittest.main()
