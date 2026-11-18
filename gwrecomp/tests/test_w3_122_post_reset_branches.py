import unittest

from tools.w3_122_post_reset_branches import (
    CORE, TARGETS, capture_events, parse_jsonl, prior_return,
    short_branch, source_coverage, summarize,
)


class PostResetBranchTests(unittest.TestCase):
    def test_signed_short_branch_destinations(self):
        self.assertEqual(short_branch(0x92AE9, bytes.fromhex("7440")), (0x92AEB, 0x92B2B))
        self.assertEqual(short_branch(0x92AF2, bytes.fromhex("7437")), (0x92AF4, 0x92B2B))

    def test_prior_original_return_is_hash_bound(self):
        prior = prior_return()
        self.assertEqual(prior["first_branch"]["target"], 0x92B2B)
        self.assertEqual(prior["second_branch"]["target"], 0x92B2B)

    def test_event_parser_caps_and_orders_selected_targets(self):
        rows = [
            {"w3_122_post_reset_branch": True, "link_va": 0x92AE9, "bytes": "7440", "eflags": 0x202},
            {"w3_122_post_reset_branch": True, "link_va": 0x92AEB},
            {"w3_122_post_reset_branch": True, "link_va": 0x92AF2, "bytes": "7437", "eflags": 0x202},
            {"w3_122_post_reset_branch": True, "link_va": 0x92AF4},
            {"w3_122_post_reset_branch": True, "link_va": 0x92B2B},
        ]
        events = capture_events(rows + rows)
        self.assertEqual(len(events), 5)
        summary = summarize(events)
        self.assertTrue(summary["ordered"])
        self.assertFalse(summary["first_branch"]["taken"])
        self.assertEqual(summary["first_branch"]["expected_next_link"], 0x92AEB)
        self.assertFalse(summary["second_branch"]["taken"])
        self.assertEqual(summary["second_branch"]["expected_next_link"], 0x92AF4)
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * 4, cap_bytes=3)

    def test_core_arm_sites_and_event_limit(self):
        coverage = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(coverage.values()), coverage)

    def test_original_flags_and_next_eips_prove_both_je_fallthroughs(self):
        import json
        from pathlib import Path
        result = json.loads(Path("evidence/w3_122_post_reset_branches.json").read_text(encoding="utf-8"))
        first = result["capture"]["first_branch"]
        second = result["capture"]["second_branch"]
        self.assertFalse(first["taken"])
        self.assertEqual(first["next_captured_link"], 0x92AEB)
        self.assertTrue(first["captured_path_matches_flags"])
        self.assertFalse(second["taken"])
        self.assertEqual(second["next_captured_link"], 0x92AF4)
        self.assertTrue(second["captured_path_matches_flags"])
        self.assertTrue(result["capture"]["common_target_observed_later"])


if __name__ == "__main__":
    unittest.main()
