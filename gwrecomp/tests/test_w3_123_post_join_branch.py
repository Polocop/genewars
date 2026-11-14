import unittest

from tools.w3_123_post_join_branch import (
    BRANCH, CORE, FALLTHROUGH, TARGET, capture_events, prior_callsite,
    short_jcc, source_coverage, summarize,
)


class PostJoinBranchTests(unittest.TestCase):
    def test_jne_rel8_target_and_fallthrough(self):
        self.assertEqual(short_jcc(BRANCH, bytes.fromhex("753a")), (FALLTHROUGH, TARGET, True))

    def test_prior_original_bytes_are_trace_hash_bound(self):
        prior = prior_callsite()
        self.assertEqual(prior["join_link_va"], 0x92B2B)
        self.assertEqual(prior["taken_target_link_va"], TARGET)

    def test_flags_determine_jne_outcome_and_order(self):
        rows = [
            {"w3_123_post_join_branch": True, "link_va": BRANCH, "bytes": "753a", "eflags": 0x202},
            {"w3_123_post_join_branch": True, "link_va": TARGET},
        ]
        events = capture_events(rows)
        result = summarize(events)
        self.assertTrue(result["ordered"])
        self.assertTrue(result["branch"]["taken"])
        self.assertEqual(result["branch"]["expected_next_link"], TARGET)
        self.assertTrue(result["branch"]["captured_path_matches_flags"])

    def test_instrumentation_is_mapped_armed_and_bounded(self):
        coverage = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(coverage.values()), coverage)

    def test_guarded_original_branch_is_not_taken_and_later_target_is_separate(self):
        import json
        from pathlib import Path
        result = json.loads(Path("evidence/w3_123_post_join_branch.json").read_text(encoding="utf-8"))
        branch = result["capture"]["branch"]
        self.assertFalse(branch["taken"])
        self.assertEqual(branch["next_captured_link"], FALLTHROUGH)
        self.assertTrue(branch["captured_path_matches_flags"])
        self.assertFalse(result["capture"]["taken_target_observed_immediately"])
        self.assertTrue(result["capture"]["taken_target_observed_later"])


if __name__ == "__main__":
    unittest.main()
