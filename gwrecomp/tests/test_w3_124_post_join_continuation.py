import json
import unittest
from pathlib import Path

from tools.w3_124_post_join_continuation import (
    ANCHOR, BRANCH, FALLTHROUGH, TARGET, CORE, capture_events, parse_jsonl,
    prior_anchor, short_jcc, source_coverage, summarize,
)


class PostJoinContinuationTests(unittest.TestCase):
    def test_signed_rel8_branch_and_prior_anchor_hash_binding(self):
        self.assertEqual(short_jcc(BRANCH, bytes.fromhex("7516")),
                         (FALLTHROUGH, TARGET, True))
        prior = prior_anchor()
        self.assertEqual(prior["anchor_link_va"], ANCHOR)
        self.assertEqual(prior["fallthrough_link_va"], FALLTHROUGH)
        self.assertEqual(prior["taken_target_link_va"], TARGET)
        self.assertEqual(prior["local_ebp_minus_4"], "UNKNOWN")

    def test_jne_outcome_from_zf_and_immediate_path(self):
        rows = [
            {"w3_124_post_join_continuation": True, "link_va": ANCHOR},
            {"w3_124_post_join_continuation": True, "link_va": BRANCH,
             "bytes": "7516a178", "eflags": 0x202},
            {"w3_124_post_join_continuation": True, "link_va": TARGET},
        ]
        result = summarize(capture_events(rows))
        self.assertTrue(result["ordered"])
        self.assertTrue(result["branch"]["taken"])
        self.assertTrue(result["branch"]["captured_path_matches_flags"])
        self.assertTrue(result["taken_target_observed_immediately"])

    def test_duplicates_and_non_targets_are_suppressed_with_cap(self):
        rows = [{"w3_124_post_join_continuation": True, "link_va": 0x1234}]
        rows += [{"w3_124_post_join_continuation": True, "link_va": link}
                 for link in (ANCHOR, ANCHOR, BRANCH, BRANCH, FALLTHROUGH, TARGET)]
        events = capture_events(rows)
        self.assertEqual([row["link_va"] for row in events],
                         [ANCHOR, BRANCH, FALLTHROUGH, TARGET])
        self.assertEqual(len(events), 4)

    def test_jsonl_byte_limit(self):
        self.assertEqual(parse_jsonl(b'{"x":1}\n'), [{"x": 1}])
        with self.assertRaises(ValueError):
            parse_jsonl(b"12345", cap_bytes=4)

    def test_source_is_runtime_mapped_armed_and_bounded(self):
        coverage = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(coverage.values()), coverage)

    def test_prior_capture_is_original_and_does_not_claim_local_value(self):
        result = json.loads(Path("evidence/w3_123_post_join_branch.json").read_text(encoding="utf-8"))
        anchor = next(row for row in result["trace"]["target_events"]
                      if row.get("link_va") == ANCHOR)
        self.assertTrue(anchor["w3_123_post_join_branch"])
        self.assertTrue(anchor["bytes"].startswith("807dfc007516"))
        self.assertIsNone(anchor.get("w3_124_ebp_minus_4"))


if __name__ == "__main__":
    unittest.main()
