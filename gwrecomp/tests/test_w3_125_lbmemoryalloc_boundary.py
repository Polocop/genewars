import json
import unittest
from pathlib import Path

from tools.w3_125_lbmemoryalloc_boundary import (
    ANCHOR, CALLSITE, CALLEE, FALLTHROUGH, RETURN, CORE, branch_context, capture_events,
    parse_jsonl, prior_call, rel32_call, source_coverage, summarize,
)


class LbMemoryAllocBoundaryTests(unittest.TestCase):
    def test_signed_rel32_and_hash_bound_original_call(self):
        self.assertEqual(rel32_call(CALLSITE, bytes.fromhex("e87ef2ffff")), (CALLEE, RETURN))
        prior = prior_call()
        self.assertEqual(prior["anchor_link_va"], ANCHOR)
        self.assertEqual(prior["callee_symbol"], "LbMemoryAlloc_")
        self.assertEqual(prior["callsite_link_va"], CALLSITE)
        self.assertEqual(prior["runtime_call_byte_prefix"], "e87ef2ff")
        self.assertFalse(prior["runtime_call_bytes_complete"])

    def test_event_filter_order_and_duplicate_suppression(self):
        rows = [{"w3_125_lbmemoryalloc_boundary": True, "link_va": link}
                for link in (ANCHOR, ANCHOR, CALLSITE, CALLEE, CALLEE, RETURN)]
        events = capture_events(rows)
        self.assertEqual([event["link_va"] for event in events],
                         [ANCHOR, CALLSITE, CALLEE, RETURN])
        result = summarize(events)
        self.assertTrue(result["ordered"])
        self.assertTrue(result["callee_entry_observed"])
        self.assertTrue(result["caller_return_observed"])

    def test_jsonl_byte_limit(self):
        self.assertEqual(parse_jsonl(b'{"v":2}\n'), [{"v": 2}])
        with self.assertRaises(ValueError):
            parse_jsonl(b"12345", cap_bytes=4)

    def test_source_is_mapped_armed_and_bounded(self):
        coverage = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(coverage.values()), coverage)

    def test_prior_anchor_is_dynamic_original_and_hash_bound(self):
        evidence = json.loads(Path("evidence/w3_124_post_join_continuation.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["trace"]["summary"]["link_vas"],
                         ["0x00092B6B", "0x00092B6F", "0x00092B71"])
        event = next(row for row in evidence["trace"]["target_events"]
                     if row.get("link_va") == ANCHOR)
        self.assertTrue(event["w3_124_post_join_continuation"])

    def test_guarded_replay_branch_path_and_missing_callee_hook_are_explicit(self):
        evidence = json.loads(Path("evidence/w3_125_lbmemoryalloc_boundary.json").read_text(encoding="utf-8"))
        path = evidence["capture"]["post_join_branch_context"]
        self.assertFalse(path["jne_taken"])
        self.assertEqual(path["next_captured_link_va"], FALLTHROUGH)
        self.assertTrue(path["path_matches_flags"])
        self.assertFalse(evidence["capture"]["callee_entry_observed"])
        self.assertIn("No W3-125 event emitted", evidence["capture"]["instrumentation_gap"])


if __name__ == "__main__":
    unittest.main()
