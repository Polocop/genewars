import json
import unittest

from tools.w3_117_play_smacker_call_boundary import (
    CALLSITE, CALLEE, RETURN, CALL_BYTES, CORE, MAP, PRIOR_TRACE, capture_events,
    parse_jsonl, relative_call_target, source_coverage, target_order,
    verify_prior_static_evidence,
)


class PlaySmackerCallBoundaryTests(unittest.TestCase):
    def test_observed_call_bytes_resolve_to_map_symbol_and_return(self):
        self.assertEqual(relative_call_target(CALLSITE, CALL_BYTES), (CALLEE, RETURN))

    def test_capture_is_ordered_and_missing_return_is_not_inferred(self):
        rows = [
            {"w3_117_play_smacker_call_boundary": True, "link_va": CALLSITE},
            {"w3_117_play_smacker_call_boundary": True, "link_va": CALLEE},
        ]
        summary = target_order(capture_events(rows))
        self.assertTrue(summary["ordered"])
        self.assertTrue(summary["callee_entry_observed"])
        self.assertFalse(summary["return_observed"])

    def test_suppresses_duplicates_and_rejects_out_of_order_targets(self):
        rows = [
            {"w3_117_play_smacker_call_boundary": True, "link_va": CALLEE},
            {"w3_117_play_smacker_call_boundary": True, "link_va": CALLSITE},
        ]
        self.assertFalse(target_order(capture_events(rows))["ordered"])
        duplicate = [{"w3_117_play_smacker_call_boundary": True, "link_va": CALLSITE}] * 4
        self.assertEqual(len(capture_events(duplicate)), 1)

    def test_jsonl_size_and_source_coverage_are_bounded(self):
        self.assertEqual(parse_jsonl(b'{"ok":true}\n'), [{"ok": True}])
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * 4, cap=3)
        facts = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(facts.values()), facts)

    def test_prior_original_trace_and_map_support_static_call_edge(self):
        result = verify_prior_static_evidence(PRIOR_TRACE.read_bytes(), MAP.read_text(encoding="utf-8"))
        self.assertEqual(result["call_bytes"], CALL_BYTES.hex())
        self.assertEqual(result["callee_link_va"], CALLEE)
        self.assertEqual(result["return_link_va"], RETURN)

    def test_guarded_run_reached_callsite_but_not_callee(self):
        from pathlib import Path
        trace = Path("build/dosboxx_oracle/C/W3_117_PLAYSMACKER_CALL_20261009_01.jsonl")
        events = capture_events(parse_jsonl(trace.read_bytes()))
        summary = target_order(events)
        self.assertTrue(summary["callsite_observed"])
        self.assertFalse(summary["callee_entry_observed"])
        self.assertFalse(summary["return_observed"])
        self.assertEqual(events[0]["bytes"][:10], CALL_BYTES.hex())

    def test_corrected_guarded_run_captured_full_call_boundary(self):
        from pathlib import Path
        trace = Path("build/dosboxx_oracle/C/W3_118_PLAYSMACKER_CALL_20261009_01.jsonl")
        events = capture_events(parse_jsonl(trace.read_bytes()))
        self.assertEqual([e["link_va"] for e in events], [CALLSITE, CALLEE, RETURN])
        self.assertTrue(target_order(events)["ordered"])


if __name__ == "__main__":
    unittest.main()
