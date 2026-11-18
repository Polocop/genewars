import unittest

from tools.w3_121_reset_inputs_boundary import (
    CALLSITE, CALLEE, RETURN, CORE, capture_events, prior_frontier,
    source_coverage, summarize,
)


class ResetInputsBoundaryTests(unittest.TestCase):
    def test_prior_callsite_is_hash_bound_to_static_symbol(self):
        prior = prior_frontier()
        self.assertEqual(prior["callee_link_va"], CALLEE)
        self.assertEqual(prior["return_link_va"], RETURN)
        self.assertEqual(prior["instruction_bytes"], "e8998dfcff")

    def test_capture_order_and_duplicate_suppression(self):
        rows = [
            {"w3_121_reset_inputs_boundary": True, "link_va": CALLSITE},
            {"w3_121_reset_inputs_boundary": True, "link_va": CALLSITE},
            {"w3_121_reset_inputs_boundary": True, "link_va": CALLEE},
            {"w3_121_reset_inputs_boundary": True, "link_va": RETURN},
        ]
        events = capture_events(rows)
        self.assertEqual([r["link_va"] for r in events], [CALLSITE, CALLEE, RETURN])
        self.assertTrue(summarize(events)["ordered"])

    def test_source_requires_mapping_order_and_three_event_cap(self):
        coverage = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(coverage.values()), coverage)

    def test_guarded_original_run_measured_all_three_points(self):
        import json
        from pathlib import Path
        result = json.loads(Path("evidence/w3_121_reset_inputs_boundary.json").read_text(encoding="utf-8"))
        events = result["trace"]["target_events"]
        self.assertEqual([e["link_va"] for e in events], [CALLSITE, CALLEE, RETURN])
        self.assertEqual([e["eip"] for e in events], [0x27DAE2, 0x246880, 0x27DAE7])
        self.assertTrue(result["trace"]["summary"]["ordered"])
        self.assertTrue(result["guard"]["sandbox_verified"])


if __name__ == "__main__":
    unittest.main()
