import json
import unittest
from pathlib import Path

from tools.w3_158_loader_call_runner import (
    MAX_TRACE_BYTES,
    event_relation,
    expected_runtime,
    simulate_gate,
)


class WscreenLoaderCallDiscriminatorTests(unittest.TestCase):
    def test_runtime_mapping_round_trip(self):
        rebase = 0x1EB000
        runtime = expected_runtime(rebase, 0x94DBC)
        self.assertEqual(runtime, 0x27FDBC)
        self.assertEqual(runtime - rebase, 0x94DBC)

    def test_one_shot_callsite_arms_loader_entry_without_return_filter(self):
        state = {}
        self.assertEqual(simulate_gate(0x94DBC, state), "callsite")
        self.assertEqual(simulate_gate(0x15090, state), "loader_entry")
        self.assertIsNone(simulate_gate(0x15090, state))
        self.assertNotIn("expected_return", state)

    def test_raw_stack_return_is_compared_to_static_call_return(self):
        call, entry, returned = ({"sequence": n} for n in (1, 2, 3))
        entry.update(link_va=0x15090, edx=0x1DA000 + 0x104054,
                     w3_158_raw_return_address=0x1EB000 + 0x94DC1,
                     w3_158_descriptor_name="*W_SCREEN")
        result = event_relation(call, entry, returned, 0x1EB000, 0x1DA000)
        self.assertTrue(result["return_address_matches_static_call"])
        self.assertTrue(result["previous_w3_157_filter_would_match"])

    def test_event_order_is_required(self):
        call, entry, returned = ({"sequence": n} for n in (2, 1, 3))
        result = event_relation(call, entry, returned, 0x1EB000, 0x1DA000)
        self.assertFalse(result["ordered_same_run"])

    def test_pending_entry_and_return_state_transition(self):
        state = {}
        self.assertEqual(simulate_gate(0x94DBC, state), "callsite")
        self.assertEqual(simulate_gate(0x15090, state), "loader_entry")
        self.assertEqual(simulate_gate(0x94DC1, state), "call_return")
        self.assertIsNone(simulate_gate(0x94DC1, state))

    def test_json_serialization_and_trace_cap(self):
        record = {"sequence": 1, "checkpoint": "W3_158_WSCREEN_CALLSITE",
                  "link_va": 0x94DBC, "return_address": 0}
        self.assertEqual(json.loads(json.dumps(record)), record)
        self.assertEqual(MAX_TRACE_BYTES, 1_048_576)
        runner = Path("tools/w3_158_loader_call_runner.py").read_text(encoding="utf-8")
        self.assertIn("if len(raw) > MAX_TRACE_BYTES", runner)

    def test_cpp_has_one_shot_callsites_and_unfiltered_entry_gate(self):
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertIn("candidate_link_va == 0x00094dbc", source)
        self.assertIn("candidate_link_va == 0x00015090", source)
        self.assertIn("candidate_link_va == 0x00094dc1", source)
        entry_gate = source.split("const bool w3_158_loader_entry_candidate", 1)[1].split(";", 1)[0]
        self.assertIn("w3_158_loader_pending", entry_gate)
        self.assertNotIn("entry_stack_return", entry_gate)


if __name__ == "__main__":
    unittest.main()
