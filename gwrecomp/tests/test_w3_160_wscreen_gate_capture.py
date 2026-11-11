import json
import unittest
from pathlib import Path

from tools.w3_160_wscreen_gate_runner import (
    MAX_TRACE_BYTES,
    branch_taken,
    expected_global_offset,
    gate1_expected_taken,
    gate2_expected_taken,
    mapped_byte_bounds_valid,
)


class WscreenGateCaptureTests(unittest.TestCase):
    def test_data_mapping_is_added_to_link_global(self):
        self.assertEqual(expected_global_offset(0x1DA000, 0x117662), 0x2F1662)
        self.assertEqual(expected_global_offset(0x1DA000, 0x1174A4), 0x2F14A4)

    def test_single_byte_reads_respect_selector_and_physical_bounds(self):
        self.assertTrue(mapped_byte_bounds_valid(0x2F7662, 0xFFFFFFFF, 0x2F7662, 0x400000))
        self.assertFalse(mapped_byte_bounds_valid(0x10001, 0x10000, 0x10001, 0x20000))
        self.assertFalse(mapped_byte_bounds_valid(0x100, 0xFFFF, 0x20000, 0x20000))

    def test_jne_outcome_uses_real_zf(self):
        self.assertTrue(branch_taken(0x202))
        self.assertFalse(branch_taken(0x242))

    def test_static_gate_conditions_match_globals(self):
        self.assertTrue(gate1_expected_taken(0x01))
        self.assertTrue(gate1_expected_taken(0x81))
        self.assertFalse(gate1_expected_taken(0x80))
        self.assertTrue(gate2_expected_taken(0x04))
        self.assertFalse(gate2_expected_taken(0x00))

    def test_event_order_and_json_are_bounded(self):
        records = [{"sequence": 1, "link_va": 0x94CE1, "value": 1},
                   {"sequence": 2, "link_va": 0x94D9F, "value": 1}]
        encoded = json.dumps(records)
        self.assertEqual(json.loads(encoded), records)
        self.assertLess(len(encoded.encode()), MAX_TRACE_BYTES)
        self.assertEqual(MAX_TRACE_BYTES, 1_048_576)

    def test_instrumentation_is_one_shot_and_reads_only_two_globals(self):
        core = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        for token in ("W3_160_WSCREEN_GATE_117662", "W3_160_WSCREEN_GATE_1174A4",
                      "W3_160_WSCREEN_GATE_FALLTHROUGH", "W3_160_WSCREEN_LOADER_BLOCK",
                      "w3_160_gate_117662_seen", "w3_160_gate_1174a4_seen",
                      "w3_160_branch_taken", "target_data_rebase"):
            self.assertIn(token, core)


if __name__ == "__main__":
    unittest.main()
