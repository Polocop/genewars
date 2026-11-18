import json
import unittest

from tools.w3_072_setup_this_checkpoints import (
    SITES, sample_this_value, select_first_checkpoints,
    this_linear_address, runtime_address,
)


class SetupThisCheckpointTests(unittest.TestCase):
    def test_link_to_runtime_uses_measured_code_rebase(self):
        self.assertEqual(runtime_address(0x94B51, 0x1EB000), 0x27FB51)
        self.assertIsNone(runtime_address(0x94B51, None))

    def test_this_slot_uses_data_rebase_and_segment_base(self):
        self.assertEqual(this_linear_address(0x1DA000, 0), 0x2EECA8)
        self.assertIsNone(this_linear_address(None, 0))
        self.assertIsNone(this_linear_address(0x1DA000, None))

    def test_first_matching_event_only_and_bounded_site_set(self):
        events = [
            {"checkpoint": "SETUP_THIS_GLOBAL_READ", "ordinal": 1},
            {"checkpoint": "SETUP_THIS_GLOBAL_READ", "ordinal": 2},
            {"checkpoint": "UNRELATED", "ordinal": 3},
        ]
        result = select_first_checkpoints(events)
        self.assertEqual(result["SETUP_THIS_GLOBAL_READ"]["ordinal"], 1)
        self.assertEqual(set(result), set(SITES.values()))
        self.assertIsNone(result["SETUP_THIS_GLOBAL_WRITE"])

    def test_value_requires_matching_global_sample_and_json_roundtrips(self):
        event = {"checkpoint": "SETUP_THIS_GLOBAL_READ", "selected_global_samples": [
            {"link_offset": 0x114CA8, "value_u32": 0x12345678}]}
        encoded = json.dumps(event)
        self.assertEqual(sample_this_value(json.loads(encoded)), 0x12345678)
        self.assertIsNone(sample_this_value({"selected_global_samples": []}))


if __name__ == "__main__":
    unittest.main()
