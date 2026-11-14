import json
import unittest

from tools.w3_073_video_checkpoints import (
    FRAMEBUFFER_GLOBAL_LINK, VIDEO_SITES, first_video_events,
    global_sample, runtime_address,
)


class VideoCheckpointTests(unittest.TestCase):
    def test_runtime_address_requires_measured_mapping(self):
        self.assertEqual(runtime_address(0xA3A00, 0x1EB000), 0x28EA00)
        self.assertIsNone(runtime_address(0xA3A00, None))

    def test_first_events_are_deduplicated_and_capped(self):
        events = [
            {"sequence": 4, "checkpoint": "VIDEO_VESA_SET_PAGE_ENTRY"},
            {"sequence": 8, "checkpoint": "VIDEO_VESA_SET_PAGE_ENTRY"},
            {"sequence": 6, "checkpoint": "VIDEO_INT10_FIRST_ENTRY"},
            {"sequence": 9, "checkpoint": "UNRELATED"},
        ]
        selected = first_video_events(events, limit=2)
        self.assertEqual([event["sequence"] for event in selected], [4, 6])
        self.assertEqual(len(first_video_events(events, limit=0)), 0)
        with self.assertRaises(ValueError):
            first_video_events(events, limit=11)

    def test_global_sample_is_linked_by_symbol_offset(self):
        event = {"selected_global_samples": [
            {"link_offset": FRAMEBUFFER_GLOBAL_LINK, "runtime_offset": 0x351A58,
             "linear": 0x351A58, "value_u32": 0xA0000}]}
        decoded = json.loads(json.dumps(event))
        self.assertEqual(global_sample(decoded)["value_u32"], 0xA0000)
        self.assertIsNone(global_sample({"selected_global_samples": []}))
        self.assertIn(0x9FDEF, VIDEO_SITES)


if __name__ == "__main__":
    unittest.main()
