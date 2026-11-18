import json
import unittest

from tools.w3_074_vesa_page_capture import first_page_events, framebuffer_value


class VesaPageCaptureTests(unittest.TestCase):
    def test_first_page_events_are_filtered_deduped_and_bounded(self):
        events = [
            {"sequence": 2, "checkpoint": "VIDEO_VESA_SET_PAGE_ENTRY"},
            {"sequence": 3, "checkpoint": "VIDEO_VESA_SET_PAGE_ENTRY"},
            {"sequence": 4, "checkpoint": "VIDEO_INT10_FIRST_ENTRY"},
            {"sequence": 5, "checkpoint": "VIDEO_SCREEN_SETUP_ANY_MODE"},
        ]
        selected = first_page_events(events)
        self.assertEqual([event["sequence"] for event in selected], [2, 4])
        self.assertEqual(first_page_events(events, limit=0), [])
        with self.assertRaises(ValueError):
            first_page_events(events, limit=7)

    def test_framebuffer_sample_roundtrips_and_requires_measured_field(self):
        event = {"framebuffer_global_samples": [
            {"link_offset": 0x19CA58, "value_u32": 0xA0000}]}
        self.assertEqual(framebuffer_value(json.loads(json.dumps(event))), 0xA0000)
        self.assertIsNone(framebuffer_value({}))


if __name__ == "__main__":
    unittest.main()
