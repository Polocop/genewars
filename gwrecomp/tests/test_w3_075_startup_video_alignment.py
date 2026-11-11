import unittest

from tools.w3_075_startup_video_alignment import first_startup_video_events


class StartupVideoAlignmentTests(unittest.TestCase):
    def test_first_events_keep_dynamic_order_and_dedupe(self):
        events = [
            {"sequence": 10, "checkpoint": "PLAYINTRO_CALLSITE"},
            {"sequence": 11, "checkpoint": "PLAYINTRO_CALLSITE"},
            {"sequence": 15, "checkpoint": "VIDEO_VESA_SET_PAGE_ENTRY"},
            {"sequence": 12, "checkpoint": "GAME_CALLSITE"},
            {"sequence": 13, "checkpoint": "UNRELATED"},
        ]
        selected = first_startup_video_events(events)
        self.assertEqual([event["sequence"] for event in selected], [10, 12, 15])

    def test_strict_selection_limit(self):
        self.assertEqual(first_startup_video_events([], limit=0), [])
        with self.assertRaises(ValueError):
            first_startup_video_events([], limit=11)


if __name__ == "__main__":
    unittest.main()
