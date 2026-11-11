import unittest

from tools.w3_083_setup_continuation import summarize


class SetupContinuationTests(unittest.TestCase):
    def test_measured_order_and_mapping_are_preserved(self):
        events = [
            {"event": "target_runtime_checkpoint", "sequence": 1,
             "checkpoint": "MAIN_ENTRY_CHECKPOINT", "link_va": 0x93f30,
             "eip": 0x27ef30, "cs": 0x160, "ds": 0x168,
             "data_rebase": 0x1da000},
            {"event": "target_runtime_checkpoint", "sequence": 2,
             "checkpoint": "SETUP_GAME_ENTRY", "link_va": 0x94ac0,
             "eip": 0x27fac0, "return_address": 0x279342},
            {"event": "target_runtime_checkpoint", "sequence": 3,
             "checkpoint": "SETUP_FIRST_CALLEE", "link_va": 0x14bf0,
             "eip": 0x200bf0},
            {"event": "target_runtime_checkpoint", "sequence": 4,
             "checkpoint": "SETUP_GAME_CONTINUATION_94AE9", "link_va": 0x94ae9,
             "eip": 0x27fae9, "eflags": 0x202},
            {"event": "target_runtime_checkpoint", "sequence": 5,
             "checkpoint": "PLAYINTRO_CALLSITE", "link_va": 0x94342,
             "eip": 0x27f342},
        ]
        result = summarize(events)
        self.assertEqual(result["classification"], "CONTINUATION_CAPTURED")
        self.assertEqual(result["main_mapping"]["code_rebase"], 0x1eb000)
        self.assertTrue(result["continuation_order_valid"])
        self.assertFalse(result["playintro_reached"])
        self.assertEqual(result["route"][-1]["checkpoint"], "PLAYINTRO_CALLSITE")

    def test_video_base_assignment_alone_does_not_imply_continuation(self):
        result = summarize([{"event": "target_runtime_checkpoint", "sequence": 1,
                             "checkpoint": "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
                             "link_va": 0x9fdf9, "framebuffer_value_u32": 0xa0000}])
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertIsNone(result["setup_game_continuation_94ae9"])
        self.assertFalse(result["playintro_reached"])


if __name__ == "__main__":
    unittest.main()
