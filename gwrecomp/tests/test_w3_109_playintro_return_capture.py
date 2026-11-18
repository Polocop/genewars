import json
import unittest

from tools.w3_109_playintro_return_capture import (
    CAP,
    FilterState,
    accept,
    arm_at_natural_main_entry,
    measured_rebase,
    parse_jsonl,
    parse_target_events,
    summarize,
)


class PlayIntroReturnCaptureTests(unittest.TestCase):
    def test_natural_arm_first_hit_and_order(self):
        state = FilterState()
        self.assertFalse(accept(state, 0x92A16))
        arm_at_natural_main_entry(state, 0x93F30)
        self.assertTrue(accept(state, 0x92983))
        self.assertTrue(accept(state, 0x92996))
        self.assertFalse(accept(state, 0x92996))
        self.assertTrue(accept(state, 0x92A16))
        self.assertEqual([row["link_va"] for row in state.events], [0x92983, 0x92996, 0x92A16])

    def test_absent_targets_and_cap(self):
        state = FilterState()
        arm_at_natural_main_entry(state, 0x93F30)
        targets = [0x9FEAF, 0x962FC, 0x962FF, 0x92A11, 0x92A16, 0x92A24,
                   0x92ADD, 0x92983, 0x92996, 0x929A9, 0x929C8]
        self.assertFalse(accept(state, 0x12345))
        for index, address in enumerate(targets):
            self.assertTrue(accept(state, address, {"link_va": address, "index": index}))
        self.assertTrue(accept(state, 0x94347, {"link_va": 0x94347, "index": 11}))
        self.assertEqual(len(state.events), CAP)
        self.assertTrue(state.complete)
        self.assertFalse(accept(state, 0x92A24))

    def test_jsonl_mapping_and_bounded_parse(self):
        base = 0x1EB000
        raw = b"\n".join(json.dumps({
            "w3_109_targeted_playintro_return": True,
            "link_va": link,
            "eip": link + base,
            "checkpoint": name,
        }).encode() for link, name in ((0x92A16, "POST_SCREEN_SETUP"), (0x92ADD, "PLAY_SMK_CALL")))
        rows = parse_jsonl(raw)
        targets = parse_target_events(rows)
        self.assertEqual(len(targets), 2)
        self.assertEqual(measured_rebase(targets[0]), base)
        self.assertEqual(summarize(targets)["link_vas"], ["0x00092A16", "0x00092ADD"])
        self.assertTrue(summarize(targets)["mapping_consistent"])
        self.assertLessEqual(len(raw), 1024)


if __name__ == "__main__":
    unittest.main()
