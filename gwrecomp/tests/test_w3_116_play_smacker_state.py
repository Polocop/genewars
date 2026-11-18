import json
import unittest

from tools.w3_115_play_smacker_branch import (
    branch_outcome,
    parse_events,
    parse_jsonl,
    source_coverage,
    state_updates_are_siblings,
    CORE,
)


class PlaySmackerStateTests(unittest.TestCase):
    def test_live_state_updates_are_independent(self):
        source = CORE.read_text(encoding="utf-8")
        self.assertTrue(state_updates_are_siblings(source))
        self.assertTrue(source_coverage(source)["state_updates_are_siblings"])

    def test_nested_state_update_is_rejected_synthetically(self):
        nested = (
            "if (w3_107_target_checkpoint) {\n"
            "\t\t\t\t\t++w3_107_checkpoint_count;\n"
            "\t\t\t\t\tif (w3_107_checkpoint_count >= 14) {\n"
            "\t\t\t\t\t\tclose_capture();\n"
            "\t\t\t\t\t}\n"
            "if (w3_109_target_checkpoint) {\n"
            "\t\t\t\t\t++w3_109_checkpoint_count;\n"
            "\t\t\t\t}\n"
            "if (w3_115_target_checkpoint) {\n"
            "\t\t\t\t\t++w3_115_checkpoint_count;\n"
            "\t\t\t\t}\n"
            "if (w3_103_page_mode_trigger)\n"
        )
        self.assertFalse(state_updates_are_siblings(nested))

    def test_branch_and_bounded_event_parse(self):
        row = {"w3_115_play_smacker_branch": True, "link_va": 0x92A00, "eip": 0x27DA00}
        raw = json.dumps(row).encode("utf-8")
        events = parse_events(parse_jsonl(raw))
        self.assertEqual(len(events), 1)
        self.assertEqual(branch_outcome(events), "JE_NOT_TAKEN_TO_92A00")
        self.assertTrue(parse_jsonl(raw, max_bytes=1024))


if __name__ == "__main__":
    unittest.main()
