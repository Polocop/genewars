import json
import unittest

from tools.w3_115_play_smacker_branch import (
    CAP,
    branch_outcome,
    mapping,
    parse_events,
    parse_jsonl,
    source_coverage,
    summarize,
    state_updates_are_siblings,
    CORE,
)


class PlaySmackerBranchTests(unittest.TestCase):
    def test_live_instrumentation_covers_only_bounded_branch_targets(self):
        coverage = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(coverage.values()))

    def test_state_update_nesting_regression(self):
        prefix = (
            "if (w3_107_target_checkpoint) {\n"
            "\t\t\t\t\t++w3_107_checkpoint_count;\n"
            "\t\t\t\t\tif (w3_107_checkpoint_count >= 14) {\n"
            "\t\t\t\t\t\tstop_w3_107();\n"
            "\t\t\t\t\t}\n"
        )
        suffix = (
            "if (w3_109_target_checkpoint) {\n"
            "\t\t\t\t\t++w3_109_checkpoint_count;\n"
            "\t\t\t\t}\n"
            "if (w3_115_target_checkpoint) {\n"
            "\t\t\t\t\t++w3_115_checkpoint_count;\n"
            "\t\t\t\t}\n"
            "if (w3_103_page_mode_trigger)\n"
        )
        self.assertTrue(state_updates_are_siblings(prefix + "}\n" + suffix))
        self.assertFalse(state_updates_are_siblings(prefix + suffix))

    def test_destination_classification_and_mapping(self):
        events = [
            {"w3_115_play_smacker_branch": True, "link_va": 0x929FA, "eip": 0x27D9FA},
            {"w3_115_play_smacker_branch": True, "link_va": 0x92A4F, "eip": 0x27DA4F},
        ]
        self.assertEqual(branch_outcome(events), "JE_TAKEN_TO_92A4F")
        self.assertEqual(mapping(events), {"rebases": ["0x001EB000"], "consistent": True})
        self.assertEqual(summarize(events)["event_count"], 2)

    def test_bounded_parse_filters_unrelated_rows_and_caps(self):
        rows = [{"w3_115_play_smacker_branch": True, "link_va": 0x929D0, "eip": 0x27D9D0}]
        rows.extend({"w3_115_play_smacker_branch": False, "link_va": i, "eip": i} for i in range(3))
        self.assertEqual(len(parse_events(rows)), 1)
        self.assertEqual(branch_outcome([]), "BRANCH_DESTINATION_NOT_OBSERVED")
        raw = json.dumps(rows[0]).encode()
        self.assertEqual(len(parse_jsonl(raw)), 1)
        with self.assertRaises(ValueError):
            parse_jsonl(raw, max_bytes=1)
        capped = parse_events(rows + [rows[0]] * (CAP + 1))
        self.assertEqual(len(capped), CAP)


if __name__ == "__main__":
    unittest.main()
