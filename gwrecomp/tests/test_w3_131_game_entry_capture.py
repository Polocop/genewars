import json
import unittest

from tools.w3_131_game_entry_capture import parse_jsonl, relevant, source_coverage, summarize


class W3131GameEntryCaptureTests(unittest.TestCase):
    def test_filtered_order_and_mapping(self):
        base = 0x1EB000
        links = [(0x92AE2, "W3_117_PLAYSMACKER_CALL_RETURN", "w3_117_play_smacker_call_boundary"),
                 (0x92B71, "W3_124_BRANCH_FALLTHROUGH", "w3_124_post_join_continuation"),
                 (0x929C8, "W3_109_PLAYINTRO_RETURN_CHECKPOINT", "w3_109_targeted_playintro_return"),
                 (0x94347, "GAME_CALLSITE", "w3_109_targeted_playintro_return"),
                 (0x92710, "W3_106_GAME_ENTRY", "w3_106_targeted_game_page")]
        rows = [{"event": "target_runtime_checkpoint", "link_va": link, "eip": link + base,
                 "checkpoint": name, marker: True, "sequence": n}
                for n, (link, name, marker) in enumerate(links, 1)]
        result = summarize(rows)
        self.assertEqual(result["classification"], "GAME_ENTRY_OBSERVED")
        self.assertTrue(result["mapping_consistent"])
        self.assertEqual(result["runtime_rebases"], ["0x001EB000"])
        self.assertEqual(result["link_vas"], [f"0x{x[0]:08X}" for x in links])

    def test_ignores_unmarked_or_unrelated_events_and_caps(self):
        rows = [{"event": "target_runtime_checkpoint", "link_va": 0x92710, "eip": 0x27B710,
                 "checkpoint": "unmarked"}]
        rows.extend({"event": "target_runtime_checkpoint", "link_va": link, "eip": link + 0x1EB000,
                     "checkpoint": "marked", "w3_109_targeted_playintro_return": True}
                    for link in [0x92AE2, 0x92B6B, 0x92B71, 0x929C8, 0x94347] * 3)
        self.assertEqual(len(relevant(rows)), 12)
        self.assertFalse(summarize(rows)["game_entry_seen"])

    def test_jsonl_limit_and_json_validity(self):
        raw = (json.dumps({"event": "target_runtime_checkpoint", "link_va": 0x94347,
                           "eip": 0x27E347, "checkpoint": "GAME",
                           "w3_109_targeted_playintro_return": True}) + "\n").encode()
        self.assertEqual(len(parse_jsonl(raw)), 1)
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))

    def test_pinned_source_contains_ordered_bounded_targets(self):
        from pathlib import Path
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text()
        self.assertTrue(all(source_coverage(source).values()))


if __name__ == "__main__":
    unittest.main()
