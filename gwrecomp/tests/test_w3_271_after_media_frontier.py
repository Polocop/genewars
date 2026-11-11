from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_271_after_media_frontier import (
    MAX_TARGET_EVENTS,
    analyze_rows,
    parse_bounded_jsonl,
    runtime_to_link,
    validate_source,
)


class AfterMediaFrontierTests(unittest.TestCase):
    def test_fresh_runtime_mapping_and_bounded_target_filter(self):
        self.assertEqual(runtime_to_link(0x27D983, 0x1EB000), 0x92983)
        self.assertIsNone(runtime_to_link(0x1000, 0x1EB000))
        rows = [
            {"event": "main_mapping", "mapping_matches": True},
            {"event": "w3_269_first_guest_checkpoint_after_present",
             "runtime_linear": 0x27D983, "code_rebase": 0x1EB000,
             "link_va": 0x92983},
            {"event": "w3_269_game_transition_checkpoint", "link_va": 0x92AE2},
            {"event": "dos_file_read", "link_va": 0x99999},
        ]
        result = analyze_rows(rows, sum(len(json.dumps(x)) + 1 for x in rows))
        self.assertTrue(result["main_mapping_seen"])
        self.assertTrue(result["post_media_return_seen"])
        self.assertEqual(result["target_count"], 1)
        self.assertFalse(result["menu_verified"])

    def test_jsonl_caps_and_invalid_rows_fail_closed(self):
        raw = b"\n".join(json.dumps({"i": i}).encode() for i in range(1008)) + b"\n"
        self.assertEqual(len(parse_bounded_jsonl(raw)), 1008)
        with self.assertRaisesRegex(ValueError, "2048-row"):
            parse_bounded_jsonl(b"{}\n" * 2049)
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            parse_bounded_jsonl(b"x" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "invalid JSONL"):
            parse_bounded_jsonl(b"{nope}\n")

    def test_target_cap_duplicate_marker_and_source_scope(self):
        rows = [{"event": "w3_269_game_transition_checkpoint", "link_va": 0x92AE2}
                for _ in range(MAX_TARGET_EVENTS + 1)]
        with self.assertRaisesRegex(ValueError, "target event cap"):
            analyze_rows(rows, 100)
        duplicate = [
            {"event": "w3_269_first_guest_checkpoint_after_present",
             "runtime_linear": 0x27D983, "code_rebase": 0x1EB000,
             "link_va": 0x92983},
            {"event": "w3_269_first_guest_checkpoint_after_present",
             "runtime_linear": 0x27D983, "code_rebase": 0x1EB000,
             "link_va": 0x92983},
        ]
        with self.assertRaisesRegex(ValueError, "duplicate mapping"):
            analyze_rows(duplicate, 100)
        source = (Path(__file__).resolve().parents[1] /
                  "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text()
        self.assertTrue(validate_source(source))


if __name__ == "__main__":
    unittest.main()
