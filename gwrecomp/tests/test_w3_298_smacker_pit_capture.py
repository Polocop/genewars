from __future__ import annotations

import json
import unittest

from tools.w3_298_smacker_pit_capture import (
    MAX_SELECTED_EVENTS, analyze, parse_trace, validate_first_hit,
)


def row(event: str, **fields) -> bytes:
    return (json.dumps({"event": event, **fields}, separators=(",", ":")) + "\n").encode()


class W3298CaptureTests(unittest.TestCase):
    def test_mapping_and_first_hit_events_preserve_order(self):
        raw = b"".join([
            row("target_code_anchor", anchor="MAIN_ENTRY", candidate_rebase=0x1EB000),
            row("W3_298_SOUND_PIT_CHECKPOINT", ordinal=1,
                checkpoint="PLAY_SMK_DIRECT_ENTRY", link_va=0xAE308),
            row("W3_298_SOUND_GATE_BRANCH", ordinal=2,
                branch_link_va=0xAE32F, taken=True, destination_link_va=0xAE340),
            row("W3_298_SOUND_PIT_CHECKPOINT", ordinal=3,
                checkpoint="SMACK_CALLBACK_INDIRECT_CALL", link_va=0xC460A,
                callback_pointer_valid=True, callback_pointer=0xC4270),
            row("W3_298_PIT_PORT_IO", ordinal=4, operation="OUT", port=0x43),
        ])
        rows = parse_trace(raw)
        validate_first_hit(rows)
        rows.extend([
            {"event": "target_runtime_checkpoint", "sequence": 8,
             "checkpoint": "VIDEO_FRAMEBUFFER_ASSIGN_AFTER", "link_va": 0x9FDF9},
            {"event": "setup_dos_api", "sequence": 9, "ordinal": 128,
             "operation": "INT21_AH3F", "cwd": "GENEWARS", "cf": False},
        ])
        summary = analyze(rows)
        self.assertEqual(summary["main_anchor_count"], 1)
        self.assertEqual(summary["checkpoint_names_in_order"],
                         ["PLAY_SMK_DIRECT_ENTRY", "SMACK_CALLBACK_INDIRECT_CALL"])
        self.assertTrue(summary["pit_io_observed"])
        self.assertEqual(summary["branches"][0]["taken"], True)
        self.assertEqual(summary["last_original_checkpoint"]["checkpoint"],
                         "VIDEO_FRAMEBUFFER_ASSIGN_AFTER")
        self.assertEqual(summary["last_dos_api"]["operation"], "INT21_AH3F")

    def test_selected_event_cap_is_enforced(self):
        raw = b"".join(row("W3_298_SOUND_GATE_BRANCH", ordinal=i + 1)
                       for i in range(MAX_SELECTED_EVENTS + 1))
        with self.assertRaisesRegex(ValueError, "event count exceeds 32"):
            parse_trace(raw)

    def test_duplicate_checkpoint_is_rejected(self):
        rows = parse_trace(b"".join([
            row("W3_298_SOUND_PIT_CHECKPOINT", ordinal=1, checkpoint="PIT_CALLBACK_ENTRY"),
            row("W3_298_SOUND_PIT_CHECKPOINT", ordinal=2, checkpoint="PIT_CALLBACK_ENTRY"),
        ]))
        with self.assertRaisesRegex(ValueError, "duplicates"):
            validate_first_hit(rows)

    def test_invalid_jsonl_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid JSONL"):
            parse_trace(b"{broken\n")

    def test_unobserved_callback_is_not_inferred(self):
        summary = analyze([])
        self.assertFalse(summary["callback_indirect_site_reached"])
        self.assertFalse(summary["pit_io_observed"])
        self.assertIn("INCONCLUSIVE", summary["conclusion"])


if __name__ == "__main__":
    unittest.main()
