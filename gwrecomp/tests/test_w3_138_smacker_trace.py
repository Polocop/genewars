import json
import unittest

from tools.w3_136_smacker_restart_coverage import inspect_source
from tools.w3_138_smacker_trace import parse_jsonl, summarize


class W3137SmackerTraceTests(unittest.TestCase):
    def event(self, sequence, link, checkpoint, **extra):
        base = 0x1EB000
        return {"event": "target_runtime_checkpoint", "sequence": sequence,
                "checkpoint_ordinal": sequence, "w3_133_target_checkpoint": True,
                "link_va": link, "eip": link + base, "checkpoint": checkpoint,
                "ebx": 0, **extra}

    def test_direct_route_mapping_and_copy_target(self):
        rows = [
            self.event(1, 0xAE2D0, "W3_133_PLAY_SMK_ENTRY", ebx=0,
                       w3_133_draw_callback_valid=True, w3_133_draw_callback_value=0),
            self.event(2, 0xAE308, "W3_133_PLAY_SMK_DIRECT_ENTRY"),
            self.event(3, 0xC62F0, "W3_133_SMACKOPEN_ENTRY"),
            self.event(4, 0xAE63C, "W3_133_RADMALLOC_ENTRY"),
            self.event(5, 0xAE668, "W3_133_COPY_TO_SCREEN_ENTRY"),
        ]
        result = summarize(rows)
        self.assertEqual(result["classification"], "COPY_TO_SCREEN_TARGET_OBSERVED")
        self.assertEqual(result["route_entry_observed"], "direct")
        self.assertEqual(result["runtime_rebases"], ["0x001EB000"])
        self.assertTrue(result["mapping_consistent"])
        self.assertFalse(result["framebuffer_write_observed"])

    def test_callback_route_inference_remains_distinct_from_entry(self):
        row = self.event(1, 0xAE2D0, "W3_133_PLAY_SMK_ENTRY", ebx=0,
                         w3_133_draw_callback_valid=True, w3_133_draw_callback_value=0)
        result = summarize([row])
        self.assertEqual(result["route_inference"]["route"], "direct")
        self.assertIsNone(result["route_entry_observed"])
        self.assertFalse(result["route_inference"]["dynamic_selected_entry_observed"])

    def test_duplicate_suppression_event_cap_and_unknown(self):
        duplicate = self.event(1, 0xAE2D0, "W3_133_PLAY_SMK_ENTRY")
        rows = [duplicate, {**duplicate, "sequence": 2}] + [
            self.event(i + 3, 0x100000 + i, f"target_{i}") for i in range(20)]
        result = summarize(rows)
        self.assertEqual(result["event_count"], 12)
        self.assertEqual(sum(row.get("link_va") == 0xAE2D0 for row in result["events"]), 1)
        self.assertTrue(summarize([])["mapping_consistent"])
        self.assertEqual(summarize([])["classification"], "NO_W3_133_TARGET")

    def test_json_byte_cap_and_restart_gate(self):
        raw = (json.dumps(self.event(1, 0xAE308, "W3_133_PLAY_SMK_DIRECT_ENTRY")) + "\n").encode()
        self.assertEqual(len(parse_jsonl(raw)), 1)
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))
        from pathlib import Path
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text()
        self.assertTrue(all(inspect_source(source).values()))


if __name__ == "__main__":
    unittest.main()
