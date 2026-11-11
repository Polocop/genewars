import unittest
from pathlib import Path

from tools.w3_142_direct_smacker import parse_jsonl, summarize


class DirectSmackerTests(unittest.TestCase):
    def test_first_route_sequence_mapping_and_process_are_bounded(self):
        base = 0x001EB000
        direct = {"event": "target_runtime_checkpoint", "checkpoint": "W3_133_PLAY_SMK_DIRECT_ENTRY",
                  "link_va": 0xAE308, "eip": 0xAE308 + base, "sequence": 1,
                  "process_psp": 10, "cs": 0x160}
        rows = [direct]
        for sequence, (name, link) in enumerate((
            ("W3_142_SMACKTOBUFFER_ENTRY", 0xC5140),
            ("W3_142_SMACKDOFRAME_ENTRY", 0xC5BD0),
            ("W3_142_LBSCREENSWAP_CALLSITE", 0xAE47F),
            ("W3_142_LBSCREENSWAP_ENTRY", 0x9FFE0),
        ), 2):
            rows.append({"event": "target_runtime_checkpoint", "checkpoint": name, "link_va": link,
                         "eip": link + base, "sequence": sequence, "process_psp": 10, "cs": 0x160})
        result = summarize(rows)
        self.assertTrue(result["direct_entry_observed"])
        self.assertEqual(result["classification"], "DIRECT_ROUTE_CHECKPOINTS_CAPTURED")
        self.assertTrue(result["all_same_runtime_rebase"])
        self.assertTrue(result["strictly_ordered"])
        self.assertTrue(result["same_process_context"])
        self.assertFalse(result["draw_or_framebuffer_proven"])

    def test_direct_entry_without_transfer_is_inconclusive_not_not_reached(self):
        direct = {"event": "target_runtime_checkpoint", "checkpoint": "W3_133_PLAY_SMK_DIRECT_ENTRY",
                  "link_va": 0xAE308, "sequence": 1, "eip": 0x00299308}
        result = summarize([direct])
        self.assertEqual(result["classification"], "DIRECT_ENTRY_CAPTURED_TRANSFER_NOT_OBSERVED")

    def test_trace_cap_and_unrelated_events(self):
        self.assertEqual(parse_jsonl(b'{"event":"unrelated"}\n')[0]["event"], "unrelated")
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (MAX_TRACE_BYTES + 1))

    def test_emulator_hooks_are_ordered_and_first_route_only(self):
        source = Path(
            "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
        ).read_text(encoding="utf-8")
        anchors = (
            '"W3_133_PLAY_SMK_DIRECT_ENTRY"',
            '"W3_142_SMACKTOBUFFER_ENTRY"',
            '"W3_142_SMACKDOFRAME_ENTRY"',
            '"W3_142_LBSCREENSWAP_CALLSITE"',
            '"W3_142_LBSCREENSWAP_ENTRY"',
        )
        self.assertTrue(all(anchor in source for anchor in anchors))
        for addr in ("0x000c5140", "0x000c5bd0", "0x000ae47f", "0x0009ffe0"):
            self.assertIn(addr, source)
        self.assertIn("w3_142_direct_capture_armed", source)


from tools.w3_142_direct_smacker import MAX_TRACE_BYTES

if __name__ == "__main__":
    unittest.main()
