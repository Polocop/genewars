import json
import unittest

from tools.w3_133_smacker_draw_route import parse_jsonl, source_coverage, summarize


class W3133SmackerDrawRouteTests(unittest.TestCase):
    def test_via_buffer_route_and_first_draw(self):
        base = 0x1EB000
        pairs = [(0xAE2D0, "W3_133_PLAY_SMK_ENTRY"),
                 (0xAE4D8, "W3_133_PLAY_SMK_BUFFER_ENTRY"),
                 (0xC62F0, "W3_133_SMACKOPEN_ENTRY"),
                 (0xAE63C, "W3_133_RADMALLOC_ENTRY"),
                 (0x91E00, "W3_133_LBMEMORYALLOC_4AC_ENTRY"),
                 (0xAE668, "W3_133_COPY_TO_SCREEN_ENTRY")]
        rows = [{"event": "target_runtime_checkpoint", "w3_133_target_checkpoint": True,
                 "sequence": i, "link_va": link, "eip": link + base,
                 "checkpoint": name, "eax": 0x4AC if link == 0x91E00 else 0,
                 "ebx": 0,
                 "return_address": 0x27D001 if link == 0x91E00 else 0,
                 "w3_133_draw_callback_valid": True, "w3_133_draw_callback_value": 0x123456,
                 "w3_133_smack_malloc_valid": True, "w3_133_smack_malloc_value": 0x91E00}
                for i, (link, name) in enumerate(pairs, 1)]
        result = summarize(rows)
        self.assertEqual(result["classification"], "COPY_TO_SCREEN_OBSERVED")
        self.assertEqual(result["selected_playback_route"], "via_buffer")
        self.assertTrue(result["mapping_consistent"])
        self.assertTrue(result["copy_to_screen_observed"])
        self.assertEqual(result["allocation_request_eax"], "0x000004AC")
        self.assertEqual(result["playback_route_inference"]["path"], "via_buffer")

    def test_measured_zero_callback_and_bl_infer_direct_without_claiming_entry(self):
        row = {"event": "target_runtime_checkpoint", "w3_133_target_checkpoint": True,
               "link_va": 0xAE2D0, "eip": 0x2992D0, "checkpoint": "W3_133_PLAY_SMK_ENTRY",
               "ebx": 0, "w3_133_draw_callback_valid": True, "w3_133_draw_callback_value": 0,
               "w3_133_smack_malloc_valid": True, "w3_133_smack_malloc_value": 0x27CE00}
        result = summarize([row])
        self.assertEqual(result["classification"], "DIRECT_ROUTE_INFERRED_FROM_ENTRY_STATE")
        self.assertEqual(result["selected_playback_route"], None)
        self.assertEqual(result["playback_route_inference"]["path"], "direct")
        self.assertFalse(result["playback_route_inference"]["dynamic_selected_function_entry_observed"])
        self.assertTrue(result["smack_malloc_matches_lbmemoryalloc_runtime"])

    def test_unknown_callback_and_unmarked_rows_remain_unknown(self):
        rows = [{"event": "target_runtime_checkpoint", "link_va": 0xAE668,
                 "checkpoint": "unmarked"}]
        result = summarize(rows)
        self.assertEqual(result["classification"], "NO_W3_133_TARGET")
        self.assertIsNone(result["selected_playback_route"])
        self.assertFalse(result["copy_to_screen_observed"])

    def test_jsonl_and_byte_cap(self):
        raw = (json.dumps({"event": "target_runtime_checkpoint", "w3_133_target_checkpoint": True,
                           "link_va": 0xAE308, "eip": 0x27D308,
                           "checkpoint": "W3_133_PLAY_SMK_DIRECT_ENTRY"}) + "\n").encode()
        self.assertEqual(len(parse_jsonl(raw)), 1)
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))

    def test_instrumenter_covers_bounded_dynamic_targets(self):
        from pathlib import Path
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text()
        self.assertTrue(all(source_coverage(source).values()))


if __name__ == "__main__":
    unittest.main()
