import json
import unittest

from tools.w3_129_b_screen_capture import parse_jsonl, relevant_checkpoints, source_coverage, summarize


class BScreenCaptureTests(unittest.TestCase):
    def test_source_is_narrow_and_mapping_checked(self):
        from tools.w3_129_b_screen_capture import CORE
        checks = source_coverage(CORE.read_text(encoding="utf-8", errors="replace"))
        self.assertTrue(all(checks.values()), checks)

    def test_store_and_matching_free_are_ordered(self):
        rows = [
            {"event": "target_code_anchor", "anchor": "MAIN_ENTRY", "candidate_rebase": 0x1EB000},
            {"event": "target_code_anchor", "anchor": "CRT_ARGV_LOAD", "data_rebase": 1933312},
            {"event": "w3_127_target_instruction_restart", "sequence": 9, "link_va": 0x92B71},
            {"event": "w3_127_target_instruction_restart", "sequence": 10, "link_va": 0x91E00,
             "eax": 0x4B000},
            {"event": "w3_127_target_instruction_restart", "sequence": 11, "link_va": 0x92B82,
             "eax": 0x8B03C8},
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_129_B_SCREEN_POST_STORE",
             "sequence": 12,
             "w3_129_target_checkpoint": True, "link_va": 0x92B87, "eax": 0x8B03C8,
             "w3_129_b_screen_sample_valid": True, "w3_129_b_screen_offset": 0x2000,
             "w3_129_b_screen_value": 0x8B03C8, "data_rebase": 0x1D9000,
             "ds_descriptor_valid": True, "ds_base": 0, "ds_limit": 0xFFFFFFFF,
             "checkpoint_ordinal": 12},
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_129_MEMORY_FREE_ENTRY",
             "sequence": 13,
             "w3_129_target_checkpoint": True, "link_va": 0x92030, "eax": 0x8B03C8,
             "return_address": 0x27D9FA, "w3_129_b_screen_sample_valid": True,
             "w3_129_b_screen_value": 0x8B03C8, "checkpoint_ordinal": 13},
        ]
        result = summarize(rows)
        self.assertEqual(result["raw_checkpoint_order"], ["W3_129_B_SCREEN_POST_STORE", "W3_129_MEMORY_FREE_ENTRY"])
        self.assertTrue(result["store_sample_valid"])
        self.assertEqual(result["allocator_request_eax"], "0x0004B000")
        self.assertEqual(result["allocator_return_eax"], "0x008B03C8")
        self.assertTrue(result["allocator_and_store_same_pointer"])
        self.assertTrue(result["first_later_free_linked"])
        self.assertEqual(result["free_return_link_va"], "0x000929FA")

    def test_irrelevant_and_pre_store_free_are_excluded(self):
        rows = [
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_129_MEMORY_FREE_ENTRY",
             "w3_129_target_checkpoint": False, "eax": 1},
            {"event": "other", "checkpoint": "W3_129_B_SCREEN_POST_STORE",
             "w3_129_target_checkpoint": True},
        ]
        self.assertEqual(relevant_checkpoints(rows), [])
        self.assertFalse(summarize(rows)["store_seen"])

    def test_jsonl_byte_cap_and_json_validity(self):
        self.assertEqual(parse_jsonl(b'{"event":"x"}\n')[0]["event"], "x")
        with self.assertRaises(ValueError):
            parse_jsonl(b"12345", max_bytes=4)
        with self.assertRaises(json.JSONDecodeError):
            parse_jsonl(b"{bad}\n")


if __name__ == "__main__":
    unittest.main()
