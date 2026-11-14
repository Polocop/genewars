import json
import unittest

from tools.w3_135_allocator_return_reconcile import parse_jsonl, summarize


class W3135AllocatorReturnReconcileTests(unittest.TestCase):
    def rows(self):
        base = 0x1EB000
        return [
            {"event": "target_runtime_checkpoint", "sequence": 10,
             "checkpoint": "W3_117_PLAYSMACKER_CALLSITE", "link_va": 0x92ADD,
             "eip": base + 0x92ADD, "process_psp": 7811, "cs": 0x160},
            {"event": "target_runtime_checkpoint", "sequence": 11,
             "checkpoint": "W3_133_PLAY_SMK_ENTRY", "link_va": 0xAE2D0,
             "eip": base + 0xAE2D0, "process_psp": 7811, "cs": 0x160,
             "return_address": base + 0x92AE2},
            {"event": "target_runtime_checkpoint", "sequence": 12,
             "checkpoint": "W3_134_LBMEMORYALLOC_4AC_ENTRY", "link_va": 0x91E00,
             "eip": base + 0x91E00, "eax": 0x4AC, "process_psp": 7811, "cs": 0x160,
             "return_address": base + 0xAE64F},
            {"event": "target_runtime_checkpoint", "sequence": 13,
             "checkpoint": "W3_109_PLAYINTRO_RETURN_CHECKPOINT", "link_va": 0x92AE2,
             "eip": base + 0x92AE2, "eax": 1, "process_psp": 7811, "cs": 0x160},
        ]

    def test_same_process_stack_join_infers_nested_return_not_value(self):
        result = summarize(self.rows())
        self.assertEqual(result["classification"],
                         "ENCLOSING_PLAY_SMK_RETURN_OBSERVED_ALLOCATOR_COMPLETION_INFERRED")
        self.assertTrue(result["same_invocation_join_valid"])
        self.assertTrue(result["nested_allocator_call_completion_inferred"])
        self.assertFalse(result["direct_allocator_return_checkpoint_observed"])
        self.assertIsNone(result["allocator_return_eax"])
        self.assertEqual(result["play_smk_return_eax"], 1)

    def test_wrong_process_or_stack_target_does_not_join(self):
        rows = self.rows()
        rows[-1]["process_psp"] = 7
        self.assertFalse(summarize(rows)["same_invocation_join_valid"])
        rows = self.rows()
        rows[1]["return_address"] += 1
        self.assertFalse(summarize(rows)["same_invocation_join_valid"])

    def test_missing_return_remains_unknown(self):
        result = summarize(self.rows()[:-1])
        self.assertFalse(result["nested_allocator_call_completion_inferred"])
        self.assertEqual(result["allocator_ownership_free_lifetime"], "UNKNOWN")

    def test_json_byte_cap(self):
        raw = (json.dumps(self.rows()[0]) + "\n").encode()
        self.assertEqual(len(parse_jsonl(raw)), 1)
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))


if __name__ == "__main__":
    unittest.main()
