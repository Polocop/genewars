import json
import unittest

from tools.w3_134_allocator_caller import parse_jsonl, source_coverage, summarize


class W3134AllocatorCallerTests(unittest.TestCase):
    def test_entry_stack_and_same_invocation_return(self):
        base = 0x1EB000
        rows = [
            {"event": "target_runtime_checkpoint", "sequence": 10,
             "checkpoint": "W3_117_PLAYSMACKER_CALLSITE", "link_va": 0x92ADD,
             "eip": base + 0x92ADD},
            {"event": "target_runtime_checkpoint", "sequence": 11,
             "checkpoint": "W3_134_LBMEMORYALLOC_4AC_ENTRY", "link_va": 0x91E00,
             "eip": base + 0x91E00, "eax": 0x4AC, "esp": 0x1000,
             "stack_words_u32": [base + 0xAE35A, 0x1234]},
            {"event": "target_runtime_checkpoint", "sequence": 12,
             "checkpoint": "W3_134_LBMEMORYALLOC_RETURN", "link_va": 0xAE35A,
             "eip": base + 0xAE35A, "eax": 0x12345678},
        ]
        result = summarize(rows)
        self.assertEqual(result["classification"], "ALLOCATOR_ENTRY_AND_MATCHED_RETURN")
        self.assertEqual(result["stack_return_link_va"], "0x000AE35A")
        self.assertTrue(result["same_invocation_return_observed"])
        self.assertEqual(result["caller_identity"], "DYNAMIC_RETURN_TARGET")

    def test_entry_without_return_preserves_limited_caller_claim(self):
        base = 0x1EB000
        row = {"event": "target_runtime_checkpoint", "checkpoint": "W3_134_LBMEMORYALLOC_4AC_ENTRY",
               "link_va": 0x91E00, "eip": base + 0x91E00,
               "stack_words_u32": [base + 0xAE35A]}
        result = summarize([row])
        self.assertEqual(result["classification"], "ALLOCATOR_ENTRY_CALLER_CANDIDATE")
        self.assertEqual(result["caller_identity"], "STACK_RETURN_ADDRESS_ONLY")
        self.assertFalse(result["same_invocation_return_observed"])

    def test_stack_return_inside_verified_radm_malloc_resolves_direct_caller(self):
        base = 0x1EB000
        row = {"event": "target_runtime_checkpoint", "checkpoint": "W3_134_LBMEMORYALLOC_4AC_ENTRY",
               "link_va": 0x91E00, "eip": base + 0x91E00,
               "stack_words_u32": [base + 0xAE64F]}
        result = summarize([row])
        self.assertEqual(result["classification"], "ALLOCATOR_CALLER_RESOLVED")
        self.assertEqual(result["stack_return_function"], "RADMALLOC")
        self.assertEqual(result["caller_identity"], "RADMALLOC_STACK_RETURN_TARGET")

    def test_json_byte_limit_and_unknown(self):
        raw = (json.dumps({"event": "target_runtime_checkpoint", "link_va": 0x92ADD}) + "\n").encode()
        self.assertEqual(len(parse_jsonl(raw)), 1)
        self.assertEqual(summarize([])["caller_identity"], "UNKNOWN")
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))

    def test_source_has_one_shot_filtered_capture(self):
        from pathlib import Path
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text()
        self.assertTrue(all(source_coverage(source).values()))


if __name__ == "__main__":
    unittest.main()
