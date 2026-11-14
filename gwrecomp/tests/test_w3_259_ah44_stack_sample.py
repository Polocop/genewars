from __future__ import annotations

import json
import unittest

from tools.w3_259_ah44_stack_sample import (
    MAX_EVENTS,
    TRACE_CAP,
    reduce_trace,
    SOURCE,
)


def event(**overrides):
    result = {
        "event": "original_cpu_int21_ah44_bx1_entry",
        "w3_259_stack_sample_target": True,
        "mapping_valid": True,
        "int21_bytes_verified": True,
        "int_instruction_link_va": 0xC8973,
        "eax": 0x4400,
        "ebx": 1,
        "esp": 0x1000,
        "ss": 0x20,
        "ss_descriptor_valid": True,
        "ss_present": True,
        "ss_writable_data": True,
        "stack_sample_status": "sampled",
        "stack_sample_bytes": 24,
        "stack_words_u32": [0x123456, 2, 3, 4, 5, 6],
    }
    result.update(overrides)
    return result


def raw_events(*items):
    return b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n" for item in items)


class W3Ah44StackSampleTests(unittest.TestCase):
    def test_accepts_exact_verified_callsite_and_bounds_stack_sample(self):
        result = reduce_trace(raw_events(event()))
        self.assertEqual(result["verified_bx1_count"], 1)
        self.assertEqual(result["return_candidate"], 0x123456)
        self.assertEqual(len(result["raw_stack_words_u32"]), 6)
        self.assertIn("UNKNOWN", result["caller_identification"])

    def test_rejects_bad_mapping_selector_path_and_bx(self):
        for changes in (
            {"mapping_valid": False},
            {"int21_bytes_verified": False},
            {"int_instruction_link_va": 0xC8974},
            {"eax": 0x4300},
            {"ebx": 2},
        ):
            with self.subTest(changes=changes):
                result = reduce_trace(raw_events(event(**changes)))
                self.assertEqual(result["verified_bx1_count"], 0)
                self.assertIsNone(result["first_verified_event"])

    def test_records_descriptor_and_memory_read_failures_without_inventing_words(self):
        for status in ("invalid_descriptor", "descriptor_not_present",
                       "range_outside_descriptor_bounds", "linear_address_overflow",
                       "checked_memory_read_failed"):
            with self.subTest(status=status):
                result = reduce_trace(raw_events(event(stack_sample_status=status,
                                                       stack_sample_bytes=0,
                                                       stack_words_u32=[])))
                self.assertEqual(result["verified_bx1_count"], 1)
                self.assertEqual(result["raw_stack_words_u32"], [])
                self.assertIsNone(result["return_candidate"])

    def test_first_valid_capture_is_unique_and_duplicates_are_reported(self):
        result = reduce_trace(raw_events(event(), event()))
        self.assertEqual(result["verified_bx1_count"], 1)
        self.assertEqual(result["valid_bx1_event_count"], 2)
        self.assertEqual(result["duplicate_target_count"], 1)
        self.assertEqual(result["first_verified_event"]["stack_words_u32"][0], 0x123456)

    def test_rejects_malformed_json_and_hard_caps(self):
        with self.assertRaises(ValueError):
            reduce_trace(b"{not json}\n")
        with self.assertRaises(ValueError):
            reduce_trace(b"x" * (TRACE_CAP + 1))
        many = raw_events(*({"event": str(i)} for i in range(MAX_EVENTS + 1)))
        with self.assertRaises(ValueError):
            reduce_trace(many)

    def test_hook_is_read_only_and_single_target(self):
        source = (SOURCE / "src/cpu/cpu.cpp").read_text(encoding="utf-8")
        start = source.index("// W3-259 samples only the first verified protected MAIN BX=1 callsite.")
        end = source.index("bool ds_descriptor_valid", start)
        hook = source[start:end]
        self.assertIn("static bool w3_259_stack_sample_attempted", hook)
        self.assertIn("mem_readb_checked", hook)
        self.assertNotIn("mem_writeb", hook)
        self.assertNotIn("mem_writew", hook)
        self.assertNotIn("mem_writed", hook)
        self.assertIn("cpu.gdt.GetDescriptor(ss_selector, ss_descriptor)", hook)


if __name__ == "__main__":
    unittest.main()
