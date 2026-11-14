"""Synthetic matching, descriptor-bound, and source-bound tests for W3-202."""
import unittest

from tools.w3_202_bscreen_free_sample import (
    SAMPLE_BYTES, SOURCE, inspect_source, matching_free_candidate, validate_range,
)


class BScreenFreeSampleTests(unittest.TestCase):
    def test_only_matching_same_psp_allocation_is_eligible_once(self):
        kwargs = dict(allocation_pointer=0x8B03C8, stored_pointer=0x8B03C8,
                      eax=0x8B03C8, allocation_size=0x4B000, psp=7811,
                      allocation_psp=7811, attempted=False)
        self.assertTrue(matching_free_candidate(**kwargs))
        self.assertFalse(matching_free_candidate(**{**kwargs, "eax": 0x8B0400}))
        self.assertFalse(matching_free_candidate(**{**kwargs, "psp": 2}))
        self.assertFalse(matching_free_candidate(**{**kwargs, "allocation_size": 0x4AFFF}))
        self.assertFalse(matching_free_candidate(**{**kwargs, "attempted": True}))

    def test_sample_is_exactly_64_bytes_and_inside_full_allocation(self):
        result = validate_range(pointer=0x8B03C8, allocation_size=0x4B000,
                                ds_base=0, descriptor_limit=0xFFFFFFFF,
                                physical_memory_bytes=16 * 1024 * 1024)
        self.assertTrue(result["valid"])
        self.assertEqual(result["sample_bytes"], SAMPLE_BYTES)
        self.assertEqual(result["sample_start"], 0x8B03C8)
        self.assertEqual(result["sample_end_exclusive"], 0x8B0408)

    def test_invalid_descriptor_physical_range_and_size_fail_closed(self):
        args = dict(pointer=0x8B03C8, allocation_size=0x4B000, ds_base=0,
                    descriptor_limit=0xFFFFFFFF, physical_memory_bytes=16 * 1024 * 1024)
        self.assertFalse(validate_range(**{**args, "descriptor_limit": 0x8B03C7})["valid"])
        self.assertFalse(validate_range(**{**args, "physical_memory_bytes": 0x8B03C7})["valid"])
        self.assertFalse(validate_range(**{**args, "allocation_size": 0x1000})["valid"])

    def test_source_encodes_free_only_one_shot_and_live_bounds(self):
        result = inspect_source(SOURCE.read_text(encoding="utf-8"))
        self.assertTrue(result["all_checks_pass"])


if __name__ == "__main__":
    unittest.main()
