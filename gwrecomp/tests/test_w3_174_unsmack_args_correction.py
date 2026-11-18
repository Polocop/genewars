import unittest

from tools.w3_174_unsmack_args_correction import corrected


class UnsmackArgsCorrectionTests(unittest.TestCase):
    def test_preprologue_entry_uses_esp_cdecl_arguments(self):
        result = corrected()
        self.assertEqual(result["provenance"]["prologue_bytes"], "558bec")
        self.assertEqual([a["value"] for a in result["correct_arguments"]],
                         ["0x8f958c", "0x8b06c0", "0x1a0b34"])
        self.assertEqual([a["entry_stack_slot"] for a in result["correct_arguments"]],
                         ["SS:ESP+4", "SS:ESP+8", "SS:ESP+12"])

    def test_old_ebp_relative_fields_are_invalidated(self):
        result = corrected()
        self.assertEqual(len(result["supersedes"]["invalid_fields"]), 3)
        self.assertTrue(result["raw_trace_entry_matches_structured_evidence"])

    def test_call_return_and_sample_facts_are_preserved(self):
        result = corrected()
        preserved = result["preserved_valid_facts"]
        self.assertEqual(preserved["call_block_link_va"], "0xC5C62")
        self.assertEqual(preserved["entry_link_va"], "0xEDB20")
        self.assertEqual(preserved["sample_classification"], "SAMPLED_BYTES_STABLE")


if __name__ == "__main__":
    unittest.main()
