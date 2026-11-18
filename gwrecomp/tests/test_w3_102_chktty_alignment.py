import unittest

from tools.w3_102_chktty_alignment import build


class ChkttyAlignmentTests(unittest.TestCase):
    def test_original_return_resolves_to_doopen_chktty_call(self):
        result = build()
        original = result["original_first_chktty"]
        self.assertEqual(original["entry_return_link_va"], "0x98652")
        self.assertEqual(original["outer_callsite_link_va"], "0x0009864D")
        self.assertEqual(original["outer_call_target"], "__chktty_ at 0x000BA4D6")

    def test_native_first_matching_field_is_ordinal_three(self):
        result = build()["native_chktty_ordinals"]
        self.assertEqual(result["ordinal_3"]["stream_field_10_loaded"], 5)
        self.assertEqual(result["ordinal_3"]["interpreted_bx"], 5)
        self.assertEqual(result["ordinal_11"]["stream_field_10_loaded"], 1)
        self.assertEqual(result["ordinal_11"]["interpreted_bx"], 1)

    def test_original_absence_is_bounded_and_not_unblocked(self):
        result = build()
        self.assertFalse(result["alignment"]["original_bx1_observed"])
        self.assertEqual(result["original_first_chktty"]["persisted_callback_bx_values"], [2, 5])
        self.assertFalse(result["alignment"]["w2_086_unblocked"])
        self.assertEqual(result["alignment"]["causal_first_divergence"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
