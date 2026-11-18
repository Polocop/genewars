"""Read-only tests for W3-203's natural original BX=1/tail/result chain."""
import unittest

from tools.w3_206_ah44_tail_reconcile import audit


class Ah44TailReconciliationTests(unittest.TestCase):
    def test_original_entry_tail_and_callback_are_same_psp_ordinal(self):
        result = audit()
        original = result["original"]
        self.assertEqual(original["link_va"], "0xc8973")
        self.assertEqual(original["tail_text"], " -k 38928")
        self.assertEqual(original["callback_ordinal"], 24)
        self.assertEqual(original["dos_callback"]["output_dx"], "0x80d3")
        self.assertFalse(original["dos_callback"]["cf"])

    def test_stream_field_matches_but_dynamic_caller_is_not_overclaimed(self):
        result = audit()
        original = result["original"]
        self.assertEqual(original["stream_field_plus_0x10"], 1)
        self.assertFalse(original["caller"]["same_dynamic_caller_proven"])
        self.assertEqual(result["native_comparison"]["same_tail_and_request_class"], True)
        self.assertFalse(result["native_comparison"]["same_dynamic_invocation_or_full_seed_proven"])

    def test_only_reuses_existing_guarded_trace(self):
        result = audit()
        self.assertTrue(result["guard"]["sandbox_verified"])
        self.assertEqual(result["guard"]["limits"]["timeout_s"], 30)


if __name__ == "__main__":
    unittest.main()
