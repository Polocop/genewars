"""Synthetic read-only consistency checks for the W3-204 evidence audit."""
import unittest

from tools.w3_204_ax0300_mapping_audit import audit


class Ax0300MappingAuditTests(unittest.TestCase):
    def test_trace_identity_and_entry_return_pair(self):
        result = audit()
        self.assertEqual(result["classification"], "PARTIAL_ORIGINAL_OBSERVED")
        self.assertEqual(result["original_capture"]["entry_sequence"], 26)
        self.assertEqual(result["original_capture"]["return_sequence"], 27)
        self.assertEqual(result["original_capture"]["code_rebase"], "0x1eb000")

    def test_frame_storage_mapping_does_not_claim_inner_ds_si(self):
        result = audit()
        self.assertTrue(result["audit_conclusion"]["frame_storage_pointer_mapping_proven"])
        self.assertFalse(result["audit_conclusion"]["returned_inner_ds_si_mapping_proven"])
        self.assertFalse(result["audit_conclusion"]["environment_identity_proven"])
        self.assertEqual(result["original_capture"]["returned_inner_ds_si_descriptor_mapping"], "NOT_CAPTURED")

    def test_comparison_retains_cross_run_limit(self):
        result = audit()
        self.assertFalse(result["w1_070_comparison"]["original_vs_native_same_run"])
        self.assertEqual(result["w1_070_comparison"]["original_entry_return_diff_offsets"], [32, 36, 37])


if __name__ == "__main__":
    unittest.main()
