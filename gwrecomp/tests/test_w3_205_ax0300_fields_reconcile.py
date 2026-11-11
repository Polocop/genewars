"""Synthetic checks for exact numeric AX=0300 return fields and scope."""
import unittest

from tools.w3_205_ax0300_fields_reconcile import audit


class Ax0300FieldReconciliationTests(unittest.TestCase):
    def test_original_return_ds_si_are_decoded_from_packed_frame(self):
        result = audit()
        original = result["original_return"]
        self.assertEqual(original["inner_ds_si"], "C808:0000")
        self.assertEqual(original["sampled_frame_bytes"], 48)
        self.assertEqual(original["full_frame_bytes"], 50)

    def test_outer_frame_mapping_is_not_inner_ds_mapping(self):
        result = audit()
        mapping = result["mapping_and_payload"]
        self.assertFalse(mapping["inner_ds_is_outer_protected_selector"])
        self.assertFalse(mapping["bytes_at_inner_ds_si_sampled_in_w3_184"])
        self.assertTrue(mapping["candidate_is_inference_not_observed_mapping"])
        self.assertEqual(mapping["segment_linear_candidate_if_real_mode_segmentation_applies"], "0xc8080")


if __name__ == "__main__":
    unittest.main()
