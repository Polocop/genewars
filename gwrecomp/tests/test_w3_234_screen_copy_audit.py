import unittest

from tools.w3_234_screen_copy_audit import extract_copy


def rows(*, branch=False, descriptors=True, bounds=True, post=True, sample_bytes=16):
    branch_row = {
        "sequence": 1, "checkpoint": "W3_151_VESA_BRANCH", "link_va": 0xA0000,
        "branch_taken": branch, "w3_151_vesa_global_valid": True,
        "w3_151_vesa_global_u8": 0,
    }
    pre = {
        "sequence": 2, "checkpoint": "W3_151_COPY_NONVESA_PRE", "link_va": 0xA0013,
        "w3_151_copy_inputs_valid": True, "w3_151_copy_source_start": 0x1000,
        "w3_151_copy_destination_start": 0xA0000, "w3_151_copy_dword_count": 4,
        "esi": 0x1000, "edi": 0xA0000, "ecx": 4, "ds_descriptor_valid": True,
    }
    post_row = {
        "sequence": 3, "checkpoint": "W3_151_COPY_NONVESA_POST", "link_va": 0xA0015,
        "esi": 0x1010, "edi": 0xA0010, "ecx": 0,
        "w3_151_copy_ds_valid": descriptors, "w3_151_copy_es_valid": descriptors,
        "w3_151_copy_source_bounds_valid": bounds,
        "w3_151_copy_destination_bounds_valid": bounds,
        "w3_151_copy_sample_valid": True, "w3_151_copy_sample_bytes": sample_bytes,
        "w3_151_copy_sample_hex": "00" * sample_bytes,
    }
    return [branch_row, pre] + ([post_row] if post else [])


class ScreenCopyAuditTests(unittest.TestCase):
    def test_completed_copy_is_original_observed_but_not_frame_claim(self):
        result = extract_copy(rows())
        self.assertEqual(result["classification"], "ORIGINAL_OBSERVED_COPY_COMPLETED")
        self.assertTrue(result["checks"]["register_progress_matches_count"])
        self.assertEqual(result["post"]["sample_bytes"], 16)

    def test_missing_post_checkpoint_is_inconclusive(self):
        self.assertEqual(extract_copy(rows(post=False))["classification"], "INCONCLUSIVE")

    def test_invalid_descriptor_or_bounds_is_inconclusive(self):
        self.assertEqual(extract_copy(rows(descriptors=False))["classification"], "INCONCLUSIVE")
        self.assertEqual(extract_copy(rows(bounds=False))["classification"], "INCONCLUSIVE")

    def test_wrong_order_is_inconclusive(self):
        data = rows()
        data[0]["sequence"] = 4
        self.assertEqual(extract_copy(data)["classification"], "INCONCLUSIVE")

    def test_sample_over_cap_is_inconclusive(self):
        self.assertEqual(extract_copy(rows(sample_bytes=17))["classification"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
