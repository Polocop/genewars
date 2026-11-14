import unittest
from unittest.mock import patch

from tools.w3_284_smacker_dispatch_static import (
    decode_at,
    infer_second_gate,
    second_compare_paths_converge,
)


class SmackerDispatchStaticTests(unittest.TestCase):
    def test_zero_bl_infers_je_to_second_gate_without_claiming_observation(self):
        result = infer_second_gate(0)
        self.assertEqual(result["inferred_destination"], "0x000AE2F2")
        self.assertFalse(result["dynamically_observed"])
        self.assertEqual(result["evidence_level"], "STATIC_INFERENCE_FROM_ORIGINAL_OBSERVED_STATE")

    def test_nonzero_mask_infers_fallthrough(self):
        self.assertEqual(infer_second_gate(0x84)["inferred_destination"], "0x000AE2E8")

    def test_compare_paths_converge_at_callsite(self):
        self.assertTrue(second_compare_paths_converge())

    def test_decode_is_bounded_and_requires_contiguous_mapping(self):
        code = bytes.fromhex("85c9740375fe90")
        def mapping(va):
            return {
                "object": 1, "page_index_zero_based": 2, "file_offset": va - 0x1000,
                "object_base": 0, "object_size": 0x10000, "page_size": 0x1000,
                "page_number_one_based": 3, "page_flags": 0,
            }
        with patch("tools.w3_284_smacker_dispatch_static.map_le_link_va", side_effect=lambda _data, va: mapping(va)):
            _, raw, insns = decode_at(code, 0x1000, len(code))
        self.assertEqual(raw, code)
        self.assertEqual(insns[0]["mnemonic"], "test")
        self.assertLessEqual(len(raw), 96)
        bad_mapping = lambda _data, va: {**mapping(va), "file_offset": 100 if va != 0x1000 else 0}
        with patch("tools.w3_284_smacker_dispatch_static.map_le_link_va", side_effect=bad_mapping):
            with self.assertRaises(ValueError):
                decode_at(code, 0x1000, len(code))


if __name__ == "__main__":
    unittest.main()
