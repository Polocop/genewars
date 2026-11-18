import unittest
import hashlib
import json
from pathlib import Path

from tools.w3_093_ds_edx_sample import correlated_sample, sample_range_is_safe


class SafeDsEdxSampleTests(unittest.TestCase):
    def test_valid_bounded_descriptor_range(self):
        self.assertTrue(sample_range_is_safe(
            selector=0x168, descriptor_valid=True, present=True, readable_data=True,
            base=0, limit=0xFFFFFFFF, offset=0x2E4822, length=32,
        ))

    def test_rejects_invalid_or_nonreadable_descriptor(self):
        for kwargs in (
            dict(descriptor_valid=False),
            dict(present=False),
            dict(readable_data=False),
            dict(selector=0),
        ):
            values = dict(
                selector=0x168, descriptor_valid=True, present=True, readable_data=True,
                base=0, limit=0xFFFFFFFF, offset=0x2E4822, length=32,
            )
            values.update(kwargs)
            self.assertFalse(sample_range_is_safe(**values))

    def test_rejects_limit_overflow_and_wrapping_linear_address(self):
        common = dict(selector=0x168, descriptor_valid=True, present=True, readable_data=True)
        self.assertFalse(sample_range_is_safe(**common, base=0, limit=0x2E4822, offset=0x2E4822, length=32))
        self.assertFalse(sample_range_is_safe(**common, base=0xFFFFFFF0, limit=0xFFFFFFFF, offset=0, length=32))

    def test_caps_sample_size_and_rejects_nonpositive_size(self):
        common = dict(selector=0x168, descriptor_valid=True, present=True, readable_data=True,
                      base=0, limit=0xFFFFFFFF, offset=0x2E4822)
        self.assertFalse(sample_range_is_safe(**common, length=33))
        self.assertFalse(sample_range_is_safe(**common, length=0))

    def test_pairs_only_mapped_verified_caller_and_same_callback_ordinal(self):
        good = {
            "mapping_valid": True, "int21_bytes_verified": True,
            "int_instruction_link_va": 821619, "sample_status": "sampled",
            "process_psp": 7811, "setup_dos_api_callback_ordinal": 24,
        }
        callback = {
            "process_psp": 7811, "ordinal": 24, "operation": "INT21_AH44",
            "in_ax": 0x4400, "in_bx": 1,
        }
        self.assertIsNotNone(correlated_sample([good], [callback]))
        self.assertIsNone(correlated_sample([{**good, "mapping_valid": False}], [callback]))
        self.assertIsNone(correlated_sample([{**good, "int21_bytes_verified": False}], [callback]))
        self.assertIsNone(correlated_sample([good], [{**callback, "ordinal": 23}]))
        self.assertIsNone(correlated_sample([good], [{**callback, "in_bx": 2}]))

    def test_guarded_original_sample_and_provenance(self):
        root = Path(__file__).resolve().parents[1]
        evidence_path = root / "evidence/w3_093_ds_edx_sample.json"
        result = json.loads(evidence_path.read_text(encoding="utf-8"))
        for relative, expected in result["source_evidence_hashes"].items():
            actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
            self.assertEqual(actual, expected)

        contract = result["contract"]
        self.assertEqual(contract["caller"]["link_va"], "0xc8973")
        self.assertTrue(contract["caller"]["int21_bytes_verified"])
        self.assertEqual(contract["data_segment"]["selector"], "0x168")
        self.assertTrue(contract["data_segment"]["descriptor_valid"])
        self.assertTrue(contract["data_segment"]["present"])
        self.assertTrue(contract["data_segment"]["readable_expand_up"])
        self.assertEqual(contract["sample"]["length_bytes"], 32)
        self.assertEqual(contract["sample"]["dword_at_plus_0x10"], "0x1")
        self.assertTrue(contract["comparison"]["sampled_original_field_matches_native"])
        self.assertIsNone(contract["comparison"]["same_dynamic_stream_object"])
        self.assertEqual(contract["comparison"]["launch_and_seed_equivalence"],
                         "not established; W3-093 captures no effective child PSP tail or matched CPU/memory seed")
        self.assertEqual(contract["callback"]["ordinal"], 24)
        self.assertEqual(contract["callback"]["output_ax"], "0x80d3")
        self.assertFalse(contract["callback"]["cf"])
        self.assertEqual(result["scope"]["sample_cap_bytes"], 32)
        self.assertEqual(result["scope"]["sample_event_cap"], 1)
        self.assertEqual(result["guard_summary"]["cause"], "TIMEOUT")


if __name__ == "__main__":
    unittest.main()
