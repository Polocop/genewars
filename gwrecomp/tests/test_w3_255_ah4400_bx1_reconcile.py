import unittest

from tools.w3_255_ah4400_bx1_reconcile import pair_bx1


class W3255Ah4400Bx1ReconcileTests(unittest.TestCase):
    def test_pairs_only_same_psp_ordinal_and_bx1(self):
        events = [
            {"sequence": 1, "event": "original_cpu_int21_ah44_bx1_entry", "mapping_valid": True,
             "w3_093_sample_target": True, "process_psp": 7, "setup_dos_api_callback_ordinal": 24,
             "int_instruction_link_va": 0xC8973, "return_link_va": 0xC8975},
            {"sequence": 2, "event": "setup_dos_api", "operation": "INT21_AH44", "process_psp": 8,
             "ordinal": 24, "in_ax": 0x4400, "in_bx": 1, "out_ax": 0x80D3, "out_dx": 0x80D3,
             "out_eflags": 0x246},
            {"sequence": 3, "event": "setup_dos_api", "operation": "INT21_AH44", "process_psp": 7,
             "ordinal": 24, "in_ax": 0x4400, "in_bx": 1, "out_ax": 0x80D3, "out_dx": 0x80D3,
             "out_eflags": 0x246},
            {"sequence": 4, "event": "w3_095_original_psp_tail", "process_psp": 7,
             "callsite_link_va": "0xc8973", "tail_length": 9, "tail_bytes_hex": "202d6b203338393238"},
            {"sequence": 5, "event": "original_cpu_int21_ah44_bx1_entry", "mapping_valid": False,
             "process_psp": 7},
        ]
        paired = pair_bx1(events)
        self.assertEqual(paired["valid_protected_entries"], 1)
        self.assertTrue(paired["pairs"][0]["complete"])
        self.assertFalse(paired["pairs"][0]["result_cf"])
        self.assertEqual(len(paired["unmapped_entries"]), 1)

    def test_missing_matching_ordinal_stays_unpaired(self):
        events = [{"event": "original_cpu_int21_ah44_bx1_entry", "mapping_valid": True,
                   "w3_093_sample_target": True, "process_psp": 7,
                   "setup_dos_api_callback_ordinal": 4}]
        result = pair_bx1(events)
        self.assertEqual(result["valid_protected_entries"], 1)
        self.assertIsNone(result["pairs"][0]["dos_result"])

    def test_cf_uses_output_eflags_low_bit(self):
        events = [
            {"event": "original_cpu_int21_ah44_bx1_entry", "mapping_valid": True,
             "w3_093_sample_target": True, "process_psp": 1, "setup_dos_api_callback_ordinal": 2},
            {"event": "setup_dos_api", "operation": "INT21_AH44", "process_psp": 1,
             "ordinal": 2, "in_ax": 0x4400, "in_bx": 1, "out_eflags": 0x247},
        ]
        self.assertTrue(pair_bx1(events)["pairs"][0]["result_cf"])


if __name__ == "__main__":
    unittest.main()
