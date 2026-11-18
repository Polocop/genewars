import unittest

from tools.w3_077_int21_caller_capture import correlate_ah43_events, validated_return_link


class Int21CallerCaptureTests(unittest.TestCase):
    def test_uses_flat_return_eip_and_correlates_through_wrapper_event(self):
        events = [
            {"sequence": 1, "event": "target_code_anchor", "anchor": "MAIN_ENTRY",
             "byte_signature_matches": True, "candidate_rebase": 0x200000,
             "cs_descriptor_valid": True, "cs_base": 0},
            {"sequence": 2, "event": "target_runtime_checkpoint", "checkpoint": "MAIN_ENTRY_CHECKPOINT",
             "link_va": 0x93F30, "eip": 0x293F30, "linear": 0x293F30},
            {"sequence": 10, "event": "original_cpu_int21_ah43_entry", "psp": 7,
             "cs_base": 0, "old_eip": 0x2AF93C, "linear": 0x2AF93C,
             "main_code_rebase": 0x200000, "caller_link_va": 0xAF93C,
             "mapping_valid": True},
            {"sequence": 11, "event": "original_cpu_int21_ah43_entry", "psp": 7,
             "cs_base": 0x22CC0, "old_eip": 0x10B7, "linear": 0x23D97,
             "main_code_rebase": 0x200000, "caller_link_va": None,
             "mapping_valid": False},
            {"sequence": 12, "event": "original_int21_ah43", "process_psp": 7,
             "requested_path": r"C:\GENEWARS\sound.ini", "out_ax": 0x20,
             "out_cx": 0x20, "cf": False},
        ]
        self.assertEqual(validated_return_link(events[2], 0x200000), 0xAF93C)
        result = correlate_ah43_events(events, expected_rebase=0x200000,
                                       w1_frontier_link=0xAF93A)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["return_link_va"], "0xaf93c")
        self.assertEqual(result[0]["int_instruction_link_va_candidate"], "0xaf93a")
        self.assertTrue(result[0]["matches_w1_frontier"])
        self.assertTrue(result[0]["mapping_valid"])

    def test_rejects_unverified_or_inconsistent_mapping_and_callback_context(self):
        event = {"cs_base": 0, "old_eip": 0x2AF93A, "linear": 0x2AF93A,
                 "main_code_rebase": 0x200000, "caller_link_va": 0xAF93A,
                 "mapping_valid": False}
        self.assertIsNone(validated_return_link(event))
        event["mapping_valid"] = True
        event["caller_link_va"] = 0x004C
        self.assertIsNone(validated_return_link(event))

    def test_no_callback_means_no_dynamic_correlation(self):
        events = [{"sequence": 1, "event": "original_cpu_int21_ah43_entry", "psp": 4,
                   "cs_base": 0, "old_eip": 10, "linear": 10,
                   "main_code_rebase": 1, "caller_link_va": 9, "mapping_valid": True}]
        self.assertEqual(correlate_ah43_events(events), [])


if __name__ == "__main__":
    unittest.main()
