import unittest

from tools.w3_242_bx1_reconciliation import analyze


class W3242Bx1ReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = analyze()

    def test_link_mapping_and_request_state_match(self):
        comparison = self.result["comparison"]
        self.assertTrue(comparison["all_compared_fields_equal"])
        self.assertEqual(comparison["fields"]["int_instruction_link_va"]["w3_236"], 0xC8973)
        self.assertEqual(comparison["fields"]["ebx"]["w3_236"], 1)

    def test_each_run_has_its_own_paired_response(self):
        pairs = self.result["same_run_response_contracts"]
        self.assertEqual([pair["source"] for pair in pairs], ["W3-091", "W3-236"])
        self.assertEqual([pair["setup_dos_api_ordinal"] for pair in pairs], [24, 24])
        self.assertEqual([pair["response"]["ax"] for pair in pairs], ["0x80d3", "0x80d3"])
        self.assertEqual(pairs[1]["pre_dispatch_sequence"], 104)
        self.assertEqual(pairs[1]["callback_sequence"], 107)
        self.assertFalse(self.result["comparison"]["same_run"])
        self.assertFalse(self.result["comparison"]["shared_invocation_identity"])

    def test_helper_caller_not_inferred_from_other_invocation(self):
        site = self.result["site_and_caller"]
        self.assertEqual(site["containing_helper"], "isatty_")
        self.assertEqual(site["w3_241_first_eax5_helper_caller"], "sopen_")
        self.assertEqual(site["bx1_helper_caller"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
