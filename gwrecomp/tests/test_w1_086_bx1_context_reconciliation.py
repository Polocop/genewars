import unittest

from tools.verify_w1_086_bx1_context_reconciliation import build_reconciliation, validate_evidence


class W1Bx1ContextReconciliationTests(unittest.TestCase):
    def test_source_events_are_distinguished_and_unpaired(self):
        evidence = build_reconciliation()
        validate_evidence(evidence)
        original = evidence["original_observations"]
        native = evidence["native_observations"]
        self.assertEqual(original["chktty_isatty_call"]["link_va"], "0xBA4E4")
        self.assertEqual(original["chktty_isatty_call"]["eax"], "0x5")
        self.assertEqual(original["bx1_request"]["int_link_va"], "0xC8973")
        self.assertEqual(original["bx1_request"]["ebx"], "0x1")
        self.assertEqual(original["bx1_request"]["caller"], "UNKNOWN")
        self.assertEqual(native["caller"], "__chktty_ 0xBA4D6 -> isatty_ callsite 0xBA4E4")
        self.assertEqual(native["eax_at_helper_entry"], "0x1")

    def test_matching_static_address_does_not_claim_dynamic_identity(self):
        evidence = build_reconciliation()
        self.assertEqual(evidence["original_observations"]["bx1_request"]["int_link_va"], "0xC8973")
        self.assertEqual(evidence["native_observations"]["frontier_link_va"], "0xC8973")
        self.assertFalse(evidence["classification"]["same_dynamic_invocation_established"])
        self.assertFalse(evidence["classification"]["first_causal_divergence_proven"])

    def test_validator_rejects_false_pairing(self):
        evidence = build_reconciliation()
        evidence["classification"]["same_dynamic_invocation_established"] = True
        with self.assertRaises(AssertionError):
            validate_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
