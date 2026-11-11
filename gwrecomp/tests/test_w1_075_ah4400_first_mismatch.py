"""Synthetic/read-only regression for W1-075 evidence classification."""

import unittest
from pathlib import Path

from tools.verify_w1_075_ah4400_first_mismatch import ROOT, validate


class FirstAx4400MismatchTests(unittest.TestCase):
    def test_persisted_evidence_is_hash_bound_and_does_not_claim_causality(self):
        self.assertEqual(validate(ROOT / "evidence/w1_075_ah4400_first_mismatch.json"), [])

    def test_sequence_difference_is_at_original_ordinal_six(self):
        import json

        evidence = json.loads((ROOT / "evidence/w1_075_ah4400_first_mismatch.json").read_text(encoding="utf-8"))
        sequence = evidence["sequence_alignment"]
        self.assertEqual(sequence["original_bx_sequence"], [5, 5, 5, 5, 5, 2, 2, 2])
        self.assertEqual(sequence["native_bx_sequence"], [5] * 8)
        self.assertEqual(sequence["first_request_sequence_mismatch"]["ordinal_one_based"], 6)

    def test_original_address_seed_hash_is_not_invented(self):
        import json

        evidence = json.loads((ROOT / "evidence/w1_075_ah4400_first_mismatch.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["fixture"]["original_address_txt_initial_bytes_hash"], "UNKNOWN")

    def test_w2_086_is_ready_but_dependency_gated(self):
        import json

        evidence = json.loads((ROOT / "evidence/w1_075_ah4400_first_mismatch.json").read_text(encoding="utf-8"))
        gate = evidence["queue_gates"]["W2-086"]
        self.assertEqual(gate["status"], "READY")
        self.assertFalse(gate["claimable"])
        self.assertEqual(gate["dependencies"], ["W3-060", "W1-043"])


if __name__ == "__main__":
    unittest.main()
