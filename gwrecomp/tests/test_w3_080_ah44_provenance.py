import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AH44ProvenanceReconciliationTests(unittest.TestCase):
    def test_historical_original_bx1_is_not_promoted_to_current_contract(self):
        with (ROOT / "evidence/w3_080_ah44_provenance_reconciliation.json").open(encoding="utf-8") as f:
            evidence = json.load(f)
        old = evidence["historical_original_bx1"]
        self.assertEqual(old["eip_int"], "0x001C8973")
        self.assertEqual(old["registers_before"]["ebx"], "0x00000001")
        self.assertEqual(old["registers_after"]["edx"], "0x00000082")
        self.assertFalse(old["cf"])
        self.assertIsNone(old["command_tail"])
        self.assertIsNone(old["cue_sha256"])
        self.assertFalse(evidence["claims"]["W2_086_unblocked"])

    def test_fresh_original_nonhit_and_native_trap_remain_separate(self):
        with (ROOT / "evidence/w3_080_ah44_provenance_reconciliation.json").open(encoding="utf-8") as f:
            evidence = json.load(f)
        fresh = evidence["fresh_original_w3_079"]
        native = evidence["current_native_w1_051"]
        self.assertEqual(fresh["bx1_call_count"], 0)
        self.assertEqual(fresh["bx1_return_pairs"], 0)
        self.assertIn(2, fresh["generic_ah44_bx_values"])
        self.assertIn(5, fresh["generic_ah44_bx_values"])
        self.assertEqual(native["frontier"]["request_registers"]["ebx"], "00000001")
        self.assertIn("trap", native["status"])
        self.assertFalse(evidence["claims"]["current_original_bx1_reproduced"])


if __name__ == "__main__":
    unittest.main()
