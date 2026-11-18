import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/w3_092_ax4400_context_reconciliation.json"

class Ax4400ContextReconciliationTests(unittest.TestCase):
    def test_hashes_and_contract_boundaries(self):
        result = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        for path, item in result["sources"].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), item["sha256"])
        c = result["measured_comparison"]
        self.assertTrue(c["target_hash_equal"])
        self.assertTrue(c["same_link_site"])
        self.assertTrue(c["same_request_ax_bx"])
        self.assertEqual(c["original_edx_esi"], "0x2e4822")
        self.assertEqual(c["native_edx_esi"], "0x0010a822")
        self.assertFalse(c["original_w3_091_edx_dereferenced"])
        self.assertFalse(c["same_dynamic_invocation"])
        self.assertIsNone(c["same_stream_object"])
        self.assertFalse(c["whole_run_or_seed_equivalence"])
        self.assertEqual(c["queue_statuses_preserved"]["W1-043"], "BLOCKED")
        self.assertEqual(c["queue_statuses_preserved"]["W3-060"], "BLOCKED")
        self.assertIn("handle 1", c["valid_use_for_work2"])

if __name__ == "__main__":
    unittest.main()
