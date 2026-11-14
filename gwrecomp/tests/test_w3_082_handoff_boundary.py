import hashlib
import json
import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CallerHandoffBoundaryTests(unittest.TestCase):
    def test_evidence_is_hash_bound_and_does_not_claim_bx1(self):
        path = ROOT / "evidence/w3_082_ah44_handoff_boundary.json"
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["schema"], "w3-082-ah44-handoff-boundary/v1")
        self.assertEqual(evidence["original"]["caller_link_va"], "0x000BA4D6")
        self.assertEqual(evidence["original"]["stream_handle_10"], 5)
        self.assertEqual(evidence["native"]["stream_handle"], 1)
        self.assertEqual(evidence["original"]["bx1_calls"], 0)
        self.assertFalse(evidence["w2_086_unblocked"])
        for item in evidence["sources"]:
            source = ROOT / item["path"]
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                             item["sha256"])

    def test_task_dependencies_remain_unresolved(self):
        evidence = json.loads((ROOT / "evidence/w3_082_ah44_handoff_boundary.json")
                              .read_text(encoding="utf-8"))
        db = sqlite3.connect(ROOT / "coordination/tasks.sqlite3")
        try:
            rows = {r[0]: {"status": r[1], "deps": json.loads(r[2])}
                    for r in db.execute(
                        "SELECT id,status,deps FROM tasks WHERE id IN ('W2-086','W3-060','W1-043')")}
        finally:
            db.close()
        self.assertIn("W3-060", rows["W2-086"]["deps"])
        self.assertIn("W1-043", rows["W2-086"]["deps"])
        self.assertNotEqual(rows["W3-060"]["status"], "DONE")
        self.assertNotEqual(rows["W1-043"]["status"], "DONE")
        self.assertEqual(evidence["queue_at_capture"]["W2-086"]["deps"],
                         rows["W2-086"]["deps"])


if __name__ == "__main__":
    unittest.main()
