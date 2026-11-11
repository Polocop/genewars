import hashlib
import json
import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_json(relative_path):
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


class Ah4300CallerReconciliationTests(unittest.TestCase):
    def test_original_caller_and_native_response_are_separately_supported(self):
        original = load_json("evidence/w3_077_int21_caller_capture.json")
        native = load_json("evidence/native_sound_ini_replay_w1_051.json")
        evidence = load_json("evidence/w2_109_ah4300_caller_reconciliation.json")

        self.assertEqual(original["classification"], "ORIGINAL_OBSERVED")
        self.assertEqual(original["run_id"], evidence["original"]["run_id"])
        self.assertEqual(original["limitations"], evidence["original"]["limitation"])
        self.assertEqual(len(original["sound_ini_callers"]), 3)
        for caller in original["sound_ini_callers"]:
            self.assertEqual(caller["return_link_va"], "0xaf93c")
            self.assertEqual(caller["int_instruction_link_va_candidate"], "0xaf93a")
            self.assertTrue(caller["matches_w1_frontier"])

        native_record = native["sound_ini_continuation"]
        self.assertEqual(native_record["original_caller_link_va"], "UNKNOWN")
        self.assertEqual(native_record["original_callsite_candidate_link_va"], "0x000AF93A")
        self.assertTrue(native_record["original_callsite_match"])
        self.assertFalse(native_record["dynamic_invocation_equivalence"])
        self.assertFalse(native_record["original_equivalence_claimed"])
        request = native_record["fresh_native_request"]
        self.assertEqual(request["eip"], "000af93a")
        self.assertEqual(request["path"].lower(), r"c:\genewars\sound.ini")
        self.assertEqual(int(request["response_eax"], 16), 0x20)
        self.assertEqual(int(request["response_ecx"], 16) & 0xFFFF, 0x20)
        self.assertEqual(request["cf_in"], "0")
        self.assertEqual(request["cf_out"], "0")
        self.assertEqual(request["handled"], "1")

        frontier = native_record["next_frontier"]
        self.assertEqual(frontier["trap_va"], "000c8973")
        self.assertEqual(frontier["eax"], "00004400")
        self.assertEqual(frontier["ebx"], "00000001")
        self.assertEqual(native_record["next_frontier_cpu"]["flag_cf"], "0")
        self.assertEqual(native_record["runtime_fingerprint"]["matches_w2_107"], True)

    def test_evidence_hashes_and_dependency_classification_are_consistent(self):
        evidence = load_json("evidence/w2_109_ah4300_caller_reconciliation.json")
        for record in evidence["source_evidence"].values():
            path = ROOT / record["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), record["sha256"])

        queue = evidence["frontier_classification"]
        self.assertEqual(queue["W2-086"]["status"], "READY")
        self.assertEqual(queue["W2-086"]["dependencies"], {
            "W3-060": "BLOCKED", "W1-043": "BLOCKED"
        })
        self.assertFalse(queue["W2-086"]["claimable"])
        self.assertEqual(queue["W2-087"]["status"], "DONE")

        db = sqlite3.connect(f"file:{ROOT / 'coordination/tasks.sqlite3'}?mode=ro", uri=True)
        try:
            row = db.execute("SELECT status, deps FROM tasks WHERE id='W2-086'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "READY")
            self.assertEqual(json.loads(row[1]), ["W3-060", "W1-043"])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
