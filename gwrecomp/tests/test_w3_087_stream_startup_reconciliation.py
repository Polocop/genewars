import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class StreamStartupReconciliationTests(unittest.TestCase):
    def test_hash_bound_original_native_boundary(self):
        evidence_path = ROOT / "evidence/w3_087_stream_startup_reconciliation.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

        for rel, expected in evidence["source_evidence_sha256"].items():
            actual = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, rel)

        self.assertEqual(evidence["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(evidence["original"]["effective_child_argv"], ["C:\\GENEWARS\\GW.EXE", "-k", "38928"])
        self.assertEqual(evidence["original"]["psp_command_tail"], " -k 38928")
        self.assertEqual(evidence["native"]["command_tail"], " -k 38928")
        self.assertEqual(evidence["original"]["callsite_link_va"], "0xBA4E4")
        self.assertEqual(int(evidence["native"]["callsite_link_va"], 16), 0xBA4E4)
        self.assertTrue(evidence["comparison"]["same_static_callsite"])
        self.assertTrue(evidence["comparison"]["same_callee"])
        self.assertTrue(evidence["comparison"]["effective_psp_tail_matches"])
        self.assertEqual(evidence["original"]["stream_entry"], 5)
        self.assertEqual(evidence["native"]["stream_entry"], 1)
        self.assertEqual(evidence["original"]["open_lineage"]["raw_mode"], 1)
        self.assertEqual(evidence["original"]["open_lineage"]["guest_path"], "C:\\ADDRESS.TXT")
        self.assertFalse(evidence["comparison"]["same_invocation_proven"])
        self.assertFalse(evidence["comparison"]["whole_run_equivalence_proven"])
        self.assertFalse(evidence["comparison"]["original_bx1_response_observed"])
        self.assertFalse(evidence["comparison"]["w2_086_unblocked"])


if __name__ == "__main__":
    unittest.main()
