import json
import unittest
from pathlib import Path

from coordination.taskq import cd_present_gate_metrics, native_dos_ah49_frontier_metrics

ROOT = Path(__file__).resolve().parents[1]


class ProjectStateNativeFrontierTest(unittest.TestCase):
    def test_native_frontier_is_separate_and_hash_pinned(self):
        native = json.loads((ROOT / "evidence" / "native_dos_ah49_frontier_work2.json").read_text())
        projected = native_dos_ah49_frontier_metrics(native, native["target_sha256"])
        self.assertTrue(projected["valid"])
        self.assertEqual(projected["ah49"]["eip"], "0x000c3d46")
        self.assertEqual(projected["ah49"]["native_es"], "0x0014")
        self.assertEqual(projected["source_evidence"], "evidence/native_dos_ah49_frontier_work2.json")
        self.assertFalse(projected["menu_reached"])
        self.assertFalse(projected["native_differential_established"])

    def test_generated_state_labels_original_and_native_separately(self):
        state = (ROOT / "PROJECT_STATE.md").read_text(encoding="utf-8")
        self.assertIn("Original-byte CD-present gate:", state)
        self.assertIn("Native recompiled AH=49 frontier:", state)
        self.assertIn("native_es': '0x0014'", state)
        self.assertIn("original-byte AH=49 observation", state)
        self.assertIn("ES=0x004c", state)
        self.assertIn("NULL", state)
        self.assertIn("no-CD control exits cleanly with code 0", state)
        self.assertIn("MENU not reached", state)

    def test_original_frontier_comes_from_recorded_trace(self):
        evidence = json.loads((ROOT / "evidence" / "cd_present_gate_work3.json").read_text())
        projected = cd_present_gate_metrics(evidence, evidence["target_sha256"], None, None)
        # The fixture/corroboration gate is intentionally false without W1 data;
        # this assertion only checks the actual trace-derived AH=49 sample.
        self.assertEqual(projected["original_ah49_frontier"]["runtime_eip"], "0x001c3d46")
        self.assertEqual(projected["original_ah49_frontier"]["es"], "0x004c")


if __name__ == "__main__":
    unittest.main()
