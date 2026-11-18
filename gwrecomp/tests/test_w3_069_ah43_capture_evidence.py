"""Synthetic schema and prior-frontier checks for W3-069; never launches DOSBox."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class W3Ah43EvidenceTest(unittest.TestCase):
    def test_prior_capture_does_not_prove_ah43_absence(self):
        prior = json.loads((ROOT / "evidence/w3_setup_original_contract_20261008.json").read_text(encoding="utf-8"))
        w2 = json.loads((ROOT / "evidence/native_dos_ah43_frontier_work2.json").read_text(encoding="utf-8"))
        self.assertEqual(len(prior["file_operations_observed_after_setup_entry"]), 128)
        self.assertIn("cap was reached at 128", prior["limitations"][0])
        self.assertEqual(prior["file_operations_observed_after_setup_entry"][-1]["operation"], "INT21_AH3F")
        self.assertEqual(w2["w3_original_ah43_event_count"], 0)
        self.assertFalse(w2["original_equivalence_claimed"])

    def test_captured_events_are_bounded_and_report_call_boundary(self):
        path = ROOT / "evidence/w3_069_original_ah43_sound_ini.json"
        if not path.exists():
            self.skipTest("guarded replay has not produced W3-069 evidence")
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["schema"], "w3-069-original-ah43/v1")
        self.assertLessEqual(evidence["trace"]["bytes"], 1024 * 1024)
        self.assertLessEqual(evidence["ah43_event_count"], 8)
        self.assertEqual(evidence["ah43_event_count"], len(evidence["ah43_events"]))
        self.assertEqual(evidence["classification"], "ORIGINAL_OBSERVED")
        target = [event for event in evidence["ah43_events"]
                  if event.get("requested_path", "").lower() == r"c:\genewars\sound.ini"]
        self.assertEqual(len(target), 3)
        for event in evidence["ah43_events"]:
            self.assertEqual(event["event"], "original_int21_ah43")
            self.assertIn("in_ax", event)
            self.assertIn("in_ds", event)
            self.assertIn("in_dx", event)
            self.assertIn("requested_path", event)
            self.assertIn("out_ax", event)
            self.assertIn("cf", event)
            self.assertIn("result", event)
            self.assertIn("attributes", event)
            self.assertIsNone(event["caller_link_va"])
        for event in target:
            self.assertEqual(event["in_ax"], 0x4300)
            self.assertEqual(event["subfunction"], 0)
            self.assertEqual(event["out_ax"], 0x20)
            self.assertEqual(event["out_cx"], 0x20)
            self.assertFalse(event["cf"])
            self.assertTrue(event["result"])
            self.assertEqual(event["attributes"], 0x20)
            self.assertEqual(event["default_drive"], "C")
            self.assertEqual(event["cwd"].upper(), "GENEWARS")


if __name__ == "__main__":
    unittest.main()
