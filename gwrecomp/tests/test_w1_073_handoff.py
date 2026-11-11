"""Confirm the structured W1-073 handoff persists in Autopilot."""
import json
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "w1_073_work2_handoff.json"


class Work2HandoffPersistence(unittest.TestCase):
    def test_handoff_is_open_for_work2(self):
        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run([str(ROOT / "coordination" / "autopilot.cmd"), "handoffs",
                                 "--status", "ALL"],
                                cwd=ROOT, text=True, capture_output=True, check=True, env=env)
        handoffs = json.loads(result.stdout)
        match = next((item for item in handoffs if item.get("id") == evidence["handoff_id"]), None)
        self.assertIsNotNone(match)
        self.assertEqual(match["task_id"], "W1-073")
        self.assertEqual(match["to_role"], "WORK2")
        # The recipient may acknowledge the handoff before this regression runs.
        self.assertIn(match["status"], {"OPEN", "ACKNOWLEDGED"})
        if match["status"] == "ACKNOWLEDGED":
            self.assertEqual(match["acknowledged_by"], "WORK2")
        self.assertIn("reports\\coordination\\native_dpmi_ax6300_provider_w1_071.md",
                      match["payload"]["evidence"])


if __name__ == "__main__":
    unittest.main()
