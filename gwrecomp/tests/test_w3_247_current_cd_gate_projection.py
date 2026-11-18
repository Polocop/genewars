import hashlib
import json
import unittest
from pathlib import Path

from coordination import taskq

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "evidence/w3_246_current_runtime_cd_present_replay.json"
HISTORIC = ROOT / "evidence/cd_present_gate_work3.json"
EXPECTED_HISTORIC_SHA = "0556e057c30a6a6a067e14518cf6472278cc58098d4cb5d79c17f78167acd721"


class CurrentCdGateProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(SUMMARY.read_text(encoding="utf-8"))
        cls.target_sha = cls.evidence["target"]["sha256"]

    def project(self, evidence=None, work1=True, no_cd=True):
        return taskq.current_cd_present_replay_metrics(
            evidence if evidence is not None else self.evidence,
            self.target_sha,
            work1,
            no_cd,
        )

    def test_current_runtime_original_observation_validates(self):
        result = self.project()
        self.assertTrue(result["valid"], result["reason"])
        self.assertEqual(result["source_task"], "W3-246")
        self.assertEqual(result["evidence_level"], "ORIGINAL_OBSERVED")
        self.assertFalse(result["native_differential_established"])
        self.assertEqual(result["stop_eip"], "0x00194b5a")
        self.assertFalse(result["menu_reached"])
        self.assertFalse(result["framebuffer_reached"])

    def test_runtime_hash_mismatch_fails_closed(self):
        altered = json.loads(json.dumps(self.evidence))
        altered["runtime"]["files"][0]["sha256"] = "0" * 64
        self.assertFalse(self.project(altered)["valid"])

    def test_guard_and_control_requirements_fail_closed(self):
        altered = json.loads(json.dumps(self.evidence))
        altered["guard"]["exit_reason"] = "TIMEOUT"
        self.assertFalse(self.project(altered)["valid"])
        self.assertFalse(self.project(no_cd=False)["valid"])

    def test_historical_w3_046_capture_is_unchanged(self):
        self.assertEqual(hashlib.sha256(HISTORIC.read_bytes()).hexdigest(), EXPECTED_HISTORIC_SHA)

    def test_generated_state_uses_current_original_gate_without_gameplay_claims(self):
        state = (ROOT / "PROJECT_STATE.md").read_text(encoding="utf-8-sig")
        self.assertIn("'source_task': 'W3-246'", state)
        self.assertIn("'runtime_matches': True", state)
        self.assertIn("'menu_reached': False", state)
        self.assertIn("'framebuffer_reached': False", state)
        self.assertIn("'gameplay_reached': False", state)
        self.assertIn("native differential not established", state)


if __name__ == "__main__":
    unittest.main()
