from __future__ import annotations

import json
import unittest

from tools.w3_258_oracle_guard_preflight import OUT, REVISION, validate


class OracleGuardPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not OUT.is_file():
            raise AssertionError("run tools.w3_258_oracle_guard_preflight before this test")
        cls.data = json.loads(OUT.read_text(encoding="utf-8"))

    def test_verified_pinned_binary_sandbox_and_config(self) -> None:
        self.assertEqual(self.data["build"]["revision"], REVISION)
        self.assertTrue(self.data["build"]["binary_matches_recorded_hash"])
        self.assertTrue(self.data["sandbox"]["verified"])
        self.assertEqual(self.data["sandbox"]["label"], "GWORACLE")
        self.assertTrue(self.data["functional_config"]["matches_w3_067_functional_evidence"])
        self.assertEqual(validate(self.data), [])

    def test_rejects_bad_sandbox(self) -> None:
        data = json.loads(json.dumps(self.data))
        data["sandbox"]["verified"] = False
        self.assertIn("GWORACLE sandbox verification failed", validate(data))

    def test_rejects_hash_or_source_drift(self) -> None:
        data = json.loads(json.dumps(self.data))
        data["build"]["binary_matches_recorded_hash"] = False
        data["build"]["head_matches_pinned"] = False
        errors = validate(data)
        self.assertIn("instrumented binary hash mismatch", errors)
        self.assertIn("pinned source revision mismatch", errors)

    def test_preflight_does_not_authorize_or_run_replay(self) -> None:
        self.assertFalse(self.data["replay_disposition"]["replay_authorized_by_this_preflight"])
        self.assertTrue(all(value is False for value in self.data["safety"].values()))
        self.assertFalse(self.data["prior_bx1_capture"]["caller_stack_capture_present_in_bx1_cpu_event"])


if __name__ == "__main__":
    unittest.main()
