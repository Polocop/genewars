import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.w3_245_refresh_current_gate import ARCHIVE, CURRENT, REFRESH, ROOT
from coordination import taskq


class W3245CurrentGateProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = json.loads(CURRENT.read_text(encoding="utf-8-sig"))
        cls.refresh = json.loads(REFRESH.read_text(encoding="utf-8-sig"))

    def test_historical_pointer_is_preserved_and_restorable(self):
        saved = ARCHIVE.read_bytes()
        digest = hashlib.sha256(saved).hexdigest()
        self.assertEqual(digest, self.refresh["preserved_archive_sha256"])
        with tempfile.TemporaryDirectory() as tmp:
            restored = Path(tmp) / "restored.json"
            restored.write_bytes(saved)
            self.assertEqual(hashlib.sha256(restored.read_bytes()).hexdigest(), digest)

    def test_current_pointer_matches_current_runtime_and_replay(self):
        m = taskq.post_mscdex_startup_metrics(self.current, self.current["target_sha256"])
        self.assertTrue(m["valid"], m["reason"])
        self.assertEqual(m["stop_eip"], "0x001afc33")
        self.assertEqual(m["process_exit_code"], 0)
        self.assertEqual(self.current["task"], "W3-244")
        self.assertFalse(self.current["menu_reached"])

    def test_generated_project_state_uses_current_no_cd_control(self):
        state = (ROOT / "PROJECT_STATE.md").read_text(encoding="utf-8-sig")
        self.assertIn("No-CD process-exit control:", state)
        self.assertIn("'valid': True", state)
        self.assertIn("'runtime_matches': True", state)
        self.assertIn("'stop_eip': '0x001afc33'", state)
        self.assertIn("menu_reached': False", state)
        self.assertIn("Replay the exact empty-config -k fixture with the measured original CD media mounted", state)
        state_sha = hashlib.sha256((ROOT / "PROJECT_STATE.md").read_bytes()).hexdigest()
        self.assertEqual(state_sha, self.refresh["generated_project_state_sha256"])
        self.assertIn("Replay the exact empty-config -k fixture", self.refresh["next_gate"])


if __name__ == "__main__":
    unittest.main()
