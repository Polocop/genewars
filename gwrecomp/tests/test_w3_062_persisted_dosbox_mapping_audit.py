import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = (
    "dosbox_w3_059_selector_contract_work3.json",
    "dosbox_debugger_video_frontier_followup_work3.json",
)


class PersistedDosboxMappingAuditTest(unittest.TestCase):
    def test_all_persisted_debugger_transcripts_have_no_target_link_va(self):
        evidence = json.loads((ROOT / "evidence" / "w3_062_persisted_dosbox_mapping_audit.json").read_text())
        self.assertFalse(evidence["live_main_mapping_resolved"])
        self.assertEqual(evidence["target_link_vas"], ["0x001C3CA9", "0x001C3D21"])
        self.assertEqual(evidence["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        for source in evidence["transcripts"]:
            path = ROOT / source["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), source["sha256"])
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            self.assertEqual(len(data["captures"]), source["capture_count"])
            transcript = "\n".join(x.get("command", "") + "\n" + x.get("response", "") for x in data["captures"]).lower()
            self.assertNotIn("001c3ca9", transcript)
            self.assertNotIn("001c3d21", transcript)

    def test_unassociated_004c_descriptor_remains_excluded(self):
        evidence = json.loads((ROOT / "evidence" / "w3_062_persisted_dosbox_mapping_audit.json").read_text())
        self.assertEqual(evidence["selector_004c_use"], "prohibited: no association with target AH=48 event")
        self.assertFalse(evidence["w3_059_unblocked"])


if __name__ == "__main__":
    unittest.main()
