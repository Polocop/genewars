import json
import tempfile
import unittest
from pathlib import Path

from tools.w3_076_ah43_caller import audit_ah43_trace


class Ah43CallerAuditTests(unittest.TestCase):
    def test_callback_eip_is_not_promoted_to_game_caller(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            trace.write_text(json.dumps({
                "event": "original_int21_ah43", "sequence": 9, "ordinal": 1,
                "process_psp": 7811, "requested_path": r"C:\GENEWARS\sound.ini",
                "callback_cs": 0xF000, "callback_eip": 0x13E5,
                "caller_link_va": None,
            }) + "\n", encoding="utf-8")
            result = audit_ah43_trace(trace)
            self.assertEqual(result["sound_ini_count"], 1)
            self.assertFalse(result["caller_recovered"])
            self.assertEqual(result["sound_ini_events"][0]["callback_cs"], 0xF000)
            self.assertIsNone(result["sound_ini_events"][0]["caller_link_va"])

    def test_ignores_other_paths_and_non_ah43_events(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            trace.write_text("\n".join([
                json.dumps({"event": "original_int21_ah43", "requested_path": r"D:\INSTALL\GW.ICO"}),
                json.dumps({"event": "original_int21_ah44", "requested_path": r"C:\GENEWARS\sound.ini"}),
            ]) + "\n", encoding="utf-8")
            result = audit_ah43_trace(trace)
            self.assertEqual(result["ah43_count"], 1)
            self.assertEqual(result["sound_ini_count"], 0)


if __name__ == "__main__":
    unittest.main()
