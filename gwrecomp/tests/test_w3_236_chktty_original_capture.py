import hashlib
import json
import unittest
from pathlib import Path

from tools.w3_236_chktty_capture import extract_capture


class ChkttyCaptureTests(unittest.TestCase):
    def test_filters_only_chktty_bx1_and_address_file_events(self):
        events = [
            {"event": "target_runtime_checkpoint", "checkpoint": "AH44_CHKTTY_ENTRY", "sequence": 1},
            {"event": "target_runtime_checkpoint", "checkpoint": "AH44_CHKTTY_ISATTY_CALL", "sequence": 2, "eax": 1},
            {"event": "target_runtime_checkpoint", "checkpoint": "UNRELATED", "sequence": 3},
            {"event": "original_cpu_int21_ah44_bx1_entry", "mapping_valid": True,
             "int_instruction_link_va": 0xC8973, "sequence": 4, "ebx": 1},
            {"event": "original_cpu_int21_ah44_bx1_entry", "mapping_valid": False,
             "int_instruction_link_va": None, "sequence": 5},
            {"event": "dos_handle_open", "path": "ADDRESS.TXT", "sequence": 6},
            {"event": "dos_address_txt_write", "path": "ADDRESS.TXT", "written": 24, "sequence": 7},
            {"event": "dos_handle_open", "path": "GENEWARS\\GW.ERR", "sequence": 8},
        ]
        result = extract_capture(events)
        self.assertEqual([e["sequence"] for e in result["chktty_checkpoints"]], [1, 2])
        self.assertEqual([e["sequence"] for e in result["bx1_callsites"]], [4])
        self.assertEqual([e["sequence"] for e in result["address_file_events"]], [6, 7])

    def test_capture_lists_are_hard_bounded(self):
        events = [{"event": "target_runtime_checkpoint", "checkpoint": "AH44_CHKTTY_ENTRY", "sequence": i}
                  for i in range(100)]
        events += [{"event": "dos_address_txt_write", "path": "ADDRESS.TXT", "sequence": i}
                   for i in range(100, 200)]
        result = extract_capture(events)
        self.assertLessEqual(len(result["chktty_checkpoints"]), 32)
        self.assertLessEqual(len(result["address_file_events"]), 32)
        self.assertEqual(len(result["bx1_callsites"]), 0)

    def test_bx1_return_and_request_are_distinct_checkpoints(self):
        events = [
            {"event": "target_runtime_checkpoint", "checkpoint": "DOS_AH44_BX1_CALLSITE", "sequence": 1},
            {"event": "target_runtime_checkpoint", "checkpoint": "DOS_AH44_BX1_RETURN", "sequence": 2},
        ]
        result = extract_capture(events)
        self.assertEqual(result["bx1_callsites"][0]["sequence"], 1)
        self.assertEqual(result["bx1_returns"][0]["sequence"], 2)

    def test_captured_original_evidence_when_present(self):
        root = Path(__file__).resolve().parents[1]
        result_path = root / "evidence/w3_236_chktty_original_capture.json"
        if not result_path.exists():
            self.skipTest("original capture has not run yet")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        trace = Path(result["trace"]["path"])
        raw = trace.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result["trace"]["sha256"])
        self.assertLessEqual(len(raw), 1_048_576)
        self.assertEqual(result["effective_psp_tail"], " -k 38928")
        self.assertTrue(result["address_txt_initial"]["matches_read_only_functional_source"])
        self.assertEqual(hashlib.sha256(bytes.fromhex(result["address_txt_initial"]["snapshot_hex"])).hexdigest(),
                         result["address_txt_initial"]["sha256"])
        caller = [e for e in result["chktty_and_bx1"]["chktty_checkpoints"]
                  if e.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL"]
        bx1 = result["chktty_and_bx1"]["bx1_callsites"]
        self.assertTrue(caller)
        self.assertTrue(any(e.get("int_instruction_link_va") == 0xC8973 for e in bx1))
        # The captured __chktty call and the later BX=1 row are separate observations.
        self.assertEqual(caller[0]["eax"], 5)
        self.assertEqual(bx1[0]["ebx"], 1)
        self.assertIsNone(bx1[0].get("caller_link_va"))


if __name__ == "__main__":
    unittest.main()
