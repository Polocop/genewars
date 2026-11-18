import json
import unittest
from pathlib import Path

from tools.w3_081_original_ah44_caller import summarize


ROOT = Path(__file__).resolve().parents[1]


class OriginalAH44CallerCaptureTests(unittest.TestCase):
    def test_pairs_only_exact_original_bx1_call_and_return(self):
        events = [
            {"event": "target_runtime_checkpoint", "sequence": 1,
             "checkpoint": "MAIN_ENTRY_CHECKPOINT", "link_va": 0x93f30,
             "eip": 0x27ef30, "cs": 0x160, "data_rebase": 0x1da000,
             "main_argv_capture": [{"string": "C:\\GENEWARS\\GW.EXE"},
                                   {"string": "-k"}, {"string": "38928"}],
             "psp_tail_text": " -k 38928"},
            {"event": "target_runtime_checkpoint", "sequence": 2,
             "checkpoint": "AH44_CHKTTY_ISATTY_CALL", "process_psp": 12,
             "link_va": 0xba4e4, "edx": 0x10a822,
             "stream_object_sample": {"edx": 0x10a822, "field_0d_u8": 0,
                                       "field_10_u32": 1}},
            {"event": "target_runtime_checkpoint", "sequence": 3,
             "checkpoint": "DOS_AH44_BX1_CALLSITE", "process_psp": 12,
             "link_va": 0xc8973, "eax": 0x4400, "ebx": 1, "eflags": 0x202},
            {"event": "target_runtime_checkpoint", "sequence": 4,
             "checkpoint": "DOS_AH44_BX1_RETURN", "process_psp": 12,
             "link_va": 0xc8975, "eax": 0x4400, "edx": 0x82, "eflags": 0x202},
            {"event": "original_int21_ah44", "sequence": 5,
             "in_ax": 0x4400, "in_bx": 1, "out_dx": 0x82,
             "iret_flags": 0x202, "process_psp": 12},
        ]
        result = summarize(events)
        self.assertEqual(result["classification"], "ORIGINAL_OBSERVED")
        self.assertEqual(result["main_mapping"]["code_rebase"], 0x1eb000)
        self.assertEqual(result["paired_calls"][0]["return_dx"], 0x82)
        self.assertFalse(result["paired_calls"][0]["return_cf"])
        self.assertEqual(result["psp_command_tail"], " -k 38928")
        self.assertEqual(result["callback_bx1_events"][0]["out_dx"], 0x82)

    def test_bx2_is_not_promoted_to_bx1(self):
        result = summarize([{"event": "target_runtime_checkpoint", "sequence": 1,
                             "checkpoint": "DOS_AH44_CALLSITE", "link_va": 0xc8973,
                             "eax": 0x4400, "ebx": 2},
                            {"event": "original_int21_ah44", "in_ax": 0x4400,
                             "in_bx": 2, "out_dx": 2}])
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertEqual(result["ah44_bx1_calls"], [])

    def test_existing_w3_079_absence_stays_inconclusive(self):
        evidence = json.loads((ROOT / "evidence/w3_079_original_ah44_bx1.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(evidence["classification"], "INCONCLUSIVE")
        self.assertEqual(evidence["bx1_contract"]["original_call_count"], 0)
        self.assertEqual(evidence["callsite_count"], 0)


if __name__ == "__main__":
    unittest.main()
