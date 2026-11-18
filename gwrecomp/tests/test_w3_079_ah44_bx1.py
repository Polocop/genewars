import unittest
import json
from pathlib import Path

from tools.w3_079_ah44_bx1 import correlate_bx1_checkpoints


class AH44BX1EvidenceTests(unittest.TestCase):
    def test_pairs_only_original_bx1_callsite_and_return(self):
        events = [
            {"sequence": 4, "checkpoint": "DOS_AH44_BX1_CALLSITE",
             "link_va": 0xC8973, "process_psp": 7, "eax": 0x4400,
             "ebx": 1, "ecx": 0, "edx": 2, "eflags": 0x202},
            {"sequence": 5, "checkpoint": "DOS_AH44_BX1_RETURN",
             "link_va": 0xC8975, "process_psp": 7, "eax": 0x4400,
             "edx": 0x82, "eflags": 0x202},
        ]
        result = correlate_bx1_checkpoints(events)
        self.assertEqual(result["classification"], "ORIGINAL_OBSERVED")
        self.assertEqual(result["pairs"][0]["return_dx"], 0x82)
        self.assertFalse(result["pairs"][0]["return_cf"])

    def test_old_bx2_and_nonmatching_link_are_not_bx1_evidence(self):
        events = [
            {"sequence": 1, "event": "original_int21_ah44",
             "in_ax": 0x4400, "in_bx": 2, "out_ax": 2},
            {"sequence": 2, "checkpoint": "DOS_AH44_BX1_CALLSITE",
             "link_va": 0xC8973, "process_psp": 7, "eax": 0x4400,
             "ebx": 2},
            {"sequence": 3, "checkpoint": "DOS_AH44_BX1_CALLSITE",
             "link_va": 0xC8974, "process_psp": 7, "eax": 0x4400,
             "ebx": 1},
        ]
        self.assertEqual(correlate_bx1_checkpoints(events)["classification"],
                         "INCONCLUSIVE")

    def test_missing_return_does_not_infer_response(self):
        events = [{"sequence": 4, "checkpoint": "DOS_AH44_BX1_CALLSITE",
                   "link_va": "0xc8973", "process_psp": 7,
                   "eax": "0x14400", "ebx": "0x10001"}]
        result = correlate_bx1_checkpoints(events)
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertEqual(result["paired_return_count"], 0)

    def test_saved_original_capture_does_not_promote_bx2_or_bx5_to_bx1(self):
        path = Path(__file__).resolve().parents[1] / "evidence/w3_079_original_ah44_bx1.json"
        with path.open(encoding="utf-8") as stream:
            evidence = json.load(stream)
        self.assertEqual(evidence["classification"], "INCONCLUSIVE")
        self.assertEqual(evidence["bx1_contract"]["paired_return_count"], 0)
        self.assertEqual(evidence["callsite_count"], 0)
        self.assertEqual({event["in_bx"] for event in evidence["ah44_events"]}, {2, 5})


if __name__ == "__main__":
    unittest.main()
