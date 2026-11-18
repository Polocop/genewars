import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CallerContextAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = json.loads((ROOT / "evidence/native_setup_replay_w1_085.json").read_text(encoding="utf-8"))
        cls.original = json.loads((ROOT / "evidence/original_ax4400_bx1_alignment_w3_221.json").read_text(encoding="utf-8"))
        cls.result = json.loads((ROOT / "evidence/w3_235_caller_context_audit.json").read_text(encoding="utf-8"))
        cls.trace_path = ROOT / "build/dosboxx_oracle/C/W3_221_AX4400_BX1_ALIGNMENT_20261009_01.jsonl"
        cls.trace_events = [json.loads(line) for line in cls.trace_path.read_text(encoding="utf-8").splitlines()]

    def test_trace_is_hash_bound_to_original_evidence(self):
        raw = self.trace_path.read_bytes()
        self.assertEqual(len(raw), self.original["trace"]["bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.original["trace"]["sha256"])
        self.assertEqual(self.result["inputs"]["original"]["trace_sha256"], self.original["trace"]["sha256"])

    def test_native_and_original_bx1_observations_are_separate(self):
        native = [e for e in self.native["native_ah4400_origin"]["callsite_events"] if e["ordinal"] == "11"]
        self.assertEqual(len(native), 1)
        self.assertEqual(native[0]["caller"], "000ba4d6")
        self.assertEqual(native[0]["site"], "000ba4e4")
        self.assertEqual(native[0]["eax"], "00000001")
        self.assertEqual(self.result["inputs"]["original"]["bx1"]["link_va"], "0x000C8973")
        self.assertEqual(self.result["inputs"]["original"]["bx1"]["ebx"], 1)
        self.assertIsNone(self.result["inputs"]["original"]["bx1"]["dynamic_caller"])

    def test_original_seed_was_the_w1_test_fixture_and_was_written(self):
        seed = self.original["preflight"]["fixture"]["../ADDRESS.TXT"]
        self.assertEqual(seed["sha256"], self.native["fixtures"]["components"]["address_txt_sha256"])
        self.assertEqual(self.result["address_txt"]["original_preflight_source"], "tests/fixtures/w3_067_address_seed_work1.bin")
        events = {e["sequence"]: e for e in self.trace_events}
        self.assertEqual(events[34]["event"], "dos_handle_open")
        self.assertEqual(events[34]["requested_path"], "c:\\address.txt")
        self.assertEqual(events[48]["event"], "dos_address_txt_write")
        self.assertEqual(events[48]["written"], 24)
        self.assertEqual(events[49]["event"], "dos_handle_close")
        self.assertFalse(self.result["address_txt"]["authentic_original_provenance"])

    def test_audit_does_not_claim_seed_parity_or_original_caller(self):
        self.assertFalse(self.result["claims"]["same_dynamic_caller_proven"])
        self.assertFalse(self.result["claims"]["seed_equivalence_proven"])
        self.assertTrue(self.result["next_capture_justified"])


if __name__ == "__main__":
    unittest.main()
