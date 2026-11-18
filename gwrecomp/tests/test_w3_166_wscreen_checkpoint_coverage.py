import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "build/dosboxx_oracle/C/W3_165_WSCREEN_BOUNDARY_20261009_01.jsonl"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
DECODER = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h"
RESULT = ROOT / "evidence/w3_165_wscreen_instruction_boundary.json"
CFG = ROOT / "evidence/w3_159_wscreen_call_cfg.json"
GATE_LINKS = {0x94CE1, 0x94CEE, 0x94CF4, 0x94D9F, 0x94DBC}


class WScreenCheckpointCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = [json.loads(line) for line in TRACE.read_text(encoding="utf-8").splitlines() if line]
        cls.core = SOURCE.read_text(encoding="utf-8")
        cls.decoder = DECODER.read_text(encoding="utf-8")
        cls.result = json.loads(RESULT.read_text(encoding="utf-8"))
        cls.cfg = json.loads(CFG.read_text(encoding="utf-8"))

    def test_mapping_and_original_loader_pair_are_measured(self):
        self.assertEqual(self.result["mapping"]["code_rebase"], 0x1EB000)
        entry = next(row for row in self.rows if row.get("checkpoint") == "W3_157_WSCREEN_LOADER_ENTRY")
        returned = next(row for row in self.rows if row.get("checkpoint") == "W3_157_WSCREEN_LOADER_RETURN")
        self.assertEqual(entry["sequence"], 166)
        self.assertEqual(returned["sequence"], 167)
        self.assertEqual(entry["return_address"] - 0x1EB000, 0x94DC1)
        self.assertEqual(returned["link_va"], 0x94DC1)
        self.assertEqual(self.cfg["cfg"]["call_instruction"]["address"], 0x94DBC)
        self.assertEqual(self.cfg["cfg"]["call_instruction"]["operands"], "0x15090")

    def test_loader_return_proves_callsite_instruction_ran_without_its_hook(self):
        entry = next(row for row in self.rows if row.get("checkpoint") == "W3_157_WSCREEN_LOADER_ENTRY")
        returned = entry["return_address"] - self.result["mapping"]["code_rebase"]
        observed_callsite_hooks = [row for row in self.rows
                                   if row.get("checkpoint") == "W3_158_WSCREEN_CALLSITE"]
        self.assertEqual(returned, 0x94DBC + 5)
        self.assertEqual(self.cfg["cfg"]["call_instruction"]["bytes"], "e8cf02f8ff")
        self.assertEqual(observed_callsite_hooks, [])

    def test_missing_gate_events_are_not_interpreted_as_branch_values(self):
        checkpoint_rows = [row for row in self.rows if row.get("event") == "target_runtime_checkpoint"]
        observed = {row.get("link_va") for row in checkpoint_rows}
        self.assertTrue(GATE_LINKS.isdisjoint(observed))
        self.assertIsNone(self.result["checkpoints"]["gate_117662"])
        self.assertIsNone(self.result["checkpoints"]["gate_1174a4"])
        self.assertFalse(self.result["validation"]["complete_skip_path"])
        self.assertFalse(self.result["capture_complete"])

    def test_candidate_predicates_and_decode_split_are_separate(self):
        self.assertIn("candidate_link_va == 0x00094ce1", self.core)
        self.assertIn("candidate_link_va == 0x00094cee", self.core)
        self.assertIn("candidate_link_va == 0x00094cf4", self.core)
        self.assertIn("w3_165_is_wscreen_boundary(decode.code - w3_165_rebase)", self.decoder)
        # The boundary split is in CreateCacheBlock's decoder loop; it cannot
        # retroactively split an already translated/cache-hit block.
        self.assertLess(self.decoder.index("while (max_opcodes--) {"),
                        self.decoder.index("w3_165_is_wscreen_boundary(decode.code - w3_165_rebase)"))
        self.assertIn("FindCacheBlock(ip_point&4095)", self.core)


if __name__ == "__main__":
    unittest.main()
