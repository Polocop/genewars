import json
import unittest
from pathlib import Path

from tools.w3_285_smacker_callee_capture import analyze, parse, verify_instrumentation


class SmackerCalleeCaptureTests(unittest.TestCase):
    def rows(self):
        base = 0x1EB000
        return [
            {"event": "main_mapping", "mapping_matches": True, "code_rebase": base},
            {"sequence": 9, "event": "target_runtime_checkpoint", "checkpoint": "W3_133_PLAY_SMK_ENTRY",
             "link_va": 0xAE2D0, "linear": base + 0xAE2D0},
            {"sequence": 10, "event": "w3_278_branch_target", "link_va": 0xAE2E3,
             "runtime_linear": base + 0xAE2E3, "code_rebase": base},
            {"sequence": 11, "event": "w3_285_smacker_direct_entry", "link_va": 0xAE308,
             "runtime_linear": base + 0xAE308, "code_rebase": base, "cs": 0x160,
             "eip": base + 0xAE308, "eax": 1, "ebx": 0, "ecx": 0, "edx": 0,
             "esi": 2, "edi": 3, "ebp": 4, "esp": 5, "eflags": 0x202},
        ]

    def test_mapping_and_order_required_for_original_observed_hit(self):
        result = analyze(self.rows())
        self.assertTrue(result["ordered"])
        self.assertTrue(result["callee_entry_seen"])
        self.assertEqual(result["entry"]["link_va"], 0xAE308)
        self.assertTrue(result["ordered"])

    def test_missing_callee_stays_missing(self):
        rows = self.rows()[:2]
        result = analyze(rows)
        self.assertFalse(result["ordered"])
        self.assertIsNone(result["entry"])

    def test_mapping_mismatch_rejected(self):
        rows = self.rows()
        rows[-1]["runtime_linear"] += 1
        with self.assertRaisesRegex(ValueError, "mapping mismatch"):
            analyze(rows)

    def test_duplicate_one_shot_event_rejected(self):
        rows = self.rows()
        rows.append({**rows[-1], "sequence": 12})
        with self.assertRaisesRegex(ValueError, "duplicated"):
            analyze(rows)

    def test_existing_target_checkpoint_is_original_observation_without_custom_latch(self):
        base = 0x1EB000
        rows = [
            {"event": "main_mapping", "mapping_matches": True, "code_rebase": base},
            {"sequence": 328, "event": "target_runtime_checkpoint", "checkpoint": "W3_133_PLAY_SMK_ENTRY",
             "link_va": 0xAE2D0, "linear": base + 0xAE2D0},
            {"sequence": 329, "event": "target_runtime_checkpoint", "checkpoint": "W3_133_PLAY_SMK_DIRECT_ENTRY",
             "link_va": 0xAE308, "linear": base + 0xAE308, "cs": 0x160,
             "stack_words_u32": [base + 0xAE306]},
            {"sequence": 330, "event": "target_runtime_checkpoint", "checkpoint": "W3_133_SMACKOPEN_ENTRY",
             "link_va": 0xC62F0, "linear": base + 0xC62F0},
        ]
        result = analyze(rows)
        self.assertTrue(result["callee_entry_seen"])
        self.assertEqual(result["entry_source"], "EXISTING_W3_133_TARGET_CHECKPOINT")
        self.assertFalse(result["instrumented_one_shot_hook_seen"])
        self.assertFalse(result["fallthrough_latch_seen"])
        self.assertTrue(result["ordered"])
        self.assertTrue(result["return_address_matches_static_0xAE306"])

    def test_jsonl_parser_and_bounded_hook_integration(self):
        raw = b"\n".join(json.dumps(row).encode() for row in self.rows())
        self.assertEqual(len(parse(raw)), 4)
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertTrue(verify_instrumentation(source))
        self.assertFalse(verify_instrumentation(source.replace("candidate_link_va == 0x000ae308", "candidate_link_va == 0x000ae309")))


if __name__ == "__main__":
    unittest.main()
