from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_279_play_smk_step import analyze, parse, verify_step_window


class PlaySmkStepTests(unittest.TestCase):
    def rows(self, destination: int = 0xAE2E8) -> list[dict]:
        base = 0x1EB000
        rows = [{"event": "main_mapping", "mapping_matches": True,
                 "code_rebase": base}]
        events = [
            (10, "w3_278_later_play_smk_entry", 0xAE2D0),
            (11, "w3_278_global_load", 0xAE2DF),
            (12, "w3_278_branch_test", 0xAE2E1),
            (13, "w3_278_branch_target", destination),
        ]
        for sequence, event, link in events:
            rows.append({
                "sequence": sequence, "event": event, "link_va": link,
                "runtime_linear": base + link, "code_rebase": base,
                "ecx": 0x12345678, "eflags": 0x202,
            })
        return rows

    def test_analyzes_taken_jne_and_loaded_value(self) -> None:
        result = analyze(parse(b"\n".join(json.dumps(row).encode() for row in self.rows())))
        self.assertTrue(result["complete"])
        self.assertEqual(result["loaded_ecx"], "0x12345678")
        self.assertEqual(result["test_eflags"], "0x00000202")
        self.assertTrue(result["branch_taken"])
        self.assertEqual(result["branch_destination"], "0x000AE2E8")

    def test_analyzes_fallthrough_without_calling_it_taken(self) -> None:
        result = analyze(self.rows(0xAE2E3))
        self.assertTrue(result["complete"])
        self.assertFalse(result["branch_taken"])

    def test_missing_events_remain_unknown(self) -> None:
        result = analyze(self.rows()[:2])
        self.assertFalse(result["complete"])
        self.assertIsNone(result["loaded_ecx"])
        self.assertIsNone(result["branch_taken"])
        self.assertIn("test_flags", result["missing"])

    def test_mapping_and_capture_window_are_checked(self) -> None:
        rows = self.rows()
        rows[-1]["runtime_linear"] += 1
        with self.assertRaisesRegex(ValueError, "runtime mapping mismatch"):
            analyze(rows)
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertTrue(verify_step_window(source))

    def test_trace_limits(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte cap"):
            parse(b" " * (1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
