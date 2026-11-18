from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_280_play_smk_step import analyze, parse, verify_fallback_integration


class PlaySmkNormalCoreWindowTests(unittest.TestCase):
    def rows(self, destination: int = 0xAE2E8) -> list[dict]:
        base = 0x1EB000
        rows = [{"event": "main_mapping", "mapping_matches": True,
                 "code_rebase": base}]
        for sequence, event, link in [
            (1, "w3_278_later_play_smk_entry", 0xAE2D0),
            (2, "w3_278_global_load", 0xAE2DF),
            (3, "w3_278_branch_test", 0xAE2E1),
            (4, "w3_278_branch_target", destination),
        ]:
            rows.append({"sequence": sequence, "event": event, "link_va": link,
                         "runtime_linear": base + link, "code_rebase": base,
                         "ecx": 0x1234, "eflags": 0x202})
        return rows

    def test_taken_and_fallthrough_destinations(self) -> None:
        taken = analyze(self.rows())
        self.assertTrue(taken["complete"])
        self.assertTrue(taken["branch_taken"])
        self.assertEqual(taken["loaded_ecx"], "0x00001234")
        self.assertFalse(analyze(self.rows(0xAE2E3))["branch_taken"])

    def test_unknown_events_are_not_fabricated(self) -> None:
        result = analyze(self.rows()[:2])
        self.assertFalse(result["complete"])
        self.assertIsNone(result["test_eflags"])
        self.assertIsNone(result["branch_destination"])

    def test_rejects_mapping_mismatch(self) -> None:
        rows = self.rows()
        rows[-1]["runtime_linear"] += 1
        with self.assertRaisesRegex(ValueError, "runtime mapping mismatch"):
            analyze(rows)

    def test_cached_dynrec_path_reaches_one_cycle_fallback(self) -> None:
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertTrue(verify_fallback_integration(source))
        self.assertFalse(verify_fallback_integration(source.replace(" || w3_279_branch_probe_window", "")))

    def test_trace_caps(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte cap"):
            parse(b" " * (1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
