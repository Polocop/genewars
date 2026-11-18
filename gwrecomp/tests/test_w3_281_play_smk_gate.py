from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_281_play_smk_gate import analyze, parse, verify_window_integration


class PlaySmkSecondGateTests(unittest.TestCase):
    def rows(self, destination: int = 0xAE2F2) -> list[dict]:
        base = 0x1EB000
        rows = [{"event": "main_mapping", "mapping_matches": True,
                 "code_rebase": base}]
        events = [
            (20, "w3_281_second_gate_entry", 0xAE2E3),
            (21, "w3_281_second_gate_test", 0xAE2E6),
            (22, "w3_281_second_gate_target", destination),
        ]
        if destination == 0xAE2E8:
            events.append((23, "w3_281_media_callsite", 0xAE2EB))
        for sequence, event, link in events:
            rows.append({"sequence": sequence, "event": event, "link_va": link,
                         "runtime_linear": base + link, "code_rebase": base,
                         "ebx": 0x00000084, "eflags": 0x202})
        return rows

    def test_je_taken_to_alternate_path(self) -> None:
        result = analyze(parse(b"\n".join(json.dumps(row).encode() for row in self.rows())))
        self.assertTrue(result["complete"])
        self.assertEqual(result["bl_at_test_entry"], "0x84")
        self.assertTrue(result["conditional_je_taken"])
        self.assertFalse(result["media_callsite_seen"])

    def test_je_fallthrough_reaches_media_callsite(self) -> None:
        result = analyze(self.rows(0xAE2E8))
        self.assertTrue(result["complete"])
        self.assertFalse(result["conditional_je_taken"])
        self.assertTrue(result["media_callsite_seen"])

    def test_missing_state_remains_unknown(self) -> None:
        result = analyze(self.rows()[:2])
        self.assertFalse(result["complete"])
        self.assertIsNone(result["test_eflags"])
        self.assertIsNone(result["conditional_je_taken"])

    def test_bounded_window_is_connected_to_fallback(self) -> None:
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertTrue(verify_window_integration(source))
        without_fallback = source.replace(
            "w3_281_second_gate_probe_window ||\n\t    w3_223_adjust_probe_window",
            "w3_223_adjust_probe_window", 1)
        self.assertFalse(verify_window_integration(without_fallback))

    def test_trace_caps(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte cap"):
            parse(b" " * (1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
