from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.w3_262_vga_present_capture import analyze_trace, parse_trace, select_target_events


def rows_for_copy() -> list[dict]:
    pre = {
        "event": "copy_pre", "invocation_ordinal": 1, "link_va": 0xA0013,
        "runtime_linear": 0x28A013, "code_rebase": 0x1EA000,
        "mapping_matches": True, "copy_range_bounded": True, "copy_bytes": 64000,
        "source_hash_fnv1a64": 1234,
    }
    post = {
        "event": "copy_post", "invocation_ordinal": 1, "link_va": 0xA0015,
        "runtime_linear": 0x28A015, "code_rebase": 0x1EA000,
        "mapping_matches": True, "full_copy_valid": True, "copy_bytes": 64000,
        "source_hash_fnv1a64": 1234, "destination_hash_fnv1a64": 1234,
    }
    return [pre, post]


class W3VgaPresentCaptureTests(unittest.TestCase):
    def test_mapping_and_copy_hash_must_match(self):
        result = analyze_trace(rows_for_copy())
        self.assertTrue(result["main_mapping_valid"])
        self.assertTrue(result["copy_hash_match"])
        self.assertFalse(result["framebuffer_pixels_proven"])

    def test_mapping_rebase_mismatch_rejected(self):
        rows = rows_for_copy()
        rows[1]["code_rebase"] += 0x1000
        result = analyze_trace(rows)
        self.assertFalse(result["main_mapping_valid"])
        self.assertFalse(result["copy_hash_match"])

    def test_duplicate_event_ordinal_rejected(self):
        rows = rows_for_copy()
        rows.append(dict(rows[0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            analyze_trace(rows)

    def test_target_trigger_filters_unrelated_and_wrong_address_events(self):
        rows = rows_for_copy() + [
            {"event": "copy_pre", "invocation_ordinal": 1, "link_va": 0xA0014},
            {"event": "dos_open", "link_va": 0x1234},
        ]
        selected = select_target_events(rows)
        self.assertEqual([row["event"] for row in selected], ["copy_pre", "copy_post"])

    def test_invalid_copy_bounds_rejected(self):
        rows = rows_for_copy()
        rows[0]["copy_bytes"] = 65537
        rows[1]["copy_bytes"] = 65537
        result = analyze_trace(rows)
        self.assertFalse(result["copy_hash_match"])

    def test_trace_byte_and_event_caps(self):
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            parse_trace(b" " * (1_048_576 + 1))
        raw = b"\n".join(json.dumps({"event": "x", "n": i}).encode() for i in range(129))
        with self.assertRaisesRegex(ValueError, "128 event"):
            parse_trace(raw)

    def test_guard_timeout_preserved(self):
        result = analyze_trace([], {"cause": "TIMEOUT"})
        self.assertTrue(result["guard_timeout"])
        self.assertEqual(result["classification"], "TARGET_COPY_NOT_REACHED_GUARD_TIMEOUT")

    def test_present_requires_nonzero_hashed_pixels(self):
        rows = rows_for_copy() + [{"event": "backend_present_return", "frame_hash": None,
                                   "render_width_px": 640, "render_height_px": 480,
                                   "nonzero_pixels": 0}]
        self.assertFalse(analyze_trace(rows)["framebuffer_pixels_proven"])
        rows[-1].update({"frame_hash": "abc", "nonzero_pixels": 1})
        self.assertTrue(analyze_trace(rows)["framebuffer_pixels_proven"])

    def test_runner_anchors_main_without_enabling_global_trace(self):
        root = Path(__file__).resolve().parents[1]
        runner = (root / "tools/w3_262_capture_runner.py").read_text(encoding="utf-8")
        core = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertIn('"GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c"', runner)
        self.assertIn('anchor_event_written || w3_262_main_anchor', core)
        self.assertNotIn('"GWRECOMP_EXEC_TRACE_PATH"', runner)


if __name__ == "__main__":
    unittest.main()
