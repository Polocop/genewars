from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.w3_263_vga_capture import analyze_trace, parse_trace, select_target_events


def valid_rows() -> list[dict]:
    mapping = {"event": "main_mapping", "invocation_ordinal": 1,
               "link_va": 0xAF96C, "runtime_linear": 0x29A96C,
               "code_rebase": 0x1EB000, "mapping_matches": True,
               "instruction_bytes": "eb765741"}
    pre = {"event": "copy_pre", "invocation_ordinal": 1,
           "link_va": 0xA0013, "runtime_linear": 0x28B013,
           "code_rebase": 0x1EB000, "mapping_matches": True,
           "copy_range_bounded": True, "copy_bytes": 64000,
           "source_hash_fnv1a64": 99}
    post = {"event": "copy_post", "invocation_ordinal": 1,
            "link_va": 0xA0015, "runtime_linear": 0x28B015,
            "code_rebase": 0x1EB000, "mapping_matches": True,
            "full_copy_valid": True, "copy_bytes": 64000,
            "source_hash_fnv1a64": 99, "destination_hash_fnv1a64": 99}
    return [mapping, pre, post]


class W3_263VgaCaptureTests(unittest.TestCase):
    def test_mapping_and_copy_hash_match(self):
        analysis = analyze_trace(valid_rows())
        self.assertTrue(analysis["main_mapping_valid"])
        self.assertTrue(analysis["copy_mapping_valid"])
        self.assertTrue(analysis["copy_hash_match"])
        self.assertFalse(analysis["visible_screenshot_proven"])

    def test_bad_mapping_is_rejected(self):
        rows = valid_rows()
        rows[0]["runtime_linear"] += 0x1000
        analysis = analyze_trace(rows)
        self.assertFalse(analysis["main_mapping_valid"])
        self.assertFalse(analysis["copy_hash_match"])

    def test_filtering_requires_exact_target_addresses(self):
        rows = valid_rows() + [{"event": "copy_pre", "link_va": 0xA0014},
                               {"event": "dos_open", "link_va": 0x1234}]
        selected = select_target_events(rows)
        self.assertEqual([row["event"] for row in selected],
                         ["main_mapping", "copy_pre", "copy_post"])

    def test_duplicate_checkpoint_is_rejected(self):
        rows = valid_rows()
        rows.append(dict(rows[1]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            analyze_trace(rows)

    def test_copy_and_frame_hash_bounds(self):
        rows = valid_rows()
        rows[1]["copy_bytes"] = 65_537
        rows[2]["copy_bytes"] = 65_537
        self.assertFalse(analyze_trace(rows)["copy_hash_match"])
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            parse_trace(b"x" * 1_048_577)
        with self.assertRaisesRegex(ValueError, "128 event"):
            parse_trace(b"\n".join(json.dumps({"event": "x"}).encode() for _ in range(129)))

    def test_sdl_present_requires_nonzero_pixels_and_hash(self):
        rows = valid_rows() + [{"event": "backend_present_return", "surface_valid": True,
                                "sdl_render_present_returned": True, "render_width_px": 640,
                                "render_height_px": 480, "frame_hash_covered_bytes": 100,
                                "frame_hash": 44, "sampled_pixels": 25, "nonzero_pixels": 1}]
        analysis = analyze_trace(rows)
        self.assertTrue(analysis["renderer_buffer_presented"])
        rows[-1]["nonzero_pixels"] = 0
        self.assertFalse(analyze_trace(rows)["renderer_buffer_presented"])

    def test_timeout_is_preserved(self):
        self.assertTrue(analyze_trace([], {"cause": "TIMEOUT"})["guard_timeout"])

    def test_runner_sets_measured_anchor_without_global_trace(self):
        root = Path(__file__).resolve().parents[1]
        runner = (root / "tools/w3_263_capture_runner.py").read_text(encoding="utf-8")
        core = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertIn('"GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c"', runner)
        self.assertIn('anchor_event_written || w3_262_main_anchor', core)
        self.assertNotIn('"GWRECOMP_EXEC_TRACE_PATH"', runner)


if __name__ == "__main__":
    unittest.main()
