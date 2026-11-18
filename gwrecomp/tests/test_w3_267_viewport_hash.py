from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_264_opengl_frame_capture import MAX_EVENTS, parse_trace
from tools.w3_267_viewport_hash import (
    MAX_CHUNK_BYTES,
    MAX_TOTAL_BYTES,
    analyze_rows,
    plan_scanline_chunks,
    validate_chunk_coverage,
    valid_viewport_event,
)

ROOT = Path(__file__).resolve().parents[1]
OPENGL = (ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/gui/render/opengl_renderer.cpp").read_text(encoding="utf-8")


class W3_267Tests(unittest.TestCase):
    def test_scanline_chunking_covers_measured_viewport_exactly(self):
        chunks = plan_scanline_chunks(1600, 1200)
        self.assertEqual(sum(chunk["bytes"] for chunk in chunks), 5_760_000)
        self.assertTrue(all(chunk["bytes"] <= MAX_CHUNK_BYTES for chunk in chunks))
        self.assertTrue(validate_chunk_coverage(chunks, 1200, 4800, 5_760_000))
        self.assertEqual(chunks[0]["row_start"], 0)
        self.assertEqual(chunks[-1]["row_start"] + chunks[-1]["rows"], 1200)

    def test_scanline_chunker_rejects_total_or_row_over_cap(self):
        with self.assertRaises(ValueError):
            plan_scanline_chunks(1000, 3000)
        with self.assertRaises(ValueError):
            plan_scanline_chunks(400000, 1)
        self.assertEqual(MAX_TOTAL_BYTES, 6 * 1024 * 1024)

    def test_coverage_rejects_gap_overlap_or_wrong_bytes(self):
        self.assertFalse(validate_chunk_coverage(
            [{"row_start": 0, "rows": 5, "bytes": 15},
             {"row_start": 6, "rows": 4, "bytes": 12}], 10, 3, 27))
        self.assertFalse(validate_chunk_coverage(
            [{"row_start": 0, "rows": 10, "bytes": 31}], 10, 3, 30))

    def test_event_requires_full_coverage_and_bounded_chunks(self):
        event = {"sample_width_px": 1600, "sample_height_px": 1200,
                 "sample_bytes": 5_760_000, "readback_chunk_count": len(plan_scanline_chunks(1600, 1200)),
                 "max_readback_bytes": MAX_CHUNK_BYTES,
                 "max_total_readback_bytes": MAX_TOTAL_BYTES,
                 "full_visible_viewport_covered": True, "fnv1a64": 987}
        self.assertTrue(valid_viewport_event(event))
        event["sample_bytes"] += 1
        self.assertFalse(valid_viewport_event(event))

    def test_full_capture_requires_same_run_order_and_geometry(self):
        rows = [
            {"event": "main_mapping", "mapping_matches": True},
            {"event": "copy_pre"},
            {"event": "copy_post", "mapping_matches": True, "full_copy_valid": True,
             "guest_a0000_backing": {"valid": True}},
            {"event": "opengl_backbuffer_pre_swap", "copy_capture_armed": True,
             "renderer_input_full_frame_valid": True, "renderer_input_full_coverage": True,
             "renderer_input_bytes": 1_024_000,
             "sample_x_px": 628, "sample_y_px": 40,
             "sample_width_px": 1600, "sample_height_px": 1200,
             "sample_bytes": 5_760_000,
             "readback_chunk_count": len(plan_scanline_chunks(1600, 1200)),
             "max_readback_bytes": MAX_CHUNK_BYTES,
             "max_total_readback_bytes": MAX_TOTAL_BYTES,
             "full_visible_viewport_covered": True, "fnv1a64": 123},
            {"event": "backend_present_return", "present_method_returned": True,
             "visible_output_x_px": 628, "visible_output_y_px": 40,
             "visible_output_width_px": 1600, "visible_output_height_px": 1200},
        ]
        self.assertTrue(analyze_rows(rows)["same_run_full_frame_verified"])
        rows[3]["sample_y_px"] = 41
        self.assertFalse(analyze_rows(rows)["same_run_full_frame_verified"])

    def test_event_limit_and_source_gate_order(self):
        rows = b"".join((json.dumps({"event": "e", "i": i}) + "\n").encode()
                       for i in range(MAX_EVENTS + 1))
        with self.assertRaises(ValueError):
            parse_trace(rows)
        self.assertIn("VGA_W3_262_PresentCaptureActive()", OPENGL)
        marker = "glReadPixels(sample_x"
        swap = "SDL_GL_SwapWindow(window);"
        self.assertLess(OPENGL.index(marker), OPENGL.index(swap))
        self.assertIn("max_total_bytes = 6 * 1024 * 1024", OPENGL)
        self.assertIn("max_chunk_bytes = 1024 * 1024", OPENGL)
        self.assertIn("GWRECOMP_W3_267_CAPTURE_VIEWPORT", OPENGL)


if __name__ == "__main__":
    unittest.main()
