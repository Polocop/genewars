from __future__ import annotations

import unittest
from pathlib import Path

from tools.w3_264_opengl_frame_capture import (
    MAX_EVENTS,
    MAX_READBACK_BYTES,
    chained_vga_backing_offset,
    parse_trace,
    sample_region,
)
from tools.w3_265_capture_runner import post_copy_capture_valid

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/gui/render/opengl_renderer.cpp").read_text(encoding="utf-8")


class W3_265Tests(unittest.TestCase):
    def test_pixel_readback_waits_for_copy_armed_flag(self):
        gate = "!VGA_W3_262_PresentCaptureActive()"
        call = "w3_264_capture_post_shader_backbuffer(window);"
        self.assertIn("bool VGA_W3_262_PresentCaptureActive();", SOURCE)
        self.assertLess(SOURCE.index(gate), SOURCE.index(call))
        self.assertIn('std::getenv("GWRECOMP_W3_264_CAPTURE_OPENGL") == nullptr', SOURCE)

    def test_pixel_readback_precedes_swap_and_is_one_shot(self):
        call = "w3_264_capture_post_shader_backbuffer(window);"
        swap = "SDL_GL_SwapWindow(window);"
        self.assertLess(SOURCE.index(call), SOURCE.index(swap))
        self.assertIn("static bool captured = false", SOURCE)
        self.assertIn('copy_capture_armed', SOURCE)

    def test_readback_bound_and_sample_dimensions(self):
        w, h, size = sample_region(3840, 2160)
        self.assertLessEqual(size, MAX_READBACK_BYTES)
        self.assertLessEqual(w, 3840)
        self.assertLess(h, 2160)

    def test_copy_gate_mapped_to_chain4_lane_formula(self):
        self.assertEqual([chained_vga_backing_offset(i) for i in range(8)],
                         [0, 1, 2, 3, 16, 17, 18, 19])

    def test_only_copy_armed_post_present_order_is_valid(self):
        rows = [
            {"event": "main_mapping", "mapping_matches": True},
            {"event": "copy_post", "mapping_matches": True, "full_copy_valid": True,
             "guest_a0000_backing": {"valid": True}},
            {"event": "opengl_backbuffer_pre_swap", "copy_capture_armed": True,
             "drawable_width_px": 640, "drawable_height_px": 400,
             "sample_width_px": 640, "sample_height_px": 400,
             "sample_bytes": 768000, "fnv1a64": 42,
             "gl_error_queried": False,
             "gl_status": "readback_issued; error queue not consumed",
             "full_frame_covered": True},
            {"event": "backend_present_return"},
        ]
        self.assertTrue(post_copy_capture_valid(rows))
        rows[2]["copy_capture_armed"] = False
        self.assertFalse(post_copy_capture_valid(rows))

    def test_capture_event_cap(self):
        import json
        raw = b"".join((json.dumps({"event": "x", "n": n}) + "\n").encode() for n in range(MAX_EVENTS + 1))
        with self.assertRaises(ValueError):
            parse_trace(raw)


if __name__ == "__main__":
    unittest.main()
