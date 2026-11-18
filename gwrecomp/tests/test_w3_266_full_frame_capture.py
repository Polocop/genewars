from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_264_opengl_frame_capture import MAX_EVENTS, parse_trace
from tools.w3_266_full_frame_capture import (
    MAX_FRAME_BYTES,
    validate_same_present,
    valid_renderer_input,
    valid_visible_output_rect,
)

ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src"
OPENGL = (STAGING / "gui/render/opengl_renderer.cpp").read_text(encoding="utf-8")
SDL_GUI = (STAGING / "gui/sdl_gui.cpp").read_text(encoding="utf-8")


class W3_266Tests(unittest.TestCase):
    def test_full_renderer_input_hash_is_bounded_and_complete(self):
        event = {"renderer_input_full_frame_valid": True,
                 "renderer_input_full_coverage": True,
                 "renderer_input_width_px": 640, "renderer_input_height_px": 400,
                 "renderer_input_pitch_bytes": 2560, "renderer_input_bytes": 1_024_000,
                 "renderer_input_fnv1a64": 123, "renderer_input_nonzero_pixels": 10}
        self.assertTrue(valid_renderer_input(event))
        event["renderer_input_bytes"] = MAX_FRAME_BYTES + 1
        self.assertFalse(valid_renderer_input(event))

    def test_visible_rect_is_clipped_inside_canvas(self):
        event = {"canvas_width_px": 1000, "canvas_height_px": 700,
                 "visible_output_x_px": 0, "visible_output_y_px": 20,
                 "visible_output_width_px": 900, "visible_output_height_px": 600}
        self.assertTrue(valid_visible_output_rect(event))
        event["visible_output_width_px"] = 1001
        self.assertFalse(valid_visible_output_rect(event))

    def test_same_present_requires_order_mapping_copy_frame_and_return(self):
        gl = {"event": "opengl_backbuffer_pre_swap", "copy_capture_armed": True,
              "renderer_input_full_frame_valid": True, "renderer_input_full_coverage": True,
              "renderer_input_width_px": 640, "renderer_input_height_px": 400,
              "renderer_input_pitch_bytes": 2560, "renderer_input_bytes": 1_024_000,
              "renderer_input_fnv1a64": 123, "renderer_input_nonzero_pixels": 10}
        rows = [
            {"event": "main_mapping", "mapping_matches": True},
            {"event": "copy_pre"},
            {"event": "copy_post", "mapping_matches": True, "full_copy_valid": True,
             "guest_a0000_backing": {"valid": True}},
            gl,
            {"event": "backend_present_return", "canvas_width_px": 1000,
             "canvas_height_px": 700, "visible_output_x_px": 0,
             "visible_output_y_px": 20, "visible_output_width_px": 900,
             "visible_output_height_px": 600},
        ]
        self.assertTrue(validate_same_present(rows)["valid"])
        rows.reverse()
        self.assertFalse(validate_same_present(rows)["valid"])

    def test_jsonl_event_limit(self):
        raw = b"".join((json.dumps({"event": "e", "i": i}) + "\n").encode()
                       for i in range(MAX_EVENTS + 1))
        with self.assertRaises(ValueError):
            parse_trace(raw)

    def test_instrumentation_is_opt_in_and_hashes_input_without_dumping(self):
        self.assertIn("VGA_W3_262_PresentCaptureActive()", OPENGL)
        self.assertIn("GWRECOMP_W3_264_CAPTURE_OPENGL", OPENGL)
        self.assertIn("last_framebuf,", OPENGL)
        self.assertIn("renderer_input_fnv1a64", OPENGL)
        self.assertIn("visible_output_x_px", SDL_GUI)
        self.assertIn("visible_output_width_px", SDL_GUI)


if __name__ == "__main__":
    unittest.main()
