from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_264_opengl_frame_capture import (
    MAX_READBACK_BYTES,
    MAX_TRACE_BYTES,
    analyze_trace,
    chained_vga_backing_offset,
    fnv1a64,
    parse_trace,
    sample_region,
    validate_opengl_event,
)

ROOT = Path(__file__).resolve().parents[1]
OPENGL_SOURCE = (ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/gui/render/opengl_renderer.cpp").read_text(encoding="utf-8")


class W3_264Tests(unittest.TestCase):
    def test_region_full_frame_and_cap(self):
        self.assertEqual(sample_region(640, 400), (640, 400, 768000))
        width, height, size = sample_region(3840, 2160)
        self.assertEqual(width, 3840)
        self.assertLessEqual(size, MAX_READBACK_BYTES)
        self.assertLess(height, 2160)

    def test_region_rejects_invalid_dimensions(self):
        with self.assertRaises(ValueError):
            sample_region(0, 20)

    def test_chained_vga_byte_lane_mapping(self):
        self.assertEqual([chained_vga_backing_offset(i) for i in range(8)], [0, 1, 2, 3, 16, 17, 18, 19])
        self.assertEqual(chained_vga_backing_offset(0xFFFF), 0x3FFF3)
        with self.assertRaises(ValueError):
            chained_vga_backing_offset(0x10000)

    def test_fnv64_known_empty_vector(self):
        self.assertEqual(fnv1a64(b""), 14695981039346656037)

    def test_jsonl_caps(self):
        self.assertEqual(parse_trace(b'{"event":"a"}\n'), [{"event": "a"}])
        with self.assertRaises(ValueError):
            parse_trace(b" " * (MAX_TRACE_BYTES + 1))
        rows = b"".join((json.dumps({"n": i}) + "\n").encode() for i in range(129))
        with self.assertRaises(ValueError):
            parse_trace(rows)

    def test_valid_bounded_opengl_event(self):
        event = {
            "event": "opengl_backbuffer_pre_swap",
            "drawable_width_px": 640,
            "drawable_height_px": 400,
            "sample_width_px": 640,
            "sample_height_px": 400,
            "sample_bytes": 768000,
            "fnv1a64": 123,
            "nonzero_pixels": 10,
            "gl_error_queried": False,
            "gl_status": "readback_issued; error queue not consumed",
            "full_frame_covered": True,
        }
        self.assertTrue(validate_opengl_event(event))
        self.assertTrue(analyze_trace([event])["renderer_pixels_proven"])
        event["sample_bytes"] = MAX_READBACK_BYTES + 1
        self.assertFalse(validate_opengl_event(event))

    def test_duplicate_opengl_event_rejected(self):
        event = {"event": "opengl_backbuffer_pre_swap"}
        with self.assertRaises(ValueError):
            analyze_trace([event, event])

    def test_pre_main_renderer_event_not_attributed_to_game(self):
        result = analyze_trace([
            {"event": "opengl_backbuffer_pre_swap"},
            {"event": "main_mapping"},
            {"event": "copy_post", "guest_a0000_backing": {"valid": True}},
        ])
        self.assertTrue(result["first_opengl_event_precedes_main_mapping"])
        self.assertTrue(result["first_opengl_event_precedes_a0000_copy"])
        self.assertFalse(result["game_frame_attribution_proven"])

    def test_capture_opt_in_and_precedes_swap(self):
        marker = "w3_264_capture_post_shader_backbuffer(window);"
        swap = "SDL_GL_SwapWindow(window);"
        self.assertIn('std::getenv("GWRECOMP_W3_264_CAPTURE_OPENGL") == nullptr', OPENGL_SOURCE)
        self.assertLess(OPENGL_SOURCE.index(marker), OPENGL_SOURCE.index(swap))
        self.assertIn("constexpr size_t max_readback_bytes = 1024 * 1024", OPENGL_SOURCE)


if __name__ == "__main__":
    unittest.main()
