from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.w3_269_post_present_checkpoint import (
    MAX_TARGET_EVENTS,
    OneShotPresentMarker,
    guest_link_va,
    parse_bounded_trace,
    validate_trace,
)


class PostPresentCheckpointTests(unittest.TestCase):
    def test_marker_is_gated_one_shot_and_consumed_once(self):
        marker = OneShotPresentMarker()
        self.assertFalse(marker.mark(enabled=False, copy_capture_armed=True))
        self.assertFalse(marker.mark(enabled=True, copy_capture_armed=False))
        self.assertTrue(marker.mark(enabled=True, copy_capture_armed=True))
        self.assertFalse(marker.mark(enabled=True, copy_capture_armed=True))
        self.assertTrue(marker.consume())
        self.assertFalse(marker.consume())

    def test_runtime_to_link_uses_fresh_mapping_and_rejects_underflow(self):
        self.assertEqual(guest_link_va(0x27D983, 0x1EB000), 0x92983)
        self.assertIsNone(guest_link_va(0x1000, 0x1EB000))

    def test_requires_ordered_present_return_and_guest_checkpoint(self):
        events = [
            {"event": "opengl_backbuffer_pre_swap"},
            {"event": "w3_269_post_present_marker_set"},
            {"event": "backend_present_return"},
            {"event": "w3_269_first_guest_checkpoint_after_present",
             "runtime_linear": 0x27D983, "code_rebase": 0x1EB000, "link_va": 0x92983},
        ]
        result = validate_trace(("\n".join(json.dumps(x) for x in events) + "\n").encode(), events)
        self.assertTrue(result["post_present_order_valid"])
        self.assertEqual(result["first_guest_link_va"], "0x00092983")

    def test_missing_present_or_timeout_is_not_a_success(self):
        result = validate_trace(b"{}\n", [{"event": "target_runtime_checkpoint"}])
        self.assertFalse(result["first_guest_checkpoint_seen"])
        self.assertTrue(result["timeout_or_no_present"])

    def test_duplicate_marker_and_target_event_caps_fail_closed(self):
        duplicate = [{"event": "w3_269_post_present_marker_set"}] * 2
        with self.assertRaisesRegex(ValueError, "duplicated"):
            validate_trace(b"{}", duplicate)
        target_rows = [{"event": "w3_269_game_transition_checkpoint",
                        "link_va": i} for i in range(MAX_TARGET_EVENTS + 1)]
        with self.assertRaisesRegex(ValueError, "target checkpoint cap"):
            validate_trace(b"x", target_rows)

    def test_trace_size_cap(self):
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            validate_trace(b"x" * (1024 * 1024 + 1), [])

    def test_bounded_jsonl_parser_accepts_capture_over_legacy_128_rows(self):
        raw = b"\n".join(json.dumps({"event": "dos_read", "ordinal": i}).encode()
                           for i in range(1008)) + b"\n"
        rows = parse_bounded_trace(raw)
        self.assertEqual(len(rows), 1008)
        self.assertEqual(rows[-1]["ordinal"], 1007)

    def test_bounded_jsonl_parser_rejects_bad_rows_and_event_overflow(self):
        with self.assertRaisesRegex(ValueError, "invalid JSONL"):
            parse_bounded_trace(b"{not json}\n")
        overflow = b"{}\n" * 2049
        with self.assertRaisesRegex(ValueError, "2048-event"):
            parse_bounded_trace(overflow)

    def test_source_marks_after_swap_and_consumes_at_dispatch(self):
        root = Path(__file__).resolve().parents[1]
        render = (root / "third_party/dosbox-staging-w3-059-instrumented/src/gui/render/opengl_renderer.cpp").read_text(encoding="utf-8")
        core = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        present = render.index("SDL_GL_SwapWindow(window);")
        marker = render.index("w3_269_mark_post_present_once();", present)
        self.assertLess(present, marker)
        dispatcher = core.index("restart_core:")
        consume = core.index("w3_269_take_post_present_once()", dispatcher)
        self.assertGreater(consume, dispatcher)
        self.assertIn("ip_point >= target_main_rebase", core[dispatcher:consume])
        self.assertIn("candidate_link_va == 0x00092710", core)


if __name__ == "__main__":
    unittest.main()
