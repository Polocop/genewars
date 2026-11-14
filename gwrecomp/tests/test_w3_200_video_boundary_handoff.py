"""Read-only validation of the same-run W3-199 handoff evidence."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence/w3_199_ecd40_continuation.json"


class VideoBoundaryHandoffTests(unittest.TestCase):
    def test_same_run_boundary_and_video_checkpoints_are_proven_without_pixel_claim(self):
        result = json.loads(SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(result["task"], "W3-199")
        path = result["same_run_post_target_path"]
        self.assertEqual(path["step_after_link_va"], "0xECD40")
        self.assertTrue(path["same_psp"])
        self.assertTrue(path["same_code_rebase"])
        checkpoints = {row.get("checkpoint") for row in path["downstream_checkpoints"]}
        self.assertTrue({"VIDEO_VESA_MODE_CALLSITE", "VIDEO_VESA_SET_MODE_ENTRY",
                         "VIDEO_FRAMEBUFFER_ASSIGN_BEFORE", "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
                         "W3_188_B_SCREEN_ALLOC_RETURN", "W3_129_B_SCREEN_POST_STORE",
                         "W3_129_MEMORY_FREE_ENTRY"}.issubset(checkpoints))
        limits = result["first_frame_limits"]
        self.assertTrue(limits["framebuffer_assignment_before_after_observed"])
        self.assertFalse(limits["pixel_payload_or_visible_frame_proven"])
        self.assertFalse(path["interpretation"].find("No explicit ECD40 target checkpoint") < 0)


if __name__ == "__main__":
    unittest.main()
