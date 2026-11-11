import hashlib
import json
import unittest
from pathlib import Path


class PostVesaCallAlignmentTests(unittest.TestCase):
    def test_hashes_call_target_and_run_specific_boundaries(self):
        root = Path(__file__).resolve().parents[1]
        result = json.loads((root / "evidence/w3_094_post_vesa_call_alignment.json")
                            .read_text(encoding="utf-8"))
        for relative, item in result["sources"].items():
            self.assertEqual(hashlib.sha256((root / relative).read_bytes()).hexdigest(),
                             item["sha256"])

        static = result["static_link_bytes"]
        self.assertEqual(static["site_link_va"], "0x9fdcc")
        self.assertEqual(static["call_return_link_va"], "0x9fdd1")
        self.assertEqual(static["target_link_va"], "0xa3a00")
        self.assertEqual(static["jmp_target_link_va"], "0x9fdef")
        self.assertEqual(static["following_bytes"], "eb1c")

        first = result["w3_073_original_first_call"]
        self.assertEqual(first["sequence_order"], [772, 773, 774, 775])
        self.assertEqual(first["callsite_registers"]["edx"], 256)
        self.assertEqual(first["assignment_after_global"], 0xA0000)

        later = result["w3_093_later_call"]
        self.assertEqual(later["last_video_event"]["sequence"], 312)
        self.assertEqual(later["last_video_event"]["edx"], 384)
        self.assertFalse(later["post_call_mode_entry_captured"])
        self.assertFalse(later["post_call_fallthrough_captured"])
        self.assertEqual(result["comparison"]["whether_call_executed_after_callsite"],
                         "UNKNOWN; callsite is captured immediately before CALL, no subsequent entry event was persisted in W3-083/W3-093")
        self.assertEqual(result["comparison"]["page_mapping_or_framebuffer_write"],
                         "NOT OBSERVED")


if __name__ == "__main__":
    unittest.main()
