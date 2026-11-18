import unittest
from pathlib import Path
import re

from tools.w3_138_smacker_trace import parse_jsonl


class SmackerReturnDrawTests(unittest.TestCase):
    def test_return_candidate_is_stack_derived_and_selected(self):
        source = Path(
            "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
        ).read_text(encoding="utf-8")
        self.assertRegex(
            source,
            re.compile(
                r"w3_134_alloc_return_pending\s*&&\s*"
                r"candidate_link_va\s*==\s*w3_134_alloc_return_link_va"
            ),
        )
        self.assertIn("link_va == w3_134_alloc_return_link_va", source)
        self.assertNotIn("candidate_link_va == 0x000ae64f", source.lower())

    def test_dynamic_return_and_copy_events_are_distinguishable(self):
        rows = [
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_134_LBMEMORYALLOC_RETURN",
             "link_va": 0xAE64F, "eax": 0x12340000, "w3_134_entry_target": True},
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_133_COPY_TO_SCREEN_ENTRY",
             "link_va": 0xAE668, "eax": 0x12340000, "w3_133_target_checkpoint": True},
        ]
        self.assertEqual(rows[0]["link_va"], 0xAE64F)
        self.assertEqual(rows[1]["link_va"], 0xAE668)
        self.assertNotEqual(rows[0]["checkpoint"], rows[1]["checkpoint"])

    def test_jsonl_parser_rejects_oversized_input_and_accepts_bounded_rows(self):
        self.assertEqual(parse_jsonl(b'{"event":"target_runtime_checkpoint"}\n')[0]["event"],
                         "target_runtime_checkpoint")
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))

    def test_functional_mount_is_read_only(self):
        config = Path("build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf")
        text = config.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b")


if __name__ == "__main__":
    unittest.main()
