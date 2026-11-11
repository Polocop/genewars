import unittest
from pathlib import Path

from tools.w3_143_postopen_branch import MAX_TRACE_BYTES, parse_jsonl, summarize


class PostOpenBranchTests(unittest.TestCase):
    def test_success_and_failure_paths_are_distinguished(self):
        base = 0x001EB000
        direct = {"event": "target_runtime_checkpoint", "checkpoint": "W3_133_PLAY_SMK_DIRECT_ENTRY",
                  "link_va": 0xAE308, "eip": 0xAE308 + base, "process_psp": 4, "cs": 0x160}
        success = {"event": "target_runtime_checkpoint", "checkpoint": "W3_143_SMACKOPEN_SUCCESS_FLAG_ZERO",
                   "link_va": 0xAE39A, "eip": 0xAE39A + base, "eax": 1, "eflags": 0x202}
        result = summarize([direct, success])
        self.assertEqual(result["classification"], "SMACKOPEN_SUCCESS_BRANCH_OBSERVED")
        self.assertEqual(result["branch_return_eax"], 1)
        self.assertFalse(result["transfer_followed"])
        failure = {**success, "checkpoint": "W3_143_SMACKOPEN_FAILURE", "link_va": 0xAE4CE,
                   "eip": 0xAE4CE + base, "eax": 0}
        result = summarize([direct, failure])
        self.assertEqual(result["classification"], "SMACKOPEN_FAILURE_BRANCH_OBSERVED")

    def test_cap_and_one_shot_source_gates(self):
        self.assertEqual(parse_jsonl(b'{"event":"x"}\n')[0]["event"], "x")
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (MAX_TRACE_BYTES + 1))
        source = Path(
            "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
        ).read_text(encoding="utf-8")
        for token in ("0x000ae39a", "0x000ae3c9", "0x000ae4ce", "0x000c5140",
                      '"W3_143_SMACKOPEN_SUCCESS_FLAG_ZERO"',
                      '"W3_143_SMACKOPEN_SUCCESS_FLAG_ONE"', '"W3_143_SMACKOPEN_FAILURE"',
                      "w3_143_postopen_capture_armed"):
            self.assertIn(token, source)


if __name__ == "__main__":
    unittest.main()
