"""Synthetic-only tests for the W3-203 bounded capture runner."""
import unittest

from tools import w3_192_ecd40_progress_runner as shared
from tools.w3_203_bscreen_free_capture import (
    DOSBOX_SHA256, OPERATION, RESULT, RUN_ID, TRACE, classify_sample_rows,
    inspect_source, synthetic_preflight,
)


class BScreenFreeCaptureTests(unittest.TestCase):
    def test_preflight_binds_exact_new_build_and_fresh_unique_paths(self):
        result = synthetic_preflight()
        self.assertEqual(result["binary_sha256"], DOSBOX_SHA256)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["trace_path"], str(TRACE.relative_to(shared.base.ROOT)))
        self.assertEqual(result["result_path"], str(RESULT.relative_to(shared.base.ROOT)))
        self.assertTrue(result["probe"]["all_checks_pass"])
        self.assertEqual(OPERATION, shared.OPERATION)

    def test_classifier_requires_one_matching_bounded_sample(self):
        rows = [{"checkpoint": "W3_129_MEMORY_FREE_ENTRY",
                 "w3_202_b_screen_free_sample_candidate": True,
                 "w3_202_b_screen_sample_bounds_valid": True,
                 "w3_202_b_screen_sample_bytes": 64,
                 "w3_202_b_screen_sample_nonzero": 3,
                 "w3_202_b_screen_sample_reason": "captured_raw_allocation_bytes"}]
        result = classify_sample_rows(rows)
        self.assertEqual(result["classification"], "CAPTURED_RAW_ALLOCATION_BYTES")
        self.assertEqual(result["sample_bytes"], 64)

    def test_invalid_bounds_duplicate_or_missing_free_are_not_success(self):
        self.assertEqual(classify_sample_rows([])["classification"], "FREE_NOT_REACHED")
        invalid = [{"checkpoint": "W3_129_MEMORY_FREE_ENTRY",
                    "w3_202_b_screen_free_sample_candidate": True,
                    "w3_202_b_screen_sample_bounds_valid": False,
                    "w3_202_b_screen_sample_bytes": 0,
                    "w3_202_b_screen_sample_reason": "allocation_bounds_invalid"}]
        self.assertEqual(classify_sample_rows(invalid)["classification"], "ELIGIBLE_BUT_BOUNDS_FAILED")
        duplicate = invalid + [dict(invalid[0])]
        self.assertEqual(classify_sample_rows(duplicate)["classification"], "CHECKPOINT_OR_SAMPLE_DUPLICATED")

    def test_source_wiring_keeps_sample_capped_and_process_bound(self):
        self.assertTrue(inspect_source(shared.base.CORE.read_text(encoding="utf-8", errors="replace"))["all_checks_pass"])


if __name__ == "__main__":
    unittest.main()
