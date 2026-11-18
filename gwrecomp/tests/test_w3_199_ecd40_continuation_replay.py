"""Synthetic-only tests for W3-199 preflight and bounded event classification."""
import unittest

from tools.w3_199_ecd40_continuation_replay import (
    DOSBOX_SHA256, MAX_STEP_EVENTS, OPERATION, RESULT, RUN_ID, TRACE,
    classify_continuation, inspect_source, synthetic_preflight,
)
from tools import w3_192_ecd40_progress_runner as shared


class Ecd40ContinuationReplayTests(unittest.TestCase):
    def test_preflight_binds_exact_hash_fixture_and_unique_paths(self):
        result = synthetic_preflight()
        self.assertEqual(result["binary_sha256"], DOSBOX_SHA256)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["trace_path"], str(TRACE.relative_to(shared.ROOT)))
        self.assertEqual(result["result_path"], str(RESULT.relative_to(shared.ROOT)))
        self.assertTrue(result["probe"]["all_checks_pass"])
        self.assertEqual(OPERATION, shared.OPERATION)

    def test_source_requires_fresh_mapping_target_gate_and_five_step_bound(self):
        source = shared.base.CORE.read_text(encoding="utf-8", errors="replace")
        self.assertTrue(inspect_source(source)["all_checks_pass"])

    def test_classifier_recognizes_target_and_stops_short(self):
        self.assertEqual(classify_continuation([{"after_link_va": 0xECD40}], [], False)["classification"],
                         "TARGET_REACHED_CHECKPOINT_UNCONFIRMED")
        short = classify_continuation([{"after_link_va": 0xECD34}], [{"reason": "path_diverged"}], False)
        self.assertEqual(short["classification"], "STOPPED_BEFORE_TARGET")
        self.assertEqual(short["stop_reason"], "path_diverged")

    def test_classifier_enforces_event_limits_and_checkpoint_precedence(self):
        too_many = [{"after_link_va": 0xECD31}] * (MAX_STEP_EVENTS + 1)
        self.assertEqual(classify_continuation(too_many, [], False)["classification"], "EVENT_BOUND_VIOLATION")
        self.assertEqual(classify_continuation([], [], True)["classification"], "TARGET_CHECKPOINT_CAPTURED")


if __name__ == "__main__":
    unittest.main()
