import unittest

from tools.w3_290_ecd40_stall_audit import analyze


def row(event, sequence, **extra):
    return {"event": event, "sequence": sequence, **extra}


class W3290AuditTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            row("main_mapping", 1, mapping_matches=True, code_rebase=0x1EB000),
            row("target_runtime_checkpoint", 5, checkpoint="W3_177_UNSMACK_HANDLER_ENTRY", link_va=0xECCF0, elapsed_ms=72044),
            row("backend_present_return", None, renderer_active=True, present_method_returned=True, post_present_pixels=None, frame_hash=None, vga={"aperture_nonzero_bytes": 0}),
            row("W3_193_ECD40_STEP_RESULT", 10, before_link_va=0xECD2B, after_link_va=0xECD31, target_runtime=0x2D7D40, normal_core_return=0),
        ]
        transitions = [(0xECD31, 0xECD34), (0xECD34, 0xECD3A), (0xECD3A, 0xECD3C), (0xECD3C, 0xECD3E), (0xECD3E, 0xECD40)]
        self.rows.extend(row("W3_198_ECD40_CONTINUATION_STEP", 11 + i, ordinal=i, before_link_va=before, after_link_va=after, before_runtime=0x1EB000 + before, after_runtime=0x1EB000 + after, normal_core_return=0) for i, (before, after) in enumerate(transitions, 1))
        self.raw = ("\n".join(__import__("json").dumps(r) for r in self.rows) + "\n").encode()
        import hashlib
        self.capture = {
            "trace": {"sha256": hashlib.sha256(self.raw).hexdigest(), "bytes": len(self.raw), "rows": len(self.rows)},
            "guard": {"cause": "TIMEOUT", "exit_reason": "ABORTED_BY_DISK_GUARD", "duration_s": 122.8},
            "provenance": {"instrumentation_core_sha256": hashlib.sha256(b"source").hexdigest()},
        }
        self.source = '''
if (w3_198_ecd40_continuation_armed) {
  if (x) { w3_198_log_stop("mapping_or_process_changed"); }
  else if (ip_point == w3_198_ecd40_target_runtime) {
    w3_198_ecd40_continuation_armed = false;
  } else if (candidate_link_va < 0x000ecd40 &&
             w3_198_ecd40_continuation_steps < 5) {
  } else { w3_198_log_stop("five_step_cap"); }
}
if (target_context && target_main_rebase && block &&
'''

    def analyze_fixture(self):
        import hashlib
        from unittest.mock import patch
        with patch("tools.w3_290_ecd40_stall_audit.CORE") as core:
            core.is_file.return_value = True
            core.read_bytes.return_value = b"source"
            return analyze(self.raw, self.capture, self.source)

    def test_hash_and_ordered_steps(self):
        result = self.analyze_fixture()
        self.assertEqual(result["original_observations"]["last_step_derived_target"]["link_va"], "0x000ECD40")
        self.assertEqual(len(result["original_observations"]["w3_198_continuation_steps"]), 5)

    def test_trace_hash_mismatch_fails_closed(self):
        self.capture["trace"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.analyze_fixture()

    def test_later_latches_must_be_absent_for_timeout_case(self):
        import json
        from unittest.mock import patch
        self.rows.append(row("w3_278_branch_target", 99, link_va=0xAE2E3))
        self.raw = ("\n".join(json.dumps(r) for r in self.rows) + "\n").encode()
        import hashlib
        self.capture["trace"].update(sha256=hashlib.sha256(self.raw).hexdigest(), bytes=len(self.raw), rows=len(self.rows))
        with patch("tools.w3_290_ecd40_stall_audit.CORE") as core:
            core.is_file.return_value = True
            core.read_bytes.return_value = b"source"
            with self.assertRaisesRegex(ValueError, "premise changed"):
                analyze(self.raw, self.capture, self.source)

    def test_target_hit_disarms_without_stop_logging(self):
        result = self.analyze_fixture()
        self.assertTrue(result["source_observations"]["target_hit_disarms_continuation"])
        self.assertFalse(result["source_observations"]["target_hit_logs_stop_event"])
        self.assertEqual(result["assessment"]["whether_target_hit_reentry_was_processed"], "UNKNOWN: no event is emitted by the source on that branch, and the trace ends before a later checkpoint confirms re-entry")

    def test_timeout_is_not_attributed_to_instrumentation_or_framebuffer(self):
        result = self.analyze_fixture()
        self.assertFalse(result["assessment"]["cause_attributed_to_single_step_instrumentation"])
        self.assertFalse(result["assessment"]["framebuffer_verified"])


if __name__ == "__main__":
    unittest.main()
