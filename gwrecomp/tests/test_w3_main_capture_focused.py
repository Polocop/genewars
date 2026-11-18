import json
import unittest

from tools import w3_main_capture_runner as capture


class W3MainFocusedCaptureTests(unittest.TestCase):
    def test_preflight_explicitly_rejects_missing_file_size(self):
        env = capture.capture_environment({})
        del env["GWRECOMP_GW_FILE_SIZE"]
        with self.assertRaisesRegex(ValueError, "GWRECOMP_GW_FILE_SIZE"):
            capture.validate_capture_environment(env)

    def test_preflight_rejects_incorrect_file_size(self):
        env = capture.capture_environment({})
        env["GWRECOMP_GW_FILE_SIZE"] = "0"
        with self.assertRaisesRegex(ValueError, "hook would remain unarmed"):
            capture.validate_capture_environment(env)

    def test_complete_env_sets_exact_original_size_and_bounds(self):
        env = capture.capture_environment({})
        capture.validate_capture_environment(env)
        self.assertEqual(env["GWRECOMP_GW_FILE_SIZE"], "1251658")
        self.assertEqual(env["GWRECOMP_EXEC_TRACE_MAX_BYTES"], "524288")

    def test_main_candidate_signature_page_filter(self):
        self.assertTrue(capture.main_signature_candidate(0x29A96C))
        self.assertFalse(capture.main_signature_candidate(0x29A96D))
        # Page-offset candidates are cheap prefilters; bytes confirm the anchor.
        self.assertTrue(capture.main_signature_candidate(0x29A96C - 0x1000))
        self.assertTrue(capture.main_signature_matches(0x29A96C, "eb765741"))
        self.assertFalse(capture.main_signature_matches(0x29A96C - 0x1000, "00000000"))

    def test_rebase_cs_and_exact_main_entry(self):
        self.assertTrue(capture.main_anchor_matches(0x29A96C, 0x1EB000, 0x160, 0x160))
        self.assertFalse(capture.main_anchor_matches(0x29A96C, 0x1EB000, 0x150, 0x160))
        self.assertFalse(capture.main_anchor_matches(0x29A970, 0x1EB000, 0x160, 0x160))

    def test_checkpoint_filter_requires_exact_runtime_and_selected_link(self):
        self.assertTrue(capture.capture_site_matches(0x2AEE59, 0xC3E59, 0x1EB000, 0x160, 0x160))
        self.assertFalse(capture.capture_site_matches(0x2AEE5A, 0xC3E59, 0x1EB000, 0x160, 0x160))
        self.assertFalse(capture.capture_site_matches(0x2AEE59, 0xC3E59, 0x1EB000, 0x158, 0x160))
        self.assertFalse(capture.capture_site_matches(0x2AEE59, 0xC3E59, 0x1EB000, 0x160, 0x160 + 1))
        self.assertFalse(capture.capture_site_matches(0x2AEE59, 0xC3E5A, 0x1EB000, 0x160, 0x160))

    def test_guest_reads_are_length_and_limit_bounded(self):
        self.assertTrue(capture.guest_range_valid(0x80, 128, 0xFF))
        self.assertFalse(capture.guest_range_valid(0x80, 129, 0xFF))
        self.assertFalse(capture.guest_range_valid(0xFFFFFFFF, 8, 0xFFFFFFFF))
        self.assertFalse(capture.guest_range_valid(-1, 1, 0xFFFF))

    def test_targeted_sites_include_argv_and_main_and_are_small(self):
        self.assertIn(0xC8702, capture.CAPTURE_SITES)
        self.assertIn(0x93F30, capture.CAPTURE_SITES)
        self.assertLessEqual(len(capture.CAPTURE_SITES), 16)

    def test_checkpoint_json_and_size_are_bounded(self):
        record = {"event": "target_runtime_checkpoint", "checkpoint": "CRT_ARGV_LOAD",
                  "checkpoint_ordinal": 1, "phase": "crt-main-bridge",
                  "link_va": 0xC8702, "runtime": 0x2B7702, "cs": 0x160,
                  "elapsed_ms": 5500, "stack_words": [0] * 8}
        encoded = json.dumps(record, separators=(",", ":"))
        self.assertEqual(json.loads(encoded), record)
        self.assertLessEqual(len(encoded.encode("utf-8")), 2048)

    def test_cpp_has_early_filter_and_no_function_wide_ra_trace(self):
        source = capture.ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
        text = source.read_text(encoding="utf-8")
        self.assertIn("if (trace_candidate)", text)
        self.assertIn("candidate_link_va == 0x000c8702", text)
        self.assertIn("candidate_link_va == 0x00093f30", text)
        self.assertIn("in_target_function = trace_candidate", text)
        self.assertIn("static_cast<uint64_t>(reg_esp) + 31", text)
        self.assertIn("checkpoint_event_count < 32", text)
        self.assertIn("elapsed_ms", text)

    def test_old_ah48_ah49_stream_is_disabled(self):
        dos_source = (capture.ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/dos/dos.cpp").read_text(encoding="utf-8")
        self.assertNotIn("target_dos21_ah48_entry", dos_source)
        self.assertNotIn("target_dos21_ah49_entry", dos_source)
        self.assertNotIn("trace_target_alloc", dos_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
