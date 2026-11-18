from __future__ import annotations

import json
import unittest

from tools.w3_300_activation_capture import analyze, parse_trace, validate_first_hit


def event(name, **fields):
    return (json.dumps({"event": name, **fields}, separators=(",", ":")) + "\n").encode()


class W3300ActivationTests(unittest.TestCase):
    def test_marker_absence_does_not_claim_sound_path_absence(self):
        rows = parse_trace(event("target_runtime_checkpoint", checkpoint="MAIN_ENTRY_CHECKPOINT",
                                 link_va=0x93F30))
        self.assertEqual(analyze(rows)["classification"], "MAIN_ACTIVATION_MARKER_ABSENT")

    def test_main_marker_without_sites_localizes_bounded_run(self):
        rows = parse_trace(event("W3_300_MAIN_HOOK_ARMED", ordinal=1, code_rebase=0x1EB000) +
                           event("target_runtime_checkpoint", checkpoint="VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
                                 link_va=0x9FDF9))
        self.assertEqual(analyze(rows)["classification"],
                         "MAIN_ACTIVE_SOUND_SITES_NOT_DISPATCHED_IN_CAPTURE")

    def test_dispatch_without_sound_row_is_recorder_gap(self):
        rows = parse_trace(event("W3_300_MAIN_HOOK_ARMED", ordinal=1) +
                           event("W3_300_SITE_DISPATCH", ordinal=2, link_va=0xAE308))
        validate_first_hit(rows)
        summary = analyze(rows)
        self.assertEqual(summary["classification"], "DISPATCH_SEEN_W3_298_RECORDER_GAP")
        self.assertEqual(summary["dispatch_site_links"], ["0xae308"])

    def test_paired_original_rows_classify_as_observed(self):
        rows = parse_trace(event("W3_300_MAIN_HOOK_ARMED", ordinal=1) +
                           event("W3_300_SITE_DISPATCH", ordinal=2, link_va=0xAE308) +
                           event("W3_298_SOUND_PIT_CHECKPOINT", ordinal=1,
                                 checkpoint="PLAY_SMK_DIRECT_ENTRY", link_va=0xAE308))
        self.assertEqual(analyze(rows)["classification"], "PAIRED_ORIGINAL_SOUND_CAPTURE")

    def test_total_cap_and_first_hit_duplicates(self):
        oversized = b"".join(event("W3_300_SITE_DISPATCH", ordinal=i, link_va=i)
                              for i in range(49))
        with self.assertRaisesRegex(ValueError, "exceeds 48"):
            parse_trace(oversized)
        dupes = parse_trace(event("W3_300_SITE_DISPATCH", ordinal=1, link_va=0xAE308) +
                            event("W3_300_SITE_DISPATCH", ordinal=2, link_va=0xAE308))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_first_hit(dupes)


if __name__ == "__main__":
    unittest.main()
