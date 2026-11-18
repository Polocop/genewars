from __future__ import annotations

import unittest

from tools.w3_299_sound_hook_audit import analyze, child_inherits_parent_environment


class W3299SoundHookAuditTests(unittest.TestCase):
    def setUp(self):
        self.source = 'string_from_env("GWRECOMP_W3_298_CAPTURE") == "1"; W3_298_SOUND_PIT_CHECKPOINT'
        self.runner = '"GWRECOMP_W3_298_CAPTURE": "1"'
        self.guard = 'subprocess.Popen(argv, cwd=str(staging), stdout=subprocess.PIPE)'
        self.hashes = {"revision": "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f",
                       "source": "source", "binary": "binary", "recovery": "same",
                       "restored": "same", "trace": "trace"}
        self.checkpoints = [{"event": "target_runtime_checkpoint", "sequence": 4,
                             "checkpoint": "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
                             "link_va": 0x9FDF9, "eip": 0x28ADF9,
                             "data_rebase": 0x1DA000}]

    def test_guard_inheritance_detection(self):
        self.assertTrue(child_inherits_parent_environment(self.guard))
        self.assertFalse(child_inherits_parent_environment(
            'subprocess.Popen(argv, env={"PATH": "x"})'))

    def test_configured_but_unmarked_runtime_stays_ambiguous(self):
        result = analyze(self.source, self.runner, self.guard, b"W3_298_SOUND_PIT_CHECKPOINT",
                         self.checkpoints, {"evidence_level": "INCONCLUSIVE"},
                         {"cause": "TIMEOUT", "duration_s": 45, "sandbox_verified": True},
                         self.hashes)
        self.assertTrue(result["runner_sets_capture_env"])
        self.assertTrue(result["source_reads_capture_env"])
        self.assertTrue(result["compiled_binary_contains_probe_marker"])
        self.assertTrue(result["oracle_guard_child_inherits_environment"])
        self.assertFalse(result["runtime_activation_marker_present"])
        self.assertIn("unproven", result["runtime_activation_assessment"])
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertEqual(result["last_generic_checkpoint"]["link_va"], "0x9fdf9")

    def test_sound_site_overlap_requires_exact_link_va(self):
        hit = {"event": "target_runtime_checkpoint", "sequence": 5,
               "checkpoint": "test", "link_va": 0xAE308, "eip": 0,
               "data_rebase": 0}
        result = analyze(self.source, self.runner, self.guard, b"W3_298_SOUND_PIT_CHECKPOINT",
                         self.checkpoints + [hit], {}, {}, self.hashes)
        self.assertEqual(result["observed_target_sound_site_links"], ["0xae308"])

    def test_missing_environment_setting_is_localized_statically(self):
        result = analyze(self.source, "runner without flag", self.guard, b"probe",
                         [], {}, {}, self.hashes)
        self.assertEqual(result["runtime_activation_assessment"],
                         "static activation chain has a missing link")


if __name__ == "__main__":
    unittest.main()
