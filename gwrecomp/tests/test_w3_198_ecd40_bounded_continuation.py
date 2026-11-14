"""Synthetic state-machine and bounded source checks for W3-198."""
import unittest

from tools.w3_198_ecd40_bounded_continuation import (
    MAX_ADDITIONAL_STEPS, SOURCE, after_step, inspect_source, next_action, runtime_target,
)


class BoundedEcd40ContinuationTests(unittest.TestCase):
    def test_runtime_mapping_uses_measured_rebase(self):
        self.assertEqual(runtime_target(0x1EB000), 0x2D7D40)
        with self.assertRaises(ValueError):
            runtime_target(0)

    def test_target_stops_before_execution_and_rejects_wrong_context(self):
        target = runtime_target(0x1EB000)
        self.assertEqual(next_action(target, 0x1EB000, 7811, 7811, target, 5), "stop_at_target")
        self.assertEqual(next_action(0x1EB000 + 0xECD31, 0x1EB000, 1, 7811, target, 0), "context_changed")
        self.assertEqual(next_action(0x1EB000 + 0xEC000, 0x1EB000, 7811, 7811, target, 0), "path_diverged")

    def test_five_steps_reach_target_without_executing_target_instruction(self):
        rebase = 0x1EB000
        target = runtime_target(rebase)
        links = [0xECD31, 0xECD34, 0xECD3A, 0xECD3C, 0xECD3E, 0xECD40]
        count = 0
        for before_link, after_link in zip(links, links[1:]):
            action = next_action(rebase + before_link, rebase, 7811, 7811, target, count)
            self.assertEqual(action, "step_once")
            count, result = after_step(rebase + before_link, rebase + after_link,
                                      rebase, target, count)
        self.assertEqual(count, MAX_ADDITIONAL_STEPS)
        self.assertEqual(result, "target_pending_checkpoint")
        self.assertEqual(next_action(target, rebase, 7811, 7811, target, count), "stop_at_target")

    def test_step_cap_divergence_and_core_exit(self):
        rebase = 0x1EB000
        target = runtime_target(rebase)
        self.assertEqual(next_action(rebase + 0xECD31, rebase, 7811, 7811, target, 5), "step_cap")
        self.assertEqual(after_step(rebase + 0xECD31, rebase + 0xED000,
                                    rebase, target, 0)[1], "path_diverged")
        self.assertEqual(after_step(rebase + 0xECD31, rebase + 0xECD34,
                                    rebase, target, 0, normal_core_return=1)[1], "normal_core_exit")

    def test_source_contains_psp_mapping_cap_and_target_guards(self):
        result = inspect_source(SOURCE.read_text(encoding="utf-8"))
        self.assertTrue(result["all_checks_pass"])


if __name__ == "__main__":
    unittest.main()
