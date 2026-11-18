import unittest

from tools.w3_193_arm_ecd40_step import build, cache_target_seen, should_log_step


class ArmEcd40StepTests(unittest.TestCase):
    def test_source_wires_one_armed_pre_post_result(self):
        result = build()
        self.assertTrue(result["all_checks_pass"])
        self.assertTrue(all(result["checks"].values()))

    def test_pre_handler_cache_hit_does_not_arm_progress_step(self):
        self.assertTrue(cache_target_seen(False, False))
        self.assertFalse(should_log_step(True, False, False, False))

    def test_armed_step_is_one_shot_and_progress_latch_wins(self):
        self.assertFalse(cache_target_seen(False, True))
        self.assertTrue(should_log_step(True, True, False, False))
        self.assertFalse(should_log_step(True, True, False, True))
        self.assertFalse(should_log_step(True, True, True, False))
        self.assertFalse(should_log_step(False, True, False, False))


if __name__ == "__main__":
    unittest.main()
