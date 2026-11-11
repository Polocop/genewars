import unittest

from tools.w3_191_ecd40_cache_probe import build, should_step


class Ecd40CacheProbeTests(unittest.TestCase):
    def test_probe_is_bounded_and_latched(self):
        result = build()
        self.assertTrue(result["all_checks_pass"])
        self.assertEqual(result["target_link_vas"][-1], "0xecd40")
        self.assertTrue(all(result["checks"].values()))

    def test_synthetic_cache_span_decisions_are_one_shot(self):
        self.assertTrue(should_step(True, 0x2d7cf0, 0x2d7c20, False))
        self.assertFalse(should_step(True, 0x2d7cf0, 0x2d7cf0, False))
        self.assertFalse(should_step(True, 0x2d7c20, 0x2d7cf0, True))
        self.assertFalse(should_step(False, 0x2d7c20, 0x2d7cf0, False))


if __name__ == "__main__":
    unittest.main()
