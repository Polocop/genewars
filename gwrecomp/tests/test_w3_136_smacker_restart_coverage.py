import unittest

from tools.w3_136_smacker_restart_coverage import CORE, TARGETS, inspect_source


class W3136SmackerRestartCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8", errors="replace")
        cls.coverage = inspect_source(cls.source)

    def test_all_named_smacker_sites_are_restart_candidates(self):
        self.assertTrue(self.coverage["selected_gate_found"])
        for name in TARGETS:
            with self.subTest(name=name):
                self.assertTrue(self.coverage[f"target_{name}"])

    def test_dynamic_callback_requires_valid_armed_sample(self):
        self.assertTrue(self.coverage["dynamic_callback_armed_and_valid"])
        gate = self.source.split("const bool selected_capture_site =", 1)[1].split(";", 1)[0]
        self.assertIn("w3_133_capture_armed && w3_133_draw_callback_valid", gate)

    def test_event_caps_remain_bounded(self):
        self.assertTrue(self.coverage["target_event_cap"])
        self.assertTrue(self.coverage["target_event_scope"])


if __name__ == "__main__":
    unittest.main()
