import unittest
from pathlib import Path

from tools.w3_144_restart_coverage import TARGETS, audit_source, restart_step


SOURCE_PATH = Path(
    "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
)


class RestartCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.coverage = audit_source(cls.source)

    def test_branch_destinations_are_selected_and_checkpointed(self):
        self.assertTrue(all(self.coverage["selected_capture_sites"].values()))
        self.assertTrue(all(self.coverage["checkpoint_names_present"].values()))
        self.assertTrue(self.coverage["trace_candidate_gates_checkpoint_evaluation"])
        self.assertTrue(self.coverage["natural_entry_arms_window"])
        self.assertTrue(self.coverage["first_result_disarms_window"])

    def test_restart_window_requires_natural_armed_mapped_target_context(self):
        for kwargs in (
            {"target_context": False, "mapping_known": True, "armed": True, "result_seen": False},
            {"target_context": True, "mapping_known": False, "armed": True, "result_seen": False},
            {"target_context": True, "mapping_known": True, "armed": False, "result_seen": False},
            {"target_context": True, "mapping_known": True, "armed": True, "result_seen": True},
        ):
            self.assertFalse(restart_step(0xAE39A, **kwargs)["probe_window"])

    def test_first_target_captures_once_then_disarms(self):
        for address, name in TARGETS.items():
            result = restart_step(address, target_context=True, mapping_known=True,
                                  armed=True, result_seen=False)
            self.assertEqual(result["checkpoint"], name)
            self.assertFalse(result["armed_after"])
            self.assertTrue(result["result_seen_after"])
            later = restart_step(address, target_context=True, mapping_known=True,
                                 armed=result["armed_after"],
                                 result_seen=result["result_seen_after"])
            self.assertFalse(later["probe_window"])

    def test_window_and_event_caps_are_narrow_and_bounded(self):
        self.assertFalse(restart_step(0xAE307, target_context=True, mapping_known=True,
                                      armed=True, result_seen=False)["probe_window"])
        self.assertTrue(restart_step(0xAE308, target_context=True, mapping_known=True,
                                     armed=True, result_seen=False)["probe_window"])
        self.assertTrue(restart_step(0xAE4CE, target_context=True, mapping_known=True,
                                     armed=True, result_seen=False)["probe_window"])
        self.assertFalse(restart_step(0xAE4CF, target_context=True, mapping_known=True,
                                      armed=True, result_seen=False)["probe_window"])
        self.assertTrue(self.coverage["event_cap_present"])
        self.assertFalse(self.coverage["guest_state_mutation_in_probe"])


if __name__ == "__main__":
    unittest.main()
