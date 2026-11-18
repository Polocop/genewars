import unittest
from pathlib import Path

TARGETS = {
    0x94CE1: "w3_160_gate_117662_candidate",
    0x94CEE: "w3_160_gate_1174a4_candidate",
    0x94CF4: "w3_160_gate_fallthrough_candidate",
    0x94D9F: "w3_160_loader_block_candidate",
    0x94DBC: "w3_158_callsite_candidate",
}


def eligible(link_va: int, selected_capture_sites: set[int],
             target_context: bool, fresh_rebase: bool) -> bool:
    return target_context and fresh_rebase and link_va in selected_capture_sites


class WscreenGateCaptureEligibilityTests(unittest.TestCase):
    def test_exact_wscreen_gate_and_callsite_are_eligible(self):
        selected = set(TARGETS)
        for address in TARGETS:
            self.assertTrue(eligible(address, selected, True, True))

    def test_unrelated_pc_and_context_are_excluded(self):
        selected = set(TARGETS)
        self.assertFalse(eligible(0x94CE2, selected, True, True))
        self.assertFalse(eligible(0x94CE1, selected, False, True))
        self.assertFalse(eligible(0x94CE1, selected, True, False))

    def test_instrumented_source_includes_each_candidate_in_capture_filter(self):
        root = Path(__file__).resolve().parents[1]
        core = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        start = core.index("const bool selected_capture_site")
        end = core.index("// Before MAIN's runtime mapping", start)
        selected = core[start:end]
        for symbol in TARGETS.values():
            self.assertIn(symbol, selected)
        self.assertIn("target_context &&", core)
        self.assertIn("target_main_rebase", selected)

    def test_gate_measurements_stay_bound_to_exact_candidate_names(self):
        root = Path(__file__).resolve().parents[1]
        core = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        for checkpoint in ("W3_160_WSCREEN_GATE_117662",
                           "W3_160_WSCREEN_GATE_1174A4",
                           "W3_160_WSCREEN_GATE_FALLTHROUGH",
                           "W3_160_WSCREEN_LOADER_BLOCK",
                           "W3_158_WSCREEN_CALLSITE"):
            self.assertIn(checkpoint, core)
        self.assertIn("w3_160_global_117662_value", core)
        self.assertIn("w3_160_global_1174a4_value", core)
        self.assertIn("w3_160_branch_taken", core)


if __name__ == "__main__":
    unittest.main()
