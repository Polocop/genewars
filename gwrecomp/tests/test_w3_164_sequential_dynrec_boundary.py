import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
DECODER = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h"
RESULT = ROOT / "evidence/w3_163_wscreen_link_redispatch.json"


def checkpoint_would_be_seen(dispatch_pc, candidates):
    """Synthetic model of restart_core-only candidate evaluation."""
    return dispatch_pc in candidates


class SequentialDynrecBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = CORE.read_text(encoding="utf-8")
        cls.decoder = DECODER.read_text(encoding="utf-8")
        cls.result = json.loads(RESULT.read_text(encoding="utf-8"))

    def test_restart_checks_are_at_dispatch_and_range_fallback_is_scoped(self):
        restart = self.core.index("restart_core:")
        candidate = self.core.index("const bool w3_160_gate_117662_candidate", restart)
        fallback = self.core.index("if (w3_143_postopen_probe_window ||", candidate)
        self.assertLess(restart, candidate)
        self.assertLess(candidate, fallback)
        self.assertIn("candidate_link_va >= 0x00094cda && candidate_link_va <= 0x00094dc1",
                      self.core)
        self.assertIn("w3_161_probe_window ||", self.core)

    def test_non_probe_predecessor_can_create_multi_instruction_block(self):
        target_flags_start = self.core.index("in_target_function = trace_candidate ||")
        target_flags_end = self.core.index("if (trace_candidate)", target_flags_start)
        target_flags = self.core[target_flags_start:target_flags_end]
        self.assertNotIn("w3_161_probe_window", target_flags)
        create_block = self.core.index("CreateCacheBlock(chandler, ip_point,")
        self.assertIn("in_target_function ? 1 : 32", self.core[create_block:create_block + 150])
        loop = self.decoder.index("while (max_opcodes--) {", self.decoder.index("static CacheBlock * CreateCacheBlock"))
        branch_end = self.decoder.index("goto finish_block;", self.decoder.index("/* Short conditional jumps */", loop))
        self.assertGreater(branch_end, loop)

    def test_cached_link_redirect_does_not_check_internal_sequential_pcs(self):
        link_case = self.core.index("case BR_Link1:")
        self.assertIn("linked_candidate_link_va >= 0x00094cda", self.core[link_case:])
        self.assertIn("cache.block.running->LinkTo(ret==BR_Link2,block);", self.core[link_case:])
        # A decoded block can execute start..start+n in one run_block call;
        # restart_core sees only its entry PC, not each sequential instruction.
        candidates = {0x94CE1, 0x94CEE, 0x94DBC}
        self.assertFalse(checkpoint_would_be_seen(0x94CDA, candidates))
        self.assertTrue(0x94CE1 in range(0x94CDA, 0x94CE1 + 1))
        self.assertFalse(checkpoint_would_be_seen(0x94CDA, candidates))

    def test_original_loader_pair_does_not_supply_gate_values_or_prove_link_path(self):
        self.assertTrue(self.result["validation"]["loader_entry_return_pair_observed"])
        self.assertFalse(self.result["validation"]["gate_globals_and_flags_observed"])
        self.assertFalse(self.result["validation"]["callsite_checkpoint_observed"])
        self.assertFalse(self.result["interpretation"]["br_link_redispatch_activation_measured"])
        self.assertTrue(self.result["capture_complete"])


if __name__ == "__main__":
    unittest.main()
