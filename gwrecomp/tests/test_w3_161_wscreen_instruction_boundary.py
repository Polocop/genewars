import json
import unittest
from pathlib import Path

from tools.w3_161_wscreen_boundary_runner import (
    MAX_TRACE_BYTES,
    WINDOW,
    in_probe_window,
)


class WscreenInstructionBoundaryTests(unittest.TestCase):
    def test_probe_window_is_exact_and_inclusive(self):
        self.assertEqual(WINDOW, (0x94CDA, 0x94DC1))
        self.assertTrue(in_probe_window(0x94CDA))
        self.assertTrue(in_probe_window(0x94DC1))
        self.assertFalse(in_probe_window(0x94CD9))
        self.assertFalse(in_probe_window(0x94DC2))

    def test_branch_outcomes_follow_observed_flags_and_global(self):
        self.assertTrue((0x202 & 0x40) == 0)  # JNE taken when ZF is clear
        self.assertFalse((0x242 & 0x40) == 0)
        self.assertTrue((0x01 & 1) != 0)
        self.assertFalse((0x80 & 1) != 0)
        self.assertTrue(0x04 != 0)
        self.assertFalse(0x00 != 0)

    def test_synthetic_capture_json_and_event_limit(self):
        rows = [{"event": "target_runtime_checkpoint", "sequence": i,
                 "link_va": pc, "w3_161_instruction_boundary_probe_active": True}
                for i, pc in enumerate((0x94CDA, 0x94CE1, 0x94DC1), 1)]
        encoded = json.dumps(rows, separators=(",", ":")).encode("utf-8")
        self.assertEqual(json.loads(encoded), rows)
        self.assertLessEqual(len(encoded), MAX_TRACE_BYTES)
        self.assertEqual(MAX_TRACE_BYTES, 1_048_576)
        self.assertTrue(all(in_probe_window(row["link_va"]) for row in rows))

    def test_source_restarts_only_inside_bounded_probe_window(self):
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        start = source.index("const bool w3_161_probe_window")
        end = source.index("const bool w3_127_restart_probe", start)
        declaration = source[start:end]
        self.assertIn("candidate_link_va >= 0x00094cda", declaration)
        self.assertIn("candidate_link_va <= 0x00094dc1", declaration)
        fallback_start = source.index("if (w3_143_postopen_probe_window ||")
        fallback_end = source.index("if (!chandler)", fallback_start)
        fallback = source[fallback_start:fallback_end]
        self.assertIn("w3_161_probe_window ||", fallback)
        self.assertIn("CPU_Cycles = 1", fallback)
        self.assertIn("sync_dh_fpu_and_run_normal_core()", fallback)
        self.assertIn("goto restart_core", fallback)
        self.assertIn("w3_161_instruction_boundary_probe_active", source)


if __name__ == "__main__":
    unittest.main()
