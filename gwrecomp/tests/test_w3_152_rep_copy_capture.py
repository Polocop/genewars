import unittest
from pathlib import Path
from tools.w3_152_capture_runner import bounded_rep_slice, find

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_152_capture_runner.py"


class RepCopyCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_rep_budget_boundaries(self):
        self.assertIsNone(bounded_rep_slice(0))
        self.assertIsNone(bounded_rep_slice(1))
        self.assertEqual(bounded_rep_slice(2), 1)
        self.assertEqual(bounded_rep_slice(0x3E80), 0x3E7F)
        self.assertEqual(bounded_rep_slice(0x40000), 0x3FFFF)
        self.assertIsNone(bounded_rep_slice(0x40001))

    def test_pre_site_is_latched_and_saved_before_record(self):
        self.assertIn("!w3_151_copy_pre_seen", self.source)
        pre_save = self.source.index("w3_151_copy_source_start = reg_esi;")
        record = self.source.index("const auto record =", pre_save)
        self.assertLess(pre_save, record)
        self.assertIn("w3_151_copy_pre_seen = true;", self.source)

    def test_probe_budget_is_local_to_bounded_rep_sites(self):
        self.assertIn("w3_151_copy_probe_window && w3_151_copy_pre_seen", self.source)
        self.assertIn("candidate_link_va == 0x000a0013 || candidate_link_va == 0x000a005d", self.source)
        self.assertIn("reg_ecx >= 2 && reg_ecx <= 0x00040000", self.source)
        self.assertIn("CPU_Cycles = static_cast<int32_t>(reg_ecx - 1)", self.source)
        self.assertIn("w3_151_copy_probe_window ||", self.source)

    def test_sample_stays_descriptor_and_physical_memory_bounded(self):
        self.assertIn("copy_length < 16 ? copy_length : 16", self.source)
        self.assertIn("w3_151_copy_source_bounds_valid", self.source)
        self.assertIn("w3_151_copy_destination_bounds_valid", self.source)
        self.assertIn("MEM_TotalPages()", self.source)

    def test_synthetic_checkpoint_selection_and_guard_caps(self):
        rows = [
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_151_COPY_NONVESA_PRE", "link_va": 0xA0013},
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_151_COPY_NONVESA_PRE", "link_va": 0xA0013},
        ]
        self.assertEqual(find(rows, "W3_151_COPY_NONVESA_PRE", 0xA0013), rows[0])
        for token in ('str(GUARD), "run"', '"--timeout-s", "30"',
                      '"--max-file-text-mib", "1"', '"--host-floor-gib", "100"',
                      '"sample_max_bytes": 16', 'result["framebuffer_or_visible_output_proven"] = False'):
            self.assertIn(token, self.runner)


if __name__ == "__main__":
    unittest.main()
