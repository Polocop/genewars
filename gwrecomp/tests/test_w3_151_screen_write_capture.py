import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RUNNER = ROOT / "tools/w3_151_capture_runner.py"


class ScreenWriteCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CORE.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")

    def test_selected_sites_match_exact_static_audit(self):
        selected = self.source.split("const bool selected_capture_site =", 1)[1].split(
            "// Before MAIN's runtime mapping", 1)[0]
        for address in ("0x000a0000", "0x000a0013", "0x000a0015", "0x000a005d", "0x000a005f"):
            self.assertIn(f"candidate_link_va == {address}", selected)

    def test_probe_arms_only_at_natural_swap_entry_and_has_narrow_window(self):
        self.assertIn("w3_151_copy_probe_armed = true;", self.source)
        self.assertIn("w3_151_copy_probe_armed &&", self.source)
        self.assertIn("candidate_link_va >= 0x0009ffe0 && candidate_link_va <= 0x000a008f", self.source)
        self.assertIn("w3_151_copy_probe_armed = false;", self.source)

    def test_sample_is_bounded_and_descriptor_checked(self):
        self.assertIn("copy_length < 16 ? copy_length : 16", self.source)
        self.assertIn("copy_es_descriptor.GetLimit()", self.source)
        self.assertIn("MEM_TotalPages()", self.source)
        self.assertIn("w3_151_copy_source_bounds_valid", self.source)
        self.assertIn("w3_151_copy_destination_bounds_valid", self.source)
        self.assertIn('w3_151_copy_sample_hex', self.source)

    def test_runner_uses_oracle_guard_and_strict_limits(self):
        for token in ('str(GUARD), "run"', '"--timeout-s", "30"',
                      '"--max-file-text-mib", "1"', '"--host-floor-gib", "100"',
                      '"sample_max_bytes": 16', 'result["framebuffer_or_visible_output_proven"] = False'):
            self.assertIn(token, self.runner)


if __name__ == "__main__":
    unittest.main()
