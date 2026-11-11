"""Assert diagnostic completeness of the persisted native unsupported INT."""
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dos_ah43_frontier_work2.json"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def keyed_line(stdout, prefix):
    line = next((line for line in stdout.splitlines() if line.startswith(prefix + " ")), None)
    if line is None:
        raise AssertionError(f"missing diagnostic line {prefix}")
    return dict(field.split("=", 1) for field in line.split()[1:] if "=" in field)


class NativeFrontierDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        cls.progress = cls.evidence["native_generated_c_progress"]
        cls.frontier = cls.progress["next_frontier"]

    def test_evidence_is_pinned_native_ah44_frontier_with_full_guest_state(self):
        self.assertEqual(self.evidence["target_sha256"], TARGET_SHA256)
        self.assertTrue(self.evidence["passed"])
        self.assertIn("recompiled C closure", self.progress["execution_model"])
        self.assertIn("independent of the Unicorn original-byte replay",
                      self.progress["execution_model"])
        f = self.frontier
        self.assertEqual(f["event"], "interrupt_trap")
        self.assertEqual(int(f["vector"], 16), 0x21)
        self.assertEqual(int(f["eax"], 16), 0x4400)
        self.assertEqual((int(f["eax"], 16) >> 8) & 0xff, 0x44)
        self.assertEqual(int(f["eax"], 16) & 0xff, 0)
        for reg in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
            self.assertRegex(f[reg], r"^0x[0-9A-Fa-f]{8}$")
        self.assertRegex(f["instruction_va"], r"^0x[0-9A-Fa-f]{8}$")
        self.assertRegex(f["function_va"], r"^0x[0-9A-Fa-f]{8}$")
        for seg in ("cs", "ds", "es", "ss"):
            self.assertRegex(f[seg], r"^0x[0-9A-Fa-f]{4}$")
        for flag in ("flag_k", "flag_a", "flag_b", "flag_cf"):
            self.assertIn(flag, f)
        # EDX/ESI are retained as raw values. This test does not dereference them.
        self.assertEqual(f["edx"], "0x0010A83C")
        self.assertEqual(f["esi"], "0x0010A83C")

    def test_exception_snapshot_includes_extended_segments_and_runtime_maps(self):
        stdout = self.evidence["stdout"]
        cpu = keyed_line(stdout, "NATIVE_FRONTIER_CPU")
        for field in ("eip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                      "flag_k", "flag_a", "flag_b", "flag_cf", "cs", "ds", "es", "fs", "gs", "ss",
                      "cs_base", "ds_base", "es_base", "fs_base", "gs_base", "ss_base",
                      "trap_vector", "trap_eip"):
            self.assertIn(field, cpu)
        descriptors = [line for line in stdout.splitlines()
                       if line.startswith("NATIVE_FRONTIER_DESCRIPTOR ")]
        self.assertGreaterEqual(len(descriptors), 2)
        for line in descriptors:
            descriptor = dict(field.split("=", 1) for field in line.split()[1:])
            self.assertTrue({"selector", "base", "limit"}.issubset(descriptor))
        alloc = keyed_line(stdout, "NATIVE_FRONTIER_ALLOC")
        for field in ("dos_configured", "dos_begin", "dos_end", "dos_cursor",
                      "selector_begin", "selector_cursor", "linear_configured",
                      "linear_cursor", "linear_end", "measured_ah48_active", "measured_ah48_value"):
            self.assertIn(field, alloc)


if __name__ == "__main__":
    unittest.main()
