import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools" / "probes" / "unicorn_int21.py"
spec = importlib.util.spec_from_file_location("unicorn_int21", PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class UnicornEntryProbeTests(unittest.TestCase):
    def test_synthetic_int21_hook_stops_with_register_snapshot(self):
        result = probe.synthetic_probe()
        self.assertTrue(result["pass"], result)
        self.assertEqual(result["interrupts"][0]["vector"], 0x21)
        self.assertEqual(result["interrupts"][0]["eip_int_opcode_assumption"], "0x00010005")
        self.assertEqual(result["interrupts"][0]["registers"]["eax"], "0x00000021")
        self.assertTrue(result["port_hooks_installed"])

    def test_real_le_entry_reaches_first_dos_interrupt(self):
        result = probe.target_probe(5000)
        self.assertEqual(result["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(result["stop_reason"], "instruction_limit")
        self.assertEqual(result["executed_instruction_count"], 5000)
        self.assertEqual(result["instructions"][1]["eip"], "0x001af96c")
        self.assertEqual(result["instructions"][1]["cs"], "0x000c")
        self.assertEqual(result["interrupts"][0]["service"], "dos21.get_version")
        self.assertEqual(result["interrupts"][0]["registers"]["eax"], "0x00003000")
        self.assertTrue(result["interrupts"][0]["handled"])
        self.assertEqual([i["service"] for i in result["interrupts"][:5]], [
            "dos21.get_version", "dos21.dos4g_install_check", "dpmi31.get_segment_base",
            "dpmi31.allocate_memory", "dpmi31.simulate_real_mode_interrupt",
        ])
        self.assertTrue(all(i["handled"] for i in result["interrupts"][:5]))
        self.assertIsNone(result["first_unsupported"])
        self.assertTrue(result["port_hooks_installed"])
        self.assertEqual(result["gdt_setup"], "ok")
        self.assertEqual(result["initial_segments"]["ds"], "0x0014")
        self.assertTrue(result["initial_gprs_are_synthetic"])


if __name__ == "__main__":
    unittest.main()

