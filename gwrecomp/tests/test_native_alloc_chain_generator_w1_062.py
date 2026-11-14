import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class AllocatorChainGeneratorProbeTests(unittest.TestCase):
    def test_probe_targets_are_exact_and_opt_in(self):
        source = (ROOT / "tools" / "lift_entry_closure.py").read_text(encoding="utf-8")
        self.assertIn("alloc_call_sites={0x000C3E54:0x000C3D7A,0x000C3DB0:0x000C3CA9}", source)
        self.assertIn("GW_NATIVE_CAPTURE_ALLOC_CALLSITE(g_cur_func", source)
        self.assertIn("#ifdef GW_NATIVE_CAPTURE_ALLOC_CHAIN", source)
        self.assertIn("RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); gw_native_capture_alloc_callsite", source)

    def test_existing_callsite_hook_remains_separate(self):
        source = (ROOT / "tools" / "lift_entry_closure.py").read_text(encoding="utf-8")
        self.assertIn("RECOMP_CALL(sub_000C896A)", source)
        self.assertIn("RECOMP_CALL\\((sub_000C3D7A|sub_000C3CA9)\\)", source)

    def test_generated_closure_contains_only_two_targeted_probe_sites(self):
        generated = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
        expected = (
            "GW_NATIVE_CAPTURE_ALLOC_CALLSITE(g_cur_func, 0x000C3D7Au, 0x000C3E54u)",
            "GW_NATIVE_CAPTURE_ALLOC_CALLSITE(g_cur_func, 0x000C3CA9u, 0x000C3DB0u)",
        )
        for marker in expected:
            self.assertEqual(generated.count(marker), 1)


if __name__ == "__main__":
    unittest.main()
