"""Keep the W1-093 zero-header replay guard wired into the native harness."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class W1093RepeatHeapGuardTests(unittest.TestCase):
    def test_guard_stops_on_a_bounded_exact_guest_state_repeat(self):
        harness = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        start = harness.index("int gw_native_w1_093_repeat_guard(unsigned int guest_va)")
        end = harness.index("void gw_native_w1_092_instruction_observer", start)
        guard = harness[start:end]
        self.assertIn("guest_va!=0x000AE137u", guard)
        self.assertIn("seen_states[32768]", guard)
        self.assertIn("seen_slots[65536]", guard)
        self.assertIn("memcmp(&current,&seen_states[prior_index],sizeof current)==0", guard)
        self.assertIn("state_budget", guard)
        self.assertNotIn("header!=0u", guard)
        self.assertIn("NATIVE_W1_093_HEAP_WINDOW_ARM", guard)
        self.assertIn("NATIVE_W1_093_HEAP_WINDOW_WRITE", guard)
        for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "ds", "ds_base"):
            self.assertIn(register, guard)

    def test_replay_latches_a_repeat_guard_frontier_and_records_it(self):
        runtime = (ROOT / "runtime" / "recomp_context.c").read_text(encoding="utf-8")
        header = (ROOT / "runtime" / "recomp_context.h").read_text(encoding="utf-8")
        driver = (ROOT / "tests" / "test_native_guest_image.py").read_text(encoding="utf-8")
        harness = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        self.assertIn("gw_native_w1_093_repeat_guard(guest_va)", runtime)
        self.assertIn("GW_PORT_IO_TRAP_REPEATED_GUEST_STATE", runtime)
        self.assertIn("GW_PORT_IO_TRAP_REPEATED_GUEST_STATE = 5", header)
        self.assertIn('line.startswith("NATIVE_W1_093_REPEAT_GUARD ")', driver)
        self.assertIn('"kind":"repeated_guest_state_guard"', driver)
        self.assertIn("--capture-w1-094-heap-frontier", driver)
        self.assertIn("gwrecomp.native-heap-frontier-w1-094/v1", driver)
        self.assertIn('"NATIVE_DPMI_LINEAR_LOCK "', driver)
        self.assertIn("NATIVE_DPMI_LINEAR_LOCK ordinal=%u", harness)
        self.assertIn("g_eax==0x0600u", harness)
        self.assertIn("return gw_dos_services_callback(vector,va,services);", harness)
        validator = (ROOT / "tools" / "verify_w1_094_heap_frontier.py").read_text(encoding="utf-8")
        self.assertIn("identical_state_repeated", validator)
        self.assertIn("EXPECTED_TARGET", validator)


if __name__ == "__main__":
    unittest.main()
