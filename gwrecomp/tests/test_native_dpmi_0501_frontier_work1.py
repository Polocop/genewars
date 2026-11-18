import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeDpmi0501FrontierTests(unittest.TestCase):
    def test_request_construction_and_measured_response(self):
        data = json.loads((ROOT / "evidence/native_dpmi_0501_frontier_work1.json").read_text())
        self.assertEqual(data["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(data["closure"]["dynamic_endpoint_observed"]["trap_va"], "0x000C3CC1")
        self.assertEqual(data["request_construction"]["observed_request"]["eax"], "0x00000501")
        self.assertEqual(data["request_construction"]["observed_request"]["ecx"], "0x00008000")
        self.assertEqual(data["bridge_and_runtime"]["verified_response"]["eax"], "0x00008012")
        self.assertTrue(data["bridge_and_runtime"]["verified_response"]["carry"])
        self.assertEqual(data["bridge_and_runtime"]["new_runtime_semantics_added"], False)
        capture = data["native_state_capture"]
        self.assertEqual(capture["flags"]["flag_k"], "0x00000003")
        self.assertEqual(capture["segments"]["cs"], "0x000C")
        self.assertEqual(capture["segments"]["ds"], "0x0014")
        self.assertEqual(capture["stack_words_at_esp"][6], "0xDEAD0000")
        self.assertEqual(capture["missing_items"], [])
        self.assertTrue((ROOT / capture["gdb_capture"]).is_file())
        gdb = (ROOT / capture["gdb_capture"]).read_text(errors="replace")
        for frame in ("in sub_000C3CA9", "in sub_000C3D7A", "in sub_000C3E2A", "in gw_entry_start"):
            self.assertIn(frame, gdb)

    def test_lift_contains_measured_call_chain_and_ax_setup(self):
        source = (ROOT / "build/entry_path_closure.c").read_text()
        for pattern in (
            r"RECOMP_CALL\(sub_000C3D7A\); /\* 0x000C3E54: call 0xc3d7a \*/",
            r"RECOMP_CALL\(sub_000C3CA9\); /\* 0x000C3DB0: call 0xc3ca9 \*/",
            r"RECOMP_CALL\(sub_000C3A8A\); /\* 0x000C3CB8: call 0xc3a8a \*/",
            r"SET_HI8\(eax, 5\); /\* 0x000C3CBD: mov ah, 5 \*/",
            r"SET_LO8\(eax, 1\); /\* 0x000C3CBF: mov al, 1 \*/",
            r"gw_interrupt_dispatch\(0x31u, 0x000C3CC1u\)",
        ):
            self.assertRegex(source, pattern)

    def test_site_local_callback_asserts_preservation(self):
        source = (ROOT / "tests/test_native_guest_image.c").read_text()
        for name in ("alloc_req_flag_k", "alloc_req_flag_a", "alloc_req_flag_b", "alloc_req_cs",
                     "alloc_req_ds", "alloc_req_es", "alloc_req_ss", "alloc_stack_words"):
            self.assertIn(name, source)
        self.assertIn("g_flag_k==alloc_req_flag_k", source)
        self.assertIn("g_seg_ds==alloc_req_ds", source)

    def test_existing_runtime_branch_is_used_and_preserves_registers(self):
        runtime = (ROOT / "runtime/gw_dos_services.c").read_text()
        self.assertIn("if (!services->allocation_configured)", runtime)
        self.assertIn("g_eax = (g_eax & 0xffff0000u) | 0x8012u;", runtime)
        self.assertIn("g_flag_cf = 1;", runtime)
        run = json.loads((ROOT / "evidence/native_w1_036_ax0501_resume.json").read_text())
        service = run["native_generated_c_progress"]["dpmi_linear_allocation"]
        self.assertEqual(service["response_eax"], "0x00008012")
        self.assertEqual(service["carry"], 1)
        for reg in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
            self.assertEqual(service["response_" + reg], service["request_" + reg], reg)


if __name__ == "__main__":
    unittest.main()
