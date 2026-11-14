import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class NativeMscdexFrontierTests(unittest.TestCase):
    def test_original_byte_contract_matches_exact_guest_request_and_return(self):
        evidence = json.loads((ROOT / "evidence" / "dpmi_0300_frame_work2.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        request = next(x for x in evidence["real_mode_0300"] if x["interrupt_eip"] == "0x001d23a7")
        self.assertEqual(request["real_mode_vector"], 0x2F)
        self.assertEqual(request["frame"]["registers"]["eax"], 0x1500)
        self.assertEqual(request["frame"]["registers"]["ebx"], 0)
        returned = next(x for x in evidence["interrupts"] if x["eip_int_opcode_assumption"] == "0x001d23a7")
        after = returned["real_mode_interrupt"]["registers_after"]
        self.assertEqual((after["eax"], after["ebx"], after["ecx"]),
                         ("0x00001500", "0x00000000", "0x00000000"))
        self.assertTrue(returned["handled"])

    def test_native_provider_is_scoped_to_measured_empty_inventory_check(self):
        harness = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        driver = (ROOT / "tests" / "test_native_guest_image.py").read_text(encoding="utf-8")
        self.assertIn("vector==0x2fu && (uint16_t)registers->eax==0x1500u", harness)
        self.assertIn("(uint16_t)registers->ebx==0u", harness)
        self.assertIn("registers->ecx&=0xffff0000u", harness)
        self.assertIn("va==0x000D23A7u", harness)
        self.assertIn("test_native_mscdex_install_check_provider()", harness)
        self.assertIn("NATIVE_DPMI0300_INT2F1500", harness)
        self.assertIn('"NATIVE_DPMI0300_INT2F1500 "', driver)


if __name__ == "__main__":
    unittest.main()
