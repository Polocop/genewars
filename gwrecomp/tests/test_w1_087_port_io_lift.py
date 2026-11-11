"""Focused regression for x86-32 port-I/O translation in the Core lifter."""
import sys
import unittest
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = Path(__file__).resolve().parents[1]
LIFT_DIR = ROOT / "third_party" / "pcrecomp" / "tools" / "lift"
sys.path.insert(0, str(LIFT_DIR))
from lift32 import Lifter  # noqa: E402


class PortIOLiftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.md = Cs(CS_ARCH_X86, CS_MODE_32)
        cls.md.detail = True

    def lift(self, raw):
        instruction = next(self.md.disasm(raw, 0x000C427A))
        return instruction.mnemonic, "\n".join(Lifter().lift_instruction(instruction))

    def test_in_al_immediate_uses_byte_callback_and_preserves_upper_eax(self):
        mnemonic, code = self.lift(bytes((0xE4, 0x43)))
        self.assertEqual(mnemonic, "in")
        self.assertIn("gw_recomp_guest_instruction(0x000C427Au)", code)
        self.assertIn("gw_recomp_port_io(0u, (uint16_t)(0x43u), 1u", code)
        self.assertIn("SET_LO8(eax, _port_io_value)", code)
        self.assertNotIn("no port I/O", code)

    def test_in_eax_dx_uses_dword_callback(self):
        _, code = self.lift(bytes((0xED,)))
        self.assertIn("gw_recomp_port_io(0u, (uint16_t)(LO16(edx)), 4u", code)
        self.assertIn("eax = _port_io_value", code)

    def test_out_immediate_al_uses_byte_source(self):
        _, code = self.lift(bytes((0xE6, 0x43)))
        self.assertIn("gw_recomp_port_io(1u, (uint16_t)(0x43u), 1u", code)
        self.assertIn("(uint32_t)(LO8(eax))", code)

    def test_out_dx_eax_uses_dword_source(self):
        _, code = self.lift(bytes((0xEF,)))
        self.assertIn("gw_recomp_port_io(1u, (uint16_t)(LO16(edx)), 4u", code)
        self.assertIn("(uint32_t)(eax)", code)

    def test_string_port_io_is_explicitly_trapped_without_memory_guard_leak(self):
        _, code = self.lift(bytes((0x6E,)))  # OUTSB DX, [ESI]
        self.assertIn("gw_recomp_port_io(3u, (uint16_t)LO16(edx), 1u", code)
        self.assertNotIn("recomp_begin_memory_access", code)
        self.assertNotIn("no port I/O", code)

    def test_instruction_tick_is_emitted_for_each_lifted_instruction(self):
        _, code = self.lift(bytes((0x90,)))  # NOP
        self.assertTrue(code.startswith("if (!gw_recomp_guest_instruction(0x000C427Au)) return;"))


if __name__ == "__main__":
    unittest.main()
