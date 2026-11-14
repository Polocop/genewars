import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter

TARGET = ROOT / "evidence" / "genewars-1_1.exe"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


class RationalAllocCoreValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        cls.decoder.detail = True

    def lift_one(self, raw):
        insn = next(self.decoder.disasm(bytes.fromhex(raw), 0x000C3CDF))
        return "\n".join(Lifter().lift_instruction(insn))

    @staticmethod
    def generated_function(path):
        source = path.read_text(encoding="utf-8")
        start = source.index("void sub_000C3CA9(void) {")
        brace = source.index("{", start)
        depth = 0
        for index in range(brace, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    return source[start : index + 1]
        raise AssertionError(f"unclosed RationalAlloc_ body in {path}")

    def test_all_83_original_instructions_lift_identically_in_entry_artifacts(self):
        import hashlib
        import re

        def normalize_access_metadata(source):
            lines = []
            for line in source.splitlines():
                if ("gw_recomp_guest_instruction(" in line or
                    "recomp_begin_memory_access" in line or
                    "recomp_end_memory_access()" in line or
                    "recomp_memory_fault_pending()" in line or
                    "GW_NATIVE_CAPTURE_" in line):
                    continue
                if "/* 0x" in line and ": ret" in line:
                    address = line.split("/* 0x", 1)[1].split(":", 1)[0]
                    line = f"    RET_INSTRUCTION; /* 0x{address}: ret */"
                lines.append(line)
            return "\n".join(lines)

        self.assertEqual(hashlib.sha256(TARGET.read_bytes()).hexdigest(), TARGET_SHA256)
        image = load_le(TARGET)
        obj = image.objects[0]
        code = bytes(image.mem[obj.base - image.mem_base : obj.base - image.mem_base + obj.virtual_size])
        section = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
        function = Disassembler(code, 0, [section]).disassemble_function(0x000C3CA9)
        self.assertIsNotNone(function)
        self.assertEqual(function.end, 0x000C3D7A)
        self.assertEqual(sum(len(block.instructions) for block in function.blocks.values()), 83)
        function.name = "sub_000C3CA9"
        fresh = Lifter().lift_function(function)
        for relative in (
            "build/recomp_catalog_100_recursive.c",
            "build/entry_path_combined.c",
            "build/entry_path_closure.c",
        ):
            self.assertEqual(normalize_access_metadata(self.generated_function(ROOT / relative)),
                             normalize_access_metadata(fresh), relative)

    def test_allocation_and_segment_instruction_bytes_are_pinned(self):
        image = load_le(TARGET)
        obj = image.objects[0]
        code = bytes(image.mem[obj.base - image.mem_base : obj.base - image.mem_base + obj.virtual_size])
        section = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
        function = Disassembler(code, 0, [section]).disassemble_function(0x000C3CA9)
        instructions = {
            insn.address: (insn.bytes.hex().upper(), insn.mnemonic, insn.op_str)
            for block in function.blocks.values()
            for insn in block.instructions
        }
        expected = {
            0x000C3CC1: ("CD31", "int", "0x31"),
            0x000C3D21: ("CD21", "int", "0x21"),
            0x000C3D23: ("D1D0", "rcl", "eax, 1"),
            0x000C3D25: ("D1C8", "ror", "eax, 1"),
            0x000C3D27: ("89C2", "mov", "edx, eax"),
            0x000C3D35: ("CD21", "int", "0x21"),
            0x000C3D3B: ("89C6", "mov", "esi, eax"),
            0x000C3D3D: ("89C3", "mov", "ebx, eax"),
            0x000C3D3F: ("89D0", "mov", "eax, edx"),
            0x000C3D41: ("06", "push", "es"),
            0x000C3D42: ("8EC0", "mov", "es, eax"),
            0x000C3D46: ("CD21", "int", "0x21"),
            0x000C3D4C: ("07", "pop", "es"),
            0x000C3D4D: ("85F6", "test", "esi, esi"),
            0x000C3D4F: ("7C1E", "jl", "0xc3d6f"),
        }
        for address, expected_instruction in expected.items():
            self.assertEqual(instructions[address], expected_instruction, hex(address))

    def test_rationalalloc_lea_computes_offset_without_segment_or_memory_access(self):
        lifted = self.lift_one("8d5008")  # lea edx, [eax + 8]
        self.assertIn("edx = (eax + 0x8);", lifted)
        self.assertNotIn("DS_BASE", lifted)
        self.assertNotIn("recomp_begin_memory_access", lifted)
        self.assertNotIn("recomp_memory_fault_pending", lifted)

    def test_real_memory_read_still_uses_segment_base_and_guard(self):
        lifted = self.lift_one("8b5008")  # mov edx, [eax + 8]
        self.assertIn("recomp_begin_memory_access_ex(RECOMP_SEG_DS, 4u", lifted)
        self.assertIn("MEM32(DS_BASE + (eax + 0x8))", lifted)
        self.assertIn("recomp_memory_fault_pending()", lifted)

    def test_regenerated_rationalalloc_body_has_correct_lea_and_segment_load(self):
        for relative in (
            "build/recomp_catalog_100_recursive.c",
            "build/entry_path_combined.c",
            "build/entry_path_closure.c",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            start = source.index("void sub_000C3CA9(void) {")
            end = source.index("\n}", start) + 2
            body = source[start:end]
            lines = body.splitlines()
            lea = next(i for i, line in enumerate(lines) if "0x000C3CDF: lea edx" in line)
            self.assertIn("edx = (eax + 0x8);", lines[lea], relative)
            self.assertNotIn("DS_BASE", lines[lea], relative)
            self.assertNotIn("memory_access", "\n".join(lines[lea : lea + 2]), relative)
            self.assertIn("recomp_write_segment(RECOMP_SEG_ES, (uint16_t)(eax), 0x000C3D42u)", body)
            self.assertIn("0x000C3D46: int 0x21", body)


if __name__ == "__main__":
    unittest.main()
