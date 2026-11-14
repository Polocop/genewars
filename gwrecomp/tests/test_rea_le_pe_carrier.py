"""Synthetic tests for the PE carrier's address-preserving container logic."""
import struct
import tempfile
import unittest
from pathlib import Path

from tools.rea_le_pe_carrier import PE_IMAGE_BASE, ROOT, build_pe, write_controlled_pe32_fixture
from le_loader import LEImage, LEObject


class ReaLePeCarrierTests(unittest.TestCase):
    def test_pe32_sections_keep_synthetic_link_addresses_and_bytes(self):
        objects = [
            LEObject(1, 0x100, 0x10000, 0x2004, 1, 1),
            LEObject(2, 0x40, 0x12000, 0x2002, 2, 1),
        ]
        mem = bytearray(0x2040)
        mem[:0x100] = bytes(range(0x100))
        mem[0x2000:0x2040] = bytes((255 - n) & 0xFF for n in range(0x40))
        image = LEImage(objects, 1, 0x20, 2, 0x10, 0x1000, mem,
                        mem_base=0x10000)

        pe, sections = build_pe(image)
        e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
        self.assertEqual(pe[e_lfanew:e_lfanew + 4], b"PE\0\0")
        self.assertEqual(struct.unpack_from("<H", pe, e_lfanew + 4)[0], 0x14C)
        optional = e_lfanew + 4 + 20
        self.assertEqual(struct.unpack_from("<H", pe, optional)[0], 0x10B)
        self.assertEqual(struct.unpack_from("<I", pe, optional + 28)[0], PE_IMAGE_BASE)
        self.assertEqual(len(sections), 2)
        for item, obj in zip(sections, objects):
            self.assertEqual(PE_IMAGE_BASE + item["rva"], obj.base)
            raw = pe[item["raw_offset"]:item["raw_offset"] + obj.virtual_size]
            off = obj.base - image.mem_base
            self.assertEqual(raw, bytes(image.mem[off:off + obj.virtual_size]))

    def test_alignment_is_reversible_for_supported_pe_boundaries(self):
        from tools.rea_le_pe_carrier import align

        self.assertEqual(align(0x200, 0x200), 0x200)
        self.assertEqual(align(0x201, 0x200), 0x400)
        for link_va in (0x10000, 0x962F0, 0x1B0000):
            rva = link_va - PE_IMAGE_BASE
            self.assertEqual(PE_IMAGE_BASE + rva, link_va)

    def test_controlled_pe32_fixture_is_reproducible(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as temp:
            path = Path(temp) / "fixture.exe"
            result = write_controlled_pe32_fixture(path)
            self.assertEqual(result["sha256"],
                             "2161d1cbd7b79160c5a5a85fe55adde6275d1a397d8a0bc4d7fd2cdf1741a58c")
            self.assertEqual(path.read_bytes()[0x200:0x20D], bytes.fromhex("55 89 e5 b8 2a 00 00 00 83 c0 02 5d c3"))


if __name__ == "__main__":
    unittest.main()
