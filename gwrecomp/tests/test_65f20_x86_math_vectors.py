"""Small independent checks for the x86 fixed-point math recovered at 0x65F20.

This validates arithmetic against captured 14-byte map records. It does not
claim that an E19C0 record was rasterized into a particular screen pixel.
"""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
import json
import struct
import unittest
from pathlib import Path


EVIDENCE = Path((_GW_ROOT + '\\evidence\\fun_65f20_e19c0_before_after_samples.json'))


def s16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def s32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def x86_horizontal_fixed(word0: int, scale_byte: int) -> int:
    """Model 0x66040..0x66067, including 32-bit wrap and SBB carry."""
    product = s32((s16(word0) << 8) * (scale_byte & 0xFF))
    sign = -1 if product < 0 else 0
    shifted_sign = s32((sign << 6) & 0xFFFFFFFF)
    carry_from_shl = 1 if sign == -1 else 0
    adjusted = s32(product - shifted_sign - carry_from_shl)
    return (s32(adjusted >> 6) + 0x8000) & 0xFFFFFFFF


def x86_height_delta(height_word: int, scale: int) -> int:
    """Model 0x66021..0x66035: signed WORD SAR 6, then signed IMUL."""
    return s32((s16(height_word) >> 6) * s32(scale))


class Recovered65F20MathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    def test_captured_map_records_match_x86_horizontal_math(self):
        records = [r for sample in self.evidence["samples"]
                   for r in sample["map_record_candidates"]]
        self.assertGreaterEqual(len(records), 4)
        captured_vectors = set()
        for record in records:
            raw = bytes.fromhex(record["bytes14_hex"])
            self.assertEqual(len(raw), 14)
            word0 = struct.unpack_from("<H", raw, 0)[0]
            factor = raw[0x0C]
            captured_vectors.add((word0, factor))
        # Hard-coded expected results for observed source words, including the
        # one sample where byte +0x0C is 0x0B (byte +0x0D is separately 1).
        expected = {(0x1000, 0x00): 0x00008000,
                    (0x1000, 0x0B): 0x00034000}
        self.assertTrue(captured_vectors.issubset(expected.keys()))
        for word0, factor in captured_vectors:
            self.assertEqual(x86_horizontal_fixed(word0, factor),
                             expected[(word0, factor)])

    def test_signed_edge_cases_match_x86_sbb_rounding(self):
        vectors = [(0x0001, 1, 0x00008004),
                   (0xFFFF, 1, 0x00007FFC),
                   (0xF000, 1, 0x00004000),
                   (0x7FFF, 1, 0x00027FFC)]
        for word0, factor, expected in vectors:
            with self.subTest(word0=hex(word0)):
                self.assertEqual(x86_horizontal_fixed(word0, factor), expected)

    def test_captured_height_inputs_and_scale(self):
        records = [bytes.fromhex(r["bytes14_hex"])
                   for sample in self.evidence["samples"]
                   for r in sample["map_record_candidates"]]
        for raw in records:
            h = struct.unpack_from("<H", raw, 2)[0]
            for sample in self.evidence["samples"]:
                # The captured projection scale at 0x184AB4 is zero.
                self.assertEqual(sample["projection_globals_184aa4_to_184ab4"][4],
                                 "0x00000000")
            self.assertEqual(x86_height_delta(h, 0), 0)

    def test_e19c0_input_records_are_unchanged_in_captured_calls(self):
        for sample in self.evidence["samples"]:
            self.assertEqual(len(sample["vertex_records"]), 3)
            for record in sample["vertex_records"]:
                self.assertEqual(record["before_hex"], record["after_hex"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
