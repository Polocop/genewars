from __future__ import annotations

import struct
import unittest
from pathlib import Path

from tools.w3_270_post_present_static_frontier import (
    EXE,
    LINK_VA,
    map_le_link_va,
)


def synthetic_le() -> bytes:
    le_offset = 0x40
    object_table = 0xC4
    page_map = 0x124
    data_pages = 0x300
    image = bytearray(data_pages + 3 * 0x1000)
    struct.pack_into("<I", image, 0x3C, le_offset)
    image[le_offset:le_offset + 2] = b"LE"
    struct.pack_into("<I", image, le_offset + 0x28, 0x1000)
    struct.pack_into("<I", image, le_offset + 0x40, object_table)
    struct.pack_into("<I", image, le_offset + 0x44, 1)
    struct.pack_into("<I", image, le_offset + 0x48, page_map)
    struct.pack_into("<I", image, le_offset + 0x80, data_pages)
    struct.pack_into("<IIIIII", image, le_offset + object_table,
                     0x3000, 0x10000, 0x2045, 1, 3, 0)
    for index, page_number in enumerate((1, 2, 3)):
        start = le_offset + page_map + index * 4
        image[start:start + 3] = page_number.to_bytes(3, "big")
        image[start + 3] = 0
    return bytes(image)


class PostPresentStaticFrontierTests(unittest.TestCase):
    def test_le_page_map_translation_uses_object_page_and_big_endian_page_number(self):
        image = synthetic_le()
        mapped = map_le_link_va(image, 0x11234)
        self.assertEqual(mapped["object"], 1)
        self.assertEqual(mapped["object_offset"], 0x1234)
        self.assertEqual(mapped["page_number_one_based"], 2)
        self.assertEqual(mapped["page_offset"], 0x234)
        self.assertEqual(mapped["file_offset"], 0x1534)

    def test_hash_bound_gene_wars_frontier_maps_to_expected_file_bytes(self):
        image = EXE.read_bytes()
        mapped = map_le_link_va(image, LINK_VA)
        self.assertEqual(mapped["object"], 1)
        self.assertEqual(mapped["page_number_one_based"], 181)
        self.assertEqual(mapped["file_offset"], 0xF287E)
        self.assertEqual(image[mapped["file_offset"]:mapped["file_offset"] + 2],
                         bytes.fromhex("e440"))

    def test_invalid_or_unmapped_le_inputs_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "missing or truncated"):
            map_le_link_va(bytes(0x100), 0x10000)
        with self.assertRaisesRegex(ValueError, "outside all LE objects"):
            map_le_link_va(synthetic_le(), 0x20000)
        image = bytearray(synthetic_le())
        # A zero page number is explicitly not treated as file-backed data.
        image[0x40 + 0x124 + 4:0x40 + 0x124 + 7] = b"\x00\x00\x00"
        with self.assertRaisesRegex(ValueError, "not backed by file data"):
            map_le_link_va(bytes(image), 0x11234)


if __name__ == "__main__":
    unittest.main()
