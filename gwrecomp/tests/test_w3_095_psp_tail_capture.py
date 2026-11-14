import json
import unittest

from tools.w3_095_psp_tail_capture import bounded_jsonl_event, sample_tail


class PspTailCaptureTests(unittest.TestCase):
    def psp(self, length=0, tail=b"", terminator=0x0D):
        image = bytearray(256)
        image[0x80] = length
        image[0x81:0x81 + len(tail)] = tail
        image[0x81 + length] = terminator
        return bytes(image)

    def test_empty_tail_and_terminator(self):
        got = sample_tail(0x1000, 0x1010, self.psp())
        self.assertTrue(got.valid)
        self.assertEqual((got.length, got.tail_hex, got.cr_present), (0, "", True))

    def test_maximum_tail_is_bounded(self):
        tail = bytes(range(126))
        got = sample_tail(0x1000, 0x1010, self.psp(126, tail))
        self.assertTrue(got.valid)
        self.assertEqual(got.length, 126)
        self.assertEqual(bytes.fromhex(got.tail_hex), tail)

    def test_invalid_segment_or_short_allocation_rejected(self):
        self.assertEqual(sample_tail(0, 0x1010, self.psp()).status, "invalid_psp_segment")
        self.assertEqual(sample_tail(0x1000, 0x100F, self.psp()).status, "psp_range_invalid")

    def test_out_of_bounds_and_malformed_images_rejected(self):
        self.assertEqual(sample_tail(0xFFF0, 0xFFFF, self.psp()).status, "psp_range_invalid")
        self.assertEqual(sample_tail(0x1000, 0x1010, b"short").status, "psp_image_too_short")
        malformed = bytearray(self.psp())
        malformed[0x80] = 127
        self.assertEqual(sample_tail(0x1000, 0x1010, bytes(malformed)).status,
                         "length_exceeds_dos_psp_limit")

    def test_known_nine_byte_native_tail_shape(self):
        tail = b" -k 38928"
        got = sample_tail(0x1000, 0x1010, self.psp(len(tail), tail))
        self.assertTrue(got.valid)
        self.assertEqual(got.tail_hex, "202d6b203338393238")

    def test_event_json_and_one_event_limit(self):
        event = {"event": "w3_095_original_psp_tail", "tail_bytes_hex": "2d6b203338393238"}
        serialized, count = bounded_jsonl_event(event, 0)
        self.assertEqual(json.loads(serialized), event)
        self.assertEqual(count, 1)
        self.assertEqual(bounded_jsonl_event(event, count), (None, 1))


if __name__ == "__main__":
    unittest.main()
