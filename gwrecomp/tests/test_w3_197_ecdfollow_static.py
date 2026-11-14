"""Synthetic tests for bounded x86 address translation and window decoding."""
import hashlib as _hashlib


class _OrigDigest:
    """Stands in for a byte string taken from the original game.

    Only its SHA-256 and length are stored in the repository. Comparing it with
    bytes (or a hex string) from the user's own locally provided game files
    succeeds when they hash to the recorded value.
    """

    def __init__(self, sha256, length):
        self.sha256 = sha256
        self.length = length

    def __len__(self):
        return self.length

    def __eq__(self, other):
        if isinstance(other, str):
            try:
                other = bytes.fromhex(other.replace(" ", ""))
            except ValueError:
                return False
        if not isinstance(other, (bytes, bytearray, memoryview)):
            return NotImplemented
        other = bytes(other)
        return len(other) == self.length and _hashlib.sha256(other).hexdigest() == self.sha256

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    __hash__ = None

    def __repr__(self):
        return "<original bytes sha256=%s len=%d>" % (self.sha256, self.length)
import unittest

from tools.w3_197_ecdfollow_static import decode_bytes


class EcdFollowStaticTests(unittest.TestCase):
    def test_runtime_to_link_conversion_uses_measured_rebase(self):
        rebase, link = 0x1EB000, 0xECD31
        runtime = rebase + link
        self.assertEqual(runtime, 0x2D7D31)
        self.assertEqual(runtime - rebase, link)

    def test_synthetic_instruction_window_keeps_exact_boundaries(self):
        raw = bytes.fromhex("2b0d00001000c1e104890d0400100087db87c987dba008001000")
        instructions = decode_bytes(raw, 0xECD2B)
        self.assertEqual([i["link_va"] for i in instructions],
                         [0xECD2B, 0xECD31, 0xECD34, 0xECD3A, 0xECD3C, 0xECD3E, 0xECD40])
        self.assertEqual(instructions[-1]["bytes"], "a008001000")
        self.assertEqual(sum(i["size"] for i in instructions), len(raw))


if __name__ == "__main__":
    unittest.main()
