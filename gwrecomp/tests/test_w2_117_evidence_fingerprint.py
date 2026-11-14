import json
import re
import unittest
from pathlib import Path


class EvidenceFingerprintTest(unittest.TestCase):
    def test_w2_116_source_runtime_hash_matches_w3_214(self):
        w2 = json.loads(Path("evidence/w2_116_dpmi6300_native_provider.json").read_text(encoding="utf-8"))
        w3 = json.loads(Path("evidence/w3_214_ax6300_pointer_capture.json").read_text(encoding="utf-8"))
        expected = w3["source"]["runtime_sha256"]
        actual = w2["original"]["runtime_sha256"]
        self.assertRegex(actual, re.compile(r"^[0-9a-f]{64}$"))
        self.assertEqual(actual, expected)
        self.assertEqual(w2["original"]["source_runtime_sha256"], expected)


if __name__ == "__main__":
    unittest.main()