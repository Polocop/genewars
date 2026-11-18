"""Synthetic byte/hash and isolated restore regression for W2-108."""
import json
import unittest
from pathlib import Path
from tools.verify_w2_108_runtime_recovery import verify_and_restore, ROOT

RESULT = ROOT / "evidence" / "w2_108_runtime_recovery_verification.json"


class W2RuntimeRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = verify_and_restore()
        RESULT.write_text(json.dumps(cls.result, indent=2) + "\n", encoding="utf-8")

    def test_all_authorized_source_and_copy_hashes_match(self):
        self.assertTrue(self.result["all_match"])
        self.assertEqual(len(self.result["restored_files"]), 7)
        self.assertTrue(all(item["matches"] for item in self.result["restored_files"]))

    def test_restoration_is_confined_to_temporary_copy(self):
        self.assertIn("unique temporary directory", self.result["restoration_target"])
        self.assertFalse(self.result["live_sources_modified"])
        self.assertTrue(RESULT.is_file())


if __name__ == "__main__":
    unittest.main()
