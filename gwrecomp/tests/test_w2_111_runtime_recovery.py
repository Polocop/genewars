"""Verify W2-111 pre-change Runtime copies and isolated restoration hashes."""

import hashlib
import json
import pathlib
import shutil
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "w2_111_runtime_recovery_manifest.json"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeRecoveryTests(unittest.TestCase):
    def test_copies_match_manifest_and_restore_isolated(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["task"], "W2-111")
        self.assertEqual(len(manifest["files"]), 2)
        with tempfile.TemporaryDirectory(prefix="w2_111_restore_", dir=ROOT / "cache") as td:
            target = pathlib.Path(td)
            for item in manifest["files"]:
                copy = ROOT / pathlib.Path(item["recovery_copy_path"])
                self.assertEqual(copy.stat().st_size, item["byte_count"])
                self.assertEqual(sha256(copy), item["original_sha256"])
                self.assertEqual(sha256(copy), item["recovery_sha256"])
                restored = target / pathlib.Path(item["production_path"]).name
                shutil.copyfile(copy, restored)
                self.assertEqual(sha256(restored), item["isolated_restore_sha256"])
                self.assertEqual(sha256(restored), item["original_sha256"])


if __name__ == "__main__":
    unittest.main()
