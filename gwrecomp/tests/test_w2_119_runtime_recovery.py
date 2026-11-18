"""Verify W2-119 source backups and repeat restoration in temporary storage."""

import hashlib
import json
import pathlib
import shutil
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "w2_119_runtime_recovery_manifest.json"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeRecoveryTests(unittest.TestCase):
    def test_prechange_copies_match_and_restore_isolated(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["task"], "W2-119")
        self.assertTrue(manifest["verification"]["all_hashes_match"])
        self.assertTrue(manifest["verification"]["restore_was_isolated"])
        self.assertTrue(manifest["verification"]["pre_edit_copy_restore_verified_before_runtime_edits"])
        self.assertEqual(len(manifest["files"]), 2)
        cache = ROOT / "cache"
        cache.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="w2_119_restore_", dir=cache) as td:
            target = pathlib.Path(td)
            for item in manifest["files"]:
                backup = pathlib.Path(item["backup"])
                self.assertTrue(item["hashes_match"])
                self.assertEqual(backup.stat().st_size, item["bytes"])
                self.assertEqual(sha256(backup), item["source_sha256"])
                self.assertEqual(sha256(backup), item["backup_sha256"])
                self.assertEqual(sha256(ROOT / pathlib.Path(item["source"])), item["current_sha256_after_change"])
                restored = target / pathlib.Path(item["source"]).name
                shutil.copyfile(backup, restored)
                self.assertEqual(sha256(restored), item["restored_sha256"])
                self.assertEqual(sha256(restored), item["source_sha256"])


if __name__ == "__main__":
    unittest.main()
