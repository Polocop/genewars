"""Verify the W2-115 independent Runtime backup and isolated restore hashes."""
import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "w2_115_runtime_recovery_manifest.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeRecoveryTests(unittest.TestCase):
    def test_backups_and_isolated_restore_match_prechange_hashes(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["task"], "W2-115")
        self.assertEqual(len(manifest["files"]), 2)
        for row in manifest["files"]:
            self.assertTrue(row["matches"])
            self.assertEqual(row["original_sha256"], row["backup_sha256"])
            self.assertEqual(row["original_sha256"], row["restore_sha256"])
            self.assertEqual(sha(pathlib.Path(row["backup"])), row["backup_sha256"])
            self.assertEqual(sha(pathlib.Path(row["restore_test"])), row["restore_sha256"])


if __name__ == "__main__":
    unittest.main()
