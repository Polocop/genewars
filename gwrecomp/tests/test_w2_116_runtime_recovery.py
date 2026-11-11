"""Verify W2-116's fresh independent Runtime C recovery copies."""
import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "w2_116_runtime_recovery_manifest.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeRecoveryTests(unittest.TestCase):
    def test_backups_and_isolated_restore_match_prechange_hashes(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["task"], "W2-116")
        self.assertEqual(len(manifest["files"]), 2)
        for row in manifest["files"]:
            self.assertTrue(row["matches"])
            self.assertEqual(row["source_sha256"], row["backup_sha256"])
            self.assertEqual(row["source_sha256"], row["restore_test_sha256"])
            self.assertEqual(sha(pathlib.Path(row["backup"])), row["backup_sha256"])
            self.assertEqual(sha(pathlib.Path(row["restore_test"])), row["restore_test_sha256"])


if __name__ == "__main__":
    unittest.main()
