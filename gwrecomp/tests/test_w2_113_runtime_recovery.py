"""Verify W2-113 pre-edit Python sources and isolated restoration."""
import hashlib
import json
import pathlib
import shutil
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "w2_113_runtime_recovery_manifest.json"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeRecoveryTests(unittest.TestCase):
    def test_copies_and_isolated_restore(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["task_id"], "W2-113")
        self.assertEqual(len(manifest["files"]), 2)
        for row in manifest["files"]:
            original = pathlib.Path(row["original_path"])
            backup = pathlib.Path(row["copy_path"])
            restored = pathlib.Path(row["restored_path"])
            self.assertTrue(backup.is_file())
            self.assertEqual(sha256(backup), row["original_sha256"])
            self.assertEqual(row["original_sha256"], row["copy_sha256"])
            restored.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, restored)
            self.assertEqual(sha256(restored), row["original_sha256"])
            self.assertEqual(row["original_sha256"], row["restored_sha256"])
            self.assertTrue(row["copy_match"] and row["isolated_restore_match"])
