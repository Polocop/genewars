"""Verify W2-112 pre-edit Runtime copies and isolated restore remain intact."""
import hashlib
import json
import pathlib
import shutil
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "w2_112_runtime_recovery_manifest.json"
RESTORE_ROOT = ROOT / "work" / "recovery" / "W2-112-20261009" / "restore-check"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeRecoveryTests(unittest.TestCase):
    def test_recovery_copy_and_isolated_restore(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["task_id"], "W2-112")
        self.assertEqual(len(manifest["files"]), 2)
        for row in manifest["files"]:
            copy_path = pathlib.Path(row["copy_path"])
            restored_path = pathlib.Path(row["restored_path"])
            self.assertTrue(copy_path.is_file())
            self.assertEqual(sha256(copy_path), row["original_sha256"])
            self.assertEqual(row["original_sha256"], row["copy_sha256"])
            restored_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(copy_path, restored_path)
            self.assertEqual(sha256(restored_path), row["original_sha256"])
            self.assertEqual(row["original_sha256"], row["restored_sha256"])
            self.assertTrue(row["copy_match"] and row["isolated_restore_match"])
