import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "coordination"))

import autopilot
import taskq


class AutopilotFilesOwnedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="w2-121-")
        self.old_db = taskq.DB
        taskq.DB = pathlib.Path(self.temp.name) / "isolated.sqlite3"
        self.connection = taskq.con()
        migration_connection = autopilot.connect()
        if migration_connection is not self.connection:
            migration_connection.close()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.connection.close()
        taskq.DB = self.old_db
        self.temp.cleanup()

    def make_task(self, files_owned):
        return {
            "id": "W2-121-TEST",
            "title": "isolated files_owned fixture",
            "roles": ["WORK2"],
            "dependencies": [],
            "acceptance": ["synthetic isolated test"],
            "tests": [],
            "files": ["tests/owned.py"],
            "files_owned": files_owned,
        }

    def preview(self):
        out = io.StringIO()
        args = SimpleNamespace(id="W2-121-TEST", role="WORK2", resource=None)
        with mock.patch.object(autopilot, "connect", return_value=self.connection):
            with contextlib.redirect_stdout(out):
                result = autopilot.cmd_preview(args)
        return result, json.loads(out.getvalue())

    def test_null_queue_metadata_fails_closed_then_revision_restores_manifest_paths(self):
        task = self.make_task(["tests/owned.py"])
        taskq.add_task(self.connection, task, actor="WORK2")
        self.connection.execute(
            "UPDATE tasks SET files_owned='null' WHERE id=?", (task["id"],)
        )
        self.connection.commit()

        result, preview = self.preview()
        self.assertEqual(result, 2)
        self.assertFalse(preview["claimable"])
        self.assertIn("files_owned metadata", preview["reason"])

        with tempfile.TemporaryDirectory(prefix="w2-121-manifest-") as temp_dir:
            manifest = pathlib.Path(temp_dir) / "task.json"
            manifest.write_text(json.dumps(task), encoding="utf-8")
            args = SimpleNamespace(id=task["id"], file=str(manifest), actor="WORK2")
            with mock.patch.object(taskq, "con", return_value=self.connection), \
                 mock.patch.object(taskq, "rebuild_state", return_value=None):
                taskq.cmd_revise(args)

        stored = self.connection.execute(
            "SELECT files_owned,status,owner FROM tasks WHERE id=?", (task["id"],)
        ).fetchone()
        self.assertEqual(json.loads(stored["files_owned"]), ["tests/owned.py"])
        self.assertEqual(stored["status"], "READY")
        self.assertIsNone(stored["owner"])
        result, preview = self.preview()
        self.assertEqual(result, 0)
        self.assertTrue(preview["claimable"])

    def test_add_rejects_null_files_owned_instead_of_persisting_json_null(self):
        with self.assertRaisesRegex(ValueError, "files_owned must be a JSON array"):
            taskq.add_task(self.connection, self.make_task(None), actor="WORK2")
        self.assertIsNone(
            self.connection.execute(
                "SELECT 1 FROM tasks WHERE id='W2-121-TEST'"
            ).fetchone()
        )


if __name__ == "__main__":
    unittest.main()
